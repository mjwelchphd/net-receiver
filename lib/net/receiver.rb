# = net/receiver.rb
#
# Copyright (c) 2016 Michael J. Welch, Ph.D.
#
# Written and maintained by Michael J. Welch, Ph.D. <mjwelchphd@gmail.com>
#
# This work is not derived from any other author. It is original software.
#
# Documented by Michael J. Welch, Ph.D. <mjwelchphd@gmail.com>
#
# This program is free software. You can re-distribute and/or
# modify this program under the same terms as Ruby itself.
#
# See the README.md for documentation.

require 'net/server'
require 'net/item_of_mail'
require 'net/extended_classes'
require 'pdkim'
require 'spf'

class Slam < Exception; end

module Net

  # == An Email receiver
  class ReceiverCore
    CRLF = "\r\n"
    Patterns = [
      [0, "[ /t]*QUIT[ /t]*", :do_quit],
      [1, "[ /t]*AUTH[ /t]*(.+)", :do_auth],
      [1, "[ /t]*EHLO(.*)", :do_ehlo],
      [1, "[ /t]*EXPN[ /t]*", :do_expn],
      [1, "[ /t]*HELO[ /t]+(.*)", :do_ehlo],
      [1, "[ /t]*HELP[ /t]*", :do_help],
      [1, "[ /t]*NOOP[ /t]*", :do_noop],
      [1, "[ /t]*RSET[ /t]*", :do_rset],
      [1, "[ /t]*VFRY[ /t]*", :do_vfry],
      [2, "[ /t]*STARTTLS[ /t]*", :do_starttls],
      [2, "[ /t]*MAIL FROM[ /t]*:[ \t]*(.+)", :do_mail_from],
      [3, "[ /t]*RCPT TO[ /t]*:[ \t]*(.+)", :do_rcpt_to],
      [4, "[ /t]*DATA[ /t]*", :do_data]
    ]
    Kind = {:mailfrom=>"MAIL FROM", :rcptto=>"RCPT TO"}
    ReceiverTimeout = 30
    LogConversation = true
    Unexpectedly = "; probably caused by the client closing the connection unexpectedly"

    include PDKIM

    DkimOutcomes = {
      PDKIM_VERIFY_NONE=>"PDKIM_VERIFY_NONE",
      PDKIM_VERIFY_INVALID=>"PDKIM_VERIFY_INVALID",
      PDKIM_VERIFY_FAIL=>"PDKIM_VERIFY_FAIL",
      PDKIM_VERIFY_PASS=>"PDKIM_VERIFY_PASS",
      PDKIM_FAIL=>"PDKIM_FAIL",
      PDKIM_ERR_OOM=>"PDKIM_ERR_OOM",
      PDKIM_ERR_RSA_PRIVKEY=>"PDKIM_ERR_RSA_PRIVKEY",
      PDKIM_ERR_RSA_SIGNING=>"PDKIM_ERR_RSA_SIGNING",
      PDKIM_ERR_LONG_LINE=>"PDKIM_ERR_LONG_LINE",
      PDKIM_ERR_BUFFER_TOO_SMALL=>"PDKIM_ERR_BUFFER_TOO_SMALL"
    }

    def initialize(connection, options)
      @connection = connection
      @option_list = [[:ehlo_validation_check, false], [:sender_character_check, true],
        [:recipient_character_check, true], [:sender_mx_check, true],
        [:recipient_mx_check, true],[:max_failed_msgs_per_period,3],
        [:copy_to_sysout, false]]
      @options = options
      @option_list.each do |key,value|
        @options[key] = value if !options.has_key?(key)
      end
      @enc_ind = '-'
    end

#=======================================================================
# send text to the client

    def send_text(text,echo=true)
      if !text.nil?
        text = [ text ] if text.class==String
        text.each do |line|
          puts "<#{@enc_ind}  #{text.inspect}" if @options[:copy_to_sysout]
          @connection.write(line)
          @connection.write(CRLF)
          @has_level_5_warnings = true if line[0]=='5'
          LOG.info("%06d"%Process::pid) {"<#{@enc_ind}  #{text}"} if echo && LogConversation
          m = line.match(/^5[0-9]{2} [0-9]\.[0-9]\.[0-9] (.*)$/)
          LOG.error("%06d"%Process::pid) {m[1]} if m
        end
      end
      return nil
    end

#=======================================================================
# receive text from the client

    def recv_text(echo=true)
      Timeout.timeout(ReceiverTimeout) do
        raise Slam if (temp = @connection.gets).nil?
        text = temp.chomp
        LOG.info("%06d"%Process::pid) {" #{@enc_ind}> #{text}"} if echo && LogConversation
        puts " #{@enc_ind}> #{text.inspect}" if @options[:copy_to_sysout]
        return text
      end
    end

#=======================================================================
# parse the email address and investigate it

    def psych_value(kind, part, value)
      # the value gets set in both MAIL FROM and RCPT TO
      part[:value] = value

      # check for a bounce message
      case
      when (kind==:mailfrom) & (m = value.match(/^(.*)<>$/))
        # it's a bounce message
        part[:name] = m[1].strip
        part[:url] = "<>"
        return nil
      when (m = value.match(/^(.*)<(.+@.+\..+)>$/)).nil?
        # there MUST be a sender/recipient address
        return "501 5.1.7 '#{part[:value]}' No proper address (<...>) on the #{Kind[kind]} line" \
      end

      # break up the address
      part[:name] = m[1].strip
      part[:url] = url = m[2].strip

      # parse out the local-part and domain
      local_part, domain = url.split("@")
      part[:local_part] = local_part
      part[:domain] = domain

      if ((kind==:mailfrom) && (@options[:sender_character_check])) \
        || ((kind==:rcptto) && (@options[:recipient_character_check]))
        # check the local part:
        # uppercase and lowercase English letters (a-z, A-Z)
        # digits 0 to 9
        # characters ! # $ % & ' * + - / = ? ^ _ ` { | } ~
        part[:bad_characters] = local_part.match(/^[a-zA-Z0-9\!\#\$%&'*+-\/?^_`{|}~]+$/).nil?
        # check character . must not be first or last character,
        #   and must not appear two or more times consecutively
        part[:wrong_dot_usage] = !(local_part[0]=='.' || local_part[-1]=='.' || local_part.index('..')).nil?
      end

      # skip this if not needed
      if ((kind==:mailfrom) && (@options[:sender_mx_check])) \
        || ((kind==:rcptto) && (@options[:recipient_mx_check]))
        # get the ip for this domain
        part[:ip] = ip = domain.dig_a

        # get the mx record(s)
        part[:mxs] = mxs = domain.dig_mx

        # get the mx's ip records
        if mxs
          part[:ips] = ips = []
          mxs.each { |mx| ips << mx.dig_a }
        end
      end

      # email address investigation completed
      return nil
    end

#=======================================================================
# receive the connection

    def receive(local_port, local_hostname, remote_port, remote_hostname, remote_ip)
      # Start a hash to collect the information gathered from the receive process
      @mail = Net::ItemOfMail::new(local_port, local_hostname, remote_port, remote_hostname, remote_ip)
      @mail[:accepted] = false
      @mail[:prohibited] = false

      # start the main receiving process here
      @done = false
      @mail[:encrypted] = false
      @mail[:authenticated] = false
      send_text(do_connect(remote_ip))
      @level = 1
      @has_level_5_warnings = false

      begin
        break if @done
        text = recv_text
        unrecognized = true
        Patterns.each do |pattern|
          break if pattern[0]>@level
          m = text.match(/^#{pattern[1]}$/i)
          if m
            case
            when pattern[2]==:do_quit
              send_text(do_quit(m[1]))
            when @mail[:prohibited]
              send_text("450 4.7.1 Sender IP #{@mail[:remote_ip]} is temporarily prohibited from sending")
            when pattern[0]>@level
              send_text("503 5.5.1 Command out of sequence")
            else
              send_text(send(pattern[2], m[1].to_s.strip))
            end
            unrecognized = false
            break
          end
        end
        if unrecognized
          response = "500 5.5.1 Unrecognized command #{text.inspect}, incorrectly formatted command, or command out of sequence"
          send_text(response)
        end
      end until @done

    rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET, Errno::EIO, Errno::EPIPE, Timeout::Error => e
      LOG.error("%06d"%Process::pid) {e}
      @mail[:accepted] = false

    rescue Slam
      LOG.info("%06d"%Process::pid) {"Sender slammed the connection shut IP=#{@mail[:remote_ip]}"}
      @mail[:accepted] = false

    rescue => e
      # this is the "rescue of last resort"... for "when sh*t happens"
      LOG.fatal("%06d"%Process::pid) {e.inspect}
      e.backtrace.each { |line| LOG.fatal("%06d"%Process::pid) {line} }
      @mail[:accepted] = false

    ensure
      # the email is either "received" or not, then when the
      # return is executed, the process terminates
      status = if @mail[:accepted] then 'Received' else 'Rejected' end
      LOG.info("%06d"%Process::pid) {"#{status} mail with id '#{@mail[:id]}'"}
      received(@mail)
      # This is the end, beautiful friend
      # This is the end, my only friend
      # The end -- Jim Morrison
      return nil # terminates the process
    end

#=======================================================================
# these methods provide all the basic processing that needs to be done
# regardless of any additional checks that you make want to make

    def ok?(msg)
      msg[0]!='4' && msg[0]!='5'
    end

    def do_connect(value)
      LOG.info("%06d"%Process::pid) {"New item of mail opened with id '#{@mail[:id]}'"}
      @mail[:connect] = p = {}
      p[:value] = value

      # this doesn't work with IPv4 addresses 'mapped' into IPv6, ie, ::ffff...
      p[:domain] = value.dig_ptr

      @level = 1 if ok?(msg = connect(p))
      return msg
    end

    def do_ehlo(value)
      @mail[:ehlo] = p = {}
      p[:value] = value
      p[:fip] = p[:rip] = nil
      p[:rip] = rip = value.dig_a # reverse IP
      p[:domain] = domain = rip.dig_ptr if rip
      p[:fip] = domain.dig_a if domain # forward IP

      return ("550 5.5.0 The domain name in EHLO does not validate") \
        if @options[:ehlo_validation_check] && (p[:rip].nil? || p[:fip].nil? || p[:rip]!=p[:fip])

      @level = 2 if ok?(msg = ehlo(p))
      return msg
    end

    def do_quit(value)
      @done = true if ok?(msg = quit(value))
      return msg
    end

    def do_auth(value)
      auth_type, auth_encoded = value.split
      # auth_encoded contains both username and password
      case auth_type.upcase
      when "PLAIN"
        # get the password hash from the database
        username, ok = auth_encoded.validate_plain do |username|
          password(username)
        end
        if ok
          @mail[:authenticated] = username
          return "235 2.0.0 Authentication succeeded"
        else
          return "530 5.7.5 Authentication failed"
        end
      else
        return "504 5.7.6 authentication mechanism not supported"
      end
    end

    def do_expn(value)
      @mail[:expn] = p = {}
      p[:value] = value
      return expn(p)
    end

    def do_help(value)
      return help(value)
    end

    def do_noop(value)
      return noop(value)
    end

    def do_rset(value)
      @level = 0 if ok?(msg = rset(value))
      return msg
    end

    def do_vfry(value)
      @mail[:vfry] = p = {}
      p[:value] = value
      return vfry(p)
    end

    def do_starttls(value)
      send_text("220 2.0.0 TLS go ahead")
      @connection.accept
      @mail[:encrypted] = true
      @enc_ind = '~'
      return nil
    end

    def do_mail_from(value)
      @mail[:mailfrom] = p = {:accepted=>false}
      @mail[:rcptto] = []
      msg = psych_value(:mailfrom, p, value)
      return (msg) if msg

      if ok?(msg = mail_from(p))
        p[:accepted] = true
        @level = 3
      end
      return msg
    end

    def do_rcpt_to(value)
      @mail[:rcptto] ||= []
      @mail[:rcptto] << p = {:accepted=>false}

      msg = psych_value(:rcptto, p, value)
      return (msg) if msg

      if ok?(msg = rcpt_to(p))
        p[:accepted] = true
        @level = 4
      end
      return msg
    end

    def do_data(value)
      @mail[:data] = body = {}
      body[:accepted] = false
      # receive the body of the mail
      body[:value] = value # this should be nil -- no argument on the DATA command
      body[:headers] = headers = {}
      body[:text] = lines = []
      send_text("354 3.0.0 Enter message, ending with \".\" on a line by itself", false)
      LOG.info("%06d"%Process::pid) {" -> (email message)"} if LogConversation

      # get the headers into a hash
      while true
        text = recv_text(false)
        if text.strip.empty?
          body[:accepted] = true
          break
        end
        m = text.match(/^(.+?):(.+)$/)
        return "501 5.5.2 Malformed header" if m.nil?
        headers[m[1]] = m[2]
      end

      # get the body into an array of strings
      while true
        text = recv_text(false)
        if text=="."
          body[:accepted] = true
          break
        end
        lines << text
      end

      # check the DKIM headers, if any
      ok, signatures = pdkim_verify_an_email(PDKIM_INPUT_NORMAL, @mail[:data][:text])
      signatures.each do |signature|
        @log.info("%06d"%Process::pid){"Signature for '#{signature[:domain]}': #{PdkimReturnCodes[signature[:verify_status]]}"}
        @mail[:signatures] ||= []
        @mail[:signatures] << [signature[:domain], signature[:verify_status], DkimOutcomes[signature[:verify_status]]]
      end if ok==PDKIM_OK

      # check the SPF, if any
      begin
        spf_server = SPF::Server.new
        request = SPF::Request.new(
          versions:      [1, 2],
          scope:         'mfrom',
          identity:      @mail[:mailfrom][:url],
          ip_address:    @mail[:remote_ip],
          helo_identity: @mail[:ehlo][:domain])
        @mail[:mailfrom][:spf] = spf_server.process(request).code
      rescue SPF::OptionRequiredError => e
        @log.info("%06d"%Process::pid) {"SPF check failed: #{e.to_s}"}
        @mail[:mailfrom][:spf] = :fail
      end

      # test all the RCPT TOs
      any_rcptto_accepted = false
      @mail[:rcptto].each { |p| any_rcptto_accepted = true if p[:accepted] } if @mail.has_key?(:rcptto)
      # passed thru the guantlet with no failures
      @mail[:accepted] = true \
        if @mail[:mailfrom][:accepted] &&
          any_rcptto_accepted &&
          @mail[:data][:accepted] &&
          @has_level_5_warnings==false

      msg = data(p)
      @level = 1
      return msg
    end

#=======================================================================
# these are the defaults, in case the user doesn't override--you can
# override these in your Receiver class in order to add tests

    def connect(remote_ip)
      return "220 2.0.0 ESMTP RubyMTA 0.01 #{Time.new.strftime("%^a, %d %^b %Y %H:%M:%S %z")}"
    end

    def ehlo(p)
      msg = ["250-2.0.0 #{p[:value]} Hello"]
      msg << "250-STARTTLS" if !@mail[:encrypted]
      msg << "250-AUTH PLAIN"
      msg << "250 HELP"
      return msg
    end

    def quit(value)
      return "221 2.0.0 OK #{"example.com"} closing connection"
    end

    def auth(value)
      return "235 2.0.0 Authentication succeeded"
    end

    def password(username)
      return nil
    end

    def expn(value)
      return "252 2.5.1 Administrative prohibition"
    end

    def help(value)
      return "250 2.0.0 QUIT AUTH, EHLO, EXPN, HELO, HELP, NOOP, RSET, VFRY, STARTTLS, MAIL FROM, RCPT TO, DATA"
    end

    def noop(value)
      return "250 2.0.0 OK"
    end

    def rset(value)
      return "250 2.0.0 Reset OK"
    end

    def vfry(value)
      return "252 2.5.1 Administrative prohibition"
    end

    def mail_from(value)
      return "250 2.0.0 OK"
    end

    def rcpt_to(value)
      return "250 2.0.0 OK"
    end

    def data(value)
      return "250 2.0.0 OK id=#{@mail[:id]}"
    end

    def received(mail)
      # nothing here--just a placeholder
    end
  end
end
