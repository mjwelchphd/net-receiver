# = net/item_of_mail.rb
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

require 'sequel'

module Net
  class ItemOfMail < Hash
    def initialize(local_port, local_hostname, remote_port, remote_hostname, remote_ip)
      self[:local_port] = local_port
      self[:local_hostname] = local_hostname
      self[:remote_port] = remote_port
      self[:remote_hostname] = remote_hostname
      self[:remote_ip] = remote_ip

      new_id = []
      new_id[0] = Time.now.tv_sec.to_s(36).upcase
      new_id[1] = ("000000"+(2176782336*rand).to_i.to_s(36))[-6..-1].upcase
      new_id[2] = ("00"+(Time.now.usec/1000).to_i.to_s(36))[-2..-1].upcase
      self[:id] = new_id.join("-")

      self[:time] = Time.now.strftime("%Y-%m-%d %H:%M:%S %z")
    end

    def parse_headers
      self[:data][:headers] = {}
      header = ""
      self[:data][:text].each do |line|
        case
        when line.nil?
          break
        when line =~ /^[ \t]/
          header << String::new(line)
        when line.empty?
          break
        when !header.empty?
          keyword, value = header.split(":", 2)
          self[:data][:headers][keyword.downcase.gsub("-","_").to_sym] = value.strip
          header = String::new(line)
        else
          header = String::new(line)
        end
      end
      if !header.empty?
        keyword, value = header.split(":", 2)
        self[:data][:headers][keyword.downcase.gsub("-","_").to_sym] = if !value.nil? then value.strip else "" end
      end
    end

    def spf_check(scope,identity,ip,ehlo)
      spf_server = SPF::Server.new
      begin
        request = SPF::Request.new(
          versions:      [1, 2],
          scope:         scope,
          identity:      identity,
          ip_address:    ip,
          helo_identity: ehlo)
        spf_server.process(request).code
      rescue SPF::OptionRequiredError => e
        @log.info("%06d"%Process::pid) {"SPF check failed: #{e.to_s}"}
        :fail
      end
    end
  end
end
