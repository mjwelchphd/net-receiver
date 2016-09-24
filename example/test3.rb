#! /usr/bin/ruby

## For testing ...
# put in your website address in place of www.example.com
# swaks -s www.example.com:2000 -t coco@smith.com -f jamie@glock.com --ehlo example.com
# swaks -tls -s www.example.com:2000 -t coco@smith.com -f jamie@glock.com --ehlo example.com

require 'net/receiver'
require 'logger'
require 'sequel'
require 'yaml'
require 'pretty_inspect'

class Receiver < Net::ReceiverCore

  def password(username)
    DB[:mailboxes].where(:email=>username).first[:passwd]
  end

  def received(mail)
puts "--> *99* #{mail.pretty_inspect}"
  end

end

# Open the log
LOG = Logger::new('log/test3.log', 'daily')
LOG.formatter = proc do |severity, datetime, progname, msg|
  pname = if progname then '('+progname+') ' else nil end
  "#{datetime.strftime("%Y-%m-%d %H:%M:%S")} [#{severity}] #{pname}#{msg}\n"
end

# Open the database
if ['dev','live'].index(ENV['MODE']).nil?
  msg = "Environmental variable MODE not set properly--must be dev or live"
  LOG.fatal(msg)
  puts msg
  exit(1)
end
host = YAML.load_file("./database.yml")[ENV['MODE']]
DB = Sequel.connect(host)
LOG.info("Database \"#{host['database']}\" opened")

# Start the server
options = {
#  :server_name=>"www.example.com",
  :private_key=>"server.key",
  :certificate=>"server.crt",
  :listening_ports=>['2000','2001'],
  #========================================
#  :ehlo_validation_check=>true
}
Net::Server.new(options).start
