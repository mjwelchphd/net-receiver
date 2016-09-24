# Net::Receiver

# EXPERIMENTAL EMAIL RECEIVER

This is an experimental email receiver which is currently (v1.0.0) working, but may be revised in ways that I can't predict at the moment. All I can guarantee is that _if_ the interface changes, it won't be major.

Currently, I'm using this as the base for an MTA written in Ruby. There's no intention of replacing Exim, Courier, or Postfix (or any other) existing MTA. The reason I'm doing this is because I need an MTA which has capabilities the standard MTAs don't offer. In other words, I need features not previously anticipated by the makers of those standard MTAs (and why would they have anticipated something I would think up in the future?)

That being said, If you use this for anything, and want me to make special changes that don't interfere with my purpose, email me at mjwelchphd@gmail.com, and I'll work with you as best I can.

# General

This gem sits on top of my net-server gem, and receives standard emails. It has only a few checks that it makes on the incoming email, leaving the specialized checks up to you. You can change it's behavior by overriding base methods, and adding your own programming; don't worry, I'll show you how. Your Ruby overrides are the same as witing a configuration file for a standard MTA.

This document describes the interface, and provides a sample program, so you can see how it works in every detail. The sample program is stored in the `example` directory.

## What This Does

This gem received the connection from net-server, receives the email by carrying on a conversation in SMTP with the sender, and finally delivers the finished email to you. It logs stuff, if the log is enabled, and, at the moment, I have debugging in it to write to the terminal, so that I can debug more easily. Those `puts` will go away in the future.

## TODO!

There's still stuff I need to do. A few notes in the source are prefaced with TODO! to make them easy to find. To be truthful, I'm not sure of what I may need to add, if much, in the future. I've written the receiving part of my MTA on top of this gem, so I believe that this gem is 99% complete, for what it was intended.

I also need to add a method to convert the email to the format used by the Net/* standard library classes.

However, I may also move the code to do `dig`, test for live servers, and other handy stuff into here, which will help you in your project.

# A Sample Program

Here's a sample program to demonstrate how the interface works. The complete source is in the `example` directory, so you can actually run it and see what happens. Look for the notations `#(1), #(2)` and so forth.  These reference the notes below.

```ruby
#! /usr/bin/ruby #(1)

## For testing ...
# put in your website address in place of www.example.com
# swaks -s www.example.com:2000 -t coco@smith.com -f jamie@glock.com --ehlo example.com
# swaks -tls -s www.example.com:2000 -t coco@smith.com -f jamie@glock.com --ehlo example.com

require 'net/receiver' #(2)
require 'logger'
require 'sequel'
require 'yaml'
require 'pretty_inspect'

class Receiver < Net::ReceiverCore #(3)

  def password(username) #(4)
#    DB[:mailboxes].where(:email=>username).first[:passwd]
  end

  def received(mail) #(5)
    puts "--> *99* #{mail.pretty_inspect}"
  end

end

# Open the log #(6)
LOG = Logger::new('log/test3.log', 'daily')
LOG.formatter = proc do |severity, datetime, progname, msg|
  pname = if progname then '('+progname+') ' else nil end
  "#{datetime.strftime("%Y-%m-%d %H:%M:%S")} [#{severity}] #{pname}#{msg}\n"
end

# Open the database #(7)
if ['dev','live'].index(ENV['MODE']).nil?
  msg = "Environmental variable MODE not set properly--must be dev or live"
  LOG.fatal(msg)
  puts msg
  exit(1)
end
host = YAML.load_file("./database.yml")[ENV['MODE']]
DB = Sequel.connect(host)
LOG.info("Database \"#{host['database']}\" opened")

# Start the server #(8)
options = {
  :server_name=>"www.example.com",
  :private_key=>"server.key",
  :certificate=>"server.crt",
  :listening_ports=>['2000','2001'],
  :ehlo_validation_check=>true
}
Net::Server.new(options).start
```
Here's the breakdown (see references like #(1), etc.):

  1. This line makes `test3` self executing.
  2. There are requires for `net/receiver`. It will require `net/server`, so you don't have to do that. It requires `logger` to demonstrate how to open a logger file; `sequel` because I use Sequel in my programming; `yaml` for reading the database 'yaml' file in the project (you'll have to change all this database stuff to your liking); and `pretty_inspect` which makes it easier to see what's coming out (you can install the gem for that).
  3. Define your receiver like this. The base in `net-receiver` is called `ReceiverCore` in order that you can derive class `Receiver` from it.
  4. In order to use authorization (only PLAIN supported at this time), you need this code to provide the password for a user.
  5. The received email is delivered to the `received` method. See the example of what gets delivered below.
  6. This is how to open a log file. The name LOG is used because it is traditional.
  7. This is how you open a Sequel/MySQL database. You may remove this code if you don't use Sequel to read passwords from the database.
  8. The last part is the server start code. Look at "https://github.com/mjwelchphd/net-server" documentation for more information.
  
# How It Works

The class ReceiverCode uses a table named Patterns to guide the receiving process. For each line of the table, the number on the left is a 'level', i.e., STARTTLS (level 2) cannot come before EHLO or HELO (level 1). The pattern describing the value is next: the input value on the command line must match this pattern. The method which handles the command is last.

As each line is read on the communications channel, it is matched up with this table, and if all is well, the method is called to deal with it.

The `send_text` and `recv_text` methods are complex because they have to handle conditions like the client slamming the communications channel shut, and so forth.

The method `psych_value` is used with MAIL FROM and RCPT TO commands to validate and investigate the email addresses given.

  1. It checks that there is a legitimate address, with or with a preceeding name.
  2. It breaks the address up into a local-part and a domain.
  3. If the option is selected, it tests for the legal usage of dots (".") in the name, and legal characters which net-receiver defines as 
    - uppercase and lowercase English letters (a-z, A-Z)
    - digits 0 to 9
    - characters ! # $ % & ' * + - / = ? ^ _ ` { | } ~
    - dots, which must not be first or last character, and must not appear two or more times consecutively
  4. If the option is selected, it does a Dig MX lookup, followed by a Dig A (IP) lookup if the MX was successful. This is helpful to determine if the sender's domain is legitimate.

The main method is the `receive` method (which is called by net-server when a connection is requested). Receive uses the aforementioned table to read the commands and process them. It also allocates an 'item of mail' structure to put it's findings in.

If `@mail[:prohibited] gets set to `true`, the loop will terminate and the connection will be closed. This is mainly for shutting down spammers who make large numbers of calls in a short period of time (DDOS attacks).

Any method can `raise Quit` in order to terminate the reception also.

When the main loop terminates, for whatever reason, the email will be delivered to your `received` method. When your `received` method terminates, the process is cleaned up and terminated.

Methods that begin with `do_` are the methods with do any generalized processing of the commands. Typically, they create a key in the item-of-mail and all the data for that command is stored in that hash. There are very few validations of the incoming data because that is the job of your method overrides (to be described below).

Methods that are named the same as the commands, i.e., `connect`, `ehlo`, `quit`, `auth`, `expn`, `help`, `noop`, `rset`, `vfry`, `mail_from`, `rcpt_to`, and `data` deliver the default response back to the `receive` method.

You can change their behavior by overriding them like this example:

```ruby
class Receiver < Net::ReceiverCore

    def mail_from(from)
      return "556 5.7.27 Traffic on port #{@options[:submission_port]} must be authenticated" \
        if !@mail[:authenticated]
      return "556 5.7.27 Traffic on port #{@options[:submission_port]} must be encrypted" \
        if !@mail[:encrypted]
      super
    end

end
```

In this example, `def mail_from` overrides the method of the same name in ReceiverCore. It tests :authenticated and :encrypted, and if there is an error, it returns the error message; if not, it performs `super` which returns the default message. Don't forget to call `super`.

# Start Options for Server
  
  Option | Default | Description
  --- | --- | ---
  :server_name | "example.com" | This name is only used in error messages.
  :listening_ports | ["25","486","587"] | An array of one or more ports to listen on.
  :private_key | Internal key | The key for encrypting/decrypting the data when in TLS mode.
  :certificate | Internal self-signed certificate | The certificate for encrypting/decrypting the data when in TLS mode. This may be your own self-signed certificate, or one you purchase from a Certificate Authority, or you can become a Certificate Authority and sign your own.
  :user_name | nil | This name is the user name to which each process will be switched after it is created. If it is nil, the ownership of the process will not be changed after creation. If you are using a port less than 1024, you must start the server as root, and the user name and group name of the process _must be_ specified.
  :group_name | nil | This name is the group name to which each process will be switched after it is created.
  :working_directory | the current path | The location of the program running the server.
  :pid_file | "pid" | The PID of the server will be stored in this file.
  :daemon | false | If this option is true, the server will be started as a daemon.

# Start Options for Receiver
  
  Option | Default | Description
  --- | --- | ---
  :ehlo_validation_check | false | This makes `receiver` test the domain name given on the EHLO or HELO line.
  :sender_character_check | true | This makes `receiver` test for legal characters on the MAIL FROM address.
  :recipient_character_check | false | This makes `receiver`test for legal characters on the RCPT TO address.
  :sender_mx_check | true | Tries to obtain the MX name and IP from the DNS for MAIL FROM.
  :recipient_mx_check | false | Tries to obtain the MX name and IP from the DNS for RCPT TO.
  :max_failed_msgs_per_period | 3 | I use this to say, "after 3 failed attempts, lock out the sender for s short period of time (10 minutes in my case)."

I may add more defaults to this list in the future, but I'll try to make them generalized, so they fit anyone's need.

# The Structure That Comes Out

Here is a sample structure for an authenticated email.

```text
{
  :local_port=>"2001",
  :local_hostname=>"mail.example.com",
  :remote_port=>"38436",
  :remote_hostname=>"cpe-107-185-187-182.socal.res.rr.com",
  :remote_ip=>"::ffff:107.185.187.182",
  :id=>"ODZM0W-PRPAYD-49",
  :time=>"2016-09-24 02:38:56 +0000",
  :accepted=>true,
  :prohibited=>false,
  :encrypted=>true,
  :authenticated=>"admin@example.com",
  :connect=>{
    :value=>"::ffff:107.185.187.182",
    :domain=>nil
  },
  :ehlo=>{
    :value=>"mail.example.com",
    :rip=>"23.253.107.107",
    :fip=>"23.253.107.107",
    :domain=>"mail.example.com"
  },
  :mailfrom=>{
    :accepted=>true,
    :value=>"<admin@example.com>",
    :name=>"",
    :url=>"admin@example.com",
    :local_part=>"admin",
    :domain=>"example.com",
    :bad_characters=>false,
    :wrong_dot_usage=>false,
    :ip=>"23.253.107.107",
    :mxs=>[
      "mail.example.com"
    ],
    :ips=>[
      "23.253.107.107"
    ]
  },
  :rcptto=>[
    {
      :accepted=>true,
      :value=>"<coco@example.com>",
      :name=>"",
      :url=>"coco@example.com",
      :local_part=>"coco",
      :domain=>"example.com"
    }
  ],
  :data=>{
    :accepted=>true,
    :value=>"",
    :text=>[
      "Date: Fri, 23 Sep 2016 19:38:55 -0700",
      "To: coco@example.com",
      "From: admin@example.com",
      "Subject: test Fri, 23 Sep 2016 19:38:55 -0700",
      "X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/",
      "",
      "This is a test mailing",
      "",
      "."
    ],
    :headers=>{
      :date=>"Fri, 23 Sep 2016 19:38:55 -0700",
      :to=>"coco@example.com",
      :from=>"admin@example.com",
      :subject=>"test Fri, 23 Sep 2016 19:38:55 -0700",
      :x_mailer=>"swaks v20130209.0 jetmore.org/john/code/swaks/"
    }
  }
}
```

## Format of Delivered Mail

### Global Values

|Symbol |Description |
|:--- |:--- |
| :local_port | This is the port on your machine that the user connected to. |
| :local_hostname | This is the `hostname` of your machine. |
| :remote_port | This is the port on the remote machine that originated the connection. |
| :remote_hostname | This is the `hostname` of the remote machine. |
| :remote_ip | This is the IP of the remote machine. |
| :id | This is the Message ID generated by `Receiver`. Note that there should alread be header `Message-ID` in the email, but if not, this one can be inserted. |
| :time | This is the time the conncetion was made. |
| :accepted | This is a true/false which indicates whether the email should be accepted. |
| :prohibited | If you set this flag, `Receiver` will treat the email as spam, and the sender IP as a spammer. |
| :encrypted | This true/false indicates whether or not a STARTTLS was completed. |
| :authenticated | This value is nil or the email address  of the authenticated entity. |

### CONNECT Values

|Symbol |Description |
|:--- |:--- |
| :value | This is the remote IP (taken from the value above). |
| :domain | If a domain can be discovered for the remote IP, it will be here. |

### EHLO Values

|Symbol |Description |
|:--- |:--- |
| :value | This is the raw data supplied on the EHLO line. |
| :rip | This is the reverse IP, if any, obtained by looking up the value. |
| :fip | The reverse IP is used to get the MX, which is then looked up to get this forward IP. |
| :domain | This is the MX value obtained from looking up the reverse IP. |

### MAIL FROM Values

|Symbol |Description |
|:--- |:--- |
| :accepted | This true/false value indicates if the MAIL FROM value appears to be acceptable. |
| :value | This is the raw data presented on the MAIL FROM line. |
| :name | If a name preceeded the email address, it is put here. |
| :url | This is the "pure" email address in the MAIL FROM statement. |
| :local_part | This is the "local-part" of the URL above. |
| :domain | This is the domain of the URL above. |
| :bad_characters | This true/false tells whether bad characters were found in the local-part. |
| :wrong_dot_usage | This true/false tells whether dots were mis-used in the local-part. |
| :ip | This is the IP from looking up the domain. |
| :mxs | This is a list of one or more mail servers for this domain. |
| :ips | This is a list of IPs obtained by looking up the MXs above. |

### RCPT TO Values (a list)

|Symbol |Description |
|:--- |:--- |
| :accepted | This true/false value indicates if the RCPT TO value appears to be acceptable. |
| :value | This is the raw data presented on the RCPT TO line. |
| :name | If a name preceeded the email address, it is put here. |
| :url | This is the "pure" email address in the RCPT TO statement. |
| :local_part | This is the "local-part" of the URL above. |
| :domain | This is the domain of the URL above. |

### DATA Values (including the email proper)

|Symbol |Description |
|:--- |:--- |
| :accepted | This tru/false value indicates whether `Receiver` accepted the email from the sender. |
| :value | This should be an empty string. |
| :text | __This is the body of the email proper.__ It's organized as an array of lines with the CRLFs stripped off the ends. |

**NOTE! If [:data][:accepted] is *true*, you have taken full responsibility for the email. You must either deliver it, forward it, or bounce it.**

#### Headers (broken out to make access easier)

Here's an example:

|Key |Value |
|:--- |:--- |
| :date | "Fri, 23 Sep 2016 19:38:55 -0700", |
| :to | "coco@example.com", |
| :from | "admin@example.com", |
| :subject | "test Fri, 23 Sep 2016 19:38:55 -0700", |
| :x_mailer | "swaks v20130209.0 jetmore.org/john/code/swaks/" |


The headers are put into a hash like this so that you may easily locate them, or test to see if they exist or not. Modifying this Hash *does not* modify the actual email.


FIN
