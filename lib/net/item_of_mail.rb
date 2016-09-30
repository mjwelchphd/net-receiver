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
require 'spf'

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

    def reconstituted_email
      text = []
      self[:data][:headers].each { |k,v| text << "#{k}:#{v}" }
      text.concat(self[:data][:text])
      text.join(CRLF)+CRLF
    end
  end
end
