#!/usr/bin/env ruby
require 'bunny'
# URL = "amqp://ibvrgfsi:dxyzmFXNgYhhOB8U-R-Ue__Y0hMiNSqh@toad.rmq.cloudamqp.com/ibvrgfsi"
URL = "amqp://test:test@btc_test.global-ibk.com:5672"
url2 = "amqp://test:test@127.0.0.1:5672"
queue1 = "queue_neo_payment_deposit" 
conn = Bunny.new url2
conn.start

ch   = conn.create_channel
q    = ch.queue("exchangepro.deposit.neo.address_success", durable: true)


puts ' [*] Waiting for logs. To exit press CTRL+C'

begin
 q.subscribe(:block => true) do |delivery_info, properties, body|
       puts " [x] Received #{body}"
  end
rescue Interrupt => _
  channel.close
  connection.close
end
