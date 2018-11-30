#!/usr/bin/env ruby
require 'bunny'
URL = "amqp://ibvrgfsi:dxyzmFXNgYhhOB8U-R-Ue__Y0hMiNSqh@toad.rmq.cloudamqp.com/ibvrgfsi"
url1 = "amqp://test:test@0.tcp.ngrok.io:16815"
urlLocal = "amqp://deposit_neo:password@127.0.0.1:5672"
connection = Bunny.new urlLocal
connection.start

channel = connection.create_channel
queue = channel.queue('exchangepro.withdraw.eth', durable: true)

message = ARGV.empty? ? 'Hello Linh!' : ARGV.join(' ')

queue.publish(message)
puts " [x] Sent #{message}"

connection.close
