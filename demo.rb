require "bunny"
URL = "amqp://ibvrgfsi:dxyzmFXNgYhhOB8U-R-Ue__Y0hMiNSqh@toad.rmq.cloudamqp.com/ibvrgfsi"
URL2 = "amqp://test:test@127.0.0.1:5672"
conn = Bunny.new URL2
conn.start

ch = conn.create_channel
q = ch.queue("bunny.example.hello", :auto_delete => true)

q.publish("Hello", :routing_key => q.name)


q.subscribe(:block => true) do |delivery_info, properties, payload|
	puts "Received #{payload} , cancelling"
end

sleep 1.0
conn.close