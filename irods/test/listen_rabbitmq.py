#! /usr/bin/python3

import pika

def on_message(channel, method_frame, header_frame, body):
    print("method frame: %s" % method_frame)
    print("header frame: %s" % header_frame)
    print("body: %s" % body)
    print()
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


credentials = pika.PlainCredentials('irods', 'test_irods_password')
parameters = pika.ConnectionParameters('localhost',
                                   5672,
                                   '/',
                                   credentials)

connection = pika.BlockingConnection(parameters)

channel = connection.channel()

channel.queue_declare(queue='test_listen_queue', durable=True, exclusive=False, auto_delete=True)
#channel.queue_bind(queue='test_listen_queue', exchange='irods', routing_key='audit')
channel.queue_bind(queue='test_listen_queue', exchange='irods', routing_key='#')

channel.basic_consume(queue='test_listen_queue', on_message_callback=on_message)
try:
    channel.start_consuming()
except KeyboardInterrupt:
    channel.stop_consuming()
connection.close()