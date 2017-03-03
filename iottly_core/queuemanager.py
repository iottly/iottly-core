import pika
import json
from bson import json_util
import logging

from iottly_core.settings import settings


class RabbitClient():
	def init(self):
		self.rabbitconnection = pika.BlockingConnection(pika.ConnectionParameters(
		        host=settings.RABBITMQ_HOST))

		logging.info('rabbitconnection: {}'.format(settings.RABBITMQ_HOST))

		self.queuename = settings.QUEUE_NAME

		self.rabbitchannel = self.rabbitconnection.channel()

		self.rabbitchannel.queue_declare(queue=self.queuename)

	def close(self):
	    self.rabbitchannel.close()
	    self.rabbitconnection.close()
	    logging.info('Disconnected from Rabbitmq')

	def publish(self, projectid, kind, msg):

		body = json.dumps({'projectid': projectid, kind: msg }, default=json_util.default)
		self.rabbitchannel.basic_publish(exchange='',
		                      routing_key=self.queuename,
		                      body=body)



rabbitclient = RabbitClient()