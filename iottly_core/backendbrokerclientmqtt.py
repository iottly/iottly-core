import paho.mqtt.client as mqtt
import logging

from multiprocessing import Process, Queue
from tornado import gen

from iottly_core import ibcommands
from iottly_core import brokerapimqtt


class IottlyMqttClient(mqtt.Client):
    def __init__(self, username, password, on_connect,on_disconnect):
        mqtt.Client.__init__(self,client_id=None, clean_session=True, userdata=None)
        self.username_pw_set(username, password)
        self.on_connect=on_connect
        self.on_disconnect=on_disconnect


class BackEndBrokerClientMQTT:
    def __init__(self, conf):

        self.topic_commands_pattern = conf['TOPIC_COMMANDS_PATTERN']
        self.topic_events_pattern = conf['TOPIC_EVENTS_PATTERN']

        self.public_host = conf['PUBLIC_HOST']
        self.public_port = conf['PUBLIC_PORT']

        self.msg_queue = Queue()
        self.proc = None
        self.init(conf['SERVER'], conf['PORT'], conf['USER'], conf['PASSWORD'])


    def message_consumer(self, mqtt_server, mqtt_port, username, password, msg_queue):

        def on_connect(client, userdata, flags, connection_status_code):
            logging.info('Connection to message broker STATUS - result code {}'.format(str(connection_status_code)))
            if (connection_status_code==mqtt.MQTT_ERR_SUCCESS):
                logging.info("connected to %s" % str(mqtt_server))
                mqtt_c.subscribe(sub_tpc,2)
            else:
                logging.info("connection error to %s" % str(mqtt_server))

        def on_disconnect(client, userdata, connection_status_code):
            logging.info('Disonnection from message broker STATUS - result code {}'.format(str(connection_status_code)))
            if (connection_status_code==mqtt.MQTT_ERR_SUCCESS):
                logging.info('Disconnected by user')
            else:
                logging.info("lost connection from %s" % str(mqtt_server))

        try:
            mqtt_c = IottlyMqttClient(username, password, on_connect, on_disconnect)

            # Connect to the MQTT broker.
            mqtt_c.connect(mqtt_server,mqtt_port,60)

            while True:
                msg_obj = msg_queue.get()
                if msg_obj is None:
                    logging.info("kill received")
                    mqtt_c.disconnect()
                    break
                mqtt_c.publish(msg_obj['to_topic'],msg_obj['msg'],2)

        except ConnectionRefusedError as e:
            logging.info("no connection to %s" % str(mqtt_server))

        except Exception as e:
            logging.info('msg_queue: {}'.format(msg_queue.qsize()))
            logging.exception(e)

    def init(self, mqtt_server, mqtt_port, username, password):
        p = Process(target=self.message_consumer, 
            args=(mqtt_server, mqtt_port, username, password, self.msg_queue))

        p.daemon = True
        p.start()
        self.proc=p

    def terminate(self):
        if (self.proc is not None):
            self.proc.terminate()

    def send_message(self, to_topic, msg):
        self.msg_queue.put(dict(to_topic=to_topic,msg=msg))

    def send_command(self, cmd_name, to_topic, values=None, cmd=None):
        if values is None:
            values = {}

        for k, v in values.items():
            if v is None or v == '':
                del values[k]

        if cmd is None:
            cmd = ibcommands.commands_by_name.get(cmd_name)

        if cmd is None:
            raise ValueError('Unknown command [{}]'.format(cmd_name))
        logging.info('cmd: {}'.format(cmd.to_json(**values)))
        self.send_message(to_topic, cmd.to_json(**values))

    def send_sms_command(self, cmd_name, to):
        cmd = ibcommands.sms_commands_by_name.get(cmd_name)
        if cmd is None:
            raise ValueError('Unknown command [{}]'.format(cmd_name))
        send_sms(to, cmd.cmd_msg)


    @gen.coroutine
    def create_user(self, projectid, boardid, password):

        apiresult = yield brokerapimqtt.create_user(boardid, password, [
            self.topic_events_pattern.format(projectid, boardid),
            self.topic_commands_pattern.format(projectid, boardid),            
            ])

        raise gen.Return(apiresult)

    @gen.coroutine
    def create_project_user(self, projectid, password):
        pass

    @gen.coroutine
    def delete_user(self, boardid):

        apiresult = yield brokerapimqtt.delete_user(boardid)
        raise gen.Return(apiresult)

    @gen.coroutine
    def delete_project_user(self, projectid):
        pass

    def format_device_credentials(self, projectid, boardid, password):

        return {
            "IOTTLY_MQTT_SERVER_HOST": self.public_host, 
            "IOTTLY_MQTT_SERVER_PORT": self.public_port,
            "IOTTLY_MQTT_DEVICE_USER": boardid, 
            "IOTTLY_MQTT_DEVICE_PASSWORD": password,
            "IOTTLY_MQTT_TOPIC_SUBSCRIBE": self.topic_commands_pattern.format(projectid, boardid),
            "IOTTLY_MQTT_TOPIC_PUBLISH": self.topic_events_pattern.format(projectid, boardid)
        }


    @gen.coroutine
    def fetch_status(self, projectid, boardid):
        jid = JID_FORMAT.format(boardid, self.domain)

        status = yield brokerapimqtt.fetch_status(self.presence_url, self.xmpp_backend_user, jid)

        raise gen.Return(status)            

    def normalize_receiver_sender(self, msg):

        msg.update({k: self.jid_parsers[k].findall(msg[k])[0] for k in self.jid_parsers.keys()})

        return msg
        