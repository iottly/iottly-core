import paho.mqtt.client as mqtt
from iottly_core.settings import settings
from iottly_core import ibcommands
from multiprocessing import Process, Queue
import logging

class RpiIottlyMqttClientServer(mqtt.Client):
    def __init__(self,cl_id,pswd,on_connect,on_disconnect):
        mqtt.Client.__init__(self,client_id=cl_id, clean_session=True, userdata=None)
        self.username_pw_set(cl_id, password=pswd)
        self.on_connect=on_connect
        #self.on_message=self.handle_message
        self.on_disconnect=on_disconnect
        #self.message_from_broker=message_from_broker

    # def handle_message (self, paho_mqtt, userdata, msg):
    #     messg = {
    #         #'msg': (str(msg.payload)),
    #         'msg': msg.payload.decode('UTF-8'),
    #         'topic': msg.topic
    #     }

    #     self.message_from_broker(messg)

class BackEndBrokerClientMQTT:
    def __init__(self, conf):
        self.msg_queue = Queue()
        self.proc=None
        self.init(conf['server'],
                    conf['port'],
                    conf['user'],
                    conf['password'],
                    conf['tpc_sub'],
                    conf['tpc_pub'])


    def message_consumer(self, mqtt_server, mqtt_port, mqtt_user, pswd, sub_tpc, pub_tpc, msg_queue):

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
            logging.info('pre inizializzazione CLIENT')
            mqtt_c = RpiIottlyMqttClientServer(mqtt_user, pswd, on_connect, on_disconnect)

            # Connect to the MQTT broker.
            logging.info('pre_connect')
            mqtt_c.connect(mqtt_server,mqtt_port,60)
            logging.info('post connect')
            # mqtt_c.subscribe(sub_tpc,2)
            mqtt_c.loop_start()

            while True:
                msg_obj = msg_queue.get()
                if msg_obj is None:
                    logging.info("kill received")
                    mqtt_c.unsubscribe(sub_tpc)
                    mqtt_c.disconnect()
                    break
                mqtt_c.publish(pub_tpc,msg_obj['msg'],2)

        except ConnectionRefusedError as e:
            logging.info("no connection to %s" % str(mqtt_server))

        except Exception as e:
            logging.info('msg_queue: {}'.format(msg_queue.qsize()))
            logging.exception(e)

    def init(self, mqtt_server, mqtt_port, mqtt_user, mqtt_password, sub_tpc, pub_tpc):
        p = Process(target=self.message_consumer, args=(mqtt_server, mqtt_port, mqtt_user, mqtt_password, sub_tpc, pub_tpc, self.msg_queue))
        p.daemon = True
        p.start()
        self.proc=p

    def terminate(self):
        if (self.proc is not None):
            self.proc.terminate()

    def send_message(self, to, msg):
        self.msg_queue.put(dict(to=to,msg=msg))

    def send_command(self, cmd_name, to, values=None, cmd=None):
        logging.info('classe MQTT')
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
        self.send_message(to, cmd.to_json(**values))

    def send_sms_command(self, cmd_name, to):
        cmd = ibcommands.sms_commands_by_name.get(cmd_name)
        if cmd is None:
            raise ValueError('Unknown command [{}]'.format(cmd_name))
        send_sms(to, cmd.cmd_msg)