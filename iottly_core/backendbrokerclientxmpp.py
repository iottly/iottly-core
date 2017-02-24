
import sleekxmpp
import logging

from multiprocessing import Process, Queue
from tornado import gen

from iottly_core import ibcommands
from iottly_core import brokerapixmpp


# Interprocess queue for dispatching xmpp messages

JID_FORMAT = "{}@{}"

class SendMsgBot(sleekxmpp.ClientXMPP):
    def __init__(self, jid, password):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("presence_available", self.handle_available)

    def start(self, event):
        self.send_presence()
        self.get_roster()

    def send_msg(self, to, msg):
        self.send_message(mto=to,
                          mbody=msg,
                          mtype='chat')

    def handle_available(self, event):
        logging.info("PRESENCE RECEIVED: %s" % str(event))
        logging.info("PRESENCE RECEIVED FROM: %s" % event["from"])


class BackEndBrokerClientXMPP:
    def __init__(self, conf, polyglot_send_command, connected_clients):
        self.connected_clients = connected_clients
        self.xmpp_backend_user = conf['USER']
        self.domain = conf["DOMAIN"]
        self.public_host = conf['PUBLIC_HOST']
        self.public_port = conf['PUBLIC_PORT']

        self.msg_queue = Queue()
        self.proc=None
        self.init(self.xmpp_backend_user, conf['PASSWORD'], conf['SERVER'])

    # This function runs in its own process and dispatches messages in the shared queue
    def message_consumer(self, jid, password, server, q):
        xmpp = SendMsgBot(jid, password)
        xmpp.register_plugin('xep_0030') # Service Discovery
        xmpp.register_plugin('xep_0199') # XMPP Ping

        # xmpp.ssl_version = ssl.PROTOCOL_SSLv3
        # xmpp.ca_certs = None
        xmpp['feature_mechanisms'].unencrypted_plain = True

        # If you want to verify the SSL certificates offered by a server:
        # xmpp.ca_certs = "path/to/ca/cert"

        # Connect to the XMPP server and start processing XMPP stanzas.
        if xmpp.connect(server, use_ssl=False, use_tls=False):
            xmpp.process(block=False)
            while True:
                msg_obj = q.get()
                xmpp.send_msg(msg_obj['to'], msg_obj['msg'])

    def init(self, jid, password, server):
        p = Process(target=self.message_consumer, args=(jid, password, server, self.msg_queue))
        p.daemon = True
        p.start()
        self.proc=p

    def terminate(self):
        if (self.proc is not None):
            self.proc.terminate()

    # Interface for sending messages
    def send_message(self, to, msg):
        self.msg_queue.put(dict(to=to,msg=msg))

    def send_command(self, cmd_name, to, values=None, cmd=None):
        to_jid = JID_FORMAT.format(to, self.domain)
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
        self.send_message(to_jid, cmd.to_json(**values))

    def send_sms_command(self, cmd_name, to):
        cmd = ibcommands.sms_commands_by_name.get(cmd_name)
        if cmd is None:
            raise ValueError('Unknown command [{}]'.format(cmd_name))
        send_sms(to, cmd.cmd_msg)


    @gen.coroutine
    def create_user(self, boardid, password):

        apiresult = yield brokerapixmpp.create_user(boardid, password, self.xmpp_backend_user)
        raise gen.Return(apiresult)

    @gen.coroutine
    def delete_user(self, boardid):

        apiresult = yield brokerapixmpp.delete_user(boardid)
        raise gen.Return(apiresult)

    def format_device_credentials(self, boardid, password):
        return {
            "IOTTLY_XMPP_DEVICE_PASSWORD": password,
            "IOTTLY_XMPP_DEVICE_USER": JID_FORMAT.format(boardid, self.domain),
            "IOTTLY_XMPP_SERVER_HOST": self.public_host,
            "IOTTLY_XMPP_SERVER_PORT": self.public_port,
            "IOTTLY_XMPP_SERVER_USER": self.xmpp_backend_user
        }

