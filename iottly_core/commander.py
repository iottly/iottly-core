"""

Copyright 2015 Stefano Terna

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""
import sleekxmpp
import logging

from multiprocessing import Process, Queue

from iottly_core import ibcommands
from iottly_core.settings import settings

# Interprocess queue for dispatching xmpp messages
msg_queue = Queue()

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


# This function runs in its own process and dispatches messages in the shared queue
def message_consumer(jid, password, q):
    xmpp = SendMsgBot(jid, password)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0199') # XMPP Ping

    # xmpp.ssl_version = ssl.PROTOCOL_SSLv3
    # xmpp.ca_certs = None
    xmpp['feature_mechanisms'].unencrypted_plain = True

    # If you want to verify the SSL certificates offered by a server:
    # xmpp.ca_certs = "path/to/ca/cert"

    # Connect to the XMPP server and start processing XMPP stanzas.
    if xmpp.connect(settings.XMPP_SERVER, use_ssl=False, use_tls=False):
        xmpp.process(block=False)
        while True:
            msg_obj = q.get()
            xmpp.send_msg(msg_obj['to'], msg_obj['msg'])

# Launch the message dispatching process
def init(jid, password):
    p = Process(target=message_consumer, args=(jid, password, msg_queue))
    p.daemon = True
    p.start()
    return p

# Interface for sending messages
def send_message(to, msg):
    msg_queue.put(dict(to=to,msg=msg))

def send_command(cmd_name, to, values=None, cmd=None):
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
    send_message(to, cmd.to_json(**values))

def send_sms_command(cmd_name, to):
    cmd = ibcommands.sms_commands_by_name.get(cmd_name)
    if cmd is None:
        raise ValueError('Unknown command [{}]'.format(cmd_name))
    send_sms(to, cmd.cmd_msg)
