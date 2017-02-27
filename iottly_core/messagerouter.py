from tornado import gen, httpclient
from datetime import datetime
import json
import urllib
from bson import json_util
import logging
import copy

from iottly_core import dbapi
from iottly_core import messageparser
from iottly_core import flashmanager

from iottly_core.settings import settings
from iottly_core import polyglot

brokers_polyglot=polyglot.Polyglot(settings.BACKEND_BROKER_CLIENTS_CONF)


@gen.coroutine
def route(protocol, msg, connected_clients):
    msg = brokers_polyglot.normalize_receiver_sender(protocol, msg)

    msg = messageparser.annotate_message(msg)
    msgs = messageparser.parse_message(copy.deepcopy(msg))
    persist_msgs = filter(messageparser.check_persist, msgs)
    
    yield [
        dbapi.insert('message_logs', msg),
        dbapi.insert('messages', persist_msgs),
        _check_and_forward_messages(msgs)
        ]

    _broadcast({ 'msgs': msgs }, connected_clients)

    send_command_cb = brokers_polyglot.send_command_cb(protocol)
    _process_msgs(msgs, send_command_cb, connected_clients)


@gen.coroutine
def _check_and_forward_messages(msgs):
    results = yield [_forward_msg_to_client(m) for m in filter(messageparser.check_message_forward, msgs)]

@gen.coroutine
def _forward_msg_to_client(msg):
    http_client = httpclient.AsyncHTTPClient()

    # Remove mongo ID if found
    if '_id' in msg:
        del msg['_id']

    # Serializes datetime to isoformat
    dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime) else json.JSONEncoder().default(obj)
    post_data = {
        'msg': json.dumps(msg, default=dthandler)
    }
    body = urllib.urlencode(post_data)
    res = None

    try:
        res = yield http_client.fetch(settings.CLIENT_CALLBACK_URL, method='POST', body=body)
    except httpclient.HTTPError, e:
        logging.warn('Problem posting to {}: {}'.format(settings.CLIENT_CALLBACK_URL, e))

    raise gen.Return(res)

def _broadcast(msg, connected_clients):
    events_json = json.dumps({ 'events': msg }, default=json_util.default)
    for client in connected_clients:
        client.send(events_json)

def _process_msgs(msgs, send_command, connected_clients):
    for msg in msgs:
        fn = processing_map.get(msg.get('type', None))
        if fn:
            fn(msg, send_command, connected_clients)

def set_time(msg, send_command, connected_clients):
    send_command('timeset', msg['from'])

def send_firmware_chunks(msg, send_command, connected_clients):

    fw = msg.get('fw')
    if fw is None:
        return

    from_id = msg.get('from')

    num_chunks = fw.get('qty', 0)
    dim_chunk = fw.get('dim', 256)
    area = fw.get('area', 0)
    block = fw.get('block', 0)
    active_file = fw.get('file', None)
    active_projectid = fw.get('projectid', None)

    if active_file is None or active_file == '':
        send_command('Transfer Complete', from_id, {
            'fw.area': area,
            'fw.block': block,
            'fw.file': active_file,
        })
        return

    chunks = flashmanager.get_b64_chunks(active_projectid, active_file, dim_chunk)

    for i in range(num_chunks):
        data = chunks[block+i].strip() if block+i < len(chunks) else None
        values = {
            'fw.area': area,
            'fw.block': block + i,
            'fw.file': active_file,
        }
        if data is None:
            send_command('Transfer Complete', from_id, values)
            break
        else:
            values['fw.data'] = data
            send_command('Send Chunk', from_id, values)

    progress_msg = {
        'type': 'progress',
        'area': area,
        'to': from_id,
        'total_chunks': len(chunks),
        'chunks_sent': block + num_chunks if data else len(chunks)
    }

    _broadcast_interface(progress_msg, connected_clients)

def _broadcast_interface(msg, connected_clients):
    devices_json = json.dumps({ 'interface': msg }, default=json_util.default)
    for client in connected_clients:
        logging.info(client)
        client.send(devices_json)

processing_map = {
                'TimeReq': set_time,
                'Firmware': send_firmware_chunks
                }