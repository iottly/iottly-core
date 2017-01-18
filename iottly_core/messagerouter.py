from tornado import gen, httpclient
from datetime import datetime
import json
import urllib
from bson import json_util
import logging
import copy

from iottly_core import dbapi
import messageparser
from iottly_core.settings import settings

@gen.coroutine
def route(msg, send_command):
    logging.info('\n\nWITHIN MESSAGE ROUTER -> ROUTE 1\n\n')
    msg = messageparser.annotate_message(msg)
    logging.info('\n\nWITHIN MESSAGE ROUTER -> ROUTE 2\n\n')
    msgs = messageparser.parse_message(copy.deepcopy(msg))
    logging.info('\n\nWITHIN MESSAGE ROUTER -> ROUTE 3\n\n')
    persist_msgs = filter(messageparser.check_persist, msgs)
    logging.info('\n\nWITHIN MESSAGE ROUTER -> ROUTE 4\n\n')
    
    yield [
        dbapi.insert('message_logs', msg),
        dbapi.insert('messages', persist_msgs),
        _check_and_forward_messages(msgs)
        ]

    _broadcast({ 'msgs': msgs })
    _process_msgs(msgs, send_command)

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

def _broadcast(msg):
    events_json = json.dumps({ 'events': msg }, default=json_util.default)
    for client in connected_clients:
        logging.info(client)
        client.send(events_json)

def _process_msgs(msgs, send_command):
    for msg in msgs:
        fn = processing_map.get(msg.get('type', None))
        if fn:
            fn(msg, send_command)

def set_time(msg, send_command):
    send_command(settings.IOTTLY_IOT_PROTOCOL, 'timeset', msg['from'])

def send_firmware_chunks(msg, send_command):
    fw = msg.get('fw')
    if fw is None:
        returntime

    from_jid = msg.get('from').split('/')[0]

    num_chunks = fw.get('qty', 0)
    dim_chunk = fw.get('dim', 256)
    area = fw.get('area', 0)
    block = fw.get('block', 0)
    active_file = fw.get('file', None)
    active_projectid = fw.get('projectid', None)

    if active_file is None or active_file == '':
        send_command(settings.IOTTLY_IOT_PROTOCOL, 'Transfer Complete', from_jid, {
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
            send_command(settings.IOTTLY_IOT_PROTOCOL, 'Transfer Complete', from_jid, values)
            break
        else:
            values['fw.data'] = data
            send_command(settings.IOTTLY_IOT_PROTOCOL, 'Send Chunk', from_jid, values)

    progress_msg = {
        'type': 'progress',
        'area': area,
        'to': from_jid,
        'total_chunks': len(chunks),
        'chunks_sent': block + num_chunks if data else len(chunks)
    }

    _broadcast_interface(progress_msg)

def _broadcast_interface(msg):
    devices_json = json.dumps({ 'interface': msg }, default=json_util.default)
    for client in connected_clients:
        logging.info(client)
        client.send(devices_json)

connected_clients = set()
processing_map = {
                'TimeReq': set_time,
                'Firmware': send_firmware_chunks
                }