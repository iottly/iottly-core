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
import copy
import ujson
import logging
from datetime import datetime
from iottly_core.settings import settings

codes_dict = {
    1: 'BoardReset',
    2: 'BoardTamperingStart',
    3: 'BoardTamperingEnd',
    4: 'ClockSet',
    5: 'SensorConnected',
    6: 'SensorDisconnected',
    7: 'PresenceStart',
    8: 'PresenceEnd',
    9:' ActivityListStart',
    10: 'ActivityListEnd',
    12: 'UploadDone',
    13: 'FwUpdateTerminated', #In case of success idx == 0 (applies only to nn, not fw), 
                              #In case of error:  idx == 1 -> connection error 
                              #                   idx == 2 -> MD5 error)
                              #ext == updated area (ext==0 -> fw, ext==1 -> nn)

    101: 'Punchings',         #winit RFID punching messages, this is NOT generated by IB
}

forwarding_set = {
    'BoardTamperingStart',
    'BoardTamperingEnd',
    'SensorConnected',
    'SensorDisconnected',
    'PresenceStart',
    'PresenceEnd',
    'Punchings',  #winit RFID punching messages
}

types_map = {
    'globalstate': 'GlobalState',
    'event': 'Event',
    'sync': 'Sync',
    'live': 'Live',
    'timereq': 'TimeReq',
    'fw': 'Firmware',
}

def _convert_code(k, v, d):
    del d[k]
    d['tdcode'] = codes_dict[v]

def _convert_type(k, v, d):
    d.update({'type': types_map[k]}) if k in types_map else None

def _convert_datetime(k, v, d):
    #lambda k, v, d: d.update({k: settings.TIMEZONE.localize(datetime.strptime(v, settings.TIME_FMT))}),
    if not isinstance(v, int):
        d.update({k: settings.TIMEZONE.localize(datetime.strptime(v, settings.TIME_FMT))})

transform_map = {
    'code': _convert_code,
    'time': _convert_datetime,
    'start': _convert_datetime,
    'globalstate': _convert_type,
    'sync': _convert_type,
    'live': _convert_type,
    'event': _convert_type,
    'timereq': _convert_type,
    'fw': _convert_type,
}

def transform_dict(d):
    # NB: d.items() creates a copy of the entries allowing transform_map to safely 
    # insert/delete entries in the dictionary
    for k, v in d.items():
        if k in transform_map:
            transform_map[k](k, v, d)
        if isinstance(v, dict):
            transform_dict(v)
        if isinstance(v, list):
            for vi in v:
                if isinstance(vi, dict):
                    transform_dict(vi)
            

def annotate_message(msg):
    msg['timestamp'] = datetime.now(settings.TIMEZONE)
    return msg

def parse_message(msg):
    msg_string = msg['msg']

    del msg['msg']
    messages = None

    if msg_string.startswith('/json'):
        # decode json message
        json_content = {}
        try:
            json_content = ujson.loads(msg_string[6:])
        except ValueError, e:
            logging.error("JSON parsing has failed for "+msg_string[6:])

        messages = []
        if 'events' in json_content:
            events = json_content['events']
            for e in events:
                m = copy.deepcopy(msg)
                m.update(e)
                transform_dict(m)
                messages.append(m)
            return messages
        else:
            msg.update(json_content)
            transform_dict(msg)
            return [msg]

    return [msg]


def check_message_forward(msg):
    mtype = msg.get('type', None)
    if mtype == "Event":
        return msg['event'].get('tdcode', None) in forwarding_set
    elif mtype == "GlobalState":
        return True
    return True #change this to False to prevent forwarding of all but messages listed in forwarding_set

def check_persist(msg):
    is_sync = 'sync' in msg
    return not is_sync