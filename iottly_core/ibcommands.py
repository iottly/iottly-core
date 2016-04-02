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
import datetime
import hashlib
import logging
import ujson

from iottly_core.settings import settings
from iottly_core import flashmanager

class Command(object):
    def __init__(self, name, descr, cmd_msg, autoset=None, warn=False, show=True):
        self.desc = descr
        self.name = name
        self.cmd_msg = cmd_msg
        self.command = None
        self.warn = warn
        self.show = show
        self.autoset = autoset
        self._parse_json()

    def _parse_json(self):
        if self.cmd_msg.startswith('/json '):
            try:
                self.command = ujson.loads(self.cmd_msg[6:])
            except ValueError, e:
                logging.warn('JSON parsing failed', e, self.cmd_msg)
        else:
            self.command = {}

    def _apply_key_value(self, key_parts, obj, value):
        if len(key_parts) == 1:
            obj[key_parts[0]] = value
        else:
            self._apply_key_value(key_parts[1:], obj[key_parts[0]], value)

    '''
    Each command takes an optional autoset function which updates the dictionary with default
    values at runtime
    '''
    def apply_args(self, **kwargs):
        if kwargs is None:
            kwargs = {}

        if self.autoset:
            self.autoset(kwargs)
        obj = copy.deepcopy(self.command)
        for k, v in kwargs.iteritems():
            self._apply_key_value(k.split('.'), obj, v)

        return obj

    '''
    This method accepts optional keyword arguments that will be applied to the commands object.
    The key value pairs represent a flattened view into the command object. For example,
    command = {
        'key_1' : {
            'key_2': value1
        },
        'key_23': value2
    }
    If we want to override key_2 with value3 we would pass in **{ 'key_1.key_2': value3 }
    '''
    def to_json(self, **kwargs):
        if not self.cmd_msg.startswith('/json '):
            return
        obj = self.apply_args(**kwargs)
        return '/json ' + ujson.dumps(obj)

    def __str__(self):
        return "-".join((self.name, self.desc, self.cmd_msg))

    def hash(self):
        return hashlib.md5(str(self)).hexdigest()


    @staticmethod
    def deserialize(ui_command_def):
        cmd = copy.deepcopy(ui_command_def)
        metadata = cmd.pop('metadata')
        return Command(metadata['type'], metadata['description'], '/json {}'.format(metadata['jsonfmt']))

class CommandWithStandardUI(Command):
    def __init__(self, *args, **kwargs):
        self.cmd_properties = kwargs.pop('cmd_properties')
        name = args[0]
        kwargs.update({'cmd_msg': '/json {}'.format(self._render_ui_command_def(name))})
        super(CommandWithStandardUI, self).__init__(*args, **kwargs)

    def _render_ui_command_def(self, name):
        
        props = {k: self._render_property(prop) for k, prop in self.cmd_properties.items()}
        return ujson.dumps({name: props})

    def _render_property(self, prop):
        if prop['type'] == 'FixedValue':
            return prop['value']
        elif prop['type'] == 'MultipleChoice':
            return '<{}>'.format('|'.join(prop['listvalues']))
        elif prop['type'] == 'FreeValue':
            return '<free value>'

    def to_ui_command_def(self):
        obj = {self.name: self.cmd_properties}
        obj.update({'metadata': {'type': self.name, 'description': self.desc, 'direction': 'command', 'jsonfmt': self.cmd_msg[6:]}})
        return obj

class CommandWithCustomUI(Command):
    def __init__(self, *args, **kwargs):
        self.js = kwargs.pop('js', None)
        self.template = kwargs.pop('template', None)
        self.context = kwargs.pop('context', {})
        super(CommandWithCustomUI, self).__init__(*args, **kwargs)


autotimeset = lambda args_dict: args_dict.update(timeset=datetime.datetime.now(settings.TIMEZONE).strftime(settings.TIME_FMT))

commands = list()
commands_by_name = dict()

sms_commands = list()
sms_commands_by_name = dict()

commands.extend([
    CommandWithStandardUI('ECHO', 'Test the board communication with an echo request - response', cmd_properties={"content":{"type": "FixedValue", "value": "IOTTLY hello world!!!!"}}),
    CommandWithStandardUI('ECHOList', 'List to Test the board communication with an echo request - response', cmd_properties={"content":{"type": "MultipleChoice", "listvalues": ['Iottly', 'Hello', 'World']}}),
    CommandWithStandardUI('ECHOFree', 'Free value to Test the board communication with an echo request - response', cmd_properties={"content":{"type": "FreeValue"}}),

    CommandWithCustomUI(
        'Upload Firmware',
        'Upload and flash a new firmware',
        '/json {"fw":{"startupgrading":1, "area":0, "file": "", "md5": ""}}',
        warn=True,
        show=False,
        template='flash_fw.html',
        js='flash.js',
        context={
            'area': 0,
            'files': flashmanager.list_firmwares,
            'chooser_text': 'Select a firmware binary...'
        }),
    Command('Send Chunk', 'Send a b64 encoded data chunk', '/json {"fw":{"area":0,"block":0,"data":"<base64>"}}', show=False),
    Command('Transfer Complete', 'Tell the IB that the upload is complete', '/json {"fw":{"area":0,"block":0}}', show=False),
])

sms_commands.extend([
    Command('XMPP', 'Turn on XMPP', 'xmpp', warn=True),
    Command('Status', 'Request the board status', 'status', warn=True),
    Command('Reset', 'Reset the board', 'reset board', warn=True),
])

for cmd in commands:
    commands_by_name[cmd.name] = cmd

for cmd in sms_commands:
    sms_commands_by_name[cmd.name] = cmd

js_includes = set((command.js for command in commands if issubclass(command.__class__, CommandWithCustomUI) and command.js))
