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

import uuid
import random
import logging
import os
import json

import subprocess
from tornado import gen, httpclient

from iottly_core.settings import settings
from iottly_core import validator
from iottly_core import ibcommands
from iottly_core import fwcodemanager
from iottly_core.polyglot import polyglot as brokers_polyglot


class Project(validator.SchemaDictionary):
  schema = {
              "projecturl": {"type": "string"},
              "projectgetagenturl": {"type": "string"},
              "runinstallercommand": {"type": "string"},
              "_id": {"type": "objectid"},
              "name": {"type": "string", "regex": "^.+", "required": True}, 
              "user": {
                "type": "dict", 
                "schema": {
                  "email":{"type": "string", "regex": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", "required": True}
                }, 
                "required": True
              },
              "apitokens": {
                "type": "list",
                "schema": {
                  "type": "dict",
                  "schema": {
                    "token_id": {"type": "string", "required": True}
                  }
                }
              },
              "secretsalt": {"type": "string"},
              "board":{"type": "string", "allowed": settings.INSTALLER_FILE_PATHS.keys(), "required": True}, 
              "fwlanguage":{"type": "string", "allowed": ["Python"], "required": True},
              "iotprotocol":{"type": "string", "allowed": ["XMPP","MQTT"], "required": True},
              "fwextension": {"type": "string"},
              "boards": {
                "type": "list", 
                "unique": {"key": "macaddress"}, 
                "schema": {
                  "type": "dict", 
                  "schema": {
                    "name": {"type": "string"},
                    "macaddress":{"type": "string", "regex": "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", "required": True},
                    "ID": {"type": "string", "regex": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "required": True}
                  }, 
                  "required": True                  
                }
              },
              "messages": {
                "type": "list",
                "required": True,
                "uniquetype": True,
                "schema": {
                  "type": "dict", 
                  "schema": {
                    "metadata": {
                      "type": "dict", 
                      "required": True,
                      "schema": {
                        "type": {"type": "string", "required":True},
                        "description": {"type": "string", "required":True},
                        "direction": {"type": "string", "allowed": ["command", "event"], "required":True},
                        "jsonfmt": {"type": "string", "required":True}
                      }
                    }
                  },
                  "allow_unknown": {
                    "type": "dict",
                    "schema": {},
                    "allow_unknown" : {
                      "type": "dict",
                      "schema": {
                        "type": {"type": "string", "allowed": ["FixedValue", "MultipleChoice", "FreeValue"], "required": True},
                        "value": {"type": "string"},
                        "listvalues": {"type": "list", "schema": {"type": "string"}}                        
                      }
                    }
                  }                  
                }
              },
              "fwcode": {
                "type": "dict", 
                "schema": {
                  "snippets": {
                    "type": "list", 
                    "unique": {"key": "snippetid"}, 
                    "schema": {
                      "type": "dict", 
                      "schema": {
                        "name": {"type": "string"},
                        "category": {"type": "string"},
                        "description": {"type": "string"},
                        "snippetid": {"type": "string", "regex": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "required": True},
                        "code": {"type": "string"}
                      }, 
                      "required": True                  
                    }
                  }      
                }                            
              }
            }

  def __init__(self, value):
    super(Project, self).__init__(value)

    self.fwcode = fwcodemanager.FwCode(self.value, self.value["board"])

  @gen.coroutine
  def set_project_params(self, commands):
    _id = self.value.get("_id")
    protocol = self.value.get('iotprotocol')

    project_broker_password = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
    apiresult = yield brokers_polyglot.create_project_user(protocol, _id, project_broker_password)    

    self.value["projecturl"] = settings.PROJECT_URL_TEMPLATE.format(_id)
    self.value["projectgetagenturl"] = settings.GET_AGENT_URL_TEMPLATE.format(_id)
    self.value["runinstallercommand"] = settings.RUN_INSTALLER_COMMAND_TEMPLATE.format(self.value["projectgetagenturl"])

    #create repo path for over the air firmwares
    os.makedirs(os.path.join(settings.FIRMWARE_DIR, str(_id)))

    # add over the air parameters
    self.value["secretsalt"] = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
    self.value["fwextension"] = 'tar.gz'

    #create base installer for devices
    builder = [] 
    builder.append(os.path.join(settings.DEVICE_INSTALLERS_BUILDER_PATH, "build"))
    builder.append(settings.BOARDS_TYPE_MAP[self.value["board"]])             # export BOARDDIR=$1                    
    builder.append("{}".format(_id))                                          # export PROJID=$2                      
    builder.append(settings.PUBLIC_HOST_PORT)                                 # export IOTTLY_REGISTRATION_HOST=$3    
    builder.append(settings.DEVICEREGISTRATION_SERVICE_TEMPLATE.format(_id))  # export IOTTLY_REGISTRATION_SERVICE=$4 
    builder.append(settings.IOTTLY_REGISTRATION_PROTOCOL)                     # export IOTTLY_REGISTRATION_PROTOCOL=$5 

    subprocess.check_call(builder)

    self.init_messages(commands)
    self.fwcode.createbasesnippets()
    
    raise gen.Return(True)


  def get_board_by_mac(self, macaddress):
    board = None
    if 'boards' in self.value:
      boards = [b for b in self.value['boards'] if b['macaddress'] == macaddress]

      if len(boards) == 1:
        board = boards[0]

    return board

  def get_board_by_id(self, buuid):
    return [b for b in self.value['boards'] if b['ID'] == buuid][0]


  @gen.coroutine
  def add_or_update_board(self, macaddress):
    projectid = self.value.get('_id')

    if not "boards" in self.value.keys():
      self.value["boards"] = []

    newreg = True
    board = self.get_board_by_mac(macaddress)

    password = ''.join(random.choice('0123456789ABCDEF') for i in range(16))

    if board:
      # always reset password in case of already registered board. We don't store passwords!!
      newreg = False
      apiresult = yield brokers_polyglot.delete_user(self.value.get('iotprotocol'), board["ID"])
    else:
      # generate new set of credentials
      ID = str(uuid.uuid4())

      board = {
        "macaddress": macaddress, 
        "ID": ID, 
      }

    apiresult = yield brokers_polyglot.create_user(self.value.get('iotprotocol'), projectid, board["ID"], password)

    if newreg:
      self.value["boards"].append(board)


    if not self.validate():
      raise Exception(self.validator.errors)
    
    raise gen.Return((board, password, newreg))

  @gen.coroutine
  def remove_board(self, macaddress):
    board = [b for b in self.value['boards'] if b['macaddress'] == macaddress][0]

    apiresult = yield brokers_polyglot.delete_user(self.value.get('iotprotocol'), board["ID"])

    self.value['boards'].remove(board) 
    raise gen.Return(board)

  def add_message(self, message):
    if not "messages" in self.value.keys():
      self.value["messages"] = []

    self.value["messages"].append(message)
    self.fwcode.createMsgSnippet(message, self.value["fwcode"]["snippets"])

    if not self.validate():
      raise Exception(self.validator.errors)
    
    return message

  def get_command(self, cmd_type):
    return ibcommands.Command.deserialize([cmd for cmd in self.value['messages'] if cmd['metadata']['type'] == cmd_type][0])

  def init_messages(self, messages):
    self.value['messages'] = messages

    if not self.validate():
      raise Exception(self.validator.errors)


  def remove_message(self, messagetype):
    message = [m for m in self.value['messages'] if m['metadata']['type'] == messagetype][0]
    self.value['messages'].remove(message) 
    self.fwcode.setMsgSnippetZombie(message)
    return message


  @gen.coroutine
  def create_token(self):
    logging.info('create_token')
    _id = self.value.get("_id")

    headers = {
        "Content-Type": "application/json"
    }

    body = json.dumps({'project': str(_id)})

    http_client = httpclient.AsyncHTTPClient()

    logging.info(settings.AUTH_TOKEN_CREATE_URL)
    res = yield http_client.fetch(settings.AUTH_TOKEN_CREATE_URL, method='POST', headers=headers, body=body)

    logging.info(res.body)

    if res.error:
      raise Exception("Create token: " + res.error)
    else:
      if not "apitokens" in self.value.keys():
        self.value["apitokens"] = []

      #token = {
      #     'project': data['project'],
      #     'token_id': token_id
      #}

      token = json.loads(res.body)
      del token['project']
      self.value["apitokens"].append(token)

      raise gen.Return(token)


