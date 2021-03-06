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
import subprocess

from iottly_core.settings import settings
from iottly_core import validator
from iottly_core import ibcommands
from iottly_core import fwcodemanager

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
              "secretsalt": {"type": "string"},
              "board":{"type": "string", "allowed": settings.INSTALLER_FILE_PATHS.keys(), "required": True}, 
              "fwlanguage":{"type": "string", "allowed": ["Python"], "required": True},
              "fwextension": {"type": "string"},
              "boards": {
                "type": "list", 
                "unique": {"key": "macaddress"}, 
                "schema": {
                  "type": "dict", 
                  "schema": {
                    "name": {"type": "string"},
                    "macaddress":{"type": "string", "regex": "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", "required": True},
                    "ID": {"type": "string", "regex": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "required": True},
                    "jid": {"type": "string", "regex": "^.+", "required": True}, 
                    "password": {"type": "string"},
                    "simnumber": {"type": "string"}
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

  def set_project_params(self, commands):
    _id = self.value["_id"]

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
    

  def get_board_by_mac(self, macaddress):
    board = None
    if 'boards' in self.value:
      boards = [b for b in self.value['boards'] if b['macaddress'] == macaddress]

      if len(boards) == 1:
        board = boards[0]

    return board

  def get_board_by_id(self, buuid):
    return [b for b in self.value['boards'] if b['ID'] == buuid][0]


  def add_board(self, macaddress):
    if not "boards" in self.value.keys():
      self.value["boards"] = []

    ID = str(uuid.uuid4())

    board = {
      "macaddress": macaddress, 
      "ID": ID, 
      "jid": "{}@{}".format(ID, settings.XMPP_DOMAIN),
      "password": ''.join(random.choice('0123456789ABCDEF') for i in range(16)),
      "simnumber": "---"
    }
    self.value["boards"].append(board)

    if not self.validate():
      raise Exception(self.validator.errors)
    
    return board

  def remove_board(self, macaddress):
    board = [b for b in self.value['boards'] if b['macaddress'] == macaddress][0]
    self.value['boards'].remove(board) 
    return board

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

"""
Test:
{
  "name": "a", 
  "user": {
     "email":"stefano.terna@gmail.com"
  },
  "board":"Raspberry Pi", 
  "fwlanguage":"Python",
  "boards": [
    {
      "name":"a",
    },    {
      "name":"b",
    }
  ],
}

"""