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

from iottly_core.settings import settings
from iottly_core import validator

class Project(validator.SchemaDictionary):
  schema = {
                "projecturl": {"type": "string"},
                "projectgetagenturl": {"type": "string"},
                "runinstallercommand": {"type": "string"},
                "_id": {"type": "objectid"},
                "name": {"type": "string", "regex": "^.+", "required": True}, 
                "user": {"type": "dict", "schema": {
                  "email":{"type": "string", "regex": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", "required": True}
                  }, "required": True
                },
                "board":{"type": "string", "allowed": settings.INSTALLER_FILE_PATHS.keys(), "required": True}, 
                "fwlanguage":{"type": "string", "allowed": ["Python"], "required": True},
                "boards": {"type": "list", "unique": {"key": "macaddress"}, "schema": {
                  "type": "dict", "schema": {
                    "macaddress":{"type": "string", "regex": "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", "required": True},
                    "ID": {"type": "string", "regex": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "required": True},
                    "JID": {"type": "string", "regex": "^.+", "required": True}, 
                    "password": {"type": "string"},
                    "simnumber": {"type": "string"}

                    }, "required": True
                  }
                },
                "messages": {"type": "list"},
              }

  def __init__(self, value):
    super(Project, self).__init__(value)

  def set_project_urls(self):
    _id = self.value["_id"]

    self.value["projecturl"] = settings.PROJECT_URL_TEMPLATE.format(_id)
    self.value["projectgetagenturl"] = settings.GET_AGENT_URL_TEMPLATE.format(_id)
    self.value["runinstallercommand"] = settings.RUN_INSTALLER_COMMAND_TEMPLATE.format(self.value["projectgetagenturl"])


  def get_board(self, macaddress):
    board = None
    if 'boards' in self.value:
      boards = [b for b in self.value['boards'] if b['macaddress'] == macaddress]

      if len(boards) == 1:
        board = boards[0]

    return board

  def add_board(self, macaddress):
    if not "boards" in self.value.keys():
      self.value["boards"] = []

    ID = str(uuid.uuid4())

    board = {
      "macaddress": macaddress, 
      "ID": ID, 
      "JID": "{}@{}".format(ID, settings.XMPP_DOMAIN),
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