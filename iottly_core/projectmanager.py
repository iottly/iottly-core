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

from iottly_core import settings
from iottly_core import validator

class Project(validator.SchemaDictionary):
  schema = {
                "projecturl": {"type": "string"},
                "_id": {"type": "objectid"},
                "name": {"type": "string", "regex": "^.+", "required": True}, 
                "user": {"type": "dict", "schema": {
                  "email":{"type": "string", "regex": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", "required": True}
                  }, "required": True
                },
                "board":{"type": "string", "allowed": ["Raspberry Pi"], "required": True}, 
                "fwlanguage":{"type": "string", "allowed": ["Python"], "required": True},
                "boards": {"type": "list", "unique": {"key": "MAC"}, "schema": {
                  "type": "dict", "schema": {
                    "MAC":{"type": "string", "regex": "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", "required": True},
                    "ID": {"type": "string", "regex": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "required": True},

                    }, "required": True
                  }
                },
              }

  def __init__(self, value):
    super(Project, self).__init__(value)
    

  def add_board(self, MAC):
    if not "boards" in self.value.keys():
      self.value["boards"] = []

    ID = str(uuid.uuid4())

    board = {"MAC": MAC, "ID": ID}
    self.value["boards"].append(board)

    if not self.validate():
      raise Exception(self.validator.errors)
    
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