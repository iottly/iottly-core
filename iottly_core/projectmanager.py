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
                "boards": {"type": "list", "unique": {"key": "name"}, "schema": {
                  "type": "dict", "schema": {
                    "name":{"type": "string", "regex": "^.+", "required": True},
                    }, "required": True
                  }
                },
              }

  def __init__(self, value):
    super(Project, self).__init__(value)
    

  def set_IDs_and_urls(self):
    self.value['ID'] = str(uuid.uuid4())
    self.value['projecturl'] = "%s/projects/%s" % (settings.PUBLIC_URL_PREFIX, self.value['ID'])



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