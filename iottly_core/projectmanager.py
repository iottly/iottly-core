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
from iottly_core import schemadictionary as sd

class Project(sd.SchemaDictionary):
  schema = {
                "name": r"^.+", 
                "user": {
                   "email":r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
                },
                "board":r"^Raspberry Pi", 
                "fwlanguage":r"^Python",
                "boards": [
                  {
                    "name":r"^.+",
                  }        
                ],
              }

  def __init__(self, value):
    super(Project, self).__init__(value)
    #TODO: check for boards name duplicates

  def set_project_ID(self, ID):
    self.value["projectid"] = ID
    self.value["projecturl"] = get_project_url(ID)

  def set_board_ID(self, ID, url):
    #TODO: set project ID for each board and then set agent url
    board = next((b for b in self.value["boards"] if b["ID"] == ID), None)
    if board:
      board["agenturl"] = url
    else:
      raise Exception("Board %s not found in project" % ID)


def get_project_url(ID):
    return "%s/%s"

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
      "ID": "raspdev.0001@xmppbroker.localdev.iottly.org"
    }        
  ],
}

"""