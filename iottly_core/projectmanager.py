from iottly_core import util

class Project(object):
  template = {
                "name": r"^.+", 
                "user": {
                   "email":r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
                },
                "board":r"^Raspberry Pi", 
                "fwlanguage":r"^Python",
                "boards": [
                  {
                    "name":r"^.+",
                    "ID": r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
                  }        
                ],
              }

  def __init__(self, value):
    if util.checkdictionary(value, self.template):
      self.value = value
    else:
      raise Exception("Wrong project shape or data format.")

  def set_project_url(self, url):
    self.value["projecturl"] = url

  def set_agent_url(self, ID, url):
    board = next((b for b in self.value["boards"] if b["ID"] == ID), None)
    if board:
      board["agenturl"] = url
    else:
      raise Exception("Board %s not found in project" % ID)


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