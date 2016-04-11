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
import os
import uuid
import random
import logging
import os
from jinja2 import FileSystemLoader, Environment, Template
import datetime
import tarfile

from iottly_core.settings import settings


class FwCode():

  def __init__(self, value, board):
    self.value = value
    
    self.templateLoader = FileSystemLoader( searchpath=settings.FW_SNIPPET_TPL_FILE_PATHS[board] )
    self.templateEnv = Environment( loader=self.templateLoader )

  staticsnippets = ["global", "init", "loop"]

  basesnippets = [
    {
      "name": "global",
      "category": "Init sections",
      "description": "Import and globals",
      "template": "global.tpl.py",
      "body": ""
    },
    {
      "name": "init",
      "category": "Init sections",
      "description": "Init function",
      "template": "init.tpl.py",
      "body": "pass"
    },
    {
      "name": "loop",
      "category": "Loop section",
      "description": "Loop function",
      "template": "loop.tpl.py",
      "body": "pass"
    },    
    {
      "name": "command",
      "category": "Command handlers",      
      "description": "{} handler function",
      "template": "commandhandler.tpl.py",
      "body": ""
    },


  ]

  def createbasesnippets(self):
    snippets = []
    if "fwcode" not in self.value.keys():
      self.value["fwcode"] = {"snippets": snippets}

    for bn in [bn for bn in self.basesnippets if bn["name"] in self.staticsnippets]:
      template = self.templateEnv.get_template( bn["template"] )

      templateVars = { 
        "comment" : "generated on {}".format(datetime.datetime.now()),
        "body" : bn["body"] 
      }

      outputText = template.render( templateVars )
      snippets.append({
          "name": bn["name"],
          "category": bn["category"],
          "description": bn["description"],
          "snippetid": str(uuid.uuid4()),
          "code": outputText
        }
      )

    for msg in self.value["messages"]:
      self.createMsgSnippet(msg, snippets)




  def createMsgSnippet(self, msg, snippets):
    metadata = msg["metadata"]
    if metadata["direction"] == "command":
      self.createCmdSnippet(msg, snippets)

  def createCmdSnippet(self, msg, snippets):
    metadata = msg["metadata"]
    bn = [bn for bn in self.basesnippets if bn["name"] == "command"][0]

    template = self.templateEnv.get_template( bn["template"] )

    templateVars = { 
      "comment" : "generated on {}".format(datetime.datetime.now())
    }

    templateVars.update(metadata)

    outputText = template.render( templateVars )
    snippets.append({
        "name": metadata["type"],
        "category": bn["category"],
        "description": metadata["type"],
        "snippetid": str(uuid.uuid4()),
        "code": outputText
      }
    )

  def setMsgSnippetZombie(self, msg):
    snippets = self.value["fwcode"]["snippets"]
    metadata = msg["metadata"]
    msgtype = metadata["type"]

    def nextzombiename(msgtype, snippets, firstsnippet= None):

      _snippets = [sn for sn in snippets if sn["name"] == msgtype]
      if len(_snippets) == 1:
        snippet = _snippets[0]
        if not firstsnippet:
          firstsnippet = snippet
        next_zombie_name = "_{}".format(snippet["name"])
        return nextzombiename(next_zombie_name, snippets, firstsnippet)
      elif len(_snippets) == 0:
        return (firstsnippet, msgtype)

    snippet, next_zombie_name = nextzombiename(msgtype, snippets)
    
    logging.info(next_zombie_name)


    defstatement = "def {}(command):"
    template = self.templateEnv.get_template( "zombiecommandhandler.tpl.py" )
    templateVars = { 
      "type" : msgtype,
      "body": snippet["code"].replace(defstatement.format(msgtype), defstatement.format(next_zombie_name))
    }
    outputText = template.render( templateVars )

    snippet["name"] = next_zombie_name
    snippet["description"] = next_zombie_name    
    snippet["code"] = outputText


  def generateFullFw(self):

    # access project fw folder
    # create workdir tree
    # create fwdir tree inside workdir

    temppath = str(uuid.uuid4())
    workdir = os.path.join(settings.CODEREPO_DIR, str(self.value["_id"]), temppath)
    packagedir = os.path.join(workdir, settings.USERDEFINEDFWPACKAGE_PATH)
    os.makedirs(packagedir)

    uploaddir = os.path.join(settings.FIRMWARE_DIR, str(self.value["_id"]))

    logging.info("workdir: {}".format(workdir))
    logging.info("packagedir: {}".format(packagedir))
    logging.info("uploaddir: {}".format(uploaddir))
    

    # generate code inside fwdir tree
    template = self.templateEnv.get_template( "userdefinedfw.tpl.py" )
    templateVars = { 
      "date" : datetime.datetime.now(),
      "projectname": self.value["name"]
    }

    templateVars.update({
      sn["name"]: sn["code"] 
      for sn in self.value["fwcode"]["snippets"] 
      if sn["name"] in self.staticsnippets
    })

    templateVars["cmdsnippets"] = [
      sn for sn in self.value["fwcode"]["snippets"] 
      if sn["category"] == "Command handlers"
    ]

    outputText = template.render( templateVars )

    with open(os.path.join(packagedir, settings.USERDEFINEDFW_FILENAME), "wb") as fh:
      fh.write(outputText)

    # produce tar.gz inside workdir tree
    archivefile = "{}.{}".format(temppath, self.value["fwextension"])
    archive = os.path.join(uploaddir, archivefile)
    with tarfile.open(archive, "w:gz") as tar:
      tar.add(packagedir, arcname=os.path.basename(packagedir))

    # return path of tar.gz
    return archivefile
    


