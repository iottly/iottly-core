import uuid
import random
import logging
import os
from jinja2 import FileSystemLoader, Environment, Template
import datetime

from iottly_core.settings import settings


class FwCode():

  def __init__(self, value, board):
    self.value = value
    
    self.templateLoader = FileSystemLoader( searchpath=settings.FW_SNIPPET_TPL_FILE_PATHS[board] )
    self.templateEnv = Environment( loader=self.templateLoader )


  basesnippets = [
    {
      "name": "global",
      "category": "Init sections",
      "description": "Import and globals",
      "template": "global.tpl.py",
      "body": "import os"
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

    for bn in [bn for bn in self.basesnippets if bn["name"] in ["global", "init", "loop"]]:
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

    logging.info(outputText)
