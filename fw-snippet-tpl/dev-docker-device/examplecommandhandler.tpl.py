def {{ type }}(command):

  # {{ comment }}

  # function to handle the command {{ type }}
  # command description: {{ description }}
  # format of command dict:
  # {{ jsonfmt }}

  # cmdpars stores the command parameters
  cmdpars = command["{{ type }}"]

  #-----------------------------------------------------------------------------#
  # for example purpose
  # the global examplecommandstatus is set with the status from the command:
  examplecommandstatus.value = cmdpars["status"] == "start"
  
  # then the command is sent back in an ECHO message
  send_msg({"ECHO": command})
  #-----------------------------------------------------------------------------#
