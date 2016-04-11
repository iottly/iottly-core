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
  # the command is sent back in an ECHO message
  # remove this line for real purposes
  send_msg({"ECHO": command})
  #-----------------------------------------------------------------------------#

  #-----------------------------------------------------------------------------#
  # here your code!!

  #-----------------------------------------------------------------------------#
