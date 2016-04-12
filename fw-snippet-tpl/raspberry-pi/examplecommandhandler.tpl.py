def {{ type }}(command):

  # {{ comment }}

  # function to handle the command {{ type }}
  # command description: {{ description }}
  # format of command dict:
  # {{ jsonfmt }}

  # cmdpars stores the command parameters
  cmdpars = command["{{ type }}"]

  #-----------------------------------------------------------------------------#
  # example code to set GPIO Pins
  # https://sourceforge.net/p/raspberry-gpio-python/wiki/BasicUsage/
  pin = "2"
  status = cmdpars["status"] == "start"
  GPIO.output(int(pin),status)

  
  # then the command is sent back in an ECHO message
  send_msg({"ECHO": command})
  #-----------------------------------------------------------------------------#
