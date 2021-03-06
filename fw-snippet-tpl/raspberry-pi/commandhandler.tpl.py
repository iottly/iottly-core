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
  # example code to set GPIO Pins
  # https://sourceforge.net/p/raspberry-gpio-python/wiki/BasicUsage/
  # pin = "1"
  # status = True # pin on
  # GPIO.output(int(pin),status)

  #-----------------------------------------------------------------------------#
  # here your code!!

  #-----------------------------------------------------------------------------#
