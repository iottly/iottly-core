def init():
  #{{ comment }}
  {{ body }}

  GPIO.setmode(GPIO.BOARD)  
  GPIO.setwarnings(False)

  #-----------------------------------------------------------------------------#
  # for example purpose
  # remove this for real purposes
  # https://sourceforge.net/p/raspberry-gpio-python/wiki/BasicUsage/
  # pin 2 status is read from board and sent to iottly
  # pin status can be changed by issuing predefined examplecommand
  pin = "2"
  GPIO.setup(int(pin), GPIO.OUT)
  # or
  # GPIO.setup(int(pin), GPIO.INT) # to set as input
  #-----------------------------------------------------------------------------#

  #-----------------------------------------------------------------------------#
  # here your code!!
  
  #-----------------------------------------------------------------------------#
