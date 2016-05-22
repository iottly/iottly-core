def init():
  #{{ comment }}
  {{ body }}

  GPIO.setmode(GPIO.BOARD)  
  GPIO.setwarnings(False)

  #-----------------------------------------------------------------------------#
  # for example purpose
  # remove this for real purposes
  # https://sourceforge.net/p/raspberry-gpio-python/wiki/BasicUsage/
  # pin 3 status is set as OUT and initialized to False status
  # pin status can be changed by issuing predefined examplecommand
  pin = "3"
  GPIO.setup(int(pin), GPIO.OUT)
  GPIO.output(int(pin), False)
  # or
  # GPIO.setup(int(pin), GPIO.INT) # to set as input
  #-----------------------------------------------------------------------------#

  #-----------------------------------------------------------------------------#
  # here your code!!
  
  #-----------------------------------------------------------------------------#
