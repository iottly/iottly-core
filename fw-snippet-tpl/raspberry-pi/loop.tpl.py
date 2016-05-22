def loop():
  # this is the main loop of your device

  # it runs in a separate process, so:
  # remember to use multiprocessing.Value to share global variables
  # within this function
  # example bool_var = multiprocessing.Value('b', False)

  #-----------------------------------------------------------------------------#
  # for example purpose
  # remove this for real purposes
  # pin 3 status is read from board and sent to iottly if True
  # pin status can be changed by issuing predefined examplecommand
  pin = "3"
  pinstatus = GPIO.input(int(pin))
  if pinstatus:
    send_msg({"looptest": {"pinstatus": pinstatus}})
  #-----------------------------------------------------------------------------#

  #-----------------------------------------------------------------------------#
  # here your code!!


  #-----------------------------------------------------------------------------#

  # this is the timeout between loops in seconds (can be decimal)
  # changing the timeout can affect device performances
  # always leave a non zero timeout
  time.sleep(1)

