def loop():
  # this is the main loop of your device

  # it runs in a separate process, so:
  # remember to use multiprocessing.Value to share global variables
  # within this function
  # example bool_var = multiprocessing.Value('b', False)

  #-----------------------------------------------------------------------------#
  # for example purpose
  # this is a message the device will send forever
  # remove this line for real purposes
  send_msg({"looptest": {"timermessage": 1}})
  #-----------------------------------------------------------------------------#

  #-----------------------------------------------------------------------------#
  # here your code!!


  #-----------------------------------------------------------------------------#

  # this is the timeout between loops in seconds (can be decimal)
  # changing the timeout can affect device performances
  # always leave a non zero timeout
  time.sleep(1)

