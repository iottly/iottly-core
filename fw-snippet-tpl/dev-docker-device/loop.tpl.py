def loop():
  # this is the main loop of your device

  # it runs in a separate process, so:
  # remember to use multiprocessing.Value to share global variables
  # within this function
  # example bool_var = multiprocessing.Value('b', False)

  #-----------------------------------------------------------------------------#
  # for example purpose
  # remove this for real purposes
  # the message is sent depending on examplecommandstatus value
  # which can be sending the predefined examplecommand
  if examplecommandstatus.value:
    send_msg({"looptest": {"timermessage": 1}})
  #-----------------------------------------------------------------------------#

  #-----------------------------------------------------------------------------#
  # here your code!!


  #-----------------------------------------------------------------------------#

  # this is the timeout between loops in seconds (can be decimal)
  # changing the timeout can affect device performances
  # always leave a non zero timeout
  time.sleep(1)

