def loop():
    # this is the main loop of your device

    # for example purpose
    # this is a message the device will send forever
    # remove this line for real purposes
    send_msg({"looptest": {"timermessage": 1}})

    ###############################################################################
    # here your code!!

    ###############################################################################

    # this is the timeout between loops in seconds (can be decimal)
    # changing the timeout can affect device performances
    # always leave a non zero timeout
    time.sleep(1)

