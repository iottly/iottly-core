def {{ type }}(command):

    # {{ comment }}

    # function to handle the command {{ type }}
    # command description: {{ description }}
    # format of command dict:
    # {{ jsonfmt }}

    # cmdpars stores the command parameters
    cmdpars = command["{{ type }}"]

    # ECHO message to test the command (remove this line for real purposes)
    send_msg({"ECHO": command})


    ###############################################################################
    # here your code!!

    ###############################################################################
    