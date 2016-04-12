#{{ comment }}

import time
import multiprocessing
import RPi.GPIO as GPIO

from iottly.iottlyagent import send_msg

# remember to use multiprocessing.Value to share global variables
# with the loop function since it runs in a separate process
# for example this variable affect the execution of the loop function
# while it can be set by issuing the predefined examplecommand

examplecommandstatus = multiprocessing.Value('b', False)

{{ body }}
