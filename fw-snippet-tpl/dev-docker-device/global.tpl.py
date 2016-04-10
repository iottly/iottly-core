#{{ comment }}

import time
import multiprocessing

from iottly.iottlyagent import send_msg

# remember to use multiprocessing.Value to share global variables
# with the loop function since it runs in a separate process
# example bool_var = multiprocessing.Value('b', False)

{{ body }}
