"""

Copyright 2015 Stefano Terna

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""
import os
import pytz

# MongoDB settings
MONGO_DB_URL = 'mongodb://%s:%s/' % ("iottlydocker_db_1", 27017)
MONGO_DB_NAME = 'iottly'

TIMEZONE = pytz.timezone(pytz.country_timezones['it'][0])

# python iso format stringtom
TIME_FMT = "%Y-%m-%dT%H:%M:%S"

# XMPP Client settings
XMPP_SERVER = ('iottlydocker_xmppbroker_1', 5222)

XMPP_USER = 'iottlycore@xmppbroker.localdev.iottly.org'
XMPP_PASSWORD = 'iottlycore'

# See instructions for registering app with google:
# http://tornado.readthedocs.org/en/latest/auth.html#tornado.auth.GoogleOAuth2Mixin
# This key is configured for the production server at big.tomorrowdata.it:8520
GOOGLE_OAUTH2_CLIENT_ID = ''
GOOGLE_OAUTH2_CLIENT_SECRET = ''

PRESENCE_URL = 'http://iottlydocker_xmppbroker_1:9090/plugins/presence/status'
CLIENT_CALLBACK_URL = 'http://iottlydocker_iottlyclientcore_1:8521/msg'


# Filesystem binaries (FW/NN)
FIRMWARE_DIR = '/var/iottly-core/uploads/fw/'

SECRET_SALT = 'fj39Adkq49dKkxpw'

ADMINS = {
  'dimaofman@gmail.com',
  'stefano.terna@gmail.com',
  'giancarlo.capella@gmail.com',
  'raffaele.passannanti@gmail.com'
}

# Tornado specific settings, see http://www.tornadoweb.org/en/stable/web.html#tornado.web.Application.settings
static_path = os.path.join("/iottly_console", "static")
template_path = os.path.join("/iottly_console", "templates")
debug = True

cookie_secret = '/}Mt,GevcVNY8##`H}0^jH+6B+Goq|f1Y4|.P-2Bpvyl60zKY>gYQ4|XP_4k<(sM'
login_url = '/auth'

try:
    from localsettings import *
except ImportError:
    pass

google_oauth = {
  'key': GOOGLE_OAUTH2_CLIENT_ID,
  'secret': GOOGLE_OAUTH2_CLIENT_SECRET
}
