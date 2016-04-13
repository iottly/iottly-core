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
from collections import OrderedDict

import prettysettings

defaults = dict(

    # MongoDB settings
    MONGO_DB_URL = 'mongodb://{}:{}/'.format("db", 27017),
    MONGO_DB_NAME = 'iottly',

    TIMEZONESTR = pytz.country_timezones['it'][0],

    # python iso format stringtom
    TIME_FMT = "%Y-%m-%dT%H:%M:%S",

    # XMPP Client settings
    XMPP_HOST = 'xmppbroker',
    XMPP_PORT = 5222,
    XMPP_MGMT_REST_URL = 'http://xmppbroker:9090/plugins/restapi/v1/users',
    XMPP_MGMT_REST_SECRET = 'EKdj6y0USG4tP4Ki',


    XMPP_DOMAIN = 'xmppbroker.localdev.iottly.org',
    XMPP_USER = 'iottlycore@xmppbroker.localdev.iottly.org',
    XMPP_PASSWORD = 'iottlycore',

    PRESENCE_URL = 'http://xmppbroker:9090/plugins/presence/status',
    CLIENT_CALLBACK_URL = 'http://iottlyclientcore:8521/msg',


    # Filesystem binaries (FW/NN)
    FIRMWARE_DIR = '/var/iottly-core/uploads/fw/',
    CODEREPO_DIR = '/var/iottly-core/coderepo/',    
    USERDEFINEDFWPACKAGE_PATH = 'userpackage',
    USERDEFINEDFW_FILENAME = 'userdefinedfw.py',

    SECRET_SALT = 'secrect',
    FW_PADDING = chr(0x20),
    FW_CHUNK_SIZE = 1024,

    ADMINS = {
    },


    # Tornado specific settings, see http://www.tornadoweb.org/en/stable/web.html#tornado.web.Application.settings
    static_path = os.path.join("/iottly_console", "static"),
    template_path = os.path.join("/iottly_console", "templates"),
    debug = True,

    cookie_secret = 'secret',
    login_url = '/auth',

    #public urls prefix:
    #HTTP:
    API_VERSION='v1.0',
    PUBLIC_HOST='127.0.0.1',
    PUBLIC_HOST_PORT_PATTERN='',
    PUBLIC_URL_PATTERN = 'http://{}/{}',

    PROJECT_URL_PATTERN = '{}/admin/{}',
    GET_AGENT_URL_PATTERN = '{}/project/{}/getagent',
    RUN_INSTALLER_COMMAND_TEMPLATE = 'wget -O - {} | bash',
    DEVICEREGISTRATION_SERVICE_PATTERN = '/{}/project/{}/deviceregistration',

    #XMPP:
    PUBLIC_XMPP_HOST='127.0.0.1',
    PUBLIC_XMPP_PORT = 5222,


    #repo for devices' installers
    IOTTLY_REGISTRATION_PROTOCOL = 'https',
    DEVICE_INSTALLERS_BUILDER_PATH = '/iottly-device-agent-py-installers/installer-builders',
    DEVICE_INSTALLERS_REPO_PATH = '/iottly-device-agent-py-installers/installer-project-repos',
    DEVICE_INSTALLER_NAME_TEMPLATE = '{}-iottlyagentinstaller.bsx',
    #repo for devices' fw template
    DEVICE_FW_SNIPPET_TPL_REPO_PATH = '/fw-snippet-tpl',

    BOARDS_TYPE_MAP = {
        'Raspberry Pi': 'raspberry-pi', 
        'Dev Docker Device': 'dev-docker-device'
    },

    INSTALLER_FILENAME = 'installer.sh',

    # See instructions for registering app with google:
    # http://tornado.readthedocs.org/en/latest/auth.html#tornado.auth.GoogleOAuth2Mixin
    # This key is configured for the production server
    google_oauth = {
      'key': 'GOOGLE_OAUTH2_CLIENT_ID',
      'secret': 'GOOGLE_OAUTH2_CLIENT_SECRET'
    },

)

# cshooks = {
#     'TIMEZONE': lambda settings: pytz.timezone(settings.TIMEZONESTR),
#     'XMPP_SERVER': lambda settings: (settings.XMPP_HOST, settings.XMPP_PORT),
#     'PUBLIC_HOST_PORT': lambda settings: settings.PUBLIC_HOST_PORT_PATTERN.format(settings.PUBLIC_HOST),
#     'PUBLIC_URL_PREFIX': lambda settings: settings.PUBLIC_URL_PATTERN.format(settings.PUBLIC_HOST_PORT_PATTERN.format(settings.PUBLIC_HOST)),
#     'INSTALLER_FILE_PATHS': lambda settings: {
#         k: os.path.join(
#             settings.DEVICE_INSTALLERS_REPO_PATH,
#             settings.BOARDS_TYPE_MAP[k],
#             settings.INSTALLER_FILENAME) 
#         for k in settings.BOARDS_TYPE_MAP.keys()
#     }

# }

cshooks = OrderedDict([
    ('TIMEZONE', lambda settings: pytz.timezone(settings.TIMEZONESTR)),
    ('XMPP_SERVER', lambda settings: (settings.XMPP_HOST, settings.XMPP_PORT)),
    ('PUBLIC_HOST_PORT', lambda settings: settings.PUBLIC_HOST_PORT_PATTERN.format(settings.PUBLIC_HOST)),
    ('PUBLIC_URL_PREFIX', lambda settings: settings.PUBLIC_URL_PATTERN.format(settings.PUBLIC_HOST_PORT, settings.API_VERSION)),
    ('PROJECT_URL_TEMPLATE', lambda settings: settings.PROJECT_URL_PATTERN.format(settings.PUBLIC_URL_PREFIX, '{}')),
    ('GET_AGENT_URL_TEMPLATE', lambda settings: settings.GET_AGENT_URL_PATTERN.format(settings.PUBLIC_URL_PREFIX, '{}')),
    ('DEVICEREGISTRATION_SERVICE_TEMPLATE', lambda settings: settings.DEVICEREGISTRATION_SERVICE_PATTERN.format(settings.API_VERSION, '{}')),

    ('INSTALLER_FILE_PATHS', lambda settings: {
            k: os.path.join(
                settings.DEVICE_INSTALLERS_REPO_PATH,
                settings.BOARDS_TYPE_MAP[k],
                settings.INSTALLER_FILENAME) 
            for k in settings.BOARDS_TYPE_MAP.keys()
        }),
    ('FW_SNIPPET_TPL_FILE_PATHS', lambda settings: {
            k: os.path.join(
                settings.DEVICE_FW_SNIPPET_TPL_REPO_PATH,
                settings.BOARDS_TYPE_MAP[k]) 
            for k in settings.BOARDS_TYPE_MAP.keys()
        }),


])


settings = prettysettings.Settings(defaults, computed_settings_hooks = cshooks)






