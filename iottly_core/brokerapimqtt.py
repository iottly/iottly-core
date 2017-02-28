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
import json
import logging
import hashlib
from os import urandom
from base64 import b64encode, b64decode
from itertools import izip

from bson import json_util
from bson.objectid import ObjectId
from tornado import gen, httpclient

from iottly_core import dbapi

# From: https://exyr.org/2011/hashing-passwords/
# From https://github.com/mitsuhiko/python-pbkdf2
from pbkdf2 import pbkdf2_bin


# Parameters to PBKDF2. Only affect new passwords.
SALT_LENGTH = 12
KEY_LENGTH = 24
HASH_FUNCTION = 'sha256'  # Must be in hashlib.
# Linear to the hashing time. Adjust to be high but take a reasonable
# amount of time on your server. Measure with:
# python -m timeit -s 'import passwords as p' 'p.make_hash("something")'
COST_FACTOR = 901


def make_hash(password):
    """Generate a random salt and return a new hash for the password."""
    if isinstance(password, unicode):
        password = password.encode('utf-8')
    salt = b64encode(urandom(SALT_LENGTH))
    return 'PBKDF2${}${}${}${}'.format(
        HASH_FUNCTION,
        COST_FACTOR,
        salt,
        b64encode(pbkdf2_bin(password, salt, COST_FACTOR, KEY_LENGTH,
                             getattr(hashlib, HASH_FUNCTION))))


# PBKDF2$sha256$10000$WZFpK5vEb1l5JVjF$q7dJ4ZANIkEEkRd8k7pbRb/kMSGspmmH
# PBKDF2$sha256$901$G3BatbMS88ks2gpx$h2V+ufI7/UM6XjeJMHBSdQGPkdwjdWgh
# PBKDF2$sha256$901$/GKLHCHanEVIu3YU$xA7cI+hzqthrGASQYqb3CM+U/Av+MDOb

@gen.coroutine
def create_user(username, password, topics):
    logging.info('create_user {}'.format(topics))

    new_topics_id = yield dbapi.insert('boardsMqttTopics', {
            'topics': topics
        })
    logging.info('create_user new_topics_id {}'.format(new_topics_id))

    apiresult = yield dbapi.insert('boardsMqttAuth', {
            'username': username, 
            'password': make_hash(password), 
            'topics': ObjectId(new_topics_id), 
            'superuser':0        
        })

    raise gen.Return(apiresult)

@gen.coroutine
def delete_user(username):

    pass
