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
from pbkdf2 import pbkdf2_bin

from bson import json_util
from bson.objectid import ObjectId
from tornado import gen, httpclient

from iottly_core import dbapi

# From: https://exyr.org/2011/hashing-passwords/
# From https://github.com/mitsuhiko/python-pbkdf2
SALT_LENGTH = 12
KEY_LENGTH = 24
HASH_FUNCTION = 'sha256'  # Must be in hashlib.
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

    user = yield dbapi.find_one_by_condition('boardsMqttAuth', {'username': username})
    res = yield dbapi.remove_by_id('boardsMqttAuth', user.get('_id'))
    res = yield dbapi.remove_by_id('boardsMqttTopics', user.get('topics'))
    raise gen.Return(res)
