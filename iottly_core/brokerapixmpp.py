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

from bson import json_util
from tornado import gen, httpclient
from tornado.httputil import url_concat

from iottly_core.settings import settings


HEADERS = {
    "Authorization": settings.XMPP_MGMT_REST_SECRET,
    "Accept": "application/json",
    "Content-Type": "application/json"
}



@gen.coroutine
def create_user(username, password, roster=None):

    #call xmppbroker to register new JID            
    http_client = httpclient.AsyncHTTPClient()

    post_data = {
        "username": username,
        "password": password
    }

    body = json.dumps(post_data, default=json_util.default)

    logging.info('body: {}'.format(body))

    res = yield http_client.fetch(settings.XMPP_MGMT_REST_URL, method='POST', headers=HEADERS, body=body)
    if res.error:
        raise Exception("Create user: " + res.error)
    else:

        if roster:
            post_data = {
                "jid": roster,
                "subscriptionType": "3"
            }
            body = json.dumps(post_data, default=json_util.default)

            xmpp_api_url = "{}/{}/{}".format(settings.XMPP_MGMT_REST_URL, username, "roster")
            
            res = yield http_client.fetch(xmpp_api_url, method='POST', headers=HEADERS, body=body)

            if res.error:
                raise Exception("Create roster: " + res.error)



@gen.coroutine
def delete_user(username):

    #call xmppbroker to register new JID            
    http_client = httpclient.AsyncHTTPClient()

    xmpp_api_url = "{}/{}".format(settings.XMPP_MGMT_REST_URL, username)

    logging.info(xmpp_api_url)

    res = yield http_client.fetch(xmpp_api_url, method="DELETE", headers=HEADERS, body=None)
    if res.error:
        raise Exception("Create user: " + res.error)


@gen.coroutine
def fetch_status(presence_url, xmpp_backend_user, jid):

    http_client = httpclient.AsyncHTTPClient()
    url = url_concat(presence_url, {'jid': jid, 'req_jid':xmpp_backend_user, 'type': 'text'})
    res = yield http_client.fetch(url)

    if res.error:
        raise Exception(res.error)

    status = {
        'connected': True if res.body.strip() == 'null' else False
        # more statuses to come ...
    }

    raise gen.Return(status)            
