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
import base64
import copy
import hashlib
import json
import logging
import motor
import os
import pytz
import pymongo
import random
import time
import tornado
import ujson
import unicodedata
import urllib
import urlparse

from bson import json_util
from bson.objectid import ObjectId
from datetime import datetime
from tornado import gen, autoreload, httpclient
import tornado.ioloop
import tornado.web
import tornado.auth
from tornado.httputil import url_concat
from tornado.escape import json_encode
from sockjs.tornado import SockJSRouter, SockJSConnection

from iottly_core.util import module_to_dict, extract_request_dict

from iottly_core import commander
from iottly_core import ibcommands
from iottly_core import settings
from iottly_core import messageparser
from iottly_core import flashmanager
from iottly_core import permissions
from iottly_core import boards
from iottly_core import projectmanager
from iottly_core.dbapi import db
from iottly_core import dbapi

logging.getLogger().setLevel(logging.DEBUG)


xmpp_process = commander.init(settings.XMPP_USER, settings.XMPP_PASSWORD)
connected_clients = set()



class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")

class GoogleOAuth2LoginHandler(BaseHandler,
                               tornado.auth.GoogleOAuth2Mixin):
    # Adapted from https://github.com/googlewallet/jwt-decoder-python/blob/master/jwtdecoder.py
    def _jwt_decode(self, val):
        val = unicodedata.normalize('NFKD', val).encode('ascii', 'ignore')
        val += b'=' * (4 - (len(val) % 4))
        decoded = base64.standard_b64decode(val).decode('utf-8', 'ignore')
        try:
            decoded = json.loads(decoded)
        except ValueError:
            decoded = None
        return decoded

    def parse_user_info(self, response):
        """Parse repsonse from get_authenticated_user()
        The return data contains useful information in dict
        """
        (header, claims, signature) = response['id_token'].split('.')
        return self._jwt_decode(claims)

    @tornado.gen.coroutine
    def get(self):
        redirect_uri = self.request.full_url().split('?')[0]
        if self.get_argument('code', False):
            user_info = yield self.get_authenticated_user(
                redirect_uri=redirect_uri,
                code=self.get_argument('code'))

            user = self.parse_user_info(user_info)
            user_email = user.get("email", "")

            self.set_secure_cookie("user", user.get("email", ""), expires_days=None)
            self.redirect(self.get_argument("state", "/"))
        else:
            yield self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings['google_oauth']['key'],
                scope=['email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto', 'state': self.get_argument("next")})

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))

class MessagesConnection(SockJSConnection):
    def on_open(self, info):
        connected_clients.add(self)

    def on_close(self):
        connected_clients.remove(self)

class MessageHandler(BaseHandler):
    def initialize(self):
        self.processing_map = {
            'TimeReq': self.set_time,
            'Firmware': self.send_firmware_chunks
        }

    @gen.coroutine
    def post(self):
        request_args = ('to', 'from', 'msg')
        msg = { k: self.get_argument(k) for k in request_args }

        # Immediately return control to the caller
        self.set_status(200)
        self.finish()

        msg = messageparser.annotate_message(msg)
        msgs = messageparser.parse_message(copy.deepcopy(msg))
        persist_msgs = filter(messageparser.check_persist, msgs)
        msgs_json = json.dumps({ 'msgs': msgs }, default=json_util.default)

        yield [
            dbapi.insert('message_logs', msg),
            dbapi.insert('messages', persist_msgs),
            self._check_and_forward_messages(msgs)
            ]

        self._broadcast(msgs_json)
        self._process_msgs(msgs)

    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def get(self):
        jid = self.get_argument('jid')
        query_json = self.get_argument('queryJson', None)
        num_messages = int(self.get_argument('numMessages', None) or 10)
        query_dict = { 'from' : jid }
        query = {}

        if query_json:
            query = ujson.loads(query_json)
            query_dict.update(query)

        cursor = db.messages.find(query_dict)

        messages = []

        # Modify the query before iterating
        cursor.sort([('timestamp', pymongo.DESCENDING)]).limit(num_messages)
        while (yield cursor.fetch_next):
            messages.append(cursor.next_object())

        messages.reverse()

        self.write(json.dumps({
            'status': 200,
            'messages': messages
        }, default=json_util.default))
        self.set_header("Content-Type", "application/json")


    def _broadcast(self, msg):
        for client in connected_clients:
            logging.info(client)
            client.send(msg)

    @gen.coroutine
    def _check_and_forward_messages(self, msgs):
        results = yield [self._forward_msg_to_client(m) for m in filter(messageparser.check_message_forward, msgs)]

    @gen.coroutine
    def _forward_msg_to_client(self, msg):
        http_client = httpclient.AsyncHTTPClient()

        # Remove mongo ID if found
        if '_id' in msg:
            del msg['_id']

        # Serializes datetime to isoformat
        dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime) else json.JSONEncoder().default(obj)
        post_data = {
            'msg': json.dumps(msg, default=dthandler)
        }
        body = urllib.urlencode(post_data)
        res = None
        try:
            res = yield http_client.fetch(settings.CLIENT_CALLBACK_URL, method='POST', body=body)
        except tornado.httpclient.HTTPError, e:
            logging.warn('Problem posting to {}: {}'.format(settings.CLIENT_CALLBACK_URL, e))

        raise gen.Return(res)

    def set_time(self, msg):
        commander.send_command('timeset', msg['from'])

    def send_firmware_chunks(self, msg):
        fw = msg.get('fw')
        if fw is None:
            return

        from_jid = msg.get('from').split('/')[0]

        num_chunks = fw.get('qty', 0)
        dim_chunk = fw.get('dim', 256)
        area = fw.get('area', 0)
        block = fw.get('block', 0)
        active_file = fw.get('file', None)

        if active_file is None or active_file == '':
            commander.send_command('Transfer Complete', from_jid, {
                'fw.area': area,
                'fw.block': block,
                'fw.file': active_file,
            })
            return

        chunks = flashmanager.get_b64_chunks(active_file, dim_chunk)
        for i in range(num_chunks):
            data = chunks[block+i].strip() if block+i < len(chunks) else None
            values = {
                'fw.area': area,
                'fw.block': block + i,
                'fw.file': active_file,
            }
            if data is None:
                commander.send_command('Transfer Complete', from_jid, values)
                break
            else:
                values['fw.data'] = data
                commander.send_command('Send Chunk', from_jid, values)

        progress_msg = {
            'type': 'progress',
            'area': area,
            'to': from_jid,
            'total_chunks': len(chunks),
            'chunks_sent': block + num_chunks if data else len(chunks)
        }

        self._broadcast(ujson.dumps(progress_msg))

    def _process_msgs(self, msgs):
        for msg in msgs:
            fn = self.processing_map.get(msg.get('type', None))

            if fn:
                fn(msg)




class ProjectHandler(BaseHandler):


    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def post(self):
        project = self.get_argument('project', None)

        try:
            
            project = ujson.loads(project)
            project = projectmanager.Project(project)


            #store project on db
            write_result = yield dbapi.insert('projects', project.value)
            logging.info(write_result)

            #set here logic to address issues 3 to 7
            project.value["project_url"] = "%s/%s/%s" % (settings.PUBLIC_URL_PREFIX, "admin", str(project.value["_id"]))
            self.set_status(200)
            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")

        except Exception as e:
            logging.error(e)
            self.set_status(500)
            self.write(json.dumps(repr(e), default=json_util.default))
            self.set_header("Content-Type", "application/json")

    @gen.coroutine
    def get(self, _id):

        try:
            project = yield dbapi.find_one_by_id("projects", _id)

            project = projectmanager.Project(project)

            logging.info(project.value)

            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            self.write(json.dumps(repr(e), default=json_util.default))
            self.set_header("Content-Type", "application/json")

class DeviceRegistrationHandler(BaseHandler):
    @gen.coroutine
    def get(self, _id, macaddress):
        try:
            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)
            logging.info(project.value)

            #get board ID
            board = project.add_board(macaddress)
            logging.info(board)

            #call xmppbroker to register new JID            
            http_client = httpclient.AsyncHTTPClient()

            xmpp_password = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
            post_data = {
                "username": board["ID"],
                "password": xmpp_password
            }
            body = json.dumps(post_data, default=json_util.default)

            headers = {
                "Authorization": settings.XMPP_MGMT_REST_SECRET,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }

            xmpp_api_url = settings.XMPP_MGMT_REST_URL
            res = yield http_client.fetch(xmpp_api_url, method='POST', headers=headers, body=body)
            if res.error:
                raise Exception("Create user: " + res.error)
            else:

                post_data = {
                    "jid": settings.XMPP_USER,
                    "subscriptionType": "3"
                }
                body = json.dumps(post_data, default=json_util.default)
                logging.info(body)

                xmpp_api_url = "%s/%s/%s" % (settings.XMPP_MGMT_REST_URL, board["ID"], "roster")
                logging.info(xmpp_api_url)
                res = yield http_client.fetch(xmpp_api_url, method='POST', headers=headers, body=body)
    
                if res.error:
                    raise Exception("Create roster: " + res.error)
                else:

                    write_result = yield dbapi.update_by_id('projects', _id, {"boards": project.value["boards"]})
                    logging.info(write_result)

                    device_params = {
                        "jid": board["JID"],
                        "password": xmpp_password
                    }
                    self.write(json.dumps(device_params, default=json_util.default))
                    self.set_header("Content-Type", "application/json")


        except Exception as e:

            logging.error(e)
            self.set_status(500)
            self.write(json.dumps(repr(e), default=json_util.default))
            self.set_header("Content-Type", "application/json")
            
            


class FileUploadHandler(tornado.web.RequestHandler):
    def post(self):
        src_file = self.request.headers.get('X-FILE')
        dst_file = self.request.headers.get('X-DEST-FILE')
        dst_file = os.path.join(os.path.dirname(src_file), dst_file)
        os.system('sudo mv {} {}'.format(src_file, dst_file))
        logging.info("{} rename to {}".format(src_file, dst_file))


class PresenceHandler(BaseHandler):
    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def get(self):
        jid = self.get_argument('jid', '')
        http_client = httpclient.AsyncHTTPClient()
        url = url_concat(settings.PRESENCE_URL, {'jid': jid, 'req_jid':settings.XMPP_USER, 'type': 'text'})
        logging.info('PRESENCE_URL: %s' % url)
        res = yield http_client.fetch(url)
        if res.error:
            self.write("Error: %s" % response.error)
        else:
            self.write(json_encode({
                'status': 200,
                'present': True if res.body.strip() == 'null' else False
            }))
            self.set_header("Content-Type", "application/json")

class CommandHandler(BaseHandler):
    #@tornado.web.authenticated
    #@permissions.admin_only
    def post(self):
        command_name = self.get_argument('cmd', None)
        to_jid = self.get_argument('jid', None)
        values = extract_request_dict(self.request, 'values')
        try:
            commander.send_command(command_name, to_jid, values)
        except ValueError, e:
            return self.write({
                'status': 400,
                'error': str(e)
            })
        self.write(json_encode({
            'status': 200,
        }))
        self.set_header("Content-Type", "application/json")


class SmsHandler(BaseHandler):
    @tornado.web.authenticated
    @permissions.admin_only
    @gen.coroutine
    def post(self):
        command_name = self.get_argument('cmd', None)
        to_number = self.get_argument('to', None)

        cmd = ibcommands.sms_commands_by_name.get(command_name)

        if cmd is None or to_number is None:
            self.write(json_encode({
                'status': 400,
                'error': str(e)
            }))

        if to_number.startswith('+'):
            to_number = to_number[1:]

        http_client = httpclient.AsyncHTTPClient()

        post_data ={
          'method': 'send_sms_classic',
          'username': settings.SMS_USER,
          'password': settings.SMS_PASSWORD,
          'recipients[]': to_number,
          'text': cmd.cmd_msg,
        }
        if settings.SMS_SENDER_NUMBER != None:
          post_data['sender_number'] = settings.SMS_SENDER_NUMBER
        elif settings.SMS_SENDER_STRING != None:
          post_data['sender_string'] = settings.SMS_SENDER_STRING

        body = urllib.urlencode(post_data)

        res = yield http_client.fetch(settings.SMS_SEND_URL, method='POST', body=body)
        if res.error:
            self.write(json_encode({
                'status': 400,
                'error': str(e)
            }))
        else:
            self.write(json_encode({
                'status': 200,
            }))
            self.set_header("Content-Type", "application/json")

class AdminHandler(BaseHandler):
    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def get(self, _id):
        project = yield dbapi.find_one_by_id("projects", _id)
        project = projectmanager.Project(project)

        for ib in project.value["boards"]:
            ib['hash'] = hashlib.md5(ib['macaddress']).hexdigest()
        self.render('admin.html',
            ib_boards=project.value["boards"],
            commands=ibcommands.commands,
            CommandWithCustomUI=ibcommands.CommandWithCustomUI,
            sms_commands=ibcommands.sms_commands,
            js_includes=ibcommands.js_includes
        )

class MainHandler(BaseHandler):
    def get(self):
        self.render('index.html')


def shutdown():
    if xmpp_process:
        xmpp_process.terminate()

if __name__ == "__main__":
    MessagesRouter = SockJSRouter(MessagesConnection, '/messageChannel')
    app_settings = module_to_dict(settings)
    autoreload.add_reload_hook(shutdown)

    application = tornado.web.Application(
      MessagesRouter.urls +
      [
        (r'/project', ProjectHandler),
        (r'/project/([0-9a-fA-F]{24})', ProjectHandler),
        #(r'/project/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/device/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', DeviceHandler),
        (r'/project/([0-9a-fA-F]{24})/deviceregistration/(.*)', DeviceRegistrationHandler),
        (r'/file', FileUploadHandler),
        (r'/command', CommandHandler),
        (r'/sms', SmsHandler),
        (r'/msg', MessageHandler),
        (r'/presence', PresenceHandler),
        (r'/auth', GoogleOAuth2LoginHandler),
        (r'/auth/logout', LogoutHandler),
        (r'/', MainHandler),
        (r'/admin/([0-9a-fA-F]{24})', AdminHandler)
      ], **app_settings)

    application.listen(8520)
    logging.info(" [*] Listening on 0.0.0.0:8520")
    logging.info("writing to %s" % settings.MONGO_DB_URL)

    tornado.ioloop.IOLoop.instance().start()
