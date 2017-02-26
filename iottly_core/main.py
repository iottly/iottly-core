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
import shutil

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

from iottly_core import polyglot
from iottly_core import ibcommands
from iottly_core import messageparser
from iottly_core import flashmanager
from iottly_core import permissions
from iottly_core import boards
from iottly_core.dbapi import db
from iottly_core import dbapi
from iottly_core.settings import settings

logging.getLogger().setLevel(logging.DEBUG)

connected_clients=set()
brokers_polyglot=polyglot.Polyglot(settings.BACKEND_BROKER_CLIENTS_CONF, connected_clients = connected_clients)

from iottly_core import projectmanager
from iottly_core import messagerouter as msgrtr


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

    @gen.coroutine
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




class NewMessageHandler(BaseHandler):

    @gen.coroutine
    def post(self, protocol):
        request_args = ('to', 'from', 'msg')
        msg = { k: self.get_argument(k) for k in request_args }
        # Immediately return control to the caller
        self.set_status(200)
        self.finish()
        msgrtr.route(protocol.upper(), msg, brokers_polyglot.send_command, connected_clients)


class MessageHistoryHandler(BaseHandler):

    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def get(self, projectid, boardid):
        query_json = self.get_argument('queryJson', None)
        num_messages = int(self.get_argument('numMessages', None) or 10)
        query_dict = { 'to': projectid, 'from' : boardid }
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


class ProjectHandler(BaseHandler):


    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def post(self, _id):
        logging.info(_id)

        try:
            project = ujson.loads(self.request.body.decode('utf-8'))
            project = projectmanager.Project(project)

            #store project on db to get an _id:
            write_result = yield dbapi.insert('projects', project.value)
            logging.info(write_result)

            #add computed data and store them again ... FIX THIS
            result = yield project.set_project_params([cmd.to_ui_command_def() for cmd in ibcommands.commands if cmd.show])
            

            write_result = yield dbapi.update_by_id('projects', project.value["_id"], project.value)
            logging.info(write_result)

            self.set_status(200)
            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")

        except Exception as e:
            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")

    @gen.coroutine
    def put(self, _id):
        logging.info(_id)

        try:
            update = ujson.loads(self.request.body.decode('utf-8'))
            
            if not "filter" in update.keys():
                update.update({"filter": {}})

            write_result = yield dbapi.update_by_id('projects', _id, update["document"], update["filter"])
            logging.info(write_result)
            project = yield dbapi.find_one_by_id("projects", _id)
            #TODO: schema validation after update is bad ...
            project = projectmanager.Project(project)

            self.set_status(200)
            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")


        except Exception as e:
            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")


    @gen.coroutine
    def delete(self, _id):
        try:
            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)
            logging.info(project.value)

            #remove registered boards from broker
            if "boards" in project.value.keys():
                for board in project.value["boards"]:
                    apiresult = yield brokers_polyglot.delete_user(project.value.get('iotprotocol'), board["ID"])

            #remove registered project from broker
            apiresult = yield brokers_polyglot.delete_project_user(project.value.get('iotprotocol'), _id)            

            #remove over the air fw repo path:
            fwdir = os.path.join(settings.FIRMWARE_DIR, str(_id))
            if os.path.exists(fwdir):
                shutil.rmtree(fwdir)
            
            #remove installer:
            installerdir = os.path.join(
                settings.DEVICE_INSTALLERS_REPO_PATH, 
                settings.DEVICE_INSTALLER_NAME_TEMPLATE.format(str(_id)))
            if os.path.exists(installerdir):
                os.remove(installerdir)

            delete_result = yield dbapi.remove_by_id('projects', _id)
            logging.info(delete_result)
            self.set_status(200)

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")


    @gen.coroutine
    def get(self, _id):

        try:
            if _id:
                project = yield dbapi.find_one_by_id("projects", _id)

                project = projectmanager.Project(project)

                logging.info(project.value)

                self.write(json.dumps(project.value, default=json_util.default))
                self.set_header("Content-Type", "application/json")
            else:
                projects = yield dbapi.find_all("projects", sort=[('name', pymongo.ASCENDING)], limit=10)
                logging.info(projects)
                projects_val = []
                for project in projects:
                    project_val = projectmanager.Project(project)
                    projects_val.append(project_val.value)

                self.write(json.dumps(projects_val, default=json_util.default))
                self.set_header("Content-Type", "application/json")



        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")

class DeviceRegistrationHandler(BaseHandler):
    @gen.coroutine
    def get(self, _id, macaddress):
        try:

            logging.info('device registration request for mac {}'.format(macaddress))

            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)

            #get board ID
            
            board, password, newreg = yield project.add_or_update_board(macaddress)

            dispatch_board = {'registration': {'new': newreg}}

            if newreg:
                write_result = yield dbapi.update_by_id('projects', _id, {"boards": project.value["boards"]})

            #always return board ID with new password in case the board has been re-installed but was already registered

            device_params = brokers_polyglot.format_device_credentials(
                project.value.get('iotprotocol'), _id, board["ID"], password, project.value["secretsalt"])

            logging.info(device_params)

            self.write(json.dumps(device_params, default=json_util.default))
            self.set_header("Content-Type", "application/json")

            dispatch_board['registration'].update({'board': board})
            self._broadcast(dispatch_board)

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")
            

    def _broadcast(self, msg):
        devices_json = json.dumps({ 'devices': msg }, default=json_util.default)
        for client in connected_clients:
            logging.info(client)
            client.send(devices_json)

    @gen.coroutine
    def delete(self, _id, macaddress):
        try:
            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)
            logging.info(project.value)

            #delete board ID
            board = yield project.remove_board(macaddress)

            logging.info('remove board: {}'.format(board))

            write_result = yield dbapi.update_by_id('projects', _id, {"boards": project.value["boards"]})
            logging.info(write_result)

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")



class MessageDefinitionHandler(BaseHandler):
    @gen.coroutine
    def post(self, _id, messagetype):
        try:

            logging.info('message definition request')
            message = ujson.loads(self.request.body.decode('utf-8'))
            logging.info(message)

            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)

            message = project.add_message(message)
            
            write_result = yield dbapi.update_by_id('projects', _id, 
                {
                    "messages": project.value["messages"],
                    "fwcode": project.value["fwcode"]
                })
            logging.info(write_result)

            self.set_status(200)
            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")

    @gen.coroutine
    def put(self, _id, messagetype):
        try:

            logging.info('message definition request')
            message = ujson.loads(self.request.body.decode('utf-8'))
            logging.info(message)

            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)

            project.remove_message(message['metadata']['type'])
            message = project.add_message(message)
            
            write_result = yield dbapi.update_by_id('projects', _id, {
                "messages": project.value["messages"],
                "fwcode": project.value["fwcode"],
            })
            logging.info(write_result)

            self.set_status(200)
            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")            

    @gen.coroutine
    def delete(self, _id, messagetype):
        try:
            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)
            logging.info(project.value)

            #delete board ID
            message = project.remove_message(messagetype)

            logging.info('remove message: {}'.format(message))

            write_result = yield dbapi.update_by_id('projects', _id, {
                "messages": project.value["messages"],
                "fwcode": project.value["fwcode"],
            })
            logging.info(write_result)

            self.set_status(200)
            self.write(json.dumps(project.value, default=json_util.default))
            self.set_header("Content-Type", "application/json")

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")
            

class GetAgentHandler(BaseHandler):
    @gen.coroutine
    def get(self, _id):
        filename = settings.DEVICE_INSTALLER_NAME_TEMPLATE.format(str(_id))
        installerdir = os.path.join(settings.DEVICE_INSTALLERS_REPO_PATH, filename)

        with open(installerdir, "rb") as f:
            self.write(f.read())
            #self.set_header("Content-Type", "application/text")
            self.set_header('Content-Disposition', 'attachment; filename="{}"'.format(filename))

            


class FileUploadHandler(tornado.web.RequestHandler):
    def post(self):
        src_file = self.request.headers.get('X-FILE')
        dst_file = self.request.headers.get('X-DEST-FILE')
        dst_file = os.path.join(os.path.dirname(src_file), dst_file)
        os.system('sudo mv {} {}'.format(src_file, dst_file))
        logging.info("{} rename to {}".format(src_file, dst_file))




class DeviceStatusHandler(BaseHandler):
    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def get(self, _id, _buuid):
        protocol = yield dbapi.find_scalar_by_id('projects', _id, 'iotprotocol')

        status = yield brokers_polyglot.fetch_status(protocol, _id, _buuid)

        logging.info('status: {}'.format(status))

        self.write(json.dumps(status, default=json_util.default))

        self.set_header("Content-Type", "application/json")



class DeviceCommandHandler(BaseHandler):
    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def post(self, _id, _buuid):
        try:
            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)

            board = project.get_board_by_id(_buuid)

            params = ujson.loads(self.request.body.decode('utf-8'))

            cmd = project.get_command(params['cmd_type'])

            brokers_polyglot.send_command(project.value.get('iotprotocol'), cmd.name, board['ID'], values=params['values'], cmd=cmd)

            self.write(json_encode({
                'status': 200,
            }))
            self.set_header("Content-Type", "application/json")        

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
            self.set_header("Content-Type", "application/json")

class DeviceFlashHandler(BaseHandler):
    #@tornado.web.authenticated
    #@permissions.admin_only
    @gen.coroutine
    def post(self, _id, _buuid):
        try:
            project = yield dbapi.find_one_by_id("projects", _id)
            project = projectmanager.Project(project)

            board = project.get_board_by_id(_buuid)
            to_jid = board['jid']

            params = {} 
            reqbody = self.request.body.decode('utf-8')
            if reqbody:
                ujson.loads(reqbody)
            logging.info(params)
            filename = params.get("filename", None)

            if not filename:
                filename = project.fwcode.generateFullFw()
            
            firmwares = flashmanager.list_firmwares(_id, project.value['secretsalt'], project.value['fwextension'])
            #get md5
            md5 = [fw["md5"] for fw in firmwares if fw['filename'] == filename][0]

            #prepare and send command
            cmd_name = "Upload Firmware"
            values = {'fw.file': filename, 'fw.md5': md5}
            cmd = ibcommands.commands_by_name[cmd_name]

            brokers_polyglot.send_command(settings.IOTTLY_IOT_PROTOCOL, cmd_name, to_jid, values=values, cmd=cmd)

            self.write(json_encode({
                'status': 200,
            }))
            self.set_header("Content-Type", "application/json")        

        except Exception as e:

            logging.error(e)
            self.set_status(500)
            error = {'error': '{}'.format(e)}
            self.write(json.dumps(error, default=json_util.default))
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
    brokers_polyglot.terminate()

if __name__ == "__main__":
    WebSocketRouter = SockJSRouter(MessagesConnection, '/messageChannel')
    app_settings = module_to_dict(settings)
    autoreload.add_reload_hook(shutdown)

    application = tornado.web.Application(
      WebSocketRouter.urls +
      [
        (r'/project/?($|[0-9a-fA-F]{24})', ProjectHandler),
        (r'/project/([0-9a-fA-F]{24})/deviceregistration/(.*)', DeviceRegistrationHandler),
        (r'/project/([0-9a-fA-F]{24})/getagent', GetAgentHandler),
        (r'/project/([0-9a-fA-F]{24})/messagedefinition/?($|.*)', MessageDefinitionHandler),        
        (r'/project/([0-9a-fA-F]{24})/device/(.*)/command', DeviceCommandHandler),        
        (r'/project/([0-9a-fA-F]{24})/device/(.*)/flashfw', DeviceFlashHandler),        
        (r'/project/([0-9a-fA-F]{24})/device/(.*)/status', DeviceStatusHandler),        
        (r'/project/([0-9a-fA-F]{24})/device/(.*)/msgs', MessageHistoryHandler),
        (r'/newmsg/(xmpp|mqtt)', NewMessageHandler),
        (r'/auth', GoogleOAuth2LoginHandler),
        (r'/auth/logout', LogoutHandler),
        (r'/', MainHandler),
      ], **app_settings)

    application.listen(8520)
    logging.info(" [*] Listening on 0.0.0.0:8520")
    logging.info("writing to %s" % settings.MONGO_DB_URL)

    tornado.ioloop.IOLoop.instance().start()
