import logging
import importlib
from tornado import gen

backend_broker_clients={}

class Polyglot:

    def __init__(self,config, connected_clients = None):
        
        if len(backend_broker_clients.keys()) == 0:
            for k,v in config.items():
                class_name = v.get('CLASS_NAME')
                bbc = importlib.import_module(class_name.lower())
                class_ = getattr(bbc, class_name)
                instance = class_(v, self.send_command, connected_clients)
                backend_broker_clients[k] = instance

    def send_command(self, protocol, cmd_name, to, values=None, cmd=None):
        backend_broker_clients[protocol].send_command(cmd_name, to, values, cmd)

    def send_command_cb(self, protocol):
        return backend_broker_clients[protocol].send_command


    @gen.coroutine
    def create_user(self, protocol, projectid, boardid, password):
        
        apiresult = yield backend_broker_clients[protocol].create_user(projectid, boardid, password)
        raise gen.Return(apiresult)

    @gen.coroutine
    def create_project_user(self, protocol, projectid, password):
        
        apiresult = yield backend_broker_clients[protocol].create_project_user(projectid, password)
        raise gen.Return(apiresult)

        
    @gen.coroutine
    def delete_user(self, protocol, boardid):
        
        apiresult = yield backend_broker_clients[protocol].delete_user(boardid)
        raise gen.Return(apiresult)

    @gen.coroutine
    def delete_project_user(self, protocol, projectid):
        
        apiresult = yield backend_broker_clients[protocol].delete_project_user(projectid)
        raise gen.Return(apiresult)


    def format_device_credentials(self, protocol, projectid, boardid, password, secretsalt):

        device_params = {

            "IOTTLY_IOT_PROTOCOL":protocol,
            "IOTTLY_PROJECT_ID": projectid,
            "IOTTLY_SECRET_SALT": secretsalt
        }

        device_params.update(backend_broker_clients[protocol].format_device_credentials(projectid, boardid, password))


        logging.info(device_params)
        return device_params

    @gen.coroutine
    def fetch_status(self, protocol, projectid, boardid):
        status = yield backend_broker_clients[protocol].fetch_status(projectid, boardid)

        raise gen.Return(status)

    def normalize_receiver_sender(self, protocol, msg):
        return backend_broker_clients[protocol].normalize_receiver_sender(msg)

    def terminate(self):
        for k,v in backend_broker_clients.items():
            v.terminate()