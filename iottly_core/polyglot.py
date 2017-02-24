import importlib
from tornado import gen

class Polyglot:

    def __init__(self,config, connected_clients):
        self.backend_broker_clients={}

        for k,v in config.items():
            class_name = v.get('CLASS_NAME')
            bbc = importlib.import_module(class_name.lower())
            class_ = getattr(bbc, class_name)
            instance = class_(v, self.send_command, connected_clients)
            self.backend_broker_clients[k] = instance

    def send_command(self, protocol, cmd_name, to, values=None, cmd=None):
        self.backend_broker_clients[protocol].send_command(cmd_name, to, values, cmd)

    @gen.coroutine
    def create_user(self, protocol, boardid, password):
        
        apiresult = yield self.backend_broker_clients[protocol].create_user(boardid, password)
        raise gen.Return(apiresult)
        
    @gen.coroutine
    def delete_user(self, protocol, boardid):
        
        apiresult = yield self.backend_broker_clients[protocol].delete_user(boardid)
        raise gen.Return(apiresult)

    def terminate(self):
        for k,v in self.backend_broker_clients.items():
            v.terminate()