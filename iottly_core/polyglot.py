import importlib

class Polyglot:

    def __init__(self,config):
        self.bbc_list={}
        self.processes=[]
        for k,v in config.items():
            bbc=importlib.import_module(k.lower())
            class_ = getattr(bbc, v['class_name'])
            instance = class_(v['communicationconf'], self.send_command)
            self.bbc_list[v['key']]=instance

    def send_command(self, protocol, cmd_name, to, values=None, cmd=None):
        self.bbc_list[protocol].send_command(cmd_name, to, values, cmd)

    def terminate(self):
        for k,v in self.bbc_list.items():
            v.terminate()