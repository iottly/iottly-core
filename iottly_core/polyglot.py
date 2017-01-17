import importlib

class Polyglot:
    #PROTOCOL_LIST=[{'filename':'backendbrokerclientxmpp','key':'xmpp'}, {'filename':'backendbrokerclientmqtt','key':'mqtt'}]
    #PROTOCOL_LIST=['backendbrokerclientxmpp','backendbrokerclientmqtt']
    #BBC_LIST={}

    def __init__(self,config):
        self.bbc_list={}
        self.processes=[]
        for k,v in config.items():
            bbc=importlib.import_module(k.lower())
            class_ = getattr(bbc, v['class_name'])
            instance = class_(v['communicationconf'])
            self.bbc_list[v['key']]=instance

        # self.bbc_list={}
        # self.processes=[]
        # for p in self.protocol_list:
        #     bbc=importlib.import_module(p['filename'])
        #     class_ = getattr(bbc, p['class_name'])
        #     instance = class_(communicationconf)
        #     self.bbc_list[p['key']]=instance
        #     #self.processes.append(bbc.__init__())

    def send_command(self, protocol, cmd_name, to, values=None, cmd=None):
        self.bbc_list[protocol].send_command(cmd_name, to, values, cmd)

    def terminate(self):
        # for proc in self.processes:
        #     proc.terminate()
        # self.processes=[]
        # for p in protocol_list:
        #     self.bbc_list[p['key']].terminate()

        for k,v in self.bbc_list.items():
            v.terminate()