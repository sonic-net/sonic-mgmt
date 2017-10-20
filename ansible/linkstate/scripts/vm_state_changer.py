import PyClient
from pprint import pprint
import pickle
import os
import datetime
import errno


g_log_fp = None


def log(message, output_on_console=False):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if output_on_console:
        print "%s : %s" % (current_time, message)
    global g_log_fp
    if g_log_fp is not None:
        g_log_fp.write("%s : %s\n" % (current_time, message))
        g_log_fp.flush()


class FIFOServer(object):
    FIFOr = '/tmp/fifor'
    FIFOw = '/tmp/fifow'
    def __init__(self, intf_manager):
        self.intf_manager = intf_manager
        try:
            if os.path.exists(self.FIFOr):
                os.unlink(self.FIFOr)
            if os.path.exists(self.FIFOw):
                os.unlink(self.FIFOw)
            os.mkfifo(self.FIFOr)
            os.mkfifo(self.FIFOw)
        except OSError as err:
            if err.errno != errno.EEXIST:
                raise

        self.fifow = open(self.FIFOw, "w")
        self.fifor = open(self.FIFOr)

    def serve_forever(self):
        while True:
            data = pickle.load(self.fifor)
            log("Received request %s" % str(data))
            self.intf_manager.linkChange(data['intf'], data['linkStatus'])
            data = {'status': 'OK'}
            log("Send reply %s" % str(data))
            pickle.dump(data, self.fifow, pickle.HIGHEST_PROTOCOL)
            self.fifow.flush()


class IntfManager(object):
    def __init__(self):
        pc              = PyClient.PyClient("ar", "Sysdb")
        sysdb           = pc.agentRoot()
        allIntfStatus   = sysdb["interface"]["status"]["all"]
        self.intf_list  = [intf for intf in sysdb["interface"]["status"]["eth"]["phy"]['all'] if 'Ethernet' in intf]
        self.intfStatus = {intf : allIntfStatus.intfStatus[intf] for intf in self.intf_list}

    def linkChange(self, intf, state):
        if intf in self.intf_list:
            self.intfStatus[intf].linkStatus = state
        else:
            raise Exception("Interface %s doesn't exist" % intf) # FIXME: better just log it

    def linkUp(self, intf):
        self.linkChange(intf, "linkUp")

    def linkDown(self, intf):
        self.linkChange(intf, "linkDown")

    def get_interfaces(self):
        return self.intf_list


def main():
    try:
        global g_log_fp
        g_log_fp = open("/tmp/vm_state_changer.log", "w")

        intf = IntfManager()
        server = FIFOServer(intf)
        server.serve_forever()
    except:
        pass

if __name__ == '__main__':
    main()

