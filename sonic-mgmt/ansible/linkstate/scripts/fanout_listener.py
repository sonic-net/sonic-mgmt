import EntityManager
import Tac
import socket
import pickle
import argparse
import datetime
from pprint import pprint


g_ptf_host = None
g_log_fp = None


def log(message, output_on_console=False):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if output_on_console:
        print "%s : %s" % (current_time, message)
    global g_log_fp
    if g_log_fp is not None:
        g_log_fp.write("%s : %s\n" % (current_time, message))
        g_log_fp.flush()


class IntfMonitor(Tac.Notifiee):
    notifierTypeName = "Interface::EthPhyIntfStatus"
    def __init__(self, intfStatus):
        self.state = {}
        Tac.Notifiee.__init__(self, intfStatus)
        self.send()

    @Tac.handler('linkStatus')
    def handleLinkStatus(self):
        self.send()

    def close(self):
        Tac.Notifiee.close(self)

    def send(self):
        if self.notifier_.intfId in self.state and self.state[self.notifier_.intfId] == self.notifier_.linkStatus:
            return

        self.state[self.notifier_.intfId] = self.notifier_.linkStatus
        conn = Conn()
        data = {"intf": self.notifier_.intfId, "linkStatus": self.notifier_.linkStatus}
        log("Event: intf %s changed its state %s" % (self.notifier_.intfId, self.notifier_.linkStatus))
        log("Send data %s" % str(data))
        conn.write(data)
        data = conn.read()
        log("Received reply: %s" % str(data))


def setup_sw():
    em = EntityManager.Sysdb("ar")
    mg = em.mountGroup()
    intfStatusDir = mg.mount("interface/status/eth/phy/all", "Interface::AllEthPhyIntfStatusDir", "r")
    mg.close(blocking=True)

    return Tac.collectionChangeReactor(intfStatusDir.intfStatus, IntfMonitor)


class Conn(object):
    def __init__(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((g_ptf_host, 9877))

    def __del__(self):
        self.conn.close()

    def read(self):
        fp = self.conn.makefile('rb', 1024)
        data = pickle.load(fp)
        fp.close()
        return data

    def write(self, data):
        fp = self.conn.makefile('wb', 1024)
        pickle.dump(data, fp, pickle.HIGHEST_PROTOCOL)
        fp.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ptf_host", type=str, help="ip address of ptf host")
    args = parser.parse_args()
    global g_ptf_host
    g_ptf_host = str(args.ptf_host)

    global g_log_fp
    g_log_fp = open("/tmp/fanout_listener.log", "w")

    sw = setup_sw()
    try:
        Tac.runActivities()
    except:
        pass

if __name__ == '__main__':
    main()

