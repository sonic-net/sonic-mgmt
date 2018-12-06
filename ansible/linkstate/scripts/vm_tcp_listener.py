from pprint import pprint
import pickle
import SocketServer
import datetime


g_log_fp = None


def log(message, output_on_console=False):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if output_on_console:
        print "%s : %s" % (current_time, message)
    global g_log_fp
    if g_log_fp is not None:
        g_log_fp.write("%s : %s\n" % (current_time, message))
        g_log_fp.flush()


class TCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        data = pickle.load(self.rfile)
        log("Received and send request %s" % str(data))
        self.server.fifo_client.write(data)
        data = self.server.fifo_client.read()
        log("Received and send reply %s" % str(data))
        pickle.dump(data, self.wfile, pickle.HIGHEST_PROTOCOL)


class FIFOClient(object):
    FIFOr = '/tmp/fifor'
    FIFOw = '/tmp/fifow'
    def __init__(self):
        self.fifow = open(self.FIFOw)
        self.fifor = open(self.FIFOr, 'w')

    def write(self, data):
        pickle.dump(data, self.fifor, pickle.HIGHEST_PROTOCOL)
        self.fifor.flush()

    def read(self):
        return pickle.load(self.fifow)


def main():
    try:
        global g_log_fp
        g_log_fp = open("/tmp/vm_tcp_listener.log", "w")

        fifo = FIFOClient()
        server = SocketServer.TCPServer(("0.0.0.0", 9876), TCPHandler)
        server.fifo_client = fifo
        server.serve_forever()
    except:
        pass

if __name__ == '__main__':
    main()

