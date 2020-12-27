from __future__ import print_function
import os
import sys
import socket
import datetime

def get_timestamp(ms=True, this=None):
    if not this:
        this = datetime.datetime.utcnow()
    if ms:
        return this.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
    else:
        return this.strftime('%Y-%m-%d %H:%M:%S')

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def udp_server(host='0.0.0.0', port=1234):
    port = int(os.getenv("udp_server_port", port))
    host = os.getenv("udp_server_host", host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    eprint("Listening on udp %s:%s" % (host, port))
    while True:
        (data, _) = s.recvfrom(128*1024)
        yield data

for data in udp_server():
    print("{}: {}".format(get_timestamp(),data))
