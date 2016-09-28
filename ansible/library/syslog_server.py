#!/usr/bin/python

DOCUMENTATION = '''
---
module: syslog_server
version_added: "1.0"
author: John Arnold (johnar@microsoft.com)
short_description: Receive Syslog messages
description:
    - Start a Syslog listener, receive syslog messages and return them.
options:
'''

EXAMPLES = '''
# Receive Syslog messages
- name: Receive Syslog Messages
  syslog_server:
'''

from ansible.module_utils.basic import *
from collections import defaultdict
import socket
import struct
import re
import json
import time
import SocketServer
import threading


#HOST, PORT = "0.0.0.0", 5514

queuedOutput = []


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass


class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]

        newLogString = "%s %s %s\n" % ( time.time(), self.client_address[0], data)

        global queuedOutput
        queuedOutput.append(newLogString)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            timeout=dict(required=False, default=30),
            port=dict(required=False, default=5514),
            host=dict(required=False, default="0.0.0.0")
	),
        supports_check_mode=False)

    args = module.params

    try:
        server = ThreadedUDPServer((args['host'],int(args['port'])), ThreadedUDPRequestHandler)
        server.allow_reuse_address=True

	server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

	time.sleep(float(args['timeout']))
	server.shutdown()

    except Exception, e:
        module.fail_json(msg = str(e))

    Tree = lambda: defaultdict(Tree)
    results = Tree()

    global queuedOutput
    results['syslog_messages'] = queuedOutput

    module.exit_json(ansible_facts=results)

if __name__ == "__main__":
    main()

