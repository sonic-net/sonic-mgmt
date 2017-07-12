#!/usr/bin/env python

import cPickle
import os
import time
import sys

with open(sys.argv[1]) as f:
    routes = f.readlines()

routes=[x.strip() for x in routes]
ports = set()

for route in routes:
   [command, port] = route.split(";")
   port = port.strip()
   ports.add(port)
   os.system('curl -s --form "command=%s" http://localhost:%s/' % (command, port))

for n in range(0, 20):
    time.sleep(10)
    for port in ports:
        os.system('curl -s --form "command=flush route" http://localhost:%s/' % port)

