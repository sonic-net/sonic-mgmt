#!/usr/bin/env python

from sys import stdin
import json

DUMP_FILE = "/tmp/bgp_monitor_dump.log"

while True:
    try:
        line = stdin.readline()
        obj = json.loads(line)
        if 'update' not in obj['neighbor']['message']:
            continue
        f = open(DUMP_FILE, "a")
        announce = obj['neighbor']['message']['update']['announce']
        keys = ('ipv4 unicast', 'ipv6 unicast')
        for key in keys:
            if key in announce:
                for _, route in announce[key].items():
                    for ip, _ in route.items():
                        f.write(ip + "\n")
    finally:
        f.close()
