#!/usr/bin/env python

from sys import stdin
import json
DUMP_FILE = "/tmp/bgp_monitor_dump.log"

# The announcement format is different between exabgp v3 and v4
# The default value is set to 'v3' if the version cannot be determined
# from the message
exabgp_version = 'v3'
ver_found = False

while True:
    with open(DUMP_FILE, "a") as f:
        line = stdin.readline()
        obj = json.loads(line)
        ver = obj.get('exabgp')
        if ver and not ver_found:
            ver_found = True
            if ver.startswith('4'):
                exabgp_version = 'v4'
        if 'update' not in obj['neighbor']['message']:
            continue
        announce = obj['neighbor']['message']['update']['announce']
        keys = ('ipv4 unicast', 'ipv6 unicast')
        for key in keys:
            if key in announce:
                for _, route in list(announce[key].items()):
                    if exabgp_version == 'v3':
                        for ip, _ in list(route.items()):
                            f.write(ip + "\n")
                    elif exabgp_version == 'v4':
                        route_list = route
                        for r in route_list:
                            for msg_type, ip in r.items():
                                if msg_type == 'nlri':
                                    f.write(ip + "\n")
