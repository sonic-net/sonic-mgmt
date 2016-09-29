#!/usr/bin/python

DOCUMENTATION = '''
---
module: switch_arptble
version_added: "1.9"
description:
    Ansible module retrieves arp table from SONiC switch
    Depends on /sbin/ip neigh
output:
    arptable{
        "v4":{
            "10.10.1.3":{
                "interface": "Ethernet68"
                "state": "STALE"
                "macaddress": "00:00:00:01:02:03"
            },
        },
    }
    TODO: IPV6 neighbor table when we test IPV6
'''

EXAMPLES = '''
    switch_arptable: 
'''

from ansible.module_utils.basic import *
from collections import defaultdict
import socket
import struct
import re
import json

v4host = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
def parse_arptable(output):
    v4tbl = {}
    for line in output.split('\n'):
        fields = line.split()
        if len(fields) != 0:
            if v4host.match(fields[0]):
                if len(fields) == 4:
                    v4tbl[fields[0]]={'interface': fields[2], 'state':fields[3], 'macaddress': 'None'}
                if len(fields) > 4:
                     v4tbl[fields[0]]={'interface': fields[2], 'state':fields[5], 'macaddress': fields[4]}
    arps = {'v4':v4tbl}
    return arps

def main():
    module = AnsibleModule(
        argument_spec=dict(),
        supports_check_mode=False)

    rt, out, err = module.run_command("ip neigh")
    if rt != 0:
        self.module.fail_json(msg="Command 'ip neigh' failed rc=%d, out=%s, err=%s" %(rt, out, err))

    arp_tbl = parse_arptable(out)

    if arp_tbl == None:
        self.module.fail_json(msg="Parse arp table failed??")

    module.exit_json(changed=False, arptable=arp_tbl)

if __name__ == "__main__":
    main()
