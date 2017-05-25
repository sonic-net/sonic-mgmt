#!/usr/bin/python

DOCUMENTATION = '''
---
module: switch_port
version_added: "1.9"
author: Guohan Lu (gulv@microsoft.com)
short_description: Control switch port
description:
    - Control switch port
options:
    port:
        description:
            - port to control
        required: true
    pause:
        description:
            - Pause packet sending
    drain:
        description:
            - Drain queue first (default no, only use with pause=yes)
'''

EXAMPLES = '''
# Pause switch port Ethernet4
- name: Pause switch port Ethernet4
  switch_port: port="Ethernet4" pause=true
'''

from ansible.module_utils.basic import *
from collections import defaultdict
import socket
import struct
import re
import json
import time

phy_info_line_re = re.compile("xe(\d+).*TSC-A2/(\d+)/(\d+)")

def parse_phy_info(output):

    portmap = {}

    for line in output.split('\n'):
        m = phy_info_line_re.search(line)
        if m:
            portnum  = int(m.group(1))
            warpcore = int(m.group(2))
            lanenum  = int(m.group(3))
            cportname = "Ethernet" + str(portnum * 4)
            portmap[cportname] = warpcore * 4 + 1

    return portmap
 
def main():
    module = AnsibleModule(
        argument_spec=dict(
            port=dict(required=True),
            pause=dict(required=False, default=False, type='bool'),
            drain=dict(required=False, default=False, type='bool'),),
        supports_check_mode=False)

    # assume it's broadcom switch
    rc, out, err = module.run_command("bcmcmd \"phy info\"")
    if rc != 0:
        module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                (rc, out, err))

    portmap = parse_phy_info(out)

    portname = module.params['port']
    if not portmap.has_key(portname):
        module.fail_json(msg="Cannot find port %s" % portname)


    if module.params['pause']:
        if module.params['drain']:
            cmd = "bcmcmd \"mod egr_enable %d 1 prt_enable=1\"" % portmap[portname]
            rc, out, err = module.run_command(cmd)
            if rc != 0:
                module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                    (rc, out, err))
 
        cmd = "bcmcmd \"mod egr_enable %d 1 prt_enable=0\"" % portmap[portname]
    else: 
        cmd = "bcmcmd \"mod egr_enable %d 1 prt_enable=1\"" % portmap[portname]

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                (rc, out, err))
   
    module.exit_json(changed=True)

if __name__ == "__main__":
    main()
