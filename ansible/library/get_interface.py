#!/usr/bin/python

DOCUMENTATION = '''
module:         get_interface
version_added:  "1.0"
author:         Harsha Adiga (hadiga@linkedin.com)
short_description: Retrieve the interface through which traffic is flowing to
                   the destination
description:
    - Retrieve the interface through which traffic is flowing to the destination
    - Retrieved facts will be inserted into the 'iface' variable
'''

EXAMPLES = '''
- name: Get the interface through which traffic is flowing to the destination
  get_interface:
'''

from ansible.module_utils.basic import *
from collections import defaultdict
import json
import re

class GetInterfaceModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
            ),
            supports_check_mode=True)

        self.out = None
        self.facts = {}

        return

    def run(self):
        """
            Main method of the class
        """

        self.facts = self.get_iface()
        self.module.exit_json(ansible_facts={'iface':self.facts})

        return

    def get_iface(self):
        """
        Get the interface from 'show interface counter' output through which
        traffic is flowing
        """

        iface_rx = dict()

        try:
            cmd = "show interface counter"
            rc, self.out, err = self.module.run_command(cmd,
                                                        executable='/bin/bash',
                                                        use_unsafe_shell=True)

        except Exception as e:
            err_msg = "Exception occured while trying to get the interface! " + str(e)
            self.module.fail_json(msg=err_msg)

        else:
            if rc != 0:
                self.module.fail_json(msg="Command 'show interface counter' \
                                           failed with non-zero return code! \
                                           out=%s, err=%s" %(self.out, self.err))

        lines = self.out.splitlines()

        # Filter only the lines having Ethernet*
        eth_lines = [line for line in lines if line.strip().startswith('Ethernet')]

        # Find the column number (index) of RX_OK
        rx_index = lines[1].strip().split().index('RX_OK')

        # Ignore 1st 4 lines, and then get only the first 16 interfaces:
        # Ethernet0 to Ethernet 16. Since our topology is fixed, first 16
        # interfaces would give us the right set of interfaces that we need
        for line in eth_lines[:15]:
            iface_rx[line.split()[0]] = line.split()[rx_index]

        # Find out the interface having maximum RX_OK value
        iface = max(iface_rx, key=lambda key: iface_rx[key])

        return iface

def main():

    get_interface = GetInterfaceModule()
    get_interface.run()

    return

if __name__ == "__main__":
    main()
