#!/usr/bin/python

DOCUMENTATION = '''
module:         ip_route
version_added:  "1.0"
author:         Harsha Adiga (hadiga@linkedin.com)
short_description: Retrieve ECMP paths for a particular prefix
description:
    - Retrieve ECMP paths for a particular prefix, using the VTYSH command line
    - Retrieved facts will be inserted into the 'ethernet_list' array
'''

EXAMPLES = '''
- name: Get ECMP paths for a particular prefix
  ip_route: "{{ ipv6 }}"
'''

from ansible.module_utils.basic import *
from collections import defaultdict
import json
import re

DEFAULT_PREFIX = "100.1.1.1/32"
DEFAULT_IPV6_PREFIX = "2064:200::1/128"

class IpRouteModule(object):
    def __init__(self, ipv6, module):
        self.ipv6 = ipv6
        self.module = module

        self.out = None
        self.facts = {}

        return

    def run(self):
        """
            Main method of the class
        """

        if (self.ipv6 == False):
            interfaces = self.get_interfaces(DEFAULT_PREFIX)
        else:
            interfaces = self.get_interfaces(DEFAULT_IPV6_PREFIX)
        self.facts = self.parse_interfaces(interfaces)
        self.module.exit_json(ansible_facts={'ethernet_list':self.facts})

        return

    def get_interfaces(self, prefix):
        """
        Get the list of interfaces for a particular prefix using
        'show ip route <prefix>' command
        """

        try:
            if (self.ipv6 == False):
                rc, self.out, err = self.module.run_command('docker exec -i bgp vtysh \
                                                             -c "show ip route ' + prefix \
                                                             + '"', executable='/bin/bash', \
                                                             use_unsafe_shell=True)
            else:
                rc, self.out, err = self.module.run_command('docker exec -i bgp vtysh \
                                                             -c "show ipv6 route ' + prefix \
                                                             + '"', executable='/bin/bash', \
                                                             use_unsafe_shell=True) 

        except Exception as e:
            err_msg = "Exception occured while trying to get the list of \
                       interfaces! " + str(e)
            self.module.fail_json(msg=err_msg)

        else:
            if rc != 0:
                self.module.fail_json(msg="Command 'show ip route <prefix>' \
                                           failed with non-zero return code! \
                                           out=%s, err=%s" %(self.out, self.err))

        self.facts = self.parse_interfaces(self.out)
        self.module.exit_json(ansible_facts={'ethernet_list':self.facts})

        return

    def parse_interfaces(self, output):
        """
        Parse the inerfaces from 'show ip route' into an array
        """

        ifaces = []

        output = output.splitlines()[3:-1]

        for item in output:
            match = re.search('Ethernet\d+', item)
            ifaces.append(match.group(0))

        return ifaces

def main():
    module = AnsibleModule(
        argument_spec=dict(
            ipv6=dict(required=False),
        ),
        supports_check_mode=True)

    m_args = module.params
    ipv6 = m_args['ipv6']

    iproute = IpRouteModule(ipv6, module)
    iproute.run()

    return

if __name__ == "__main__":
    main()
