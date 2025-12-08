#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import re

DOCUMENTATION = '''
module: show_ipv6_interface.py
Short_description: Retrieve show ipv6 interface
Description:
    - Retrieve IPv6 address of interface and IPv6 address of its neighbor

options:
    - namespace::
          Description: In multi ASIC env, namespace to run the command
          Required: False

'''

EXAMPLES = '''
  # Get show ipv6 interface
  - show_ipv6_interface:

  # Get show ipv6 interface in namespace asic0
  - show_ipv6_interface: namespace='asic0'

'''


class ShowIpv6InterfaceModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                namespace=dict(required=False, type='str', default=None),
            ),
            supports_check_mode=False
        )
        self.m_args = self.module.params
        self.out = None
        self.facts = {}
        self.ns = ""
        ns = self.m_args["namespace"]
        if ns is not None:
            self.ns = " -n {} -d all  ".format(ns)

    def run(self):
        """
            Main method of the class
        """
        regex_int = re.compile(
            r"\s*(\S+)\s+"                                    # interface name
            r"([0-9a-fA-F:]+)\/(\d{1,3})\s*"                 # IPv6 address/prefix
            r"(up|down)\/(up|down)\s*"                        # oper/admin state
            r"(\S+)\s*"                                       # neighbor name
            r"([0-9a-fA-F:]+|N\/A)\s*"                       # peer IPv6
        )

        regex_old = re.compile(
            r"\s*(\S+)\s+"                                    # interface name
            r"([0-9a-fA-F:]+)\/(\d{1,3})\s*"                 # IPv6 address/prefix
            r"(up|down)\/(up|down)\s*"                        # oper/admin state
        )

        self.ipv6_int = {}
        try:
            rc, self.out, err = self.module.run_command(
                "show ipv6 interfaces{}".format(self.ns),
                executable='/bin/bash',
                use_unsafe_shell=True
            )
            for line in self.out.split("\n"):
                line = line.strip()
                m = re.match(regex_int, line)
                om = re.match(regex_old, line)
                if m:
                    self.ipv6_int[m.group(1)] = {}
                    self.ipv6_int[m.group(1)]["ipv6"] = m.group(2)
                    self.ipv6_int[m.group(1)]["prefix_len"] = m.group(3)
                    self.ipv6_int[m.group(1)]["admin"] = m.group(4)
                    self.ipv6_int[m.group(1)]["oper_state"] = m.group(5)
                    self.ipv6_int[m.group(1)]["bgp_neighbor"] = m.group(6)
                    self.ipv6_int[m.group(1)]["peer_ipv6"] = m.group(7)
                elif om:
                    self.ipv6_int[om.group(1)] = {}
                    self.ipv6_int[om.group(1)]["ipv6"] = om.group(2)
                    self.ipv6_int[om.group(1)]["prefix_len"] = om.group(3)
                    self.ipv6_int[om.group(1)]["admin"] = om.group(4)
                    self.ipv6_int[om.group(1)]["oper_state"] = om.group(5)
            self.facts['ipv6_interfaces'] = self.ipv6_int
        except Exception as e:
            self.module.fail_json(msg=str(e))
        if rc != 0:
            self.module.fail_json(
                msg="Command failed rc = %d, out = %s, err = %s" % (rc, self.out, err))

        self.module.exit_json(ansible_facts=self.facts)


def main():
    ShowIpv6Int = ShowIpv6InterfaceModule()
    ShowIpv6Int.run()
    return


if __name__ == "__main__":
    main()
