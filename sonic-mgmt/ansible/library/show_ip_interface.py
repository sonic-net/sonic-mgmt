#!/usr/bin/python

from ansible.module_utils.basic import *
import re

DOCUMENTATION = '''
module: show_ip_interface.py
Short_description: Retrieve show ip interface
Description:
    - Retrieve IPv4 address of interface and IPv4 address of its neighbor 

options:
    - namespace::
          Description: In multi ASIC env, namespace to run the command
          Required: False

'''

EXAMPLES = '''
  # Get show ip interface 
  - show_ip_interface: 

  # Get show ip interface in namespace asic0
  - show_ip_interface: namespace='asic0'

'''


class ShowIpInterfaceModule(object):
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
            "\s*(\S+)\s+"                                    # interface name
            "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})\s*" # IPv4
            "(up|down)\/(up|down)\s*"                        # oper/admin state
            "(\S+)\s*"                                       # neighbor name
            "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|N\/A)\s*"   # peer IPv4
        )

        regex_old = re.compile(
            "\s*(\S+)\s+"                                    # interface name
            "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})\s*" # IPv4
            "(up|down)\/(up|down)\s*"                        # oper/admin state
        )

        self.ip_int = {}
        try:
            rc, self.out, err = self.module.run_command(
                    "show ip interfaces{}".format(self.ns),
                    executable='/bin/bash',
                    use_unsafe_shell=True
                )
            for line in self.out.split("\n"):
                line = line.strip()
                m = re.match(regex_int, line)
                om = re.match(regex_old, line)
                if m:
                    self.ip_int[m.group(1)] = {}
                    self.ip_int[m.group(1)]["ipv4"] = m.group(2)
                    self.ip_int[m.group(1)]["prefix_len"] = m.group(3)
                    self.ip_int[m.group(1)]["admin"] = m.group(4)
                    self.ip_int[m.group(1)]["oper_state"] = m.group(5)
                    self.ip_int[m.group(1)]["bgp_neighbor"] = m.group(6)
                    self.ip_int[m.group(1)]["peer_ipv4"] = m.group(7)
                elif om:
                    self.ip_int[om.group(1)] = {}
                    self.ip_int[om.group(1)]["ipv4"] = om.group(2)
                    self.ip_int[om.group(1)]["prefix_len"] = om.group(3)
                    self.ip_int[om.group(1)]["admin"] = om.group(4)
                    self.ip_int[om.group(1)]["oper_state"] = om.group(5)
            self.facts['ip_interfaces'] = self.ip_int
        except Exception as e:
            self.module.fail_json(msg=str(e))
        if rc != 0:
            self.module.fail_json(msg="Command failed rc = %d, out = %s, err = %s" % (rc, self.out, err))

        self.module.exit_json(ansible_facts=self.facts)

def main():
    ShowIpInt = ShowIpInterfaceModule()
    ShowIpInt.run()
    return

if __name__ == "__main__":
    main()
