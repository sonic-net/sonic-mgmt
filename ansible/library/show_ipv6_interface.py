#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import socket

DOCUMENTATION = '''
module: show_ipv6_interface.py
Short_description: Retrieve show ipv6 interface
Description:
    - Retrieve IPv6 address of interface and IPv4 address of its neighbor

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


def split_dash(string_with_dash):
    return string_with_dash.split("/")


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
        self.ip_int = {}
        try:
            rc, self.out, err = self.module.run_command(
                "show ipv6 interfaces{}".format(self.ns),
                executable='/bin/bash',
                use_unsafe_shell=True
            )
            for line in self.out.split("\n"):
                line = line.split()

                # only collect non-link addresses
                if not len(line) or (not line[0].startswith("Ethernet") and not line[0].startswith("PortChannel")):
                    continue

                intf = line[0]

                if len(line) == 6:
                    address, prefix = split_dash(line[2])
                    admin, oper = split_dash(line[3])
                    bgp_neighbour = line[4]
                    peer_ipv6 = line[5]
                elif len(line) == 5:
                    address, prefix = split_dash(line[1])
                    admin, oper = split_dash(line[2])
                    bgp_neighbour = line[3]
                    peer_ipv6 = line[4]
                else:
                    raise Exception("Unexpected output")

                if peer_ipv6 == "N/A":
                    continue

                # sanity check ipv6 address
                try:
                    socket.inet_pton(socket.AF_INET6, address)
                except socket.error:
                    continue

                self.ip_int[intf] = {
                      "ipv6": address,
                      "prefix_len": prefix,
                      "admin": admin,
                      "oper_state": oper,
                      "bgp_neighbour": bgp_neighbour,
                      "peer_ipv6": peer_ipv6
                }
            self.facts['ipv6_interfaces'] = self.ip_int
        except Exception as e:
            self.module.fail_json(msg=str(e))
        if rc != 0:
            self.module.fail_json(
                msg="Command failed rc = %d, out = %s, err = %s" % (rc, self.out, err))

        self.module.exit_json(ansible_facts=self.facts)


def main():
    ShowIpInt = ShowIpv6InterfaceModule()
    ShowIpInt.run()
    return


if __name__ == "__main__":
    main()
