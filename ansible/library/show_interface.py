#!/usr/bin/python

from ansible.module_utils.basic import *
import time
import re

DOCUMENTATION = '''
module: show_interface.py
version_added:  2.0.0.2
Short_description: Retrieve the show interface status and show interface counter output values
Description:
    - Retrieve the show interface status and show interface counter output values
      and inserted into ansible_facts

options:
    - command:
          Description: Show interface command( counter/status)
          Required: True
    - interfaces:
          Description: Interfaces for which the facts to be gathered. By default It will gather facts for all interfaces
          Required: False
'''

EXAMPLES = '''
  # Get show interface status
  - show_interface: comamnd='status'

  # Get show interface status of interface Ethernet0
  - show_interface: comamnd='status' interfaces='Ethernet0'

  # Get show interface counter
  - show_interface: comamnd='counter' interface='Ethernet4'

   # Get show interface status for all internal and external interfaces
  - show_interface command='status' include_internal_intfs=True

  # Get show interface status external interfaces for namespace
  - show_interface command='status' namespace='asic0'

  # Get show interface status for external and interfaces for namespace
  - show_interface command='status' namespace='asic0' include_internal_intfs=True
'''

RETURN = '''
      ansible_facts:
          int_status:{
              "Ethernet0":{
                "name": "Ethernet0"
                "speed": "40G"
                "alias": "fortyGigE1/1/1"
                "vlan": "routed"
                "oper_state": "down"
                "admin_state": "up"
                }
               }
      ansible_facts:
          int_counter:{
               "Ethernet0":{
                    'IFACE'  : "Ethernet0"
                    'STATE'  :  "U"
                    'RX_OK'  :  "25000"
                    'RX_DRP' :  "3456"
                    'RX_OVR' :  "0"
                    'TX_OK'  :  "5843"
                    'TX_ERR' :  "0"
                    'TX_DRP' :  "0"
                    'TX_OVR' :  "0"

'''


class ShowInterfaceModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                command=dict(required=True, type='str'),
                namespace=dict(required=False, type='str', default=None),
                interfaces=dict(required=False, type='list', default=None),
                up_ports=dict(type='raw', default={}),
                include_internal_intfs=dict(required=False, type=bool, default=False),
            ),
            supports_check_mode=False)
        self.m_args = self.module.params
        self.out = None
        self.facts = {}
        return

    def run(self):
        """
            Main method of the class
        """
        namespace = self.m_args["namespace"]
        include_internal_intfs = self.m_args['include_internal_intfs']
        if self.m_args['command'] == 'status':
            self.collect_interface_status(namespace, include_internal_intfs)
        if self.m_args['command'] == 'counter':
            self.collect_interface_counter(namespace, include_internal_intfs)
        self.module.exit_json(ansible_facts=self.facts)

    def collect_interface_status(self, namespace=None, include_internal_intfs=False):
        regex_int_fec = re.compile(r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+(rs|fc|N\/A|none)\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')
        regex_int = re.compile(r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')
        regex_int_internal = re.compile(r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+(rs|N\/A)\s+([\w\-]+)\s+(\w+)\s+(\w+)\s+(\w+)')
        self.int_status = {}
        if self.m_args['interfaces'] is not None:
            for interface in self.m_args['interfaces']:
                self.int_status[interface] = {}
                command = 'sudo show interface status ' + interface
                try:
                    rc, self.out, err = self.module.run_command(command, executable='/bin/bash', use_unsafe_shell=True)
                    for line in self.out.split("\n"):
                        line = line.strip()
                        fec = regex_int_fec.match(line)
                        old = regex_int.match(line)
                        if fec and interface == fec.group(1):
                            self.int_status[interface]['name'] = fec.group(1)
                            self.int_status[interface]['speed'] = fec.group(2)
                            self.int_status[interface]['fec'] = fec.group(4)
                            self.int_status[interface]['alias'] = fec.group(5)
                            self.int_status[interface]['vlan'] = fec.group(6)
                            self.int_status[interface]['oper_state'] = fec.group(7)
                            self.int_status[interface]['admin_state'] = fec.group(8)
                        elif old and interface == old.group(1):
                            self.int_status[interface]['name'] = old.group(1)
                            self.int_status[interface]['speed'] = old.group(2)
                            self.int_status[interface]['fec'] = 'Unknown'
                            self.int_status[interface]['alias'] = old.group(4)
                            self.int_status[interface]['vlan'] = old.group(5)
                            self.int_status[interface]['oper_state'] = old.group(6)
                            self.int_status[interface]['admin_state'] = old.group(7)
                    self.facts['int_status'] = self.int_status
                except Exception as e:
                    self.module.fail_json(msg=str(e))
                if rc != 0:
                    self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" % (rc, self.out, err))
        else:
            try:
                cli_options = " -n {}".format(namespace) if namespace is not None else ""
                if include_internal_intfs and namespace is not None:
                    cli_options += " -d all"
                intf_status_cmd = "show interface status{}".format(cli_options)
                rc, self.out, err = self.module.run_command(intf_status_cmd, executable='/bin/bash', use_unsafe_shell=True)
                for line in self.out.split("\n"):
                    line = line.strip()
                    fec = regex_int_fec.match(line)
                    old = regex_int.match(line)
                    internal = regex_int_internal.match(line)
                    if fec:
                        interface = fec.group(1)
                        self.int_status[interface] = {}
                        self.int_status[interface]['name'] = interface
                        self.int_status[interface]['speed'] = fec.group(2)
                        self.int_status[interface]['fec'] = fec.group(4)
                        self.int_status[interface]['alias'] = fec.group(5)
                        self.int_status[interface]['vlan'] = fec.group(6)
                        self.int_status[interface]['oper_state'] = fec.group(7)
                        self.int_status[interface]['admin_state'] = fec.group(8)
                    elif old:
                        interface = old.group(1)
                        self.int_status[interface] = {}
                        self.int_status[interface]['name'] = interface
                        self.int_status[interface]['speed'] = old.group(2)
                        self.int_status[interface]['fec'] = 'Unknown'
                        self.int_status[interface]['alias'] = old.group(4)
                        self.int_status[interface]['vlan'] = old.group(5)
                        self.int_status[interface]['oper_state'] = old.group(6)
                        self.int_status[interface]['admin_state'] = old.group(7)
                    elif internal and include_internal_intfs:
                        interface = internal.group(1)
                        self.int_status[interface] = {}
                        self.int_status[interface]['name'] = interface
                        self.int_status[interface]['speed'] = internal.group(2)
                        self.int_status[interface]['fec'] = internal.group(4)
                        self.int_status[interface]['alias'] = internal.group(5)
                        self.int_status[interface]['vlan'] = internal.group(6)
                        self.int_status[interface]['oper_state'] = internal.group(7)
                        self.int_status[interface]['admin_state'] = internal.group(8)
                self.facts['int_status'] = self.int_status
            except Exception as e:
                self.module.fail_json(msg=str(e))
            if rc != 0:
                self.module.fail_json(msg="Command failed rc = %d, out = %s, err = %s" % (rc, self.out, err))

        if 'up_ports' in self.m_args:
            down_ports = []
            up_ports = self.m_args['up_ports']
            for name in up_ports:
                try:
                    if self.int_status[name]['oper_state'] != 'up':
                        down_ports += [name]
                except:
                    down_ports += [name]
            self.facts['ansible_interface_link_down_ports'] = down_ports

        return

    def collect_interface_counter(self, namespace=None, include_internal_intfs=False):
        regex_int = re.compile(r'\s*(\S+)\s+(\w)\s+([,\d]+)\s+(N\/A|[.0-9]+ B/s)\s+(\S+)\s+([,\d]+)\s+(\S+)\s+([,\d]+)\s+([,\d]+)\s+(N\/A|[.0-9]+ B/s)\s+(\S+)\s+([,\d]+)\s+(\S+)\s+([,\d]+)')
        self.int_counter = {}
        cli_options = " -n {}".format(namespace) if namespace is not None else ""
        if include_internal_intfs and namespace is not None:
            cli_options += " -d all"
        intf_status_cmd = "show interface counter{}".format(cli_options)
        try:
            rc, self.out, err = self.module.run_command(intf_status_cmd, executable='/bin/bash', use_unsafe_shell=True)
            for line in self.out.split("\n"):
                line = line.strip()
                if regex_int.match(line):
                    interface = regex_int.match(line).group(1)
                    self.int_counter[interface] = {}
                    self.int_counter[interface]['IFACE'] = interface
                    self.int_counter[interface]['STATE'] = regex_int.match(line).group(2)
                    self.int_counter[interface]['RX_OK'] = regex_int.match(line).group(3)
                    self.int_counter[interface]['RX_BPS'] = regex_int.match(line).group(4)
                    self.int_counter[interface]['RX_UTIL'] = regex_int.match(line).group(5)
                    self.int_counter[interface]['RX_ERR'] = regex_int.match(line).group(6)
                    self.int_counter[interface]['RX_DRP'] = regex_int.match(line).group(7)
                    self.int_counter[interface]['RX_OVR'] = regex_int.match(line).group(8)
                    self.int_counter[interface]['TX_OK'] = regex_int.match(line).group(9)
                    self.int_counter[interface]['TX_BPS'] = regex_int.match(line).group(10)
                    self.int_counter[interface]['TX_UTIL'] = regex_int.match(line).group(11)
                    self.int_counter[interface]['TX_ERR'] = regex_int.match(line).group(12)
                    self.int_counter[interface]['TX_DRP'] = regex_int.match(line).group(13)
                    self.int_counter[interface]['TX_OVR'] = regex_int.match(line).group(14)
        except Exception as e:
            self.module.fail_json(msg=str(e))
        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" % (rc, self.out, err))
        self.facts['int_counter'] = self.int_counter
        return


def main():
    ShowInt = ShowInterfaceModule()
    ShowInt.run()
    return

if __name__ == "__main__":
    main()

