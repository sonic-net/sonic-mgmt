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

'''

RETURN = '''
      ansible_facts:
          int_status:{
              "Ethernet0":{
                "name": "Ethernet0"
                "speed": "40G"
                "alias": "fortyGigE1/1/1"
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
            interfaces=dict(required=False, type='list', default=None),
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
        if self.m_args['command'] == 'status': self.collect_interface_status()
        if self.m_args['command'] == 'counter': self.collect_interface_counter()
        self.module.exit_json(ansible_facts=self.facts)

    def collect_interface_status(self):
        regex_int = re.compile(r'(\S+)\s+[\d,]+\s+(\w+)\s+(\d+)\s+([\w\/]+)\s+(\w+)\s+(\w+)')
        self.int_status = {}
        if self.m_args['interfaces'] is not None:
            for interface in self.m_args['interfaces']:
                self.int_status[interface] = {}
                command = 'sudo show interface status ' + interface
                try:
                    rc, self.out, err = self.module.run_command(command, executable='/bin/bash', use_unsafe_shell=True)
                    for line in self.out.split("\n"):
                        line = line.strip()
                        if regex_int.match(line):
                            self.int_status[interface]['name'] = regex_int.match(line).group(1)
                            self.int_status[interface]['speed'] = regex_int.match(line).group(2)
                            self.int_status[interface]['alias'] = regex_int.match(line).group(4)
                            self.int_status[interface]['oper_state'] = regex_int.match(line).group(5)
                            self.int_status[interface]['admin_state'] = regex_int.match(line).group(6)
                    self.facts['int_status'] = self.int_status
                except Exception as e:
                    self.module.fail_json(msg=str(e))
                if rc != 0:
                    self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" % (rc, self.out, err))
        else:
            try:
                rc, self.out, err = self.module.run_command('show interface status', executable='/bin/bash', use_unsafe_shell=True)
                for line in self.out.split("\n"):
                    line = line.strip()
                    if regex_int.match(line):
                        interface = regex_int.match(line).group(1)
                        self.int_status[interface] = {}
                        self.int_status[interface]['name'] = interface
                        self.int_status[interface]['speed'] = regex_int.match(line).group(2)
                        self.int_status[interface]['alias'] = regex_int.match(line).group(4)
                        self.int_status[interface]['oper_state'] = regex_int.match(line).group(5)
                        self.int_status[interface]['admin_state'] = regex_int.match(line).group(6)
                self.facts['int_status'] = self.int_status
            except Exception as e:
                self.module.fail_json(msg=str(e))
            if rc != 0:
                self.module.fail_json(msg="Command failed rc = %d, out = %s, err = %s" % (rc, self.out, err))

        return

    def collect_interface_counter(self):
        regex_int = re.compile(r'(\S+)\s+(\w)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)')
        self.int_counter = {}
        try:
            rc, self.out, err = self.module.run_command('show interface counter', executable='/bin/bash', use_unsafe_shell=True)
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

