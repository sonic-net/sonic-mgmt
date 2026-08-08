#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
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
                "type": "QSFP28 or later"
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
                include_internal_intfs=dict(
                    required=False, type=bool, default=False),
                include_inband_intfs=dict(
                    required=False, type=bool, default=False),
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
        include_inband_intfs = self.m_args['include_inband_intfs']
        if self.m_args['command'] == 'status':
            self.collect_interface_status(namespace, include_internal_intfs, include_inband_intfs)
        if self.m_args['command'] == 'counter':
            self.collect_interface_counter(namespace, include_internal_intfs)
        self.module.exit_json(ansible_facts=self.facts)

    def _fetch_interface_type(self, line):
        """
            Fetch the type from the line
            There can be spaces in type field so we can not match it via using regular expression
            The logic is to split the line into a list by spaces and the remove all the leading and tail elements,
            and then piece the rest together
            Eg. for output "Ethernet48  192,193,194,195  100G  9100  N/A  etp49  routed  up  up  QSFP28 or later  N/A"
            the list is ['Ethernet48', '192,193,194,195', '100G', '9100', 'N/A', 'etp49',
                         'routed', 'up', 'up'  'QSFP28', 'or', 'later', 'N/A']
            There is no space in the rest elements, so we can remove the first 9 and the last 1 elements,
            and piece 'QSFP28', 'or', 'later' together.
            This function should be called on if regex_int_fec is matched.
        """
        return ' '.join(line.split()[9:-1]) or 'N/A'

    def collect_interface_status(self, namespace=None, include_internal_intfs=False, include_inband_intfs=False):
        # Format A — modern SONiC with standard FEC (9 columns, no Type/AsymPFC).
        # FEC is constrained to the standard set: rs, fc, N/A, none.
        # Alias uses [\w\/]+ (letters, digits, slash — no hyphen).
        # Example:
        #   Interface  Lanes  Speed  MTU    FEC  Alias  Vlan    Oper  Admin
        #   Ethernet0  0      25G    9100   N/A  etp1   routed  up    up
        #   groups: 1=Ethernet0, 2=25G, 3=9100, 4=N/A, 5=etp1, 6=routed, 7=up, 8=up
        regex_int_fec = re.compile(
            r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+(rs|fc|N\/A|none)\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')

        # Format B — modern SONiC with Type and AsymPFC columns (11 columns).
        # FEC can be any non-whitespace token (catches non-standard values such as
        # "auto", "off", "llrs" that regex_int_fec rejects).
        # The $ anchor prevents a prefix match on longer lines.
        # Example:
        #   Interface   Lanes    Speed  MTU   FEC  Alias  Vlan    Oper  Admin  Type             Asym PFC
        #   Ethernet48  192,193  100G   9100  N/A  etp49  routed  up    up     QSFP28 or later  N/A
        #   groups: 1=Ethernet48, 2=100G, 3=9100, 4=N/A, 5=etp49, 6=routed,
        #           7=up, 8=up, 9=QSFP28 or later, 10=N/A
        regex_int = re.compile(
            r'(\S+)\s+[\d,N\/A]+\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(\S+)$')

        # Format C — SONiC with FEC column but no Type/AsymPFC (9 columns).
        # Handles non-standard FEC values (e.g. "auto", "off") that regex_int_fec
        # rejects, on platforms that have not yet added the Type column.
        # No $ anchor; checked only after regex_int (Format B) and regex_int_internal
        # (Format E) both fail.
        # Example:
        #   Interface  Lanes  Speed  MTU   FEC   Alias  Vlan    Oper  Admin
        #   Ethernet0  0      25G    9100  auto  etp1   routed  up    up
        #   groups: 1=Ethernet0, 2=25G, 3=9100, 4=auto, 5=etp1, 6=routed, 7=up, 8=up
        regex_int_mid = re.compile(
            r'(\S+)\s+[\d,N\/A]+\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)')

        # Format D — legacy SONiC without any FEC column (8 columns).
        # The 4th captured group is the alias, not FEC; fec is reported as 'Unknown'.
        # Example:
        #   Interface  Lanes  Speed  MTU   Alias  Vlan    Oper  Admin
        #   Ethernet0  0      25G    9100  etp1   routed  up    up
        #   groups: 1=Ethernet0, 2=25G, 3=9100, 4=etp1(alias), 5=routed, 6=up, 7=up
        regex_int_legacy = re.compile(
            r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')

        # Format E — multi-ASIC internal backplane interfaces (9 columns).
        # Discriminated by interface NAME matching 'Ethernet-BP<N>' — this is more
        # reliable than FEC or alias patterns, which vary across deployments.
        # FEC and alias use \S+ to accept any value (no constraint needed).
        # Checked BEFORE regex_int_mid so 9-column backplane lines reach the
        # include_internal_intfs guard instead of the unconditional mid branch.
        # 11-column backplane lines match regex_int (Format B) first; the elif old
        # branch applies the same Ethernet-BP guard there.
        # Overall: only populates int_status when include_internal_intfs=True (bulk)
        # or when the interface is explicitly named (per-interface).
        # Example:
        #   Interface     Lanes  Speed  MTU   FEC  Alias         Vlan    Oper  Admin
        #   Ethernet-BP0  0      100G   9100  N/A  Ethernet-BP0  routed  up    up
        #   groups: 1=Ethernet-BP0, 2=100G, 3=9100, 4=N/A, 5=Ethernet-BP0,
        #           6=routed, 7=up, 8=up
        regex_int_internal = re.compile(
            r'(Ethernet-BP\d+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\w+)\s+(\w+)\s+(\w+)')
        regex_bp = re.compile(r'Ethernet-BP')
        self.int_status = {}
        if self.m_args['interfaces'] is not None:
            for interface in self.m_args['interfaces']:
                self.int_status[interface] = {}
                command = 'sudo show interface status ' + interface
                try:
                    rc, self.out, err = self.module.run_command(
                        command, executable='/bin/bash', use_unsafe_shell=True)
                    for line in self.out.split("\n"):
                        line = line.strip()
                        fec = regex_int_fec.match(line)
                        old = regex_int.match(line) if not fec else None
                        # internal must precede mid: 9-col BP lines must reach regex_int_internal
                        # (and its include_internal_intfs gate) before regex_int_mid can claim them.
                        internal = regex_int_internal.match(line) if not fec and not old else None
                        mid = regex_int_mid.match(line) if not fec and not old and not internal else None
                        no_match = not fec and not old and not internal and not mid
                        legacy = regex_int_legacy.match(line) if no_match else None
                        if fec and interface == fec.group(1):
                            self.int_status[interface]['name'] = fec.group(1)
                            self.int_status[interface]['speed'] = fec.group(2)
                            self.int_status[interface]['fec'] = fec.group(4)
                            self.int_status[interface]['alias'] = fec.group(5)
                            self.int_status[interface]['vlan'] = fec.group(6)
                            self.int_status[interface]['oper_state'] = fec.group(
                                7)
                            self.int_status[interface]['admin_state'] = fec.group(
                                8)
                            self.int_status[interface]['type'] = self._fetch_interface_type(
                                line)
                        elif old and interface == old.group(1):
                            self.int_status[interface]['name'] = old.group(1)
                            self.int_status[interface]['speed'] = old.group(2)
                            self.int_status[interface]['fec'] = old.group(4)
                            self.int_status[interface]['alias'] = old.group(5)
                            self.int_status[interface]['vlan'] = old.group(6)
                            self.int_status[interface]['oper_state'] = old.group(
                                7)
                            self.int_status[interface]['admin_state'] = old.group(
                                8)
                            self.int_status[interface]['type'] = old.group(9)
                        elif internal and interface == internal.group(1):
                            self.int_status[interface]['name'] = internal.group(1)
                            self.int_status[interface]['speed'] = internal.group(2)
                            self.int_status[interface]['fec'] = internal.group(4)
                            self.int_status[interface]['alias'] = internal.group(5)
                            self.int_status[interface]['vlan'] = internal.group(6)
                            self.int_status[interface]['oper_state'] = internal.group(
                                7)
                            self.int_status[interface]['admin_state'] = internal.group(
                                8)
                            self.int_status[interface]['type'] = 'N/A'
                        elif mid and interface == mid.group(1):
                            self.int_status[interface]['name'] = mid.group(1)
                            self.int_status[interface]['speed'] = mid.group(2)
                            self.int_status[interface]['fec'] = mid.group(4)
                            self.int_status[interface]['alias'] = mid.group(5)
                            self.int_status[interface]['vlan'] = mid.group(6)
                            self.int_status[interface]['oper_state'] = mid.group(
                                7)
                            self.int_status[interface]['admin_state'] = mid.group(
                                8)
                            self.int_status[interface]['type'] = 'N/A'
                        elif legacy and interface == legacy.group(1):
                            self.int_status[interface]['name'] = legacy.group(1)
                            self.int_status[interface]['speed'] = legacy.group(2)
                            self.int_status[interface]['fec'] = 'Unknown'
                            self.int_status[interface]['alias'] = legacy.group(4)
                            self.int_status[interface]['vlan'] = legacy.group(5)
                            self.int_status[interface]['oper_state'] = legacy.group(
                                6)
                            self.int_status[interface]['admin_state'] = legacy.group(
                                7)
                            self.int_status[interface]['type'] = 'N/A'
                    self.facts['int_status'] = self.int_status
                except Exception as e:
                    self.module.fail_json(msg=str(e))
                if rc != 0:
                    self.module.fail_json(
                        msg="Command failed rc=%d, out=%s, err=%s" % (rc, self.out, err))
        else:
            try:
                cli_options = " -n {}".format(
                    namespace) if namespace is not None else ""
                if include_internal_intfs and namespace is not None:
                    cli_options += " -d all"
                if include_inband_intfs:
                    cli_options += " -d all"
                intf_status_cmd = "show interface status{}".format(cli_options)
                rc, self.out, err = self.module.run_command(
                    intf_status_cmd, executable='/bin/bash', use_unsafe_shell=True)
                for line in self.out.split("\n"):
                    line = line.strip()
                    fec = regex_int_fec.match(line)
                    old = regex_int.match(line) if not fec else None
                    # internal must precede mid: 9-col BP lines must reach regex_int_internal
                    # (and its include_internal_intfs gate) before regex_int_mid can claim them.
                    internal = regex_int_internal.match(line) if not fec and not old else None
                    mid = regex_int_mid.match(line) if not fec and not old and not internal else None
                    legacy = regex_int_legacy.match(line) if not fec and not old and not internal and not mid else None
                    if fec:
                        interface = fec.group(1)
                        if not regex_bp.match(interface) or include_internal_intfs:
                            self.int_status[interface] = {}
                            self.int_status[interface]['name'] = interface
                            self.int_status[interface]['speed'] = fec.group(2)
                            self.int_status[interface]['fec'] = fec.group(4)
                            self.int_status[interface]['alias'] = fec.group(5)
                            self.int_status[interface]['vlan'] = fec.group(6)
                            self.int_status[interface]['oper_state'] = fec.group(7)
                            self.int_status[interface]['admin_state'] = fec.group(
                                8)
                            self.int_status[interface]['type'] = self._fetch_interface_type(
                                line)
                    elif old:
                        interface = old.group(1)
                        # A backplane interface printed in 11-column format matches
                        # regex_int before regex_int_internal is evaluated.  Apply
                        # the same include_internal_intfs gate here.
                        if not regex_bp.match(interface) or include_internal_intfs:
                            self.int_status[interface] = {}
                            self.int_status[interface]['name'] = interface
                            self.int_status[interface]['speed'] = old.group(2)
                            self.int_status[interface]['fec'] = old.group(4)
                            self.int_status[interface]['alias'] = old.group(5)
                            self.int_status[interface]['vlan'] = old.group(6)
                            self.int_status[interface]['oper_state'] = old.group(7)
                            self.int_status[interface]['admin_state'] = old.group(
                                8)
                            self.int_status[interface]['type'] = old.group(9)
                    elif internal and include_internal_intfs:
                        interface = internal.group(1)
                        self.int_status[interface] = {}
                        self.int_status[interface]['name'] = interface
                        self.int_status[interface]['speed'] = internal.group(2)
                        self.int_status[interface]['fec'] = internal.group(4)
                        self.int_status[interface]['alias'] = internal.group(5)
                        self.int_status[interface]['vlan'] = internal.group(6)
                        self.int_status[interface]['oper_state'] = internal.group(
                            7)
                        self.int_status[interface]['admin_state'] = internal.group(
                            8)
                        self.int_status[interface]['type'] = 'N/A'
                    elif mid:
                        interface = mid.group(1)
                        if not regex_bp.match(interface) or include_internal_intfs:
                            self.int_status[interface] = {}
                            self.int_status[interface]['name'] = interface
                            self.int_status[interface]['speed'] = mid.group(2)
                            self.int_status[interface]['fec'] = mid.group(4)
                            self.int_status[interface]['alias'] = mid.group(5)
                            self.int_status[interface]['vlan'] = mid.group(6)
                            self.int_status[interface]['oper_state'] = mid.group(7)
                            self.int_status[interface]['admin_state'] = mid.group(8)
                            self.int_status[interface]['type'] = 'N/A'
                    elif legacy:
                        interface = legacy.group(1)
                        if not regex_bp.match(interface) or include_internal_intfs:
                            self.int_status[interface] = {}
                            self.int_status[interface]['name'] = interface
                            self.int_status[interface]['speed'] = legacy.group(2)
                            self.int_status[interface]['fec'] = 'Unknown'
                            self.int_status[interface]['alias'] = legacy.group(4)
                            self.int_status[interface]['vlan'] = legacy.group(5)
                            self.int_status[interface]['oper_state'] = legacy.group(6)
                            self.int_status[interface]['admin_state'] = legacy.group(7)
                            self.int_status[interface]['type'] = 'N/A'
                self.facts['int_status'] = self.int_status
            except Exception as e:
                self.module.fail_json(msg=str(e))
            if rc != 0:
                self.module.fail_json(
                    msg="Command failed rc = %d, out = %s, err = %s" % (rc, self.out, err))

        if 'up_ports' in self.m_args:
            down_ports = []
            up_ports = self.m_args['up_ports']
            for name in up_ports:
                try:
                    if self.int_status[name]['oper_state'] != 'up':
                        down_ports += [name]
                except Exception:
                    down_ports += [name]
            self.facts['ansible_interface_link_down_ports'] = down_ports

        return

    def collect_interface_counter(self, namespace=None, include_internal_intfs=False):
        regex_int = re.compile(
            r'\s*(\S+)\s+(\w)\s+([,\d]+)\s+(N\/A|[.0-9]+ K?B/s)\s+(\S+)\s+([,\d]+)\s+(\S+)\s+([,\d]+)\s+'
            r'([,\d]+)\s+(N\/A|[.0-9]+ K?B/s)\s+(\S+)\s+([,\d]+)\s+(\S+)\s+([,\d]+)')
        self.int_counter = {}
        cli_options = " -n {}".format(
            namespace) if namespace is not None else ""
        if include_internal_intfs and namespace is not None:
            cli_options += " -d all"
        intf_status_cmd = "show interface counter{}".format(cli_options)
        try:
            rc, self.out, err = self.module.run_command(
                intf_status_cmd, executable='/bin/bash', use_unsafe_shell=True)
            for line in self.out.split("\n"):
                line = line.strip()
                if regex_int.match(line):
                    interface = regex_int.match(line).group(1)
                    self.int_counter[interface] = {}
                    self.int_counter[interface]['IFACE'] = interface
                    self.int_counter[interface]['STATE'] = regex_int.match(
                        line).group(2)
                    self.int_counter[interface]['RX_OK'] = regex_int.match(
                        line).group(3)
                    self.int_counter[interface]['RX_BPS'] = regex_int.match(
                        line).group(4)
                    self.int_counter[interface]['RX_UTIL'] = regex_int.match(
                        line).group(5)
                    self.int_counter[interface]['RX_ERR'] = regex_int.match(
                        line).group(6)
                    self.int_counter[interface]['RX_DRP'] = regex_int.match(
                        line).group(7)
                    self.int_counter[interface]['RX_OVR'] = regex_int.match(
                        line).group(8)
                    self.int_counter[interface]['TX_OK'] = regex_int.match(
                        line).group(9)
                    self.int_counter[interface]['TX_BPS'] = regex_int.match(
                        line).group(10)
                    self.int_counter[interface]['TX_UTIL'] = regex_int.match(
                        line).group(11)
                    self.int_counter[interface]['TX_ERR'] = regex_int.match(
                        line).group(12)
                    self.int_counter[interface]['TX_DRP'] = regex_int.match(
                        line).group(13)
                    self.int_counter[interface]['TX_OVR'] = regex_int.match(
                        line).group(14)
        except Exception as e:
            self.module.fail_json(msg=str(e))
        if rc != 0:
            self.module.fail_json(
                msg="Command failed rc=%d, out=%s, err=%s" % (rc, self.out, err))
        self.facts['int_counter'] = self.int_counter
        return


def main():
    ShowInt = ShowInterfaceModule()
    ShowInt.run()
    return


if __name__ == "__main__":
    main()
