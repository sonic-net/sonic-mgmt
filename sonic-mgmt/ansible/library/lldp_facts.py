#!/usr/bin/env python

DOCUMENTATION = '''
---
module: lldp_facts
version_added: "1.9"
author: "Samir Jamkhande (samirja@microsoft.com)
short_description: Retrive LLDP facts for a device using SNMP.
description:
    - Retrieve LLDP facts for a device using SNMP, the facts will be
      inserted to the ansible_facts key.
requirements:
    - pysnmp
options:
    host:
        description:
            - Set to target snmp server (normally {{inventory_hostname}})
        required:True
    version:
        description:
            - SNMP Version to use, v2/v2c or v3
        choices: [ 'v2', 'v2c', 'v3' ]
        required: true
    community:
        description:
            - The SNMP community string, required if version is v2/v2c
        required: false
    level:
        description:
            - Authentication level, required if version is v3
        choices: [ 'authPriv', 'authNoPriv' ]
        required: false
    username:
        description:
            - Username for SNMPv3, required if version is v3
        required: false
    integrity:
        description:
            - Hashing algoritm, required if version is v3
        choices: [ 'md5', 'sha' ]
        required: false
    authkey:
        description:
            - Authentication key, required if version is v3
        required: false
    privacy:
        description:
            - Encryption algoritm, required if level is authPriv
        choices: [ 'des', 'aes' ]
        required: false
    privkey:
        description:
            - Encryption key, required if version is authPriv
        required: false
'''

EXAMPLES = '''
# Gather LLDP facts with SNMP version 2
- snmp_facts: host={{ inventory_hostname }} version=2c community=public
  delegate_to: localhost

# Gather LLDP facts using SNMP version 3
- lldp_facts:
    host={{ inventory_hostname }}
    version=v3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
  delegate_to: localhost
'''

from ansible.module_utils.basic import *
from collections import defaultdict

try:
    from pysnmp.entity.rfc3413.oneliner import cmdgen
    has_pysnmp = True
except:
    has_pysnmp = False

class DefineOid(object):

    def __init__(self,dotprefix=False):
        if dotprefix:
            dp = ".1"
        else:
            dp = ""

        # From IF-MIB
        self.if_descr       = dp + ".0.8802.1.1.2.1.3.7.1.3"

        # From LLDP-MIB
        self.lldp_rem_port_id      = dp + ".0.8802.1.1.2.1.4.1.1.7"
        self.lldp_rem_port_desc    = dp + ".0.8802.1.1.2.1.4.1.1.8"
        self.lldp_rem_sys_desc     = dp + ".0.8802.1.1.2.1.4.1.1.10"
        self.lldp_rem_sys_name     = dp + ".0.8802.1.1.2.1.4.1.1.9"
        self.lldp_rem_chassis_id   = dp + ".0.8802.1.1.2.1.4.1.1.5"

def get_iftable(snmp_data):
    """ Gets the interface table (if_index and interface) for a given device
        for further snmp lookups

        Args:
            snmp_data - snmp data returned by cmdgen.nextCmd() for mib = .1.3.6.1.2.1.2.2.1.2

        Returns:
            if_table - dict formatted as if:if_index
            inverse_if_table - dict formated as if_index:if

        Sample Output:
            inverse_if_table = {u'719: u'Ethernet4/29/3', u'718':u'Ethernet4/29/2'}
            if_table = {u'Ethernet4/29/3':u'719', u'Ethernet4/29/2': u'718'}
    """
    if_table = dict()
    inverse_if_table = dict()

    # Populate the if_table dict with parsed output
    for if_tuple in snmp_data:
        if_table[str(if_tuple[0][1])] = str(if_tuple[0][0]).split(".")[-1]
        inverse_if_table[str(if_tuple[0][0]).split(".")[-1]] = str(if_tuple[0][1])

    return (if_table, inverse_if_table)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            version=dict(required=True, choices=['v2', 'v2c', 'v3']),
            community=dict(required=False, default=False),
            username=dict(required=False),
            level=dict(required=False, choices=['authNoPriv', 'authPriv']),
            integrity=dict(required=False, choices=['md5', 'sha']),
            privacy=dict(required=False, choices=['des', 'aes']),
            authkey=dict(required=False),
            privkey=dict(required=False),
            removeplaceholder=dict(required=False)),
            required_together = ( ['username','level','integrity','authkey'],['privacy','privkey'],),
        supports_check_mode=False)

    m_args = module.params

    if not has_pysnmp:
        module.fail_json(msg='Missing required pysnmp module (check docs)')

    cmd_gen = cmdgen.CommandGenerator()

    # Verify that we receive a community when using snmp v2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        if not m_args['community']:
            module.fail_json(msg='Community not set when using snmp version 2')

    if m_args['version'] == "v3":
        if m_args['username'] is None:
            module.fail_json(msg='Username not set when using snmp version 3')

        if m_args['level'] == "authPriv" and m_args['privacy'] == None:
            module.fail_json(msg='Privacy algorithm not set when using authPriv')

        if m_args['integrity'] == "sha":
            integrity_proto = cmdgen.usmHMACSHAAuthProtocol
        elif m_args['integrity'] == "md5":
            integrity_proto = cmdgen.usmHMACMD5AuthProtocol

        if m_args['privacy'] == "aes":
            privacy_proto = cmdgen.usmAesCfb128Protocol
        elif m_args['privacy'] == "des":
            privacy_proto = cmdgen.usmDESPrivProtocol

    # Use SNMP Version 2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        snmp_auth = cmdgen.CommunityData(m_args['community'])

    # Use SNMP Version 3 with authNoPriv
    elif m_args['level'] == "authNoPriv":
        snmp_auth = cmdgen.UsmUserData(m_args['username'], authKey=m_args['authkey'], authProtocol=integrity_proto)

    # Use SNMP Version 3 with authPriv
    else:
        snmp_auth = cmdgen.UsmUserData(m_args['username'], authKey=m_args['authkey'], privKey=m_args['privkey'], authProtocol=integrity_proto, privProtocol=privacy_proto)

    # Use p to prefix OIDs with a dot for polling
    p = DefineOid(dotprefix=True)
    # Use v without a prefix to use with return values
    v = DefineOid(dotprefix=False)

    Tree = lambda: defaultdict(Tree)

    results = Tree()

    host = m_args['host']

    error_indication, error_status, error_index, var_binds = cmd_gen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((host, 161)),
        cmdgen.MibVariable(p.if_descr,)
    )

    if error_indication:
        module.fail_json(msg=str(error_indication))

    (if_table, inverse_if_table) = get_iftable(var_binds)

    error_indication, error_status, error_index, var_table = cmd_gen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((host, 161)),
        cmdgen.MibVariable(p.lldp_rem_port_id,),
        cmdgen.MibVariable(p.lldp_rem_port_desc,),
        cmdgen.MibVariable(p.lldp_rem_sys_desc,),
        cmdgen.MibVariable(p.lldp_rem_sys_name,),
        cmdgen.MibVariable(p.lldp_rem_chassis_id,),
    )

    if error_indication:
        module.fail_json(msg=str(error_indication))

    lldp_rem_sys = dict()
    lldp_rem_port_id = dict()
    lldp_rem_port_desc = dict()
    lldp_rem_chassis_id = dict()
    lldp_rem_sys_desc = dict()

    vbd = []

    for var_binds in var_table:
        for oid, val in var_binds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            vbd.append(current_oid)
            vbd.append(current_val)

            try:
                if_name = inverse_if_table[str(current_oid.split(".")[-2])]
            except Exception as e:
                print json.dumps({
                    "unbound_interface_index": str(current_oid.split(".")[-2])
                })
                module.fail_json(msg="unboundinterface in inverse if table")

            if v.lldp_rem_sys_name in current_oid:
                lldp_rem_sys[if_name] = current_val
                continue
            if v.lldp_rem_port_id in current_oid:
                lldp_rem_port_id[if_name] = current_val
                continue
            if v.lldp_rem_port_desc in current_oid:
                lldp_rem_port_desc[if_name] = current_val
                continue
            if v.lldp_rem_chassis_id in current_oid:
                lldp_rem_chassis_id[if_name] = current_val
                continue
            if v.lldp_rem_sys_desc in current_oid:
                lldp_rem_sys_desc[if_name] = current_val
                continue

    lldp_data = dict()

    for intf in lldp_rem_sys.viewkeys():
        lldp_data[intf] = {'neighbor_sys_name': lldp_rem_sys[intf],
                                'neighbor_port_desc': lldp_rem_port_desc[intf],
                                'neighbor_port_id': lldp_rem_port_id[intf],
                                'neighbor_sys_desc': lldp_rem_sys_desc[intf],
                                'neighbor_chassis_id': lldp_rem_chassis_id[intf]}


    results['ansible_lldp_facts'] = lldp_data
    module.exit_json(ansible_facts=results)

main()

