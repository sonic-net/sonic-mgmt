#!/usr/bin/python

# This file is part of Networklore's snmp library for Ansible
#
# The module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# The module is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = '''
---
module: snmp_facts
author: Patrick Ogenstad (@networklore)
notes:
    - Version 0.7
short_description: Retrive facts for a device using SNMP.
description:
    - Retrieve facts for a device using SNMP, the facts will be
      inserted to the ansible_facts key.
requirements:
    - pysnmp
options:
    host:
        description:
            - Set to {{ inventory_hostname }}}
        required: true
    version:
        description:
            - SNMP Version to use, v2/v2c or v3
        choices: [ 'v2', 'v2c', 'v3' ]
        required: true
    community:
        description:
            - The SNMP community string, required if version is v2/v2c
        required: false
    is_dell:
        description:
            - Whether the nos is dell or not
        required: false
    is_eos:
        description:
            - Whether the nos is eos or not
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
# Gather facts with SNMP version 2
- snmp_facts: host={{ inventory_hostname }} version=2c community=public

# Gather facts using SNMP version 3
- snmp_facts:
    host={{ inventory_hostname }}
    version=v3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
'''

from ansible.module_utils.basic import *
from collections import defaultdict

try:
    from pysnmp.proto import rfc1902
    from pysnmp.entity.rfc3413.oneliner import cmdgen
    from pyasn1.type import univ
    has_pysnmp = True
except:
    has_pysnmp = False

class DefineOid(object):

    def __init__(self,dotprefix=False):
        if dotprefix:
            dp = "."
        else:
            dp = ""

        # From SNMPv2-MIB
        self.sysDescr    = dp + "1.3.6.1.2.1.1.1.0"
        self.sysObjectId = dp + "1.3.6.1.2.1.1.2.0"
        self.sysUpTime   = dp + "1.3.6.1.2.1.1.3.0"
        self.sysContact  = dp + "1.3.6.1.2.1.1.4.0"
        self.sysName     = dp + "1.3.6.1.2.1.1.5.0"
        self.sysLocation = dp + "1.3.6.1.2.1.1.6.0"

        # From IF-MIB
        self.ifIndex       = dp + "1.3.6.1.2.1.2.2.1.1"
        self.ifDescr       = dp + "1.3.6.1.2.1.2.2.1.2"
        self.ifType        = dp + "1.3.6.1.2.1.2.2.1.3"
        self.ifMtu         = dp + "1.3.6.1.2.1.2.2.1.4"
        self.ifSpeed       = dp + "1.3.6.1.2.1.2.2.1.5"
        self.ifPhysAddress = dp + "1.3.6.1.2.1.2.2.1.6"
        self.ifAdminStatus = dp + "1.3.6.1.2.1.2.2.1.7"
        self.ifOperStatus  = dp + "1.3.6.1.2.1.2.2.1.8"
        self.ifHighSpeed   = dp + "1.3.6.1.2.1.31.1.1.1.15"
        self.ifAlias       = dp + "1.3.6.1.2.1.31.1.1.1.18"

        self.ifInDiscards  = dp + "1.3.6.1.2.1.2.2.1.13"
        self.ifOutDiscards = dp + "1.3.6.1.2.1.2.2.1.19"
        self.ifInErrors    = dp + "1.3.6.1.2.1.2.2.1.14"
        self.ifOutErrors   = dp + "1.3.6.1.2.1.2.2.1.20"
        self.ifHCInOctets  = dp + "1.3.6.1.2.1.31.1.1.1.6"
        self.ifHCOutOctets = dp + "1.3.6.1.2.1.31.1.1.1.10"
        self.ifInUcastPkts = dp + "1.3.6.1.2.1.2.2.1.11"
        self.ifOutUcastPkts= dp + "1.3.6.1.2.1.2.2.1.17"

        # From entity table MIB
        self.entPhysDescr       = dp + "1.3.6.1.2.1.47.1.1.1.1.2"
        self.entPhysContainedIn = dp + "1.3.6.1.2.1.47.1.1.1.1.4"
        self.entPhysClass       = dp + "1.3.6.1.2.1.47.1.1.1.1.5"
        self.entPhyParentRelPos = dp + "1.3.6.1.2.1.47.1.1.1.1.6"
        self.entPhysName        = dp + "1.3.6.1.2.1.47.1.1.1.1.7"
        self.entPhysHwVer       = dp + "1.3.6.1.2.1.47.1.1.1.1.8"
        self.entPhysFwVer       = dp + "1.3.6.1.2.1.47.1.1.1.1.9"
        self.entPhysSwVer       = dp + "1.3.6.1.2.1.47.1.1.1.1.10"
        self.entPhysSerialNum   = dp + "1.3.6.1.2.1.47.1.1.1.1.11"
        self.entPhysMfgName     = dp + "1.3.6.1.2.1.47.1.1.1.1.12"
        self.entPhysModelName   = dp + "1.3.6.1.2.1.47.1.1.1.1.13"
        self.entPhysIsFRU       = dp + "1.3.6.1.2.1.47.1.1.1.1.16"

        # From entity sensor MIB
        self.entPhySensorType           = dp + "1.3.6.1.2.1.99.1.1.1.1"
        self.entPhySensorScale          = dp + "1.3.6.1.2.1.99.1.1.1.2"
        self.entPhySensorPrecision      = dp + "1.3.6.1.2.1.99.1.1.1.3"
        self.entPhySensorValue          = dp + "1.3.6.1.2.1.99.1.1.1.4"
        self.entPhySensorOperStatus     = dp + "1.3.6.1.2.1.99.1.1.1.5"

        # From IP-MIB
        self.ipAdEntAddr    = dp + "1.3.6.1.2.1.4.20.1.1"
        self.ipAdEntIfIndex = dp + "1.3.6.1.2.1.4.20.1.2"
        self.ipAdEntNetMask = dp + "1.3.6.1.2.1.4.20.1.3"

        # From LLDP-MIB: lldpLocalSystemData
        self.lldpLocChassisIdSubtype    = dp + "1.0.8802.1.1.2.1.3.1"
        self.lldpLocChassisId           = dp + "1.0.8802.1.1.2.1.3.2"
        self.lldpLocSysName             = dp + "1.0.8802.1.1.2.1.3.3"
        self.lldpLocSysDesc             = dp + "1.0.8802.1.1.2.1.3.4"

        # From LLDP-MIB: lldpLocPortTable
        self.lldpLocPortIdSubtype       = dp + "1.0.8802.1.1.2.1.3.7.1.2" # + .ifindex
        self.lldpLocPortId              = dp + "1.0.8802.1.1.2.1.3.7.1.3" # + .ifindex
        self.lldpLocPortDesc            = dp + "1.0.8802.1.1.2.1.3.7.1.4" # + .ifindex

        # From LLDP-MIB: lldpLocManAddrTables
        self.lldpLocManAddrLen          = dp + "1.0.8802.1.1.2.1.3.8.1.3" # + .subtype + .man addr
        self.lldpLocManAddrIfSubtype    = dp + "1.0.8802.1.1.2.1.3.8.1.4" # + .subtype + .man addr
        self.lldpLocManAddrIfId         = dp + "1.0.8802.1.1.2.1.3.8.1.5" # + .subtype + .man addr
        self.lldpLocManAddrOID          = dp + "1.0.8802.1.1.2.1.3.8.1.6" # + .subtype + .man addr

        # From LLDP-MIB: lldpRemTable
        self.lldpRemChassisIdSubtype    = dp + "1.0.8802.1.1.2.1.4.1.1.4" # + .time mark + .ifindex + .rem index
        self.lldpRemChassisId           = dp + "1.0.8802.1.1.2.1.4.1.1.5" # + .time mark + .ifindex + .rem index
        self.lldpRemPortIdSubtype       = dp + "1.0.8802.1.1.2.1.4.1.1.6" # + .time mark + .ifindex + .rem index
        self.lldpRemPortId              = dp + "1.0.8802.1.1.2.1.4.1.1.7" # + .time mark + .ifindex + .rem index
        self.lldpRemPortDesc            = dp + "1.0.8802.1.1.2.1.4.1.1.8" # + .time mark + .ifindex + .rem index
        self.lldpRemSysName             = dp + "1.0.8802.1.1.2.1.4.1.1.9" # + .time mark + .ifindex + .rem index
        self.lldpRemSysDesc             = dp + "1.0.8802.1.1.2.1.4.1.1.10" # + .time mark + .ifindex + .rem index
        self.lldpRemSysCapSupported     = dp + "1.0.8802.1.1.2.1.4.1.1.11" # + .time mark + .ifindex + .rem index
        self.lldpRemSysCapEnabled       = dp + "1.0.8802.1.1.2.1.4.1.1.12" # + .time mark + .ifindex + .rem index

        # From LLDP-MIB: lldpRemManAddrTable
        self.lldpRemManAddrIfSubtype    = dp + "1.0.8802.1.1.2.1.4.2.1.3" # + .time mark + .ifindex + .rem index + .addr_subtype + .man addr
        self.lldpRemManAddrIfId         = dp + "1.0.8802.1.1.2.1.4.2.1.4" # + .time mark + .ifindex + .rem index + .addr_subtype + .man addr
        self.lldpRemManAddrOID          = dp + "1.0.8802.1.1.2.1.4.2.1.5" # + .time mark + .ifindex + .rem index + .addr_subtype + .man addr

        # From Dell Private MIB
        self.ChStackUnitCpuUtil5sec = dp + "1.3.6.1.4.1.6027.3.10.1.2.9.1.2.1"

        # Memory Check
        self.sysTotalMemery         = dp + "1.3.6.1.4.1.2021.4.5.0"
        self.sysTotalFreeMemery     = dp + "1.3.6.1.4.1.2021.4.6.0"
        self.sysTotalSharedMemory   = dp + "1.3.6.1.4.1.2021.4.13.0"
        self.sysTotalBuffMemory     = dp + "1.3.6.1.4.1.2021.4.14.0"
        self.sysCachedMemory        = dp + "1.3.6.1.4.1.2021.4.15.0"

        # From Cisco private MIB (PFC and queue counters)
        self.cpfcIfRequests         = dp + "1.3.6.1.4.1.9.9.813.1.1.1.1" # + .ifindex
        self.cpfcIfIndications      = dp + "1.3.6.1.4.1.9.9.813.1.1.1.2" # + .ifindex
        self.requestsPerPriority    = dp + "1.3.6.1.4.1.9.9.813.1.2.1.2" # + .ifindex.prio
        self.indicationsPerPriority = dp + "1.3.6.1.4.1.9.9.813.1.2.1.3" # + .ifindex.prio
        self.csqIfQosGroupStats     = dp + "1.3.6.1.4.1.9.9.580.1.5.5.1.4" # + .ifindex.IfDirection.QueueID

        # From Cisco private MIB (PSU)
        self.cefcFRUPowerOperStatus = dp + "1.3.6.1.4.1.9.9.117.1.1.2.1.2" # + .psuindex

        # ipCidrRouteTable MIB
        self.ipCidrRouteEntry = dp + "1.3.6.1.2.1.4.24.4.1.1.0.0.0.0.0.0.0.0.0" # + .next hop IP
        self.ipCidrRouteStatus = dp + "1.3.6.1.2.1.4.24.4.1.16.0.0.0.0.0.0.0.0.0" # + .next hop IP

def decode_hex(hexstring):

    if len(hexstring) < 3:
        return hexstring
    if hexstring[:2] == "0x":
        return hexstring[2:].decode("hex")
    else:
        return hexstring

def decode_mac(hexstring):

    if len(hexstring) != 14:
        return hexstring
    if hexstring[:2] == "0x":
        return hexstring[2:]
    else:
        return hexstring

def lookup_adminstatus(int_adminstatus):
    adminstatus_options = {
                            1: 'up',
                            2: 'down',
                            3: 'testing'
                          }
    if int_adminstatus in adminstatus_options.keys():
        return adminstatus_options[int_adminstatus]
    else:
        return ""

def lookup_operstatus(int_operstatus):
    operstatus_options = {
                           1: 'up',
                           2: 'down',
                           3: 'testing',
                           4: 'unknown',
                           5: 'dormant',
                           6: 'notPresent',
                           7: 'lowerLayerDown'
                         }
    if int_operstatus in operstatus_options.keys():
        return operstatus_options[int_operstatus]
    else:
        return ""

def decode_type(module, current_oid, val):
    tagMap = {
         rfc1902.Counter32.tagSet: long,
         rfc1902.Gauge32.tagSet: long,
         rfc1902.Integer32.tagSet: long,
         rfc1902.IpAddress.tagSet: str,
         univ.Null.tagSet: str,
         univ.ObjectIdentifier.tagSet: str,
         rfc1902.OctetString.tagSet: str,
         rfc1902.TimeTicks.tagSet: long,
         rfc1902.Counter64.tagSet: long
         }

    if val is None or not val:
        module.fail_json(msg="Unable to convert ASN1 type to python type. No value was returned for OID %s" % current_oid)

    try:
        pyVal = tagMap[val.tagSet](val)
    except KeyError as e:
        module.fail_json(msg="KeyError: Unable to convert ASN1 type to python type. Value: %s" % val)

    return pyVal


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            timeout=dict(reqired=False, type='int', default=5),
            version=dict(required=True, choices=['v2', 'v2c', 'v3']),
            community=dict(required=False, default=False),
            username=dict(required=False),
            level=dict(required=False, choices=['authNoPriv', 'authPriv']),
            integrity=dict(required=False, choices=['md5', 'sha']),
            privacy=dict(required=False, choices=['des', 'aes']),
            authkey=dict(required=False),
            privkey=dict(required=False),
            is_dell=dict(required=False, default=False, type='bool'),
            is_eos=dict(required=False, default=False, type='bool'),
            removeplaceholder=dict(required=False)),
            required_together = ( ['username','level','integrity','authkey'],['privacy','privkey'],),
        supports_check_mode=False)

    m_args = module.params

    if not has_pysnmp:
        module.fail_json(msg='Missing required pysnmp module (check docs)')

    cmdGen = cmdgen.CommandGenerator()

    # Verify that we receive a community when using snmp v2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        if m_args['community'] == False:
            module.fail_json(msg='Community not set when using snmp version 2')

    if m_args['version'] == "v3":
        if m_args['username'] == None:
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

    # Getting system description could take more than 1 second on some Dell platform
    # (e.g. S6000) when cpu utilization is high, increse timeout to tolerate the delay.
    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161), timeout=m_args['timeout']),
        cmdgen.MibVariable(p.sysDescr,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying system description.')

    for oid, val in varBinds:
        current_oid = oid.prettyPrint()
        current_val = val.prettyPrint()
        if current_oid == v.sysDescr:
            results['ansible_sysdescr'] = decode_hex(current_val)

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.sysObjectId,),
        cmdgen.MibVariable(p.sysUpTime,),
        cmdgen.MibVariable(p.sysContact,),
        cmdgen.MibVariable(p.sysName,),
        cmdgen.MibVariable(p.sysLocation,),
        lookupMib=False, lexicographicMode=False
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying system infomation.')

    for oid, val in varBinds:
        current_oid = oid.prettyPrint()
        current_val = val.prettyPrint()
        if current_oid == v.sysObjectId:
            results['ansible_sysobjectid'] = current_val
        elif current_oid == v.sysUpTime:
            results['ansible_sysuptime'] = current_val
        elif current_oid == v.sysContact:
            results['ansible_syscontact'] = current_val
        elif current_oid == v.sysName:
            results['ansible_sysname'] = current_val
        elif current_oid == v.sysLocation:
            results['ansible_syslocation'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.ifIndex,),
        cmdgen.MibVariable(p.ifDescr,),
        cmdgen.MibVariable(p.ifType,),
        cmdgen.MibVariable(p.ifMtu,),
        cmdgen.MibVariable(p.ifSpeed,),
        cmdgen.MibVariable(p.ifPhysAddress,),
        cmdgen.MibVariable(p.ifAdminStatus,),
        cmdgen.MibVariable(p.ifOperStatus,),
        cmdgen.MibVariable(p.ifHighSpeed,),
        cmdgen.MibVariable(p.ipAdEntAddr,),
        cmdgen.MibVariable(p.ipAdEntIfIndex,),
        cmdgen.MibVariable(p.ipAdEntNetMask,),
        cmdgen.MibVariable(p.ifAlias,),
        lookupMib=False, lexicographicMode=False
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying interface details')

    interface_indexes = []

    all_ipv4_addresses = []
    ipv4_networks = Tree()

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.ifIndex in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifindex'] = current_val
                interface_indexes.append(ifIndex)
            if v.ifDescr in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['name'] = current_val
            if v.ifType in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['type'] = current_val
            if v.ifMtu in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['mtu'] = current_val
            if v.ifSpeed in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['speed'] = current_val
            if v.ifPhysAddress in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['mac'] = decode_mac(current_val)
            if v.ifAdminStatus in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['adminstatus'] = lookup_adminstatus(int(current_val))
            if v.ifOperStatus in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['operstatus'] = lookup_operstatus(int(current_val))
            if v.ifHighSpeed in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifHighSpeed'] = current_val
            if v.ipAdEntAddr in current_oid:
                curIPList = current_oid.rsplit('.', 4)[-4:]
                curIP = ".".join(curIPList)
                ipv4_networks[curIP]['address'] = current_val
                all_ipv4_addresses.append(current_val)
            if v.ipAdEntIfIndex in current_oid:
                curIPList = current_oid.rsplit('.', 4)[-4:]
                curIP = ".".join(curIPList)
                ipv4_networks[curIP]['interface'] = current_val
            if v.ipAdEntNetMask in current_oid:
                curIPList = current_oid.rsplit('.', 4)[-4:]
                curIP = ".".join(curIPList)
                ipv4_networks[curIP]['netmask'] = current_val
            if v.ifAlias in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['description'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.ifInDiscards,),
        cmdgen.MibVariable(p.ifOutDiscards,),
        cmdgen.MibVariable(p.ifInErrors,),
        cmdgen.MibVariable(p.ifOutErrors,),
        cmdgen.MibVariable(p.ifHCInOctets,),
        cmdgen.MibVariable(p.ifHCOutOctets,),
        cmdgen.MibVariable(p.ifInUcastPkts,),
        cmdgen.MibVariable(p.ifOutUcastPkts,),
        lookupMib=False, lexicographicMode=False
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying interface counters')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.ifInDiscards in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifInDiscards'] = current_val
            if v.ifOutDiscards in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifOutDiscards'] = current_val
            if v.ifInErrors in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifInErrors'] = current_val
            if v.ifOutErrors in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifOutErrors'] = current_val
            if v.ifHCInOctets in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifHCInOctets'] = current_val
            if v.ifHCOutOctets in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifHCOutOctets'] = current_val
            if v.ifInUcastPkts in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifInUcastPkts'] = current_val
            if v.ifOutUcastPkts in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['ifOutUcastPkts'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.entPhysDescr,),
        cmdgen.MibVariable(p.entPhysContainedIn, ),
        cmdgen.MibVariable(p.entPhysClass,),
        cmdgen.MibVariable(p.entPhyParentRelPos, ),
        cmdgen.MibVariable(p.entPhysName,),
        cmdgen.MibVariable(p.entPhysHwVer,),
        cmdgen.MibVariable(p.entPhysFwVer,),
        cmdgen.MibVariable(p.entPhysSwVer,),
        cmdgen.MibVariable(p.entPhysSerialNum,),
        cmdgen.MibVariable(p.entPhysMfgName,),
        cmdgen.MibVariable(p.entPhysModelName,),
        cmdgen.MibVariable(p.entPhysIsFRU, ),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying physical table')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.entPhysDescr in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysDescr'] = current_val
            if v.entPhysContainedIn in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysContainedIn'] = int(current_val)
            if v.entPhysClass in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysClass'] = int(current_val)
            if v.entPhyParentRelPos in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhyParentRelPos'] = int(current_val)
            if v.entPhysName in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysName'] = current_val
            if v.entPhysHwVer in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysHwVer'] = current_val
            if v.entPhysFwVer in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysFwVer'] = current_val
            if v.entPhysSwVer in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysSwVer'] = current_val
            if v.entPhysSerialNum in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysSerialNum'] = current_val
            if v.entPhysMfgName in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysMfgName'] = current_val
            if v.entPhysModelName in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysModelName'] = current_val
            if v.entPhysIsFRU in current_oid:
                entity_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_physical_entities'][entity_oid]['entPhysIsFRU'] = int(current_val)


    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.entPhySensorType,),
        cmdgen.MibVariable(p.entPhySensorScale,),
        cmdgen.MibVariable(p.entPhySensorPrecision,),
        cmdgen.MibVariable(p.entPhySensorValue,),
        cmdgen.MibVariable(p.entPhySensorOperStatus,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying physical table')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.entPhySensorType in current_oid:
                sensor_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_sensors'][sensor_oid]['entPhySensorType'] = current_val
            if v.entPhySensorScale in current_oid:
                sensor_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_sensors'][sensor_oid]['entPhySensorScale'] = int(current_val)
            if v.entPhySensorPrecision in current_oid:
                sensor_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_sensors'][sensor_oid]['entPhySensorPrecision'] = current_val
            if v.entPhySensorValue in current_oid:
                sensor_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_sensors'][sensor_oid]['entPhySensorValue'] = current_val
            if v.entPhySensorOperStatus in current_oid:
                sensor_oid = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_sensors'][sensor_oid]['entPhySensorOperStatus'] = current_val

    interface_to_ipv4 = {}
    for ipv4_network in ipv4_networks:
        current_interface = ipv4_networks[ipv4_network]['interface']
        current_network = {
                            'address':  ipv4_networks[ipv4_network]['address'],
                            'netmask':  ipv4_networks[ipv4_network]['netmask']
                          }
        if not current_interface in interface_to_ipv4:
            interface_to_ipv4[current_interface] = []
            interface_to_ipv4[current_interface].append(current_network)
        else:
            interface_to_ipv4[current_interface].append(current_network)

    for interface in interface_to_ipv4:
        results['snmp_interfaces'][int(interface)]['ipv4'] = interface_to_ipv4[interface]

    results['ansible_all_ipv4_addresses'] = all_ipv4_addresses

    if m_args['is_dell']:
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((m_args['host'], 161)),
            cmdgen.MibVariable(p.ChStackUnitCpuUtil5sec,),
            lookupMib=False, lexicographicMode=False
        )

        if errorIndication:
            module.fail_json(msg=str(errorIndication) + ' querying CPU busy indeces')

        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if current_oid == v.ChStackUnitCpuUtil5sec:
                results['ansible_ChStackUnitCpuUtil5sec'] = decode_type(module, current_oid, val)

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.lldpLocChassisIdSubtype,),
        cmdgen.MibVariable(p.lldpLocChassisId,),
        cmdgen.MibVariable(p.lldpLocSysName,),
        cmdgen.MibVariable(p.lldpLocSysDesc,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying  lldp local system infomation.')

    for oid, val in varBinds:
        current_oid = oid.prettyPrint()
        current_val = val.prettyPrint()
        if current_oid == v.lldpLocChassisIdSubtype:
            results['snmp_lldp']['lldpLocChassisIdSubtype'] = current_val
        elif current_oid == v.lldpLocChassisId:
            results['snmp_lldp']['lldpLocChassisId'] = current_val
        elif current_oid == v.lldpLocSysName:
            results['snmp_lldp']['lldpLocSysName'] = current_val
        elif current_oid == v.lldpLocSysDesc:
            results['snmp_lldp']['lldpLocSysDesc'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.lldpLocPortIdSubtype,),
        cmdgen.MibVariable(p.lldpLocPortId,),
        cmdgen.MibVariable(p.lldpLocPortDesc,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying lldpLocPortTable counters')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.lldpLocPortIdSubtype in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['lldpLocPortIdSubtype'] = current_val
            if v.lldpLocPortId in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['lldpLocPortId'] = current_val
            if v.lldpLocPortDesc in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['lldpLocPortDesc'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.lldpLocManAddrLen,),
        cmdgen.MibVariable(p.lldpLocManAddrIfSubtype,),
        cmdgen.MibVariable(p.lldpLocManAddrIfId,),
        cmdgen.MibVariable(p.lldpLocManAddrOID,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying lldpLocPortTable counters')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.lldpLocManAddrLen in current_oid:
                address = '.'.join(current_oid.split('.')[13:])
                results['snmp_lldp']['lldpLocManAddrLen'] = current_val
            if v.lldpLocManAddrIfSubtype in current_oid:
                address = '.'.join(current_oid.split('.')[13:])
                results['snmp_lldp']['lldpLocManAddrIfSubtype'] = current_val
            if v.lldpLocManAddrIfId in current_oid:
                address = '.'.join(current_oid.split('.')[13:])
                results['snmp_lldp']['lldpLocManAddrIfId'] = current_val
            if v.lldpLocManAddrOID in current_oid:
                address = '.'.join(current_oid.split('.')[13:])
                results['snmp_lldp']['lldpLocManAddrOID'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.lldpRemChassisIdSubtype,),
        cmdgen.MibVariable(p.lldpRemChassisId,),
        cmdgen.MibVariable(p.lldpRemPortIdSubtype,),
        cmdgen.MibVariable(p.lldpRemPortId,),
        cmdgen.MibVariable(p.lldpRemPortDesc,),
        cmdgen.MibVariable(p.lldpRemSysName,),
        cmdgen.MibVariable(p.lldpRemSysDesc,),
        cmdgen.MibVariable(p.lldpRemSysCapSupported,),
        cmdgen.MibVariable(p.lldpRemSysCapEnabled,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying lldpLocPortTable counters')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.lldpRemChassisIdSubtype in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemChassisIdSubtype'] = current_val
            if v.lldpRemChassisId in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemChassisId'] = current_val
            if v.lldpRemPortIdSubtype in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemPortIdSubtype'] = current_val
            if v.lldpRemPortId in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemPortId'] = current_val
            if v.lldpRemPortDesc in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemPortDesc'] = current_val
            if v.lldpRemSysName in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemSysName'] = current_val
            if v.lldpRemSysDesc in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemSysDesc'] = current_val
            if v.lldpRemSysCapSupported in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemSysCapSupported'] = current_val
            if v.lldpRemSysCapEnabled in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                results['snmp_interfaces'][ifIndex]['lldpRemSysCapEnabled'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.lldpRemManAddrIfSubtype,),
        cmdgen.MibVariable(p.lldpRemManAddrIfId,),
        cmdgen.MibVariable(p.lldpRemManAddrOID,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying lldpLocPortTable counters')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.lldpRemManAddrIfSubtype in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                address = '.'.join(current_oid.split('.')[16:])
                results['snmp_interfaces'][ifIndex]['lldpRemManAddrIfSubtype'] = current_val
            if v.lldpRemManAddrIfId in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                address = '.'.join(current_oid.split('.')[16:])
                results['snmp_interfaces'][ifIndex]['lldpRemManAddrIfId'] = current_val
            if v.lldpRemManAddrOID in current_oid:
                ifIndex = int(current_oid.split('.')[12])
                address = '.'.join(current_oid.split('.')[16:])
                results['snmp_interfaces'][ifIndex]['lldpRemManAddrOID'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.cpfcIfRequests,),
        cmdgen.MibVariable(p.cpfcIfIndications,),
        cmdgen.MibVariable(p.requestsPerPriority,),
        cmdgen.MibVariable(p.indicationsPerPriority,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying PFC counters')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.cpfcIfRequests in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['cpfcIfRequests'] = current_val
            if v.cpfcIfIndications in current_oid:
                ifIndex = int(current_oid.rsplit('.', 1)[-1])
                results['snmp_interfaces'][ifIndex]['cpfcIfIndications'] = current_val
            if v.requestsPerPriority in current_oid:
                ifIndex = int(current_oid.split('.')[-2])
                prio = int(current_oid.split('.')[-1])
                results['snmp_interfaces'][ifIndex]['requestsPerPriority'][prio] = current_val
            if v.indicationsPerPriority in current_oid:
                ifIndex = int(current_oid.split('.')[-2])
                prio = int(current_oid.split('.')[-1])
                results['snmp_interfaces'][ifIndex]['indicationsPerPriority'][prio] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.csqIfQosGroupStats,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying QoS stats')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.csqIfQosGroupStats in current_oid:
                ifIndex = int(current_oid.split('.')[-4])
                ifDirection = int(current_oid.split('.')[-3])
                queueId = int(current_oid.split('.')[-2])
                counterId = int(current_oid.split('.')[-1])
                results['snmp_interfaces'][ifIndex]['queues'][ifDirection][queueId][counterId] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.cefcFRUPowerOperStatus,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying FRU')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.cefcFRUPowerOperStatus in current_oid:
                psuIndex = int(current_oid.split('.')[-1])
                results['snmp_psu'][psuIndex]['operstatus'] = current_val

    errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
        snmp_auth,
        cmdgen.UdpTransportTarget((m_args['host'], 161)),
        cmdgen.MibVariable(p.ipCidrRouteEntry,),
        cmdgen.MibVariable(p.ipCidrRouteStatus,),
    )

    if errorIndication:
        module.fail_json(msg=str(errorIndication) + ' querying CidrRouteTable')

    for varBinds in varTable:
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if v.ipCidrRouteEntry in current_oid:
                # extract next hop ip from oid
                next_hop = current_oid.split(v.ipCidrRouteEntry + ".")[1]
                results['snmp_cidr_route'][next_hop]['route_dest'] = current_val
            if v.ipCidrRouteStatus in current_oid:
                next_hop = current_oid.split(v.ipCidrRouteStatus + ".")[1]
                results['snmp_cidr_route'][next_hop]['status'] = current_val

    if not m_args['is_eos']:
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((m_args['host'], 161)),
            cmdgen.MibVariable(p.sysTotalMemery,),
            cmdgen.MibVariable(p.sysTotalFreeMemery,),
            cmdgen.MibVariable(p.sysTotalSharedMemory,),
            cmdgen.MibVariable(p.sysTotalBuffMemory,),
            cmdgen.MibVariable(p.sysCachedMemory,),
            lookupMib=False, lexicographicMode=False
        )

        if errorIndication:
            module.fail_json(msg=str(errorIndication) + ' querying system infomation.')

        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if current_oid == v.sysTotalMemery:
                results['ansible_sysTotalMemery'] = decode_type(module, current_oid, val)
            elif current_oid == v.sysTotalFreeMemery:
                results['ansible_sysTotalFreeMemery'] = decode_type(module, current_oid, val)
            elif current_oid == v.sysTotalSharedMemory:
                results['ansible_sysTotalSharedMemory'] = decode_type(module, current_oid, val)
            elif current_oid == v.sysTotalBuffMemory:
                results['ansible_sysTotalBuffMemory'] = decode_type(module, current_oid, val)
            elif current_oid == v.sysCachedMemory:
                results['ansible_sysCachedMemory'] = decode_type(module, current_oid, val)

    module.exit_json(ansible_facts=results)

main()
