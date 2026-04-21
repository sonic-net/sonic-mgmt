#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_cgnat_lsn_pool
short_description: Manage CGNAT LSN Pools
description:
  - Manage CGNAT LSN (Large Scale NAT) Pools.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the LSN pool to manage.
    type: str
    required: True
  description:
    description:
      - User created LSN pool description.
    type: str
  client_conn_limit:
    description:
      - Specifies the maximum number of simultaneous translated connections a client or subscriber is allowed to have.
      - Valid range of values is between C(0) and C(4294967295) inclusive.
    type: int
  harpin_mode:
    description:
      - Enables or disables hairpinning for incoming connections to active translation end-points.
    type: bool
  icmp_echo:
    description:
      - Enables or disables ICMP echo on translated addresses.
    type: bool
  inbound_connections:
    description:
      - Controls whether or not the BIG-IP system supports inbound connections for each outbound mapping.
      - When C(disabled), system does not support inbound connections for outbound mappings, which prevents
        Port Control Protocol C(pcp) from functioning.
      - When C(explicit), the system supports inbound connections for explicit outbound mappings.
      - When C(automatic) the system supports inbound connections for every outbound mapping as it gets used.
    type: str
    choices:
      - disabled
      - explicit
      - automatic
  mode:
    description:
      - Specifies the translation address mapping mode.
      - The C(napt) mode provides standard address and port translation allowing multiple clients in a private network
        to access remote networks using the single IP address assigned to their router.
      - The C(deterministic) address translation mode provides address translation that eliminates the logging of every
        address mapping, while still allowing internal client address tracking using only an external address and port,
        and a destination address and port.
      - The C(pba) mode logs the allocation and release of port blocks for subscriber translation requests,
        instead of separately logging each translation request.
    type: str
    choices:
      - napt
      - deterministic
      - pba
  persistence_mode:
    description:
      - Specifies the persistence settings for LSN translation entries.
      - When C(address), the translation attempts to reuse the address mapping, but not the port mapping.
      - When C(address-port), the translation attempts to reuse both the address and port mapping for subsequent
        packets sent from the same internal IP address and port.
      - When C(none), peristence is disabled.
    type: str
    choices:
      - address
      - address-port
      - none
  persistence_timeout:
    description:
      - Specifies the persistence timeout value for LSN translation entries.
      - "If a particular mapping is unused for this length of time, the mapping expires and the public-side address/port
        pair is free for use in other mappings."
      - Valid range of values is between C(0) and C(31536000) inclusive.
    type: int
  route_advertisement:
    description:
      - Specifies whether the translation addresses are passed to the Advanced Routing Module
        for advertisement through dynamic routing protocols.
    type: bool
  pba_block_idle_timeout:
    description:
      - Specifies the timeout duration subsequent to the point when the port block becomes idle.
      - Valid range of values is between C(0) and C(4294967295) inclusive."
    type: int
  pba_block_lifetime:
    description:
      - Specifies the timeout for the port block, after which the block is not used for new port allocations.
      - Valid range of values is between C(0) and C(4294967295) inclusive.
      - The value of C(0) corresponds to an infinite timeout.
    type: int
  pba_block_size:
    description:
      - Specifies the number of ports in a block.
      - Valid range of values is between C(0) and C(65535) inclusive.
      - The C(pba_block_size) value should be less than or equal to the LSN pool range, i.e the range of ports defined by
        C(port_range_low) and C(port_range_high) values.
    type: int
  pba_client_block_limit:
    description:
      - Specifies the number of blocks that can be assigned to a single subscriber IP address.
    type: int
  pba_zombie_timeout:
    description:
      - Specifies the timeout duration for a zombie port block, which is a timed out port block with one or more active
        connections. When the timeout duration expires, connections using the zombie block are killed and the zombie
        port block becomes an available port block.
      - The value of C(0) corresponds to an infinite timeout.
      - System ignores this parameter value if C(pba_block_lifetime) is C(0).
    type: int
  port_range_low:
    description:
      - Specifies the low end of the range of port numbers available for use with translation IP addresses.
      - The C(port_range_low) must always be lower or equal to C(port_range_high) value.
      - Valid range of values is between C(0) and C(65535) inclusive.
    type: int
  port_range_high:
    description:
      - Specifies the high end of the range of port numbers available for use with translation IP addresses.
      - The C(port_range_high) must always be higher or equal to C(port_range_high) value.
      - Valid range of values is between C(0) and C(65535) inclusive.
    type: int
  egress_intf_enabled:
    description:
      - Specifies how the system handles address translation on the interfaces specified in C(egress_interfaces).
      - When set to C(true), source address translation is allowed only on the specified C(egress_interfaces).
      - When set to C(false), source address translation is disabled on the specified C(egress_interfaces).
    type: bool
  egress_interfaces:
    description:
      - Specifies the set of interfaces on which the source address translation is allowed or disallowed,
        as determined by the C(egress_intf_enabled) setting.
    type: list
    elements: str
  members:
    description:
      - Specifies the set of translation IP addresses available in the pool. This is a collection of IP prefixes with
        their prefix lengths.
      - All public-side addresses come from the addresses in this group of subnets. Members of two or more deterministic
        LSN pools must not overlap. Every external address used for deterministic mapping must occur only in one LSN
        pool.
    type: list
    elements: str
  backup_members:
    description:
      - Specifies translation IP addresses available for backup members, which are used by Deterministic translation
        mode if C(deterministic) mode translation fails and falls back to C(napt) mode.
      - This is a collection of IP prefixes with their prefix lengths.
    type: list
    elements: str
  log_profile:
    description:
      - Specifies the name of the logging profile the pool uses.
    type: str
  log_publisher:
    description:
      - Specifies the name of the log publisher that logs translation events.
    type: str
  partition:
    description:
      - Device partition on which to manage resources.
    type: str
    default: Common
  state:
    description:
      - When C(state) is C(present), ensures the LSN pool exists.
      - When C(state) is C(absent), ensures the LSN pool is removed.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - Requires CGNAT is licensed and enabled on BIG-IP.
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create an lsn pool
  bigip_cgnat_lsn_pool:
    name: foo
    mode: napt
    client_conn_limit: 100
    log_profile: foo_profile
    log_publisher: foo_publisher
    members:
      - 10.1.1.0/24
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Update lsn pool
  bigip_cgnat_lsn_pool:
    name: foo
    mode: pba
    pba_block_size: 128
    pba_block_lifetime: 7200
    pba_block_idle_timeout: 1800
    pba_zombie_timeout: 900
    log_profile: foo_profile
    log_publisher: foo_publisher
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove lsn pool
  bigip_cgnat_lsn_pool:
    name: foo
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
description:
  description: User created LSN pool description.
  returned: changed
  type: str
  sample: some description
client_conn_limit:
  description: The maximum number of simultaneous translated connections a client or subscriber is allowed to have.
  returned: changed
  type: int
  sample: 50
harpin_mode:
  description: Enables or disables hairpinning for incoming connections to active translation end-points.
  returned: changed
  type: bool
  sample: true
icmp_echo:
  description: Enables or disables ICMP echo on translated addresses.
  returned: changed
  type: bool
  sample: false
inbound_connections:
  description: Controls BIG-IP system support of inbound connections for each outbound mapping.
  returned: changed
  type: str
  sample: explicit
mode:
  description: Specifies the translation address mapping mode.
  returned: changed
  type: str
  sample: napt
persistence_mode:
  description: Specifies the persistence settings for LSN translation entries.
  returned: changed
  type: str
  sample: address
persistence_timeout:
  description: Specifies the persistence timeout value for LSN translation entries.
  returned: changed
  type: int
  sample: 500
route_advertisement:
  description: Specifies whether the translation addresses are advertised through dynamic routing protocols.
  returned: changed
  type: bool
  sample: true
pba_block_idle_timeout:
  description: The timeout duration subsequent to the point when the port block becomes idle.
  returned: changed
  type: int
  sample: 3600
pba_block_lifetime:
  description: The timeout for the port block.
  returned: changed
  type: int
  sample: 7200
pba_block_size:
  description: The number of ports in a block.
  returned: changed
  type: int
  sample: 128
pba_client_block_limit:
  description: The number of blocks that can be assigned to a single subscriber IP address.
  returned: changed
  type: int
  sample: 3
pba_zombie_timeout:
  description: The timeout duration for a zombie port block.
  returned: changed
  type: int
  sample: 180
port_range_low:
  description: The low end of the range of port numbers available for use with translation IP addresses.
  returned: changed
  type: int
  sample: 1025
port_range_high:
  description: The high end of the range of port numbers available for use with translation IP addresses.
  returned: changed
  type: int
  sample: 65535
egress_intf_enabled:
  description: Specifies how the system handles address translation on the egress interfaces.
  returned: changed
  type: bool
  sample: false
egress_interfaces:
  description: The set of interfaces on which source address translation is allowed or disallowed.
  returned: changed
  type: list
  sample: ['/Common/tunnel1', '/Common/tunnel2']
members:
  description: The set of translation IP addresses available in the pool.
  returned: changed
  type: list
  sample: ['/Common/10.10.10.0/24', '/Common/11.11.11.0/25']
backup_members:
  description: The translation IP addresses available for backup members.
  returned: changed
  type: list
  sample: ['/Common/10.10.10.0/24', '/Common/11.11.11.0/25']
log_profile:
  description: The name of the logging profile the pool uses.
  returned: changed
  type: str
  sample: /Common/foo_log_profile
log_publisher:
  description: The name of the log publisher that logs translation events.
  returned: changed
  type: list
  sample: /Common/publisher_1
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean, is_empty_list, fq_name, transform_name
)
from ..module_utils.compare import cmp_simple_list
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'clientConnectionLimit': 'client_conn_limit',
        'hairpinMode': 'harpin_mode',
        'routeAdvertisement': 'route_advertisement',
        'egressInterfaces': 'egress_interfaces',
        'icmpEcho': 'icmp_echo',
        'inboundConnections': 'inbound_connections',
        'backupMembers': 'backup_members',
        'portBlockAllocation': 'port_block_allocation',
        'translationPortRange': 'translation_port_range',
        'egressInterfacesEnabled': 'egress_interfaces_enabled',
        'egressInterfacesDisabled': 'egress_interfaces_disabled',
        'logProfile': 'log_profile',
        'logPublisher': 'log_publisher',
    }

    api_attributes = [
        'clientConnectionLimit',
        'egressInterfacesEnabled',
        'egressInterfacesDisabled',
        'hairpinMode',
        'icmpEcho',
        'inboundConnections',
        'mode',
        'persistence',
        'portBlockAllocation',
        'routeAdvertisement',
        'translationPortRange',
        'egressInterfaces',
        'members',
        'backupMembers',
        'logProfile',
        'logPublisher',
        'description',
    ]

    returnables = [
        'client_conn_limit',
        'harpin_mode',
        'icmp_echo',
        'inbound_connections',
        'mode',
        'persistence_mode',
        'persistence_timeout',
        'route_advertisement',
        'pba_block_idle_timeout',
        'pba_block_lifetime',
        'pba_block_size',
        'pba_client_block_limit',
        'pba_zombie_timeout',
        'port_range_low',
        'port_range_high',
        'egress_intf_enabled',
        'egress_interfaces',
        'translation_port_range',
        'members',
        'backup_members',
        'log_profile',
        'log_publisher',
        'description',
    ]

    updatables = [
        'client_conn_limit',
        'harpin_mode',
        'icmp_echo',
        'inbound_connections',
        'mode',
        'persistence_mode',
        'persistence_timeout',
        'route_advertisement',
        'translation_port_range',
        'port_range_low',
        'port_range_high',
        'pba_block_idle_timeout',
        'pba_block_lifetime',
        'pba_block_size',
        'pba_client_block_limit',
        'pba_zombie_timeout',
        'egress_intf_enabled',
        'egress_interfaces',
        'members',
        'backup_members',
        'log_profile',
        'log_publisher',
        'description',
    ]


class ApiParameters(Parameters):
    @property
    def pba_block_idle_timeout(self):
        if self._values['port_block_allocation'] is None:
            return None
        return self._values['port_block_allocation']['blockIdleTimeout']

    @property
    def pba_block_lifetime(self):
        if self._values['port_block_allocation'] is None:
            return None
        return self._values['port_block_allocation']['blockLifetime']

    @property
    def pba_block_size(self):
        if self._values['port_block_allocation'] is None:
            return None
        return self._values['port_block_allocation']['blockSize']

    @property
    def pba_client_block_limit(self):
        if self._values['port_block_allocation'] is None:
            return None
        return self._values['port_block_allocation']['clientBlockLimit']

    @property
    def pba_zombie_timeout(self):
        if self._values['port_block_allocation'] is None:
            return None
        return self._values['port_block_allocation']['zombieTimeout']

    @property
    def port_range_low(self):
        if self._values['translation_port_range'] is None:
            return None
        return int(self._values['translation_port_range'].split('-')[0])

    @property
    def port_range_high(self):
        if self._values['translation_port_range'] is None:
            return None
        return int(self._values['translation_port_range'].split('-')[1])

    @property
    def egress_intf_enabled(self):
        if self._values['egress_interfaces_enabled'] is None and self._values['egress_interfaces_disabled'] is True:
            return 'no'
        if self._values['egress_interfaces_disabled'] is None and self._values['egress_interfaces_enabled'] is True:
            return 'yes'

    @property
    def persistence_mode(self):
        if self._values['persistence'] is None:
            return None
        return self._values['persistence']['mode']

    @property
    def persistence_timeout(self):
        if self._values['persistence'] is None:
            return None
        return self._values['persistence']['timeout']


class ModuleParameters(Parameters):
    @property
    def client_conn_limit(self):
        if self._values['client_conn_limit'] is None:
            return None
        if 0 <= self._values['client_conn_limit'] <= 4294967295:
            return self._values['client_conn_limit']
        raise F5ModuleError(
            "Valid 'client_conn_limit' must be in range 0 - 4294967295."
        )

    @property
    def harpin_mode(self):
        result = flatten_boolean(self._values['harpin_mode'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def icmp_echo(self):
        result = flatten_boolean(self._values['icmp_echo'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def persistence_timeout(self):
        if self._values['persistence_timeout'] is None:
            return None
        if 0 <= self._values['persistence_timeout'] <= 31536000:
            return self._values['persistence_timeout']
        raise F5ModuleError(
            "Valid 'persistence_timeout' must be in range 0 - 31536000."
        )

    @property
    def route_advertisement(self):
        result = flatten_boolean(self._values['route_advertisement'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def pba_block_idle_timeout(self):
        if self._values['pba_block_idle_timeout'] is None:
            return None
        if 0 <= self._values['pba_block_idle_timeout'] <= 4294967295:
            return self._values['pba_block_idle_timeout']
        raise F5ModuleError(
            "Valid 'pba_block_idle_timeout' must be in range 0 - 4294967295."
        )

    @property
    def pba_block_lifetime(self):
        if self._values['pba_block_lifetime'] is None:
            return None
        if 0 <= self._values['pba_block_lifetime'] <= 4294967295:
            return self._values['pba_block_lifetime']
        raise F5ModuleError(
            "Valid 'pba_block_lifetime' must be in range 0 - 4294967295."
        )

    @property
    def pba_block_size(self):
        if self._values['pba_block_size'] is None:
            return None
        if 0 <= self._values['pba_block_size'] <= 65535:
            return self._values['pba_block_size']
        raise F5ModuleError(
            "Valid 'pba_block_size' must be in range 0 - 65535."
        )

    @property
    def pba_client_block_limit(self):
        if self._values['pba_client_block_limit'] is None:
            return None
        if 0 <= self._values['pba_client_block_limit'] <= 65535:
            return self._values['pba_client_block_limit']
        raise F5ModuleError(
            "Valid 'pba_client_block_limit' must be in range 0 - 65535."
        )

    @property
    def pba_zombie_timeout(self):
        if self._values['pba_zombie_timeout'] is None:
            return None
        if 0 <= self._values['pba_zombie_timeout'] <= 4294967295:
            return self._values['pba_zombie_timeout']
        raise F5ModuleError(
            "Valid 'pba_zombie_timeout' must be in range 0 - 4294967295."
        )

    @property
    def port_range_low(self):
        if self._values['port_range_low'] is None:
            return None
        high = self.port_range_high
        if 0 <= self._values['port_range_low'] <= 65535:
            if high:
                if high < self._values['port_range_low']:
                    raise F5ModuleError(
                        "The 'port_range_low' value: {0} is lower than 'port_range_high' value: {1}".format(
                            self._values['port_range_low'], high)
                    )
            return self._values['port_range_low']
        raise F5ModuleError(
            "Valid 'port_range_low' must be in range 0 - 65535."
        )

    @property
    def translation_port_range(self):
        if self._values['port_range_low'] is None:
            return None
        result = '{0}-{1}'.format(self.port_range_low, self.port_range_high)
        return result

    @property
    def port_range_high(self):
        if self._values['port_range_high'] is None:
            return None
        if 0 <= self._values['port_range_high'] <= 65535:
            return self._values['port_range_high']
        raise F5ModuleError(
            "Valid 'port_range_high' must be in range 0 - 65535."
        )

    @property
    def egress_intf_enabled(self):
        result = flatten_boolean(self._values['egress_intf_enabled'])
        return result

    @property
    def egress_interfaces(self):
        if self._values['egress_interfaces'] is None:
            return None
        if is_empty_list(self._values['egress_interfaces']):
            return ''
        result = []
        for interface in self._values['egress_interfaces']:
            result.append(fq_name(self.partition, interface))
        return result

    @property
    def log_profile(self):
        if self._values['log_profile'] is None:
            return None
        if self._values['log_profile'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['log_profile'])
        return result

    @property
    def log_publisher(self):
        if self._values['log_publisher'] is None:
            return None
        if self._values['log_publisher'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['log_publisher'])
        return result

    @property
    def members(self):
        if self._values['members'] is None:
            return None
        if is_empty_list(self._values['members']):
            return ''
        return self._values['members']

    @property
    def backup_members(self):
        if self._values['backup_members'] is None:
            return None
        if is_empty_list(self._values['backup_members']):
            return ''
        return self._values['backup_members']


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    @property
    def persistence(self):
        to_filter = dict(
            mode=self._values['persistence_mode'],
            timeout=self._values['persistence_timeout'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def port_block_allocation(self):
        to_filter = dict(
            blockIdleTimeout=self._values['pba_block_idle_timeout'],
            blockLifetime=self._values['pba_block_lifetime'],
            blockSize=self._values['pba_block_size'],
            clientBlockLimit=self._values['pba_client_block_limit'],
            zombieTimeout=self._values['pba_zombie_timeout'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def egress_interfaces_enabled(self):
        if self._values['egress_intf_enabled'] is None:
            return None
        if self._values['egress_intf_enabled'] == 'yes':
            return True

    @property
    def egress_interfaces_disabled(self):
        if self._values['egress_intf_enabled'] is None:
            return None
        if self._values['egress_intf_enabled'] == 'no':
            return True


class ReportableChanges(Changes):
    returnables = [
        'client_conn_limit',
        'harpin_mode',
        'icmp_echo',
        'inbound_connections',
        'mode',
        'persistence_mode',
        'persistence_timeout',
        'route_advertisement',
        'pba_block_idle_timeout',
        'pba_block_lifetime',
        'pba_block_size',
        'pba_client_block_limit',
        'pba_zombie_timeout',
        'port_range_low',
        'port_range_high',
        'egress_intf_enabled',
        'egress_interfaces',
        'members',
        'backup_members',
        'log_profile',
        'log_publisher',
        'description',
    ]

    @property
    def route_advertisement(self):
        result = flatten_boolean(self._values['route_advertisement'])
        return result

    @property
    def icmp_echo(self):
        result = flatten_boolean(self._values['icmp_echo'])
        return result

    @property
    def harpin_mode(self):
        result = flatten_boolean(self._values['harpin_mode'])
        return result


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def translation_port_range(self):
        if self.want.port_range_low is None:
            return None
        if self.want.port_range_low != self.have.port_range_low:
            result = "{0}-{1}".format(self.want.port_range_low, self.want.port_range_high)
            return result
        if self.want.port_range_high != self.have.port_range_high:
            result = "{0}-{1}".format(self.want.port_range_low, self.want.port_range_high)
            return result
        return None

    @property
    def members(self):
        return cmp_simple_list(self.want.members, self.have.members)

    @property
    def backup_members(self):
        return cmp_simple_list(self.want.backup_members, self.have.backup_members)

    @property
    def egress_interfaces(self):
        return cmp_simple_list(self.want.egress_interfaces, self.have.egress_interfaces)

    @property
    def log_profile(self):
        if self.want.log_profile is None:
            return None
        if self.want.log_profile == '' and self.have.log_profile in [None, 'none']:
            return None
        if self.want.log_profile == '':
            if self.have.log_publisher not in [None, 'none'] and self.want.log_publisher is None:
                raise F5ModuleError(
                    "The log_profile cannot be removed if log_publisher is defined on device."
                )
        if self.want.log_profile != '':
            if self.want.log_publisher is None and self.have.log_publisher in [None, 'none']:
                raise F5ModuleError(
                    "The log_profile cannot be specified without an existing valid log_publisher."
                )
        if self.want.log_profile != self.have.log_profile:
            return self.want.log_profile

    @property
    def log_publisher(self):
        if self.want.log_publisher is None:
            return None
        if self.want.log_publisher == '' and self.have.log_publisher in [None, 'none']:
            return None
        if self.want.log_publisher == '':
            if self.want.log_profile is None and self.have.log_profile not in [None, 'none']:
                raise F5ModuleError(
                    "The log_publisher cannot be removed if log_profile is defined on device."
                )
        if self.want.log_publisher != self.have.log_publisher:
            return self.want.log_publisher

    @property
    def description(self):
        if self.want.description is None:
            return None
        if self.have.description in [None, 'none'] and self.want.description == '':
            return None
        if self.want.description != self.have.description:
            return self.want.description


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        self.check_create_dependencies()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def check_create_dependencies(self):
        if self.want.log_publisher is None:
            if self.want.log_profile is not None:
                raise F5ModuleError(
                    "The 'log_profile' cannot be used without a defined 'log_publisher'."
                )

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/ltm/lsn-pool/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 404 or 'code' in response and response['code'] == 404:
            return False
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/ltm/lsn-pool/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/lsn-pool/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/lsn-pool/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/lsn-pool/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            description=dict(),
            client_conn_limit=dict(type='int'),
            harpin_mode=dict(type='bool'),
            icmp_echo=dict(type='bool'),
            inbound_connections=dict(choices=['disabled', 'explicit', 'automatic']),
            mode=dict(choices=['deterministic', 'pba', 'napt']),
            persistence_mode=dict(choices=['address', 'address-port', 'none']),
            persistence_timeout=dict(type='int'),
            route_advertisement=dict(type='bool'),
            pba_block_idle_timeout=dict(type='int'),
            pba_block_lifetime=dict(type='int'),
            pba_block_size=dict(type='int'),
            pba_client_block_limit=dict(type='int'),
            pba_zombie_timeout=dict(type='int'),
            port_range_low=dict(type='int'),
            port_range_high=dict(type='int'),
            egress_intf_enabled=dict(type='bool'),
            egress_interfaces=dict(
                type='list',
                elements='str',
            ),
            members=dict(
                type='list',
                elements='str',
            ),
            backup_members=dict(
                type='list',
                elements='str',
            ),
            log_profile=dict(),
            log_publisher=dict(),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            )
        )
        self.required_together = [
            ['port_range_low', 'port_range_high']
        ]
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_together=spec.required_together,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
