#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_apm_network_access
short_description: Manage APM Network Access resource
description:
  - Manage APM Network Access resource.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the APM network access to manage/create.
    type: str
    required: True
  description:
    description:
      - User created network access description.
    type: str
  ip_version:
    description:
      - Supported IP version on the network access resource.
    type: str
    choices:
      - ipv4
      - ipv4-ipv6
  allow_local_subnet:
    description:
      - Enables local subnet access and local access to any host or subnet in routes specified in the client routing
        table.
      - When C(true) the system does not support integrated IP filtering.
    type: bool
  allow_local_dns:
    description:
      - Enables local access to DNS servers configured on the client prior to establishing a network access connection.
    type: bool
  split_tunnel:
    description:
      - Specifies that only the traffic targeted to a specified address space is sent over the network access tunnel.
    type: bool
  snat_pool:
    description:
      - Specifies the name of a SNAT pool used for implementing selective and intelligent SNATs.
      - When C(none) the system uses no SNAT pool for this network resource.
      - When C(automap) the system uses all of the self IP addresses as the translation addresses for the pool.
    type: str
  dtls:
    description:
      - When C(true) the network access connection uses Datagram Transport Level Security instead of TCP,
        to provide better throughput for high demand applications like VoIP or streaming video.
    type: bool
  dtls_port:
    description:
      - Specifies the port number the network access resource uses for secure UDP traffic with DTLS.
    type: int
  ipv4_lease_pool:
    description:
      - Specifies the IPV4 lease pool resource to use with network access.
      - Referencing a lease pool can be done in the full path format, for example C(/Common/pool_name).
      - When a lease pool is referenced in full path format, the C(partition) parameter is ignored.
    type: str
  ipv6_lease_pool:
    description:
      - Specifies the IPV6 lease pool resource to use with network access.
      - Referencing a lease pool can be done in the full path format, for example C(/Common/pool_name).
      - When a lease pool is referenced in full path format, the C(partition) parameter is ignored.
    type: str
  excluded_ipv6_adresses:
    description:
      - Specifies IPV6 address spaces for which traffic is not forced through the tunnel.
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
          - "The address of a subnet in CIDR format, e.g. C(2001:db8:abcd:8000::/52)"
          - Host addresses can be specified without the CIDR mask notation.
        type: str
  excluded_ipv4_adresses:
    description:
      - Specifies IPV4 address spaces for which traffic is not forced through the tunnel.
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
          - "The address of subnet in CIDR format, e.g. C(192.168.1.0/24)"
          - Host addresses can be specified without the CIDR mask notation.
        type: str
  excluded_dns_addresses:
    description:
      - Specifies the DNS address spaces for which traffic is not forced through the tunnel.
    type: list
    elements: str
  dns_address_space:
    description:
      - Specifies a list of domain names describing the target LAN DNS addresses.
    type: list
    elements: str
  ipv4_address_space:
    description:
      - Specifies a list of IPv4 hosts or networks describing the target LAN.
      - This option is mandatory when creating a new resource and C(split_tunnel) is set to C(true).
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
          - "The address of subnet in CIDR format, e.g. C(192.168.1.0/24)"
          - Host addresses can be specified without the CIDR mask notation.
        type: str
  ipv6_address_space:
    description:
      - Specifies a list of IPv6 hosts or networks describing the target LAN.
      - This option is mandatory when creating a new resource and C(split_tunnel) is set to C(true).
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
          - "The address of subnet in CIDR format, e.g. C(2001:db8:abcd:8000::/52)"
          - Host addresses can be specified without the CIDR mask notation.
        type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(state) is C(present), ensures the ACL exists.
      - When C(state) is C(absent), ensures the ACL is removed.
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create a split tunnel IPV4 Network Access
  bigip_apm_network_access:
    name: foobar
    ip_version: ipv4
    split_tunnel: true
    snat_pool: "none"
    ipv4_lease_pool: leasefoo
    ipv4_address_space:
      - subnet: 10.10.1.1
      - subnet: 10.10.2.0/24
    excluded_ipv4_adresses:
      - subnet: 192.168.1.0/24
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Modify a split tunnel IPV4 Network Access
  bigip_apm_network_access:
    name: foobar
    snat_pool: /Common/poolsnat
    ipv4_address_space:
      - subnet: 172.16.23.0/24
    excluded_ipv4_adresses:
      - subnet: 10.10.2.0/24
    allow_local_subnet: true
    allow_local_dns: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove Network Access
  bigip_apm_network_access:
    name: foobar
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
description:
  description: The new description of Network Access.
  returned: changed
  type: str
  sample: My Access
ip_version:
  description: Supported IP version on the network access resource.
  returned: changed
  type: str
  sample: ipv4-ipv6
allow_local_subnet:
  description: Enables local subnet access.
  returned: changed
  type: bool
  sample: true
allow_local_dns:
  description: Enables local access to DNS servers configured on the client.
  returned: changed
  type: bool
  sample: true
split_tunnel:
  description: Enables split tunnel on the network access resource.
  returned: changed
  type: bool
  sample: true
snat_pool:
  description: The name of a SNAT pool used by the network access resource.
  returned: changed
  type: str
  sample: /Common/my-pool
dtls:
  description: Enables use of DTLS by network access.
  returned: changed
  type: bool
  sample: false
dtls_port:
  description: Specifies the port number the network access resource uses for DTLS.
  returned: changed
  type: int
  sample: 4433
ipv4_lease_pool:
  description: Specifies a IPV4 lease pool resource to use with network access.
  returned: changed
  type: str
  sample: /Common/leasepoolv4
ipv6_lease_pool:
  description: Specifies a IPV6 lease pool resource to use with network access.
  returned: changed
  type: str
  sample: /Common/leasepoolv6
excluded_ipv6_adresses:
  description: Specifies IPV6 address spaces for which traffic is not forced through the tunnel.
  type: complex
  returned: changed
  contains:
    subnet:
      description: The host or network address.
      returned: changed
      type: str
      sample: "2001:DB8:ABCD:0012::0"
  sample: hash/dictionary of values
excluded_ipv4_adresses:
  description: Specifies IPV4 address spaces for which traffic is not forced through the tunnel.
  type: complex
  returned: changed
  contains:
    subnet:
      description: The host or network address.
      returned: changed
      type: str
      sample: 192.168.10.1
  sample: hash/dictionary of values
excluded_dns_addresses:
  description: Specifies the DNS address spaces for which traffic is not forced through the tunnel.
  returned: changed
  type: list
  sample: ['foobar.com', 'bazbar.org']
dns_address_space:
  description: Specifies a list of domain names describing the target LAN DNS addresses.
  returned: changed
  type: list
  sample: ['internal.net', '*.engnet.org']
ipv6_address_space:
  description: Specifies a list of IPv6 hosts or networks describing the target LAN.
  type: complex
  returned: changed
  contains:
    subnet:
      description: The host or network address.
      returned: changed
      type: str
      sample: "2001:DB8:ABCD:0012::0"
  sample: hash/dictionary of values
ipv4_address_space:
  description: Specifies a list of IPv4 hosts or networks describing the target LAN.
  type: complex
  returned: changed
  contains:
    subnet:
      description: The host or network address.
      returned: changed
      type: str
      sample: 192.168.10.1
  sample: hash/dictionary of values
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, is_empty_list, fq_name
)
from ..module_utils.compare import (
    cmp_str_with_none, cmp_simple_list, compare_complex_list
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version
)
from ..module_utils.ipaddress import ip_network
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'supportedIpVersion': 'ip_version',
        'splitTunneling': 'split_tunnel',
        'addressSpaceLocalSubnetsExcluded': 'allow_local_subnet',
        'addressSpaceLocDnsServersExcluded': 'allow_local_dns',
        'dtlsPort': 'dtls_port',
        'leasepoolName': 'ipv4_lease_pool',
        'ipv6LeasepoolName': 'ipv6_lease_pool',
        'ipv6AddressSpaceExcludeSubnet': 'excluded_ipv6_adresses',
        'addressSpaceExcludeSubnet': 'excluded_ipv4_adresses',
        'addressSpaceExcludeDnsName': 'excluded_dns_addresses',
        'addressSpaceIncludeDnsName': 'dns_address_space',
        'addressSpaceIncludeSubnet': 'ipv4_address_space',
        'ipv6AddressSpaceIncludeSubnet': 'ipv6_address_space',
        'snatpool': 'snat_pool',
    }

    api_attributes = [
        'supportedIpVersion',
        'splitTunneling',
        'addressSpaceLocalSubnetsExcluded',
        'addressSpaceLocDnsServersExcluded',
        'dtlsPort',
        'leasepoolName',
        'ipv6LeasepoolName',
        'ipv6AddressSpaceExcludeSubnet',
        'addressSpaceExcludeSubnet',
        'addressSpaceExcludeDnsName',
        'addressSpaceIncludeSubnet',
        'ipv6AddressSpaceIncludeSubnet',
        'addressSpaceIncludeDnsName',
        'snat',
        'snatpool',
        'dtls',
        'description',
    ]

    returnables = [
        'description',
        'ip_version',
        'split_tunnel',
        'allow_local_subnet',
        'allow_local_dns',
        'snat_pool',
        'dtls',
        'dtls_port',
        'ipv4_lease_pool',
        'ipv6_lease_pool',
        'excluded_ipv6_adresses',
        'excluded_ipv4_adresses',
        'excluded_dns_addresses',
        'dns_address_space',
        'ipv4_address_space',
        'ipv6_address_space',
    ]

    updatables = [
        'description',
        'ip_version',
        'split_tunnel',
        'allow_local_subnet',
        'allow_local_dns',
        'snat_pool',
        'dtls',
        'dtls_port',
        'ipv4_lease_pool',
        'ipv6_lease_pool',
        'excluded_ipv6_adresses',
        'excluded_ipv4_adresses',
        'excluded_dns_addresses',
        'dns_address_space',
        'ipv4_address_space',
        'ipv6_address_space',
    ]


class ApiParameters(Parameters):
    @property
    def snat_pool(self):
        if self._values['snat'] is None and self._values['snat_pool'] is None:
            return None
        if self._values['snat'] in ['automap', 'none']:
            return self._values['snat']
        return self._values['snat_pool']


class ModuleParameters(Parameters):
    def _handle_booleans(self, item):
        result = flatten_boolean(item)
        if result == 'yes':
            return 'true'
        if result == 'no':
            return 'false'
        return None

    def _convert_address(self, item):
        ip = ip_network(u'{0}'.format(item))
        return ip.with_prefixlen

    def _format_subnets(self, items):
        result = []
        for x in items:
            to_change = dict()
            to_change['subnet'] = self._convert_address(x['subnet'])
            result.append(to_change)
        return result

    @property
    def description(self):
        if self._values['description'] is None:
            return None
        if self._values['description'] in ['none', '']:
            return ''
        return self._values['description']

    @property
    def split_tunnel(self):
        return self._handle_booleans(self._values['split_tunnel'])

    @property
    def allow_local_subnet(self):
        return self._handle_booleans(self._values['allow_local_subnet'])

    @property
    def allow_local_dns(self):
        return self._handle_booleans(self._values['allow_local_dns'])

    @property
    def dtls(self):
        return self._handle_booleans(self._values['dtls'])

    @property
    def dtls_port(self):
        if self._values['dtls_port'] is None:
            return None
        if 0 < self._values['dtls_port'] > 65535:
            raise F5ModuleError(
                "Specified port number is out of valid range, correct range is between 0 and 65535."
            )
        return self._values['dtls_port']

    @property
    def ipv4_lease_pool(self):
        if self._values['ipv4_lease_pool'] is None:
            return None
        if self._values['ipv4_lease_pool'] in ['none', '']:
            return ''
        return fq_name(self.partition, self._values['ipv4_lease_pool'])

    @property
    def ipv6_lease_pool(self):
        if self._values['ipv6_lease_pool'] is None:
            return None
        if self._values['ipv6_lease_pool'] in ['none', '']:
            return ''
        return fq_name(self.partition, self._values['ipv6_lease_pool'])

    @property
    def excluded_ipv6_adresses(self):
        if self._values['excluded_ipv6_adresses'] is None:
            return None
        if is_empty_list(self._values['excluded_ipv6_adresses']):
            return []
        result = self._format_subnets(self._values['excluded_ipv6_adresses'])
        return result

    @property
    def excluded_ipv4_adresses(self):
        if self._values['excluded_ipv4_adresses'] is None:
            return None
        if is_empty_list(self._values['excluded_ipv4_adresses']):
            return []
        result = self._format_subnets(self._values['excluded_ipv4_adresses'])
        return result

    @property
    def ipv4_address_space(self):
        if self._values['ipv4_address_space'] is None:
            return None
        if is_empty_list(self._values['ipv4_address_space']):
            return []
        result = self._format_subnets(self._values['ipv4_address_space'])
        return result

    @property
    def ipv6_address_space(self):
        if self._values['ipv6_address_space'] is None:
            return None
        if is_empty_list(self._values['ipv6_address_space']):
            return []
        result = self._format_subnets(self._values['ipv6_address_space'])
        return result

    @property
    def dns_address_space(self):
        if self._values['dns_address_space'] is None:
            return None
        if is_empty_list(self._values['dns_address_space']):
            return []
        return self._values['dns_address_space']

    @property
    def excluded_dns_addresses(self):
        if self._values['excluded_dns_addresses'] is None:
            return None
        if is_empty_list(self._values['excluded_dns_addresses']):
            return []
        return self._values['excluded_dns_addresses']

    @property
    def snat_pool(self):
        if self._values['snat_pool'] is None:
            return None
        if self._values['snat_pool'] in ['automap', 'none']:
            return self._values['snat_pool']
        result = fq_name(self.partition, self._values['snat_pool'])
        return result


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
    def snat(self):
        if self._values['snat_pool'] is None:
            return None
        if self._values['snat_pool'] in ['automap', 'none']:
            return self._values['snat_pool']

    @property
    def snat_pool(self):
        if self._values['snat_pool'] in [None, 'automap', 'none']:
            return None
        return self._values['snat_pool']


class ReportableChanges(Changes):
    def _parse_hosts(self, item):
        ip = ip_network(u'{0}'.format(item))
        if ip.prefixlen in [32, 128]:
            result = item.split('/')[0]
            return result
        return item

    def _format_subnets(self, items):
        result = []
        for x in items:
            to_change = dict()
            to_change['subnet'] = self._parse_hosts(x['subnet'])
            result.append(to_change)
        return result

    @property
    def split_tunnel(self):
        return flatten_boolean(self._values['split_tunnel'])

    @property
    def allow_local_subnet(self):
        return flatten_boolean(self._values['allow_local_subnet'])

    @property
    def allow_local_dns(self):
        return flatten_boolean(self._values['allow_local_dns'])

    @property
    def dtls(self):
        return flatten_boolean(self._values['dtls'])

    @property
    def excluded_ipv4_adresses(self):
        if self._values['excluded_ipv4_adresses'] is None:
            return None
        if not self._values['excluded_ipv4_adresses']:
            return []
        result = self._format_subnets(self._values['excluded_ipv4_adresses'])
        return result

    @property
    def excluded_ipv6_adresses(self):
        if self._values['excluded_ipv6_adresses'] is None:
            return None
        if not self._values['excluded_ipv6_adresses']:
            return []
        result = self._format_subnets(self._values['excluded_ipv6_adresses'])
        return result

    @property
    def ipv4_address_space(self):
        if self._values['ipv4_address_space'] is None:
            return None
        if not self._values['ipv4_address_space']:
            return []
        result = self._format_subnets(self._values['ipv4_address_space'])
        return result

    @property
    def ipv6_address_space(self):
        if self._values['ipv6_address_space'] is None:
            return None
        if not self._values['ipv6_address_space']:
            return []
        result = self._format_subnets(self._values['ipv6_address_space'])
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
    def description(self):
        result = cmp_str_with_none(self.want.description, self.have.description)
        return result

    @property
    def ipv4_lease_pool(self):
        result = cmp_str_with_none(self.want.ipv4_lease_pool, self.have.ipv4_lease_pool)
        return result

    @property
    def ipv6_lease_pool(self):
        result = cmp_str_with_none(self.want.ipv6_lease_pool, self.have.ipv6_lease_pool)
        return result

    @property
    def excluded_dns_addresses(self):
        result = cmp_simple_list(self.want.excluded_dns_addresses, self.have.excluded_dns_addresses)
        return result

    @property
    def dns_address_space(self):
        result = cmp_simple_list(self.want.dns_address_space, self.have.dns_address_space)
        return result

    @property
    def excluded_ipv4_adresses(self):
        result = compare_complex_list(self.want.excluded_ipv4_adresses, self.have.excluded_ipv4_adresses)
        return result

    @property
    def excluded_ipv6_adresses(self):
        result = compare_complex_list(self.want.excluded_ipv6_adresses, self.have.excluded_ipv6_adresses)
        return result

    @property
    def ipv4_address_space(self):
        result = compare_complex_list(self.want.ipv4_address_space, self.have.ipv4_address_space)
        return result

    @property
    def ipv6_address_space(self):
        result = compare_complex_list(self.want.ipv6_address_space, self.have.ipv6_address_space)
        return result


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
        if not module_provisioned(self.client, 'apm'):
            raise F5ModuleError(
                "APM must be provisioned to use this module."
            )
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
        self.check_required_params()
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
        self.check_required_params()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def check_required_params(self):
        if self.want.split_tunnel == 'true':
            if self.want.ip_version == 'ipv4':
                if self.want.ipv4_address_space in [None, []]:
                    raise F5ModuleError(
                        'The ipv4_address_space cannot be empty, when split_tunnel is set to {0}'.format(
                            self.want.split_tunnel
                        )
                    )
            if self.want.ip_version == 'ipv4-ipv6':
                if self.want.ipv4_address_space in [None, []]:
                    raise F5ModuleError(
                        'The ipv4_address_space cannot be empty, when split_tunnel is set to {0}'.format(
                            self.want.split_tunnel
                        )
                    )
                if self.want.ipv6_address_space in [None, []]:
                    raise F5ModuleError(
                        'The ipv6_address_space cannot be empty, when split_tunnel is set to {0}'.format(
                            self.want.split_tunnel
                        )
                    )
        if self.have.split_tunnel == 'true':
            if self.have.ip_version == 'ipv4':
                if self.want.ipv4_address_space is not None and not self.want.ipv4_address_space:
                    raise F5ModuleError(
                        'Cannot remove ipv4_address_space when split_tunnel on device is: {0}'.format(
                            self.have.split_tunnel
                        )
                    )
            if self.have.ip_version == 'ipv4-ipv6':
                if self.want.ipv4_address_space is not None and not self.want.ipv4_address_space:
                    raise F5ModuleError(
                        'Cannot remove ipv4_address_space when split_tunnel on device is: {0}'.format(
                            self.have.split_tunnel
                        )
                    )
                if self.want.ipv6_address_space is not None and not self.want.ipv6_address_space:
                    raise F5ModuleError(
                        'Cannot remove ipv6_address_space when split_tunnel on device is: {0}'.format(
                            self.have.split_tunnel
                        )
                    )

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/apm/resource/network-access/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/apm/resource/network-access/".format(
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
        uri = "https://{0}:{1}/mgmt/tm/apm/resource/network-access/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/apm/resource/network-access/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/apm/resource/network-access/{2}".format(
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
            ip_version=dict(
                choices=['ipv4', 'ipv4-ipv6']
            ),
            split_tunnel=dict(
                type='bool',
            ),
            allow_local_subnet=dict(type='bool'),
            allow_local_dns=dict(type='bool'),
            snat_pool=dict(),
            description=dict(),
            dtls=dict(type='bool'),
            dtls_port=dict(type='int'),
            ipv4_lease_pool=dict(),
            ipv6_lease_pool=dict(),
            excluded_ipv6_adresses=dict(
                type='list',
                elements='dict',
                options=dict(
                    subnet=dict(),
                )
            ),
            excluded_ipv4_adresses=dict(
                type='list',
                elements='dict',
                options=dict(
                    subnet=dict(),
                )
            ),
            excluded_dns_addresses=dict(
                type='list',
                elements='str',
            ),
            dns_address_space=dict(
                type='list',
                elements='str',
            ),
            ipv4_address_space=dict(
                type='list',
                elements='dict',
                options=dict(
                    subnet=dict(),
                )
            ),
            ipv6_address_space=dict(
                type='list',
                elements='dict',
                options=dict(
                    subnet=dict(),
                )
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
