#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_virtual_address
short_description: Manage LTM virtual addresses on a BIG-IP
description:
  - Manage LTM virtual addresses on a BIG-IP system.
version_added: "1.0.0"
options:
  name:
    description:
      - Name of the virtual address.
      - If this parameter is not provided, the system uses the value of C(address).
    type: str
  address:
    description:
      - Specifies the virtual address. This value cannot be modified after it is set.
      - If you never created a virtual address, but did create virtual servers,
        a virtual address for each virtual server was created automatically. The name
        of this virtual address is its IP address value.
    type: str
  netmask:
    description:
      - Specifies the netmask of the provided virtual address. This value cannot be
        modified after it is set.
      - When creating a new virtual address, if this parameter is not specified, the
        default value is C(255.255.255.255) for IPv4 addresses and
        C(ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) for IPv6 addresses.
    type: str
  connection_limit:
    description:
      - Specifies the number of concurrent connections the system
        allows on this virtual address.
    type: int
  arp:
    description:
      - Specifies whether the system accepts ARP requests.
      - When C(false), specifies the system does not accept ARP requests.
      - When C(true), the packets are dropped.
      - Both ARP and ICMP Echo must be disabled in order for forwarding
        virtual servers using that virtual address to forward ICMP packets.
      - When creating a new virtual address, if this parameter is not specified,
        the default value is C(true).
    type: bool
  auto_delete:
    description:
      - Specifies whether the system automatically deletes the virtual
        address with the deletion of the last associated virtual server.
        When C(false), specifies the system leaves the virtual
        address, even when all associated virtual servers have been deleted.
        When creating the virtual address, the default value is C(true).
    type: bool
  icmp_echo:
    description:
      - Specifies how the system sends responses to (ICMP) echo requests
        on a per-virtual address basis for enabling route advertisement.
        When C(enabled), the BIG-IP system intercepts ICMP echo request
        packets and responds to them directly. When C(disabled), the BIG-IP
        system passes ICMP echo requests through to the backend servers.
        When (selective), causes the BIG-IP system to internally enable or
        disable responses based on virtual server state; C(when_any_available),
        C(when_all_available, or C(always), regardless of the state of any
        virtual servers.
    type: str
    choices:
      - enabled
      - disabled
      - selective
  state:
    description:
      - The virtual address state. If C(absent), the system makes an attempt
        to delete the virtual address. This will only succeed if this
        virtual address is not in use by a virtual server. C(present) creates
        the virtual address and enables it. If C(enabled), enables the virtual
        address if it exists. If C(disabled), creates the virtual address if
        needed, and sets the state to C(disabled).
    type: str
    choices:
      - present
      - absent
      - enabled
      - disabled
    default: present
  availability_calculation:
    description:
      - Specifies which routes of the virtual address the system advertises.
        When C(when_any_available), advertises the route when any virtual
        server is available. When C(when_all_available), advertises the
        route when all virtual servers are available. When (always), always
        advertises the route regardless of the virtual servers available.
    type: str
    choices:
      - always
      - when_all_available
      - when_any_available
    aliases: ['advertise_route']
  route_advertisement:
    description:
      - Specifies whether the system uses route advertisement for this
        virtual address.
      - When disabled, the system does not advertise routes for this virtual address.
      - The majority of these options are only supported on versions 13.0.0-HF1 or
        later. On versions prior than this, all choices expect C(disabled)
        translate to C(enabled).
      - When C(always), the BIG-IP system always advertises the route for the
        virtual address, regardless of availability status. This requires an C(enabled)
        virtual address.
      - When C(enabled), the BIG-IP system advertises the route for the available
        virtual address, based on the calculation method in the availability calculation.
      - When C(disabled), the BIG-IP system does not advertise the route for the virtual
        address, regardless of the availability status.
      - When C(selective), you can also selectively enable ICMP echo responses, which
        causes the BIG-IP system to internally enable or disable responses based on
        virtual server state.
      - When C(any), the BIG-IP system advertises the route for the virtual address
        when any virtual server is available.
      - When C(all), the BIG-IP system advertises the route for the virtual address
        when all virtual servers are available.
    type: str
    choices:
      - disabled
      - enabled
      - always
      - selective
      - any
      - all
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  traffic_group:
    description:
      - The traffic group for the virtual address. When creating a new address,
        if this value is not specified, the default is C(/Common/traffic-group-1).
    type: str
  route_domain:
    description:
      - The route domain of the C(address) you want to use.
      - This value cannot be modified after it is set.
    type: str
  spanning:
    description:
      - Enables all BIG-IP systems in a device group to listen for and process traffic
        on the same virtual address.
      - Spanning for a virtual address occurs when you enable the C(spanning) option on a
        device, and then sync the virtual address to the other members of the device group.
      - Spanning also relies on the upstream router to distribute application flows to the
        BIG-IP systems using ECMP routes. ECMP defines a route to the virtual address using
        distinct Floating self-IP addresses configured on each BIG-IP system.
      - You must also configure MAC masquerade addresses and disable C(arp) on the virtual
        address when Spanning is enabled.
      - When creating a new virtual address, if this parameter is not specified, the default
        valus is C(false).
    type: bool
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Add virtual address
  bigip_virtual_address:
    state: present
    partition: Common
    address: 10.10.10.10
    provider:
      server: lb.mydomain.net
      user: admin
      password: secret
  delegate_to: localhost

- name: Enable route advertisement on the virtual address
  bigip_virtual_address:
    state: present
    address: 10.10.10.10
    route_advertisement: any
    provider:
      server: lb.mydomain.net
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
availability_calculation:
  description: Specifies which routes of the virtual address the system advertises.
  returned: changed
  type: str
  sample: always
auto_delete:
  description: New setting for auto deleting virtual address.
  returned: changed
  type: bool
  sample: true
icmp_echo:
  description: New ICMP echo setting applied to virtual address.
  returned: changed
  type: str
  sample: disabled
connection_limit:
  description: The new connection limit of the virtual address.
  returned: changed
  type: int
  sample: 1000
netmask:
  description: The netmask of the virtual address.
  returned: created
  type: int
  sample: 2345
arp:
  description: The new way the virtual address handles ARP requests.
  returned: changed
  type: bool
  sample: true
address:
  description: The address of the virtual address.
  returned: created
  type: int
  sample: 2345
state:
  description: The new state of the virtual address.
  returned: changed
  type: str
  sample: disabled
spanning:
  description: Whether spanning is enabled or not.
  returned: changed
  type: str
  sample: disabled
'''
import traceback
from datetime import datetime

try:
    from packaging.version import Version
except ImportError:
    HAS_PACKAGING = False
    Version = None
    PACKAGING_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_PACKAGING = True
    PACKAGING_IMPORT_ERROR = None

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib, env_fallback
)
from ansible.module_utils.parsing.convert_bool import (
    BOOLEANS_TRUE, BOOLEANS_FALSE
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, fq_name, flatten_boolean
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.ipaddress import (
    is_valid_ip, compress_address
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'routeAdvertisement': 'route_advertisement_type',
        'autoDelete': 'auto_delete',
        'icmpEcho': 'icmp_echo',
        'connectionLimit': 'connection_limit',
        'serverScope': 'availability_calculation',
        'mask': 'netmask',
        'trafficGroup': 'traffic_group',
    }

    updatables = [
        'route_advertisement_type',
        'auto_delete',
        'icmp_echo',
        'connection_limit',
        'arp',
        'enabled',
        'availability_calculation',
        'traffic_group',
        'spanning',
    ]

    returnables = [
        'route_advertisement_type',
        'auto_delete',
        'icmp_echo',
        'connection_limit',
        'netmask',
        'arp',
        'address',
        'state',
        'traffic_group',
        'route_domain',
        'spanning',
        'availability_calculation',
    ]

    api_attributes = [
        'routeAdvertisement',
        'autoDelete',
        'icmpEcho',
        'connectionLimit',
        'advertiseRoute',
        'arp',
        'mask',
        'enabled',
        'serverScope',
        'trafficGroup',
        'spanning',
        'serverScope',
    ]

    @property
    def availability_calculation(self):
        if self._values['availability_calculation'] is None:
            return None
        elif self._values['availability_calculation'] in ['any', 'when_any_available']:
            return 'any'
        elif self._values['availability_calculation'] in ['all', 'when_all_available']:
            return 'all'
        elif self._values['availability_calculation'] in ['none', 'always']:
            return 'none'

    @property
    def connection_limit(self):
        if self._values['connection_limit'] is None:
            return None
        return int(self._values['connection_limit'])

    @property
    def enabled(self):
        if self._values['state'] in ['enabled', 'present']:
            return 'yes'
        elif self._values['enabled'] in BOOLEANS_TRUE:
            return 'yes'
        elif self._values['state'] == 'disabled':
            return 'no'
        elif self._values['enabled'] in BOOLEANS_FALSE:
            return 'no'
        else:
            return None

    @property
    def netmask(self):
        if self._values['netmask'] is None:
            return None
        if is_valid_ip(self._values['netmask']):
            return self._values['netmask']
        else:
            raise F5ModuleError(
                "The provided 'netmask' is not a valid IP address"
            )

    @property
    def auto_delete(self):
        result = flatten_boolean(self._values['auto_delete'])
        if result == 'yes':
            return 'true'
        if result == 'no':
            return 'false'

    @property
    def state(self):
        if self.enabled == 'yes' and self._values['state'] != 'present':
            return 'enabled'
        elif self.enabled == 'no':
            return 'disabled'
        else:
            return self._values['state']

    @property
    def traffic_group(self):
        if self._values['traffic_group'] is None:
            return None
        else:
            result = fq_name(self.partition, self._values['traffic_group'])
        if result.startswith('/Common/'):
            return result
        else:
            raise F5ModuleError(
                "Traffic groups can only exist in /Common"
            )

    @property
    def route_advertisement_type(self):
        if self.route_advertisement:
            return self.route_advertisement
        else:
            return self._values['route_advertisement_type']

    @property
    def route_advertisement(self):
        if self._values['route_advertisement'] is None:
            return None
        version = tmos_version(self.client)
        if Version(version) <= Version('13.0.0'):
            if self._values['route_advertisement'] == 'disabled':
                return 'disabled'
            else:
                return 'enabled'
        else:
            return self._values['route_advertisement']


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def address(self):
        if self._values['address'] is None:
            return None
        if is_valid_ip(self._values['address']):
            return compress_address(self._values['address'])
        else:
            raise F5ModuleError(
                "The provided 'address' is not a valid IP address"
            )

    @property
    def full_address(self):
        if self.route_domain is not None:
            return '{0}%{1}'.format(self.address, self.route_domain)
        return self.address

    @property
    def name(self):
        if self._values['name'] is None:
            result = str(self.address)
            if self.route_domain:
                result = "{0}%{1}".format(result, self.route_domain)
        else:
            result = self._values['name']
        return result

    @property
    def route_domain(self):
        if self._values['route_domain'] is None:
            return None
        try:
            return int(self._values['route_domain'])
        except ValueError:
            uri = "https://{0}:{1}/mgmt/tm/net/route-domain/{2}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self._values['partition'], self._values['route_domain'])
            )
            resp = self.client.api.get(uri)
            try:
                response = resp.json()
            except ValueError:
                raise F5ModuleError(
                    "The specified 'route_domain' was not found."
                )
            if resp.status == 404 or 'code' in response and response['code'] == 404:
                raise F5ModuleError(
                    "The specified 'route_domain' was not found."
                )

            return int(response['id'])

    @property
    def arp(self):
        result = flatten_boolean(self._values['arp'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def spanning(self):
        result = flatten_boolean(self._values['spanning'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'


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
    def address(self):
        if self._values['address'] is None:
            return None
        if self._values['route_domain'] is None:
            return self._values['address']
        result = "{0}%{1}".format(self._values['address'], self.route_domain)
        return result


class ReportableChanges(Changes):
    @property
    def arp(self):
        if self._values['arp'] == 'disabled':
            return 'no'
        elif self._values['arp'] == 'enabled':
            return 'yes'

    @property
    def spanning(self):
        if self._values['spanning'] == 'disabled':
            return 'no'
        elif self._values['spanning'] == 'enabled':
            return 'yes'


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
    def traffic_group(self):
        if self.want.traffic_group != self.have.traffic_group:
            return self.want.traffic_group

    @property
    def spanning(self):
        if self.want.spanning is None:
            return None
        if self.want.spanning != self.have.spanning:
            return self.want.spanning

    @property
    def arp(self):
        if self.want.arp is None:
            return None
        if self.want.arp != self.have.arp:
            return self.want.arp


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.have = ApiParameters()
        self.want = ModuleParameters(client=self.client, params=self.module.params)
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

        if state in ['present', 'enabled', 'disabled']:
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)

        if self.module._diff and self.have:
            result['diff'] = self.make_diff()

        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def _grab_attr(self, item):
        result = dict()
        updatables = Parameters.updatables
        for k in updatables:
            if getattr(item, k) is not None:
                result[k] = getattr(item, k)
        return result

    def make_diff(self):
        result = dict(before=self._grab_attr(self.have), after=self._grab_attr(self.want))
        return result

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        changed = False
        if self.exists():
            changed = self.remove()
        return changed

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the virtual address")
        return True

    def create(self):
        self._set_changed_options()

        if self.want.traffic_group is None:
            self.want.update({'traffic_group': '/Common/traffic-group-1'})
        if self.want.arp is None:
            self.want.update({'arp': True})
        if self.want.spanning is None:
            self.want.update({'spanning': False})

        if self.want.netmask is None:
            if is_valid_ip(self.want.address, type='ipv4'):
                self.want.update({'netmask': '255.255.255.255'})
            else:
                self.want.update({'netmask': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'})

        if self.want.arp == 'enabled' and self.want.spanning == 'enabled':
            raise F5ModuleError(
                "'arp' and 'spanning' cannot both be enabled on virtual address."
            )
        if self.module.check_mode:
            return True
        self.create_on_device()
        if self.exists():
            return True
        else:
            raise F5ModuleError("Failed to create the virtual address")

    def update(self):
        self.have = self.read_current_from_device()
        if self.want.netmask is not None:
            if self.have.netmask != self.want.netmask:
                raise F5ModuleError(
                    "The netmask cannot be changed. Delete and recreate "
                    "the virtual address if you need to do this."
                )
        if self.want.address is not None:
            if self.have.address != self.want.full_address:
                raise F5ModuleError(
                    "The address cannot be changed. Delete and recreate "
                    "the virtual address if you need to do this."
                )
        if self.changes.arp == 'enabled' and self.changes.spanning == 'enabled':
            raise F5ModuleError(
                "'arp' and 'spanning' cannot both be enabled on virtual address."
            )

        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual-address/{2}".format(
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

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual-address/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual-address/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        params['address'] = self.changes.address
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual-address/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403, 409]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        return response['selfLink']

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual-address/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent', 'disabled', 'enabled']
            ),
            name=dict(),
            address=dict(),
            netmask=dict(),
            connection_limit=dict(
                type='int'
            ),

            auto_delete=dict(
                type='bool'
            ),
            icmp_echo=dict(
                choices=['enabled', 'disabled', 'selective'],
            ),
            availability_calculation=dict(
                choices=['always', 'when_all_available', 'when_any_available'],
                aliases=['advertise_route']
            ),
            traffic_group=dict(),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            route_domain=dict(),
            spanning=dict(type='bool'),
            route_advertisement=dict(
                choices=[
                    'disabled',
                    'enabled',
                    'always',
                    'selective',
                    'any',
                    'all',
                ]
            ),
            arp=dict(type='bool'),
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.required_one_of = [
            ['name', 'address']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_one_of=spec.required_one_of
    )

    if not HAS_PACKAGING:
        module.fail_json(
            msg=missing_required_lib('packaging'),
            exception=PACKAGING_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
