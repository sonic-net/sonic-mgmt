#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_traffic_selector
short_description: Manage IPSec Traffic Selectors on BIG-IP
description:
  - Manage IPSec Traffic Selectors on BIG-IP.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the traffic selector.
    type: str
    required: True
  destination_address:
    description:
      - Specifies the host or network IP address to which the application traffic is destined.
      - When creating a new traffic selector, this parameter is required.
    type: str
  source_address:
    description:
      - Specifies the host or network IP address from which the application traffic originates.
      - When creating a new traffic selector, this parameter is required.
    type: str
  ipsec_policy:
    description:
      - Specifies the IPsec policy that tells the BIG-IP system how to handle the packets.
      - When creating a new traffic selector, if this parameter is not specified, the default
        is C(default-ipsec-policy).
    type: str
  order:
    description:
      - Specifies the order in which traffic is matched, if traffic can be matched to multiple
        traffic selectors.
      - Traffic is matched to the traffic selector with the highest priority (lowest order number).
      - When creating a new traffic selector, if this parameter is not specified, the default
        is C(last).
    type: int
  description:
    description:
      - Description of the traffic selector.
    type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the resource exists.
      - When C(absent), ensures the resource is removed.
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create a traffic selector
  bigip_traffic_selector:
    name: selector1
    destination_address: 1.1.1.1
    ipsec_policy: policy1
    order: 1
    source_address: 2.2.2.2
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
destination_address:
  description: The new Destination IP Address.
  returned: changed
  type: str
  sample: 1.2.3.4/32
source_address:
  description: The new Source IP address.
  returned: changed
  type: str
  sample: 2.3.4.5/32
ipsec_policy:
  description: The new IPSec policy.
  returned: changed
  type: str
  sample: /Common/policy1
order:
  description: The new sort order.
  returned: changed
  type: int
  sample: 1
'''

import re
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ipaddress import ip_interface

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, fq_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'destinationAddress': 'destination_address',
        'sourceAddress': 'source_address',
        'ipsecPolicy': 'ipsec_policy',
    }

    api_attributes = [
        'destinationAddress',
        'sourceAddress',
        'ipsecPolicy',
        'order',
        'description',
    ]

    returnables = [
        'destination_address',
        'source_address',
        'ipsec_policy',
        'order',
        'description',
    ]

    updatables = [
        'destination_address',
        'source_address',
        'ipsec_policy',
        'order',
        'description',
    ]


class ApiParameters(Parameters):
    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']


class ModuleParameters(Parameters):
    @property
    def ipsec_policy(self):
        if self._values['ipsec_policy'] is None:
            return None
        return fq_name(self.partition, self._values['ipsec_policy'])

    @property
    def destination_address(self):
        result = self._format_address('destination_address')
        if result == -1:
            raise F5ModuleError(
                "No IP address found in 'destination_address'."
            )
        return result

    @property
    def source_address(self):
        result = self._format_address('source_address')
        if result == -1:
            raise F5ModuleError(
                "No IP address found in 'source_address'."
            )
        return result

    @property
    def description(self):
        if self._values['description'] is None:
            return None
        elif self._values['description'] in ['none', '']:
            return ''
        return self._values['description']

    def _format_address(self, type):
        if self._values[type] is None:
            return None
        pattern = r'(?P<addr>[^%/]+)(%(?P<rd>\d+))?(/(?P<cidr>\d+))?'
        if '%' in self._values[type]:
            # Handle route domains
            matches = re.match(pattern, self._values[type])
            if not matches:
                return None
            addr = matches.group('addr')
            if addr is None:
                return -1
            cidr = matches.group('cidr')
            rd = matches.group('rd')
            if cidr is not None:
                ip = ip_interface(u'{0}/{1}'.format(addr, cidr))
            else:
                ip = ip_interface(u'{0}'.format(addr))
            if rd:
                result = '{0}%{1}/{2}'.format(str(ip.ip), rd, ip.network.prefixlen)
            else:
                result = '{0}/{1}'.format(str(ip.ip), ip.network.prefixlen)
            return result
        return str(ip_interface(u'{0}'.format(self._values[type])))


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            pass
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


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
        return cmp_str_with_none(self.want.description, self.have.description)


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

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

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

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/traffic-selector/{2}".format(
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
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/traffic-selector/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/traffic-selector/{2}".format(
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

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/traffic-selector/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/traffic-selector/{2}".format(
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


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            destination_address=dict(),
            source_address=dict(),
            ipsec_policy=dict(),
            order=dict(type='int'),
            description=dict(),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
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
