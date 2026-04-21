#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_gtm_dns_listener
short_description: Configures the BIG-IP DNS system to answer TCP or UDP DNS requests
description:
  - Defines one or more Listener objects to control which protocols are available for the BIG-IP DNS system to process DNS requests.
  - BIG-IP DNS Listeners allow TCP and UDP protocols.
version_added: "1.4.0"
options:
  name:
    description:
      - Specifies the name of the DNS Listener.
    type: str
    required: True
  description:
    description:
      - Provides a brief description for DNS Listener.
    type: str
  address:
    description:
      - Specifies the IP address on which the system listens.
    type: str
    required: True
  mask:
    description:
      - Specifies the netmask for a network Listener only.
      - Netmask clarifies whether the host bit is an actual zero or a wildcard representation.
    type: str
  enabled_vlans:
    description:
      - List of VLANs to be enabled. When a VLAN named C(all) is used, all
        VLANs will be allowed. VLANs can be specified with or without the
        leading partition. If the partition is not specified in the VLAN,
        then the C(partition) option of this module will be used.
      - This parameter is mutually exclusive with the C(disabled_vlans) parameter.
    type: list
    elements: str
  disabled_vlans:
    description:
      - List of VLANs to be disabled. If the partition is not specified in the VLAN,
        then the C(partition) option of this module will be used.
      - This parameter is mutually exclusive with the C(enabled_vlans) parameters.
    type: list
    elements: str
  pool:
    description:
      - Specifies a default pool to which the Listener automatically directs traffic.
    type: str
  port:
    description:
      - Specifies the port on which the Listener listens for connections.
      - Valid range of values is between C(0) and C(65535) inclusive.
    type: int
  source_port:
    description:
      - Specifies whether the system preserves the source port of the connection.
    type: str
  translate_address:
    description:
      - Enables or disables address translation for the Listener.
    type: bool
  translate_port:
    description:
      - Enables or disables port translation.
    type: bool
  irules:
    description:
      - Specifies list of iRules to run on the Listener.
      - iRules help automate the intercepting, processing, and routing of application traffic.
      - If you want to remove existing iRules, provide an empty list value; C([]).
        See the documentation for an example.
    type: list
    elements: str
  advertise:
    description:
      - Specifies whether this Listener's address is advertised to surrounding routers.
    type: bool
  auto_lasthop:
    description:
      - Specifies whether to automatically map the last hop for pools or not.
    type: str
  last_hop_pool:
    description:
      - Specifies the name of the last hop pool that you want the Listener to use to direct reply traffic to the last hop router.
    type: str
  fallback_persistence:
    description:
      - Specifies a fallback persistence profile for the Listener to use when the default persistence profile is not available.
    type: str
  ip_protocol:
    description:
      - Specifies the protocol on which this Listener receives network traffic.
    type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - DNS Listener state.
      - When C(present), ensures the pool is created and enabled.
      - When C(absent), ensures the pool is removed from the system.
      - When C(enabled) or C(disabled), ensures the pool is enabled or disabled respectively) on the remote device.
    type: str
    choices:
      - present
      - absent
      - enabled
      - disabled
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Andrey Kashcheev (@andreykashcheev)
'''

EXAMPLES = r'''

- name: 'Create DNS Listener'
  bigip_gtm_dns_listener:
    address: '192.0.1.0'
    advertise: false
    auto_lasthop: default
    description: 'this is a test DNS listener'
    enabled_vlans:
      - /Common/external
    ip_protocol: tcp
    irules:
      - /Common/irule1
    mask: '255.255.255.0'
    pool: /Common/webpool
    name: test-dns-listener
    port: 30025
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
    source_port: preserve
    state: present
    translate_address: true
    translate_port: true
  delegate_to: localhost

- name: 'Disable a DNS Listener'
  bigip_gtm_dns_listener:
    address: '192.0.1.0'
    state: disabled
    name: test-dns-listener
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
name:
  description: DNS Listener name.
  returned: changed
  type: str
  sample: test-dns-listener
mask:
  description: Subnet mask used by the Listener to identify address range.
  returned: changed
  type: str
  sample: 255.255.0.0
address:
  description: IP address on which the system listens.
  returned: changed
  type: str
  sample: 10.0.0.2
port:
  description: Port on which the system listens.
  returned: changed
  type: int
  sample: 53
source_port:
  description: Specifies if system preserves the source port of the connection.
  returned: changed
  type: str
  sample: preserve
advertise:
  description: Specifies if the Listener advertises to surrounding routers.
  returned: changed
  type: bool
  sample: true
auto_lasthop:
  description: Shows whether the system automatically maps the last hop for pools.
  returned: changed
  type: str
  sample: default
translate_address:
  description: Specifies if address translation is enabled.
  returned: changed
  type: str
  sample: enabled
translate_port:
  description: Specifies if port translation is enabled.
  returned: changed
  type: str
  sample: enabled
fallback_persistence:
  description: Fallback persistence profile for the Listener to use when the default persistence profile is not available.
  returned: changed
  type: str
  sample: /Common/fallback-profile
enabled:
  description: Provides DNS Listener state.
  returned: changed
  type: bool
  sample: true
ip_protocol:
  description: IP protocol used by the DNS Listener.
  returned: changed
  type: str
  sample: tcp
disabled_vlans:
  description: List of VLANs the virtual is disabled for.
  returned: changed
  type: list
  sample: ['/Common/vlan1', '/Common/vlan2']
enabled_vlans:
  description: List of VLANs the virtual is enabled for.
  returned: changed
  type: list
  sample: ['/Common/vlan5', '/Common/vlan6']
irules:
  description: List of rules run by the DNS Listener.
  returned: changed
  type: list
  sample: ['/Common/rule1', '/Common/rule2']
'''
from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, is_empty_list, fq_name
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'sourcePort': 'source_port',
        'translateAddress': 'translate_address',
        'translatePort': 'translate_port',
        'vlansDisabled': 'vlans_disabled',
        'vlansEnabled': 'vlans_enabled',
        'rules': 'irules',
        'autoLasthop': 'auto_lasthop',
        'lastHopPool': 'last_hop_pool',
        'fallbackPersistence': 'fallback_persistence',
        'ipProtocol': 'ip_protocol'
    }

    api_attributes = [
        'address',
        'port',
        'advertise',
        'description',
        'sourcePort',
        'translateAddress',
        'translatePort',
        'vlansDisabled',
        'vlansEnabled',
        'vlans',
        'rules',
        'autoLasthop',
        'pool',
        'lastHopPool',
        'fallbackPersistence',
        'ipProtocol',
        'mask',
        'disabled',
        'enabled'
    ]

    returnables = [
        'description',
        'disabled',
        'enabled',
        'ip_protocol',
        'mask',
        'address',
        'disabled_vlans',
        'enabled_vlans',
        'port',
        'advertise',
        'auto_lasthop',
        'translate_address',
        'translate_port',
        'fallback_persistence',
        'source_port',
        'vlans',
        'pool',
        'last_hop_pool',
        'irules',
        'vlans_enabled',
        'vlans_disabled'
    ]

    updatables = [
        'description',
        'disabled',
        'enabled',
        'mask',
        'address',
        'port',
        'advertise',
        'auto_lasthop',
        'disabled_vlans',
        'enabled_vlans',
        'state',
        'ip_protocol',
        'fallback_persistence',
        'translate_address',
        'translate_port',
        'source_port',
        'vlans',
        'pool',
        'last_hop_pool',
        'irules',
        'vlans_enabled',
        'vlans_disabled'
    ]

    @property
    def state(self):
        if self._values['state'] == 'enabled':
            return 'present'
        return self._values['state']

    @property
    def enabled(self):
        if self._values['enabled'] is None:
            return None
        return True

    @property
    def disabled(self):
        if self._values['disabled'] is None:
            return None
        return True


class ApiParameters(Parameters):
    @property
    def irules(self):
        if self._values['irules'] is None:
            return []
        return self._values['irules']


class ModuleParameters(Parameters):
    @property
    def description(self):
        if self._values['description'] is None:
            return None
        elif self._values['description'] in ['none', '']:
            return ''
        return self._values['description']

    @property
    def translate_address(self):
        result = flatten_boolean(self._values['translate_address'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def translate_port(self):
        result = flatten_boolean(self._values['translate_port'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def advertise(self):
        if self._values['advertise'] is None:
            return None
        return flatten_boolean(self._values['advertise'])

    @property
    def vlans_enabled(self):
        if self._values['enabled_vlans'] is None:
            return None
        # elif self._values['vlans_enabled'] is False:
        #     # This is a special case for 'all' enabled VLANs
        #     return False
        if self._values['disabled_vlans'] is None:
            return True
        return False

    @property
    def vlans_disabled(self):
        if self._values['disabled_vlans'] is None:
            return None
        # elif self._values['vlans_disabled'] is True:
        #     # This is a special case for 'all' enabled VLANs
        #     return True
        elif self._values['enabled_vlans'] is None:
            return True
        return False

    @property
    def enabled_vlans(self):
        if self._values['enabled_vlans'] is None:
            return None
        elif any(x.lower() for x in self._values['enabled_vlans'] if x.lower() in ['all', '*']):
            result = [fq_name(self.partition, 'all')]
            self._values['vlans_disabled'] = True
            self._values['vlans_enabled'] = False
            return result
        results = list(set([fq_name(self.partition, x) for x in self._values['enabled_vlans']]))
        results.sort()
        return results

    @property
    def disabled_vlans(self):
        if self._values['disabled_vlans'] is None:
            return None
        elif any(x.lower() for x in self._values['disabled_vlans'] if x.lower() in ['all', '*']):
            raise F5ModuleError(
                'You cannot disable all VLANs. You must name them individually.'
            )
        results = list(set([fq_name(self.partition, x) for x in self._values['disabled_vlans']]))
        results.sort()
        return results

    @property
    def vlans(self):
        disabled = self.disabled_vlans
        if disabled:
            return self.disabled_vlans
        return self.enabled_vlans

    @property
    def irules(self):
        results = []
        if self._values['irules'] is None:
            return None
        if is_empty_list(self._values['irules']):
            return []
        for irule in self._values['irules']:
            result = fq_name(self.partition, irule)
            results.append(result)
        return results


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
    def vlans(self):
        if self._values['vlans'] is None:
            return None
        elif len(self._values['vlans']) == 0:
            return []
        elif any(x for x in self._values['vlans'] if x.lower() in ['/common/all', 'all']):
            return []
        return self._values['vlans']


class ReportableChanges(Changes):
    @property
    def enabled_vlans(self):
        if self._values['vlans'] is None:
            return None
        if len(self._values['vlans']) == 0 and self._values['vlans_disabled'] is True:
            return 'all'
        elif len(self._values['vlans']) > 0 and self._values['vlans_enabled'] is True:
            return self._values['vlans']

    @property
    def disabled_vlans(self):
        if self._values['vlans'] is None:
            return None
        if len(self._values['vlans']) > 0 and self._values['vlans_disabled'] is True:
            return self._values['vlans']

    @property
    def irules(self):
        if self._values['irules'] is None:
            return None
        if not self._values['irules']:
            return []
        return self._values['irules']


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

    def _update_vlan_status(self, result):
        if self.want.vlans_disabled is not None:
            if self.want.vlans_disabled != self.have.vlans_disabled:
                result['vlans_disabled'] = self.want.vlans_disabled
                result['vlans_enabled'] = not self.want.vlans_disabled
        elif self.want.vlans_enabled is not None:
            if any(x.lower().endswith('/all') for x in self.want.vlans):
                if self.have.vlans_enabled is True:
                    return None
            elif self.want.vlans_enabled != self.have.vlans_enabled:
                result['vlans_disabled'] = not self.want.vlans_enabled
                result['vlans_enabled'] = self.want.vlans_enabled

    @property
    def state(self):
        if self.want.state == 'disabled' and self.have.enabled:
            return dict(
                disabled=True
            )
        elif self.want.state in ['present', 'enabled'] and self.have.disabled:
            return dict(
                enabled=True
            )

    @property
    def vlans(self):
        if self.want.vlans is None:
            return None
        elif self.want.vlans == [] and self.have.vlans is None:
            return None
        elif self.want.vlans == self.have.vlans:
            return None

        # Specifically looking for /all because the vlans return value will be
        # an FQDN list. This means that 'all' will be returned as '/partition/all',
        # ex, /Common/all.
        #
        # We do not want to accidentally match values that would end with the word
        # 'all', like 'vlansall'. Therefore we look for the forward slash because this
        # is a path delimiter.
        elif any(x.lower().endswith('/all') for x in self.want.vlans):
            if self.have.vlans is None:
                return None
            else:
                return []
        else:
            return self.want.vlans

    @property
    def enabled_vlans(self):
        return self.vlan_status

    @property
    def disabled_vlans(self):
        return self.vlan_status

    @property
    def vlan_status(self):
        result = dict()
        vlans = self.vlans
        if vlans is not None:
            result['vlans'] = vlans
        self._update_vlan_status(result)
        return result

    @property
    def irules(self):
        if self.want.irules is None:
            return None
        if self.want.irules == '' and len(self.have.irules) > 0:
            return []
        if not self.want.irules:
            return None
        if self.want.irules != self.have.irules:
            return self.want.irules


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

        if state in ['present', 'disabled']:
            changed = self.present()
        elif state == 'absent':
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
            raise F5ModuleError('Failed to delete the resource.')
        return True

    def create(self):
        if self.want.state == 'disabled':
            self.want.update({'disabled': True})
        elif self.want.state in ['present', 'enabled']:
            self.want.update({'enabled': True})
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = 'https://{0}:{1}/mgmt/tm/gtm/listener/{2}'.format(
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

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = 'https://{0}:{1}/mgmt/tm/gtm/listener/'.format(
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
        uri = 'https://{0}:{1}/mgmt/tm/gtm/listener/{2}'.format(
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
        uri = 'https://{0}:{1}/mgmt/tm/gtm/listener/{2}'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = 'https://{0}:{1}/mgmt/tm/gtm/listener/{2}'.format(
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
            address=dict(required=True),
            port=dict(type='int'),
            advertise=dict(type='bool'),
            enabled_vlans=dict(
                type='list',
                elements='str',
            ),
            disabled_vlans=dict(
                type='list',
                elements='str',
            ),
            irules=dict(
                type='list',
                elements='str'
            ),
            translate_address=dict(type='bool'),
            translate_port=dict(type='bool'),
            fallback_persistence=dict(),
            last_hop_pool=dict(),
            pool=dict(),
            auto_lasthop=dict(),
            source_port=dict(),
            ip_protocol=dict(),
            mask=dict(),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['absent', 'present', 'enabled', 'disabled']
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['enabled_vlans', 'disabled_vlans']
        ]


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
