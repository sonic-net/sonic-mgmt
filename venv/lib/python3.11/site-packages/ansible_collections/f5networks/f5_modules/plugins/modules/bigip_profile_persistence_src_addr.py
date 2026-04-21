#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_profile_persistence_src_addr
short_description: Manage source address persistence profiles
description:
  - Manages source address persistence profiles on a BIG-IP.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the profile.
    type: str
    required: True
  parent:
    description:
      - Specifies the profile from which this profile inherits settings.
      - When creating a new profile, if this parameter is not specified, the default
        is the system-supplied C(source_addr) profile.
    type: str
  match_across_services:
    description:
      - When C(true), specifies all persistent connections from a client IP address that go
        to the same virtual IP address also go to the same node.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
    type: bool
  match_across_virtuals:
    description:
      - When C(true), specifies all persistent connections from the same client IP address
        go to the same node.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
    type: bool
  match_across_pools:
    description:
      - When C(true), specifies the system can use any pool that contains this persistence
        record.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
    type: bool
  mirror:
    description:
      - When C(true), specifies that if the active unit goes into the standby mode, the system
        mirrors any persistence records to its peer.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
    type: bool
  mask:
    description:
      - Specifies a value the system applies as the prefix length.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
    type: str
  hash_algorithm:
    description:
      - Specifies the algorithm the system uses for hash persistence load balancing. The hash
        result is the input for the algorithm.
      - When C(default), specifies the system uses the index of pool members to obtain the
        hash result for the input to the algorithm.
      - When C(carp), specifies the system uses the Cache Array Routing Protocol (CARP)
        to obtain the hash result for the input to the algorithm.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
    type: str
    choices:
      - default
      - carp
  entry_timeout:
    description:
      - Specifies the duration of the persistence entries.
      - When creating a new profile, if this parameter is not specified, the
        default is provided by the parent profile.
      - To specify an indefinite timeout, use the value C(indefinite).
      - If specifying a numeric timeout, the value must be between C(1) and C(4294967295).
    type: str
  override_connection_limit:
    description:
      - When C(true), specifies the system allows you to specify that pool member connection
        limits will be overridden for persisted clients.
      - Per-virtual connection limits remain hard limits and are not overridden.
    type: bool
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the profile exists.
      - When C(absent), ensures the profile is removed.
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
'''

EXAMPLES = r'''
- name: Create a profile
  bigip_profile_persistence_src_addr:
    name: foo
    state: present
    hash_algorithm: carp
    match_across_services: true
    match_across_virtuals: true
    mirror: true
    mask: 255.255.255.255
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
parent:
  description: The parent profile.
  returned: changed
  type: str
  sample: /Common/cookie
hash_algorithm:
  description: The algorithm used for hash persistence.
  returned: changed
  type: str
  sample: default
match_across_pools:
  description: The new Match Across Pools value.
  returned: changed
  type: bool
  sample: true
match_across_services:
  description: The new Match Across Services value.
  returned: changed
  type: bool
  sample: false
match_across_virtuals:
  description: The new Match Across Virtuals value.
  returned: changed
  type: bool
  sample: true
override_connection_limit:
  description: The new Override Connection Limit value.
  returned: changed
  type: bool
  sample: false
entry_timeout:
  description: The duration of the persistence entries.
  returned: changed
  type: str
  sample: 180
mirror:
  description: The new Mirror value.
  returned: changed
  type: bool
  sample: true
mask:
  description: The persist mask value.
  returned: changed
  type: str
  sample: 255.255.255.255
'''
from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'defaultsFrom': 'parent',
        'hashAlgorithm': 'hash_algorithm',
        'matchAcrossPools': 'match_across_pools',
        'matchAcrossServices': 'match_across_services',
        'matchAcrossVirtuals': 'match_across_virtuals',
        'overrideConnectionLimit': 'override_connection_limit',

        # This timeout name needs to be overridden because 'timeout' is a connection
        # parameter and we don't want that to be the value that is always set here.
        'timeout': 'entry_timeout'
    }

    api_attributes = [
        'defaultsFrom',
        'hashAlgorithm',
        'matchAcrossPools',
        'matchAcrossServices',
        'matchAcrossVirtuals',
        'overrideConnectionLimit',
        'timeout',
        'mirror',
        'mask',
    ]

    returnables = [
        'parent',
        'hash_algorithm',
        'match_across_pools',
        'match_across_services',
        'match_across_virtuals',
        'override_connection_limit',
        'entry_timeout',
        'mirror',
        'mask',
    ]

    updatables = [
        'hash_algorithm',
        'match_across_pools',
        'match_across_services',
        'match_across_virtuals',
        'override_connection_limit',
        'entry_timeout',
        'parent',
        'mirror',
        'mask',
    ]

    @property
    def entry_timeout(self):
        if self._values['entry_timeout'] in [None, 'indefinite']:
            return self._values['entry_timeout']
        timeout = int(self._values['entry_timeout'])
        if 1 > timeout > 4294967295:
            raise F5ModuleError(
                "'timeout' value must be between 1 and 4294967295, or the value 'indefinite'."
            )
        return timeout

    @property
    def match_across_pools(self):
        return flatten_boolean(self._values['match_across_pools'])

    @property
    def match_across_services(self):
        return flatten_boolean(self._values['match_across_services'])

    @property
    def match_across_virtuals(self):
        return flatten_boolean(self._values['match_across_virtuals'])

    @property
    def override_connection_limit(self):
        return flatten_boolean(self._values['override_connection_limit'])


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def parent(self):
        if self._values['parent'] is None:
            return None
        result = fq_name(self.partition, self._values['parent'])
        return result

    @property
    def mirror(self):
        if self._values['mirror'] is None:
            return None
        result = flatten_boolean(self._values['mirror'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def mask(self):
        if self._values['mask'] is None:
            return None
        if is_valid_ip(self._values['mask']):
            return self._values['mask']
        else:
            raise F5ModuleError(
                "The provided 'mask' is not a valid IP address"
            )


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
    @property
    def match_across_pools(self):
        if self._values['match_across_pools'] is None:
            return None
        elif self._values['match_across_pools'] == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def match_across_services(self):
        if self._values['match_across_services'] is None:
            return None
        elif self._values['match_across_services'] == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def match_across_virtuals(self):
        if self._values['match_across_virtuals'] is None:
            return None
        elif self._values['match_across_virtuals'] == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def override_connection_limit(self):
        if self._values['override_connection_limit'] is None:
            return None
        elif self._values['override_connection_limit'] == 'yes':
            return 'enabled'
        return 'disabled'


class ReportableChanges(Changes):
    @property
    def match_across_pools(self):
        return flatten_boolean(self._values['match_across_pools'])

    @property
    def match_across_services(self):
        return flatten_boolean(self._values['match_across_services'])

    @property
    def match_across_virtuals(self):
        return flatten_boolean(self._values['match_across_virtuals'])

    @property
    def override_connection_limit(self):
        return flatten_boolean(self._values['override_connection_limit'])


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
        uri = "https://{0}:{1}/mgmt/tm/ltm/persistence/source-addr/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/persistence/source-addr/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/persistence/source-addr/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/persistence/source-addr/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True
        raise F5ModuleError(resp.content)

    def read_current_from_device(self):  # lgtm [py/similar-function]
        uri = "https://{0}:{1}/mgmt/tm/ltm/persistence/source-addr/{2}".format(
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
            parent=dict(),
            match_across_services=dict(type='bool'),
            match_across_virtuals=dict(type='bool'),
            match_across_pools=dict(type='bool'),
            mirror=dict(type='bool'),
            mask=dict(),
            hash_algorithm=dict(choices=['default', 'carp']),
            entry_timeout=dict(),
            override_connection_limit=dict(type='bool'),
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
