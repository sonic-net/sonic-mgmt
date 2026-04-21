#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_advanced_settings
short_description: Manage BIG-IP system ASM advanced settings
description:
  - Manage BIG-IP system ASM advanced settings.
version_added: "1.4.0"
options:
  name:
    description:
      - The ASM setting to manipulate.
    type: str
    required: True
  state:
    description:
      - The state of the setting on the system. When C(present), guarantees
        that an existing setting is set to C(value). When C(reset), sets the
        setting back to the default value. At least one of value and state
        C(reset) are required.
    type: str
    choices:
      - present
      - reset
    default: present
  value:
    description:
      - The value to set the key to. At least one of value and state C(reset)
        are required.
    type: str
notes:
  - Requires BIG-IP version 12.0.0 or greater
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Set the long_request_buffer_size asm setting
  bigip_asm_advanced_settings:
    name: long_request_buffer_size
    value: 20000000
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Reset the long_request_buffer_size to default value
  bigip_asm_advanced_settings:
    name: long_request_buffer_size
    state: reset
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost
'''

RETURN = r'''
name:
  description: The name of the ASM setting that was specified
  returned: changed and success
  type: str
  sample: long_request_buffer_size
default_value:
  description: The default value of the specified ASM setting
  returned: changed and success
  type: str
  sample: '10000000'
value:
  description: The value you set the ASM setting to
  returned: changed and success
  type: str
  sample: '20000000'
'''
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'defaultValue': 'default_value',
    }
    api_attributes = [
        'value',
    ]
    updatables = [
        'value',
    ]
    returnables = [
        'name',
        'value',
        'default_value',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):

    @property
    def value(self):
        if self._values['value'] is None:
            return None
        try:
            return int(self._values['value'])
        except ValueError:
            return self._values['value']


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
    pass


class ReportableChanges(Changes):
    @property
    def value(self):
        if self._values['value'] is None:
            return None
        return str(self._values['value'])

    @property
    def default_value(self):
        if self._values['default_value'] is None:
            return None
        return str(self._values['default_value'])


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
    def value(self):
        if self.want.state == 'reset':
            if str(self.have.value) != str(self.have.default_value):
                return self.have.default_value
        if self.want.value != self.have.value:
            return self.want.value


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.pop('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()
        self.setting_id = None

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

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
            changed['name'] = self.want.name
            changed['default_value'] = self.have.default_value
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        if not module_provisioned(self.client, 'asm'):
            raise F5ModuleError(
                "ASM must be provisioned to use this module."
            )
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "reset":
            changed = self.reset()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if self.exists():
            return False
        else:
            return self.update()

    def reset(self):
        self._get_setting_id()
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.reset_on_device()
        self.want.update({'name': self.want.name})
        self.want.update({'value': self.have.default_value})
        if self.exists():
            return True
        else:
            raise F5ModuleError(
                "Failed to reset the: {0} asm setting.".format(self.want.key)
            )

    def update(self):
        if self.want.value is None:
            raise F5ModuleError(
                "When setting a key, a value must be supplied"
            )
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def _get_setting_id(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/advanced-settings/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$filter=name+eq+'{0}'&$select=id".format(self.want.name)
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        if 'items' in response and response['items'] != []:
            self.setting_id = response['items'][0]['id']

        if not self.setting_id:
            raise F5ModuleError("The setting: {0} was not found.".format(self.want.name))

    def exists(self):
        self._get_setting_id()
        uri = "https://{0}:{1}/mgmt/tm/asm/advanced-settings/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.setting_id
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if str(response['value']) == str(self.want.value):
            return True
        return False

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/advanced-settings/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.setting_id
        )

        resp = self.client.api.get(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        return ApiParameters(params=response)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/asm/advanced-settings/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.setting_id
        )

        resp = self.client.api.patch(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def reset_on_device(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/advanced-settings/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.setting_id
        )
        params = dict(
            value=self.have.default_value
        )

        resp = self.client.api.patch(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            state=dict(
                default='present',
                choices=['present', 'reset']
            ),
            value=dict()
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
