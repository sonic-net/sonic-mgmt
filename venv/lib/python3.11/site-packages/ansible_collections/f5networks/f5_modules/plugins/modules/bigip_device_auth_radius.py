#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_device_auth_radius
short_description: Manages RADIUS auth configuration on a BIG-IP device
description:
  - Module creates a RADIUS configuration.
version_added: "1.3.0"
options:
  servers:
    description:
      - Specifies the names of RADIUS servers for use with RADIUS authentication profiles.
    type: list
    elements: str
  accounting_bug:
    description:
      - Enables or disables validation of the accounting response vector.
      - This option should be necessary only on older servers.
    type: bool
  retries:
    description:
      - Specifies the number of authentication retries the BIG-IP Local Traffic Management system allows before
        authentication fails.
    type: int
  service_type:
    description:
      - Specifies the type of service requested from the RADIUS server. The default value is C(authenticate-only).
    type: str
    choices:
      - authenticate-only
      - login
      - default
      - framed
      - callback-login
      - callback-framed
      - outbound
      - administrative
      - nas-prompt
      - callback-nas-prompt
      - call-check
      - callback-administrative
  fallback_to_local:
    description:
      - Specifies the system uses the Local authentication method if the remote
        authentication method is not available.
      - Option only available on C(TMOS 13.0.0) and above.
    type: bool
  use_for_auth:
    description:
      - Specifies whether or not this auth source is put in use on the system.
      - If C(true), the module sets the current system auth type to the value of C(radius).
      - If C(false), the module sets the authentication type to C(local), similar behavior to when C(state) is C(absent),
        without removing the configured RADIUS resource.
    type: bool
  state:
    description:
      - When C(state) is C(present), ensures the RADIUS server exists.
      - When C(state) is C(absent), ensures the RADIUS server is removed.
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
notes:
  - This module is based on the command line (TMSH) configuration capabilities of RADIUS authentication,
    not the GUI.
author:
  - Andrey Kashcheev (@andreykashcheev)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create an RADIUS device configuration
  bigip_device_auth_radius:
    servers:
      - "ansible_test1"
      - "ansible_test2"
    retries: 3
    service_type: authenticate-only
    accounting_bug: false
    use_for_auth: true
    fallback_to_local: true
    state: present
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Update an RADIUS device configuration
  bigip_device_auth_radius:
    retries: 5
    service_type: administrative
    accounting_bug: true
    state: present
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Delete RADIUS auth configuration
  bigip_device_auth_radius:
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
servers:
  description: The servers value of the resource.
  returned: changed
  type: list
  sample: hash/dictionary of values
service_type:
  description: Type of service requested from the RADIUS server.
  returned: changed
  type: str
  sample: login
retries:
  description: Number of authentication retries before authentication fails.
  type: int
  returned: changed
  sample: 10
accounting_bug:
  description: Enables or disables validation of the accounting response vector.
  type: bool
  returned: changed
  sample: true
'''
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name, is_empty_list
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'serviceType': 'service_type',
        'accountingBug': 'accounting_bug',
        'fallback': 'fallback_to_local',
    }

    api_attributes = [
        'accountingBug',
        'serviceType',
        'servers',
        'retries',
    ]

    returnables = [
        'accounting_bug',
        'servers',
        'service_type',
        'retries',
        'fallback_to_local',
    ]

    updatables = [
        'accounting_bug',
        'servers',
        'service_type',
        'retries',
        'auth_source',
        'fallback_to_local',
    ]

    @property
    def fallback_to_local(self):
        return flatten_boolean(self._values['fallback_to_local'])


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def accounting_bug(self):
        result = flatten_boolean(self._values['accounting_bug'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def use_for_auth(self):
        return flatten_boolean(self._values['use_for_auth'])

    @property
    def auth_source(self):
        if self._values['use_for_auth'] is None:
            return None
        if self.use_for_auth == 'yes':
            return 'radius'
        if self.use_for_auth == 'no':
            return 'local'

    @property
    def servers(self):
        if self._values['servers'] is None:
            return None
        if is_empty_list(self._values['servers']):
            return []
        result = list()
        for item in self._values['servers']:
            result.append(fq_name('Common', item))
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
    def fallback_to_local(self):
        if self._values['fallback_to_local'] is None:
            return None
        elif self._values['fallback_to_local'] == 'yes':
            return 'true'
        return 'false'


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
        want = getattr(self.want, param)
        try:
            have = getattr(self.have, param)
            if want != have:
                return want
        except AttributeError:
            return want


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
        if self.want.fallback_to_local == 'yes':
            self.update_fallback_on_device('true')
        elif self.want.fallback_to_local == 'no':
            self.update_fallback_on_device('false')
        if self.want.use_for_auth and self.changes.auth_source:
            self.update_auth_source_on_device(self.changes.auth_source)
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.update_auth_source_on_device('local')
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        if self.want.fallback_to_local == 'yes':
            self.update_fallback_on_device('true')
        elif self.want.fallback_to_local == 'no':
            self.update_fallback_on_device('false')
        if self.want.use_for_auth:
            self.update_auth_source_on_device(self.want.auth_source)
        return True

    def update_fallback_on_device(self, fallback):
        params = dict(
            fallback=fallback
        )
        uri = 'https://{0}:{1}/mgmt/tm/auth/source/'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/radius/~Common~system-auth".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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
        params['name'] = 'system-auth'
        params['partition'] = 'Common'
        uri = 'https://{0}:{1}/mgmt/tm/auth/radius'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
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
        if not params:
            return
        uri = "https://{0}:{1}/mgmt/tm/auth/radius/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
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
        uri = "https://{0}:{1}/mgmt/tm/auth/radius/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/radius/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response.update(self.read_current_auth_source_from_device())
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)

    def read_current_auth_source_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/source".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        result = {}
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            if 'fallback' in response:
                result['fallback'] = response['fallback']
            if 'type' in response:
                result['auth_source'] = response['type']
            return result
        raise F5ModuleError(resp.content)

    def update_auth_source_on_device(self, source):
        """Set the system auth source.

        Configuring the authentication source is only one step in the process of setting
        up an auth source. The other step is to inform the system of the auth source
        you want to use.

        This method is used for situations where

        * The ``use_for_auth`` parameter is set to ``yes``
        * The ``use_for_auth`` parameter is set to ``no``
        * The ``state`` parameter is set to ``absent``

        When ``state`` equal to ``absent``, before you can delete the Radius+ configuration,
        you must set the system auth to "something else". The system ships with a system
        auth called "local", so this is the logical "something else" to use.

        When ``use_for_auth`` is no, the same situation applies as when ``state`` equal
        to ``absent`` is done above.

        When ``use_for_auth`` is ``yes``, this method will set the current system auth
        state to Radius+.

        Arguments:
            source (string): The source that you want to set on the device.
        """
        params = dict(
            type=source
        )
        uri = 'https://{0}:{1}/mgmt/tm/auth/source/'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
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
            retries=dict(
                type='int'
            ),
            service_type=dict(
                choices=[
                    'authenticate-only',
                    'login',
                    'default',
                    'framed',
                    'callback-login',
                    'callback-framed',
                    'outbound',
                    'administrative',
                    'nas-prompt',
                    'callback-nas-prompt',
                    'call-check',
                    'callback-administrative'
                ]
            ),
            accounting_bug=dict(
                type='bool'
            ),
            servers=dict(
                type='list',
                elements='str',
            ),
            fallback_to_local=dict(type='bool'),
            use_for_auth=dict(type='bool'),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
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
