#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_profile_ftp
short_description: Manages FTP profiles
description:
  - Manages FTP profiles on the BIG-IP system.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the profile.
    type: str
    required: True
  allow_ftps:
    description:
      - Allows explicit FTPS negotiation.
    type: bool
  description:
    description:
      - Description of the profile.
    type: str
  parent:
    description:
      - Specifies the profile from which this profile inherits settings.
      - When creating a new profile, if this parameter is not specified, the default
        is the system-supplied C(ftp) profile.
    type: str
  inherit_parent_profile:
    description:
      - Enables the FTP data channel to inherit the TCP profile used by the control channel.
      - "When C(false), the data channel uses FastL4 (BigProto) only."
    type: bool
  log_profile:
    description:
      - Configures the ALG log profile that controls logging.
    type: str
  log_publisher:
    description:
      - Configures the log publisher that handles events logging for this profile.
    type: str
  translate_extended:
    description:
      - Translates RFC 2428 extended requests C(EPSV) and C(EPRT) to C(PASV) and C(PORT)
        when communicating with IPv4 servers.
      - This option can only be used if the system is licensed for the BIG-IP Application Security Manager (ASM).
    type: bool
  port:
    description:
      - Specifies a service for the data channel port used for this FTP profile.
      - Valid range of values is between C(0) and C(65535) inclusive.
    type: int
  security:
    description:
      - Enables secure FTP traffic for the BIG-IP Application Security Manager.
      - This option can only be used if the system is licensed for the BIG-IP ASM.
    type: bool
  state:
    description:
      - When C(state) is C(present), ensures the ftp profile exists.
      - When C(state) is C(absent), ensures the ftp profile is removed.
    type: str
    choices:
      - present
      - absent
    default: present
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create an ftp profile
  bigip_profile_ftp:
    name: foo
    parent: /Common/barfoo
    port: 2221
    allow_ftps: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Modify an ftp profile
  bigip_profile_ftp:
    name: foo
    log_profile: /Common/alg_log
    log_publisher: /Common/foo_publisher
    security: true
    description: my description
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove an ftp profile
  bigip_profile_ftp:
    name: foo
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
allow_ftps:
  description: Allow explicit FTPS negotiation.
  returned: changed
  type: bool
  sample: true
description:
  description: Description of the profile.
  returned: changed
  type: str
  sample: Foo is bar
parent:
  description: Specifies the profile from which this profile inherits settings.
  returned: changed
  type: str
  sample: /Common/ftp
inherit_parent_profile:
  description: Enables the FTP data channel to inherit the TCP profile used by the control channel.
  returned: changed
  type: bool
  sample: false
log_profile:
  description: The ALG log profile that controls logging.
  returned: changed
  type: str
  sample: /Common/foo_log_profile
log_publisher:
  description: The name of the log publisher that handles events logging for this profile.
  returned: changed
  type: list
  sample: /Common/publisher_1
translate_extended:
  description: Translates RFC 2428 extended requests when communicating with IPv4 servers.
  returned: changed
  type: bool
  sample: true
port:
  description: Specifies a service for the data channel port used for this FTP profile.
  returned: changed
  type: int
  sample: 20
security:
  description: Enables secure FTP traffic for the BIG-IP Application Security Manager.
  returned: changed
  type: bool
  sample: false
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'allowFtps': 'allow_ftps',
        'defaultsFrom': 'parent',
        'inheritParentProfile': 'inherit_parent_profile',
        'logProfile': 'log_profile',
        'logPublisher': 'log_publisher',
        'translateExtended': 'translate_extended',
    }

    api_attributes = [
        'allowFtps',
        'description',
        'inheritParentProfile',
        'logProfile',
        'logPublisher',
        'port',
        'security',
        'translateExtended',
    ]

    returnables = [
        'allow_ftps',
        'description',
        'inherit_parent_profile',
        'log_profile',
        'log_publisher',
        'parent',
        'port',
        'security',
        'translate_extended',
    ]

    updatables = [
        'allow_ftps',
        'description',
        'inherit_parent_profile',
        'log_profile',
        'log_publisher',
        'parent',
        'port',
        'security',
        'translate_extended',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def allow_ftps(self):
        result = flatten_boolean(self._values['allow_ftps'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def inherit_parent_profile(self):
        result = flatten_boolean(self._values['inherit_parent_profile'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

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
    def parent(self):
        if self._values['parent'] is None:
            return None
        result = fq_name(self.partition, self._values['parent'])
        return result

    @property
    def port(self):
        if self._values['port'] is None:
            return None
        if 0 <= self._values['port'] <= 65535:
            return self._values['port']
        raise F5ModuleError(
            "Valid 'port' must be in range 0 - 65535."
        )

    @property
    def security(self):
        result = flatten_boolean(self._values['security'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def translate_extended(self):
        result = flatten_boolean(self._values['translate_extended'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'


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

    @property
    def allow_ftps(self):
        result = flatten_boolean(self._values['allow_ftps'])
        return result

    @property
    def inherit_parent_profile(self):
        result = flatten_boolean(self._values['inherit_parent_profile'])
        return result

    @property
    def security(self):
        result = flatten_boolean(self._values['security'])
        return result

    @property
    def translate_extended(self):
        result = flatten_boolean(self._values['translate_extended'])
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
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/ftp/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/ftp/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 409]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/ftp/{2}".format(
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/ftp/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/ftp/{2}".format(
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
            allow_ftps=dict(type='bool'),
            description=dict(),
            parent=dict(),
            inherit_parent_profile=dict(type='bool'),
            log_profile=dict(),
            log_publisher=dict(),
            translate_extended=dict(type='bool'),
            port=dict(type='int'),
            security=dict(type='bool'),
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
