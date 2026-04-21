#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_profile_sip
short_description: Manage SIP profiles on a BIG-IP
description:
  - Manage SIP profiles on a BIG-IP system.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the SIP profile to manage.
    type: str
    required: True
  parent:
    description:
      - Specifies the profile from which this profile inherits settings.
      - When creating a new profile, if this parameter is not specified, the default
        is the system-supplied C(sip) profile.
    type: str
  community:
    description:
      - When the C(dialog_aware) is C(true) and the configuration requires multiple SIP virtual server-profile pairings,
        this string value indicates whether the pair belongs to the same SIP proxy functional group.
    type: str
  description:
    description:
      - Description of the profile.
      - To remove the entry completely, set a value of C('').
    type: str
  dialog_aware:
    description:
      - When C(true), the system gathers SIP dialog information and automatically forwards SIP messages belonging to
        the known SIP dialog.
    type: bool
  enable_sip_firewall:
    description:
      - Specifies whether the Advanced Firewall Manager (AFM) policy is enabled.
      - When C(true), the SIP Security settings configured in the DoS Profile in AFM apply to the virtual servers that
        use this profile.
    type: bool
  insert_record_route_header:
    description:
      - When C(true), inserts a Record-Route SIP header, which indicates the next hop for the following SIP request
        messages.
    type: bool
  insert_via_header:
    description:
      - When C(true), inserts a Via header in the forwarded SIP request.
      - Via headers indicate the path taken through proxy devices and transports used. The response message uses this
        routing information.
    type: bool
  user_via_header:
    description:
      - When C(insert_via_header) is C(true), specifies the Via value the system inserts as the top Via header in a
        SIP REQUEST message.
      - "The valid value must include SIP protocol and sent_by settings, for example: C(SIP/2.0/UDP 10.10.10.10:5060)."
      - To remove the entry completely, set a value of C('').
    type: str
  log_profile:
    description:
      - Specifies the logging settings the publisher uses to send log messages.
      - The format of the name can be either be prepended by partition (C(/Common/foo)), or specified
        just as an object name (C(foo)).
      - To remove the entry. set a value of C(''), however the profile C(log_publisher)
        must also be set as C('').
    type: str
  log_publisher:
    description:
      - Specifies the publisher defined to log messages.
      - Format of the name can be either be prepended by partition (C(/Common/foo)), or specified
        just as an object name (C(foo)).
      - To remove the entry. set a value of C(''), however the profile C(log_profile)
        must also be set as C('').
    type: str
  secure_via_header:
    description:
      - When checked (enabled), inserts a secure Via header in the forwarded SIP request.
      - A secure Via header indicates where the message originated.
      - This parameter causes the inserted Via header to specify Transport Layer Security. For this option to take
        effect, C(insert_via_header) must be set to (true).
    type: bool
  security:
    description:
      - "When C(true), enables the use of enhanced Horizontal Security Layer (HSL) security checking."
    type: bool
  terminate_on_bye:
    description:
      - When C(true), closes a connection when a BYE transaction finishes.
      - A BYE transaction is a message an application sends to another application when it is ready to close the
        connection between the two.
    type: bool
  max_size:
    description:
      - Specifies the maximum SIP message size that the BIG-IP system accepts.
      - The accepted value range is C(0 - 4294967295) bytes.
    type: int
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
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create a SIP profile
  bigip_profile_sip:
    name: foo
    parent: sip
    log_profile: alg_log
    log_publisher: foo-publisher
    description: this is a new profile
    security: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Update SIP profile
  bigip_profile_sip:
    name: foo
    insert_record_route_header: true
    enable_sip_firewall: true
    insert_via_header: true
    user_via_header: "SIP/2.0/UDP 10.10.10.10:5060"
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Delete a SIP profile
  bigip_profile_sip:
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
  description: Description of the profile.
  returned: changed
  type: str
  sample: "custom description"
community:
  description: Indicates whether the pair belongs to the same SIP proxy functional group.
  returned: changed
  type: str
  sample: foo_community
parent:
  description: Specifies the profile from which this profile inherits settings.
  returned: changed
  type: str
  sample: /Common/sip
dialog_aware:
  description: Specifies if the system gathers SIP dialog information.
  returned: changed
  type: bool
  sample: false
enable_sip_firewall:
  description: Specifies whether the Advanced Firewall Manager policy is enabled.
  returned: changed
  type: bool
  sample: true
insert_record_route_header:
  description: Specifies if the system will insert a Record-Route SIP header.
  returned: changed
  type: bool
  sample: true
insert_via_header:
  description: Specifies if the system will insert a Via header in the forwarded SIP request.
  returned: changed
  type: bool
  sample: true
user_via_header:
  description: The value the system inserts as the top Via header in a SIP REQUEST message.
  returned: changed
  type: str
  sample: "SIP/2.0/UDP 10.10.10.10:5060"
log_profile:
  description: The logging settings the publisher uses to send log messages.
  returned: changed
  type: str
  sample: "/Common/alg_profile"
log_publisher:
  description: The publisher defined to log messages.
  returned: changed
  type: str
  sample: "/Common/foo_publisher"
secure_via_header:
  description: Specifies if the system will insert a secure Via header in the forwarded SIP request.
  returned: changed
  type: bool
  sample: false
security:
  description: Enables the use of enhanced Horizontal Security Layer security checking.
  returned: changed
  type: bool
  sample: true
terminate_on_bye:
  description: Specifies if the system will close a connection when a BYE transaction finishes.
  returned: changed
  type: bool
  sample: false
max_size:
  description: Specifies if the system will close a connection when a BYE transaction finishes.
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
        'defaultsFrom': 'parent',
        'dialogAware': 'dialog_aware',
        'enableSipFirewall': 'enable_sip_firewall',
        'insertRecordRouteHeader': 'insert_record_route_header',
        'insertViaHeader': 'insert_via_header',
        'userViaHeader': 'user_via_header',
        'logProfile': 'log_profile',
        'logPublisher': 'log_publisher',
        'secureViaHeader': 'secure_via_header',
        'terminateOnBye': 'terminate_on_bye',
        'maxSize': 'max_size',
    }

    api_attributes = [
        'community',
        'description',
        'defaultsFrom',
        'dialogAware',
        'enableSipFirewall',
        'insertRecordRouteHeader',
        'insertViaHeader',
        'logProfile',
        'logPublisher',
        'secureViaHeader',
        'security',
        'terminateOnBye',
        'userViaHeader',
        'maxSize',

    ]

    returnables = [
        'description',
        'community',
        'parent',
        'dialog_aware',
        'enable_sip_firewall',
        'insert_record_route_header',
        'insert_via_header',
        'user_via_header',
        'log_profile',
        'log_publisher',
        'secure_via_header',
        'security',
        'terminate_on_bye',
        'max_size',
    ]

    updatables = [
        'description',
        'community',
        'parent',
        'dialog_aware',
        'enable_sip_firewall',
        'insert_record_route_header',
        'insert_via_header',
        'user_via_header',
        'log_profile',
        'log_publisher',
        'secure_via_header',
        'security',
        'terminate_on_bye',
        'max_size',
    ]


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
    def security(self):
        if self._values['security'] is None:
            return None
        result = flatten_boolean(self._values['security'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def dialog_aware(self):
        if self._values['dialog_aware'] is None:
            return None
        result = flatten_boolean(self._values['dialog_aware'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def enable_sip_firewall(self):
        if self._values['enable_sip_firewall'] is None:
            return None
        result = flatten_boolean(self._values['enable_sip_firewall'])
        return result

    @property
    def insert_via_header(self):
        if self._values['insert_via_header'] is None:
            return None
        result = flatten_boolean(self._values['insert_via_header'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def secure_via_header(self):
        if self._values['secure_via_header'] is None:
            return None
        result = flatten_boolean(self._values['secure_via_header'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def terminate_on_bye(self):
        if self._values['terminate_on_bye'] is None:
            return None
        result = flatten_boolean(self._values['terminate_on_bye'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def insert_record_route_header(self):
        if self._values['insert_record_route_header'] is None:
            return None
        result = flatten_boolean(self._values['insert_record_route_header'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def max_size(self):
        if self._values['max_size'] is None:
            return None
        if 0 <= self._values['max_size'] <= 4294967295:
            return self._values['max_size']
        raise F5ModuleError(
            "Valid 'max_size' must be in range 0 - 4294967295 bytes."
        )

    @property
    def log_profile(self):
        if self._values['log_profile'] in [None, '']:
            return self._values['log_profile']
        result = fq_name(self.partition, self._values['log_profile'])
        return result

    @property
    def log_publisher(self):
        if self._values['log_publisher'] in [None, '']:
            return self._values['log_publisher']
        result = fq_name(self.partition, self._values['log_publisher'])
        return result


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
    def security(self):
        result = flatten_boolean(self._values['security'])
        return result

    @property
    def dialog_aware(self):
        result = flatten_boolean(self._values['dialog_aware'])
        return result

    @property
    def enable_sip_firewall(self):
        result = flatten_boolean(self._values['enable_sip_firewall'])
        return result

    @property
    def insert_via_header(self):
        result = flatten_boolean(self._values['insert_via_header'])
        return result

    @property
    def terminate_on_bye(self):
        result = flatten_boolean(self._values['terminate_on_bye'])
        return result

    @property
    def insert_record_route_header(self):
        result = flatten_boolean(self._values['insert_record_route_header'])
        return result

    @property
    def secure_via_header(self):
        result = flatten_boolean(self._values['secure_via_header'])
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
        if self.want.description is None:
            return None
        if self.want.description == '':
            if self.have.description in [None, "none"]:
                return None
        if self.want.description != self.have.description:
            return self.want.description

    @property
    def user_via_header(self):
        if self.want.user_via_header is None:
            return None
        if self.want.user_via_header == '':
            if self.have.user_via_header in [None, "none"]:
                return None
        if self.want.user_via_header != self.have.user_via_header:
            return self.want.user_via_header

    @property
    def log_profile(self):
        if self.want.log_profile is None:
            return None
        if self.want.log_profile == '':
            if self.have.log_profile in [None, "none"]:
                return None
        if self.want.log_profile != self.have.log_profile:
            return self.want.log_profile

    @property
    def log_publisher(self):
        if self.want.log_publisher is None:
            return None
        if self.want.log_publisher == '':
            if self.have.log_publisher in [None, "none"]:
                return None
        if self.want.log_publisher != self.have.log_publisher:
            return self.want.log_publisher


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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/sip/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/sip/".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/sip/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/sip/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/sip/{2}".format(
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
            security=dict(type='bool'),
            description=dict(),
            community=dict(),
            dialog_aware=dict(type='bool'),
            enable_sip_firewall=dict(type='bool'),
            insert_via_header=dict(type='bool'),
            user_via_header=dict(),
            secure_via_header=dict(type='bool'),
            terminate_on_bye=dict(type='bool'),
            max_size=dict(type='int'),
            log_profile=dict(),
            log_publisher=dict(),
            insert_record_route_header=dict(type='bool'),
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
