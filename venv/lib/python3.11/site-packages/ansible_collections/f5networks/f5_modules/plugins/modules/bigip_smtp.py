#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_smtp
short_description: Manages SMTP settings on the BIG-IP
description:
  - Allows configuring of the BIG-IP to send mail via an SMTP server by
    configuring the parameters of an SMTP server.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the SMTP server configuration.
    type: str
    required: True
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  smtp_server:
    description:
      - SMTP server host name in the format of a fully qualified domain name.
      - This value is required when creating a new SMTP configuration.
    type: str
  smtp_server_port:
    description:
      - Specifies the SMTP port number.
      - When creating a new SMTP configuration, the default is C(25) when
        C(encryption) is C(none) or C(tls). The default is C(465) when C(ssl) is selected.
    type: int
  local_host_name:
    description:
      - Hostname used in SMTP headers in the format of a fully qualified
        domain name. This setting does not refer to the hostname of the BIG-IP system.
    type: str
  from_address:
    description:
      - Email address from which the email is being sent. This is the "Reply-to"
        address the recipient sees.
    type: str
  encryption:
    description:
      - Specifies whether the SMTP server requires an encrypted connection in
        order to send mail.
    type: str
    choices:
      - none
      - ssl
      - tls
  authentication:
    description:
      - Credentials can be set on an SMTP server's configuration even if that
        authentication is not used (for example, staging configs or emergency changes).
        This parameter acts as a switch to make the specified C(smtp_server_username)
        and C(smtp_server_password) parameters active or not.
      - When C(true), the authentication parameters are active.
      - When C(false), the authentication parameters are inactive.
    type: bool
  smtp_server_username:
    description:
      - User name the SMTP server requires when validating a user.
    type: str
  smtp_server_password:
    description:
      - Password the SMTP server requires when validating a user.
    type: str
  state:
    description:
      - When C(present), ensures the SMTP configuration exists.
      - When C(absent), ensures the SMTP configuration does not exist.
    type: str
    choices:
      - present
      - absent
    default: present
  update_password:
    description:
      - Passwords are stored encrypted, so the module cannot know if the supplied
        C(smtp_server_password) is the same or different than the existing password.
        This parameter controls the updating of the C(smtp_server_password)
        credential.
      - When C(always), the system always updates the password.
      - When C(on_create), the system only sets the password for newly created SMTP server
        configurations.
    type: str
    choices:
      - always
      - on_create
    default: always
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
'''

EXAMPLES = r'''
- name: Create a base SMTP server configuration
  bigip_smtp:
    name: my-smtp
    smtp_server: 1.1.1.1
    smtp_server_username: mail-admin
    smtp_server_password: mail-secret
    local_host_name: smtp.mydomain.com
    from_address: no-reply@mydomain.com
    state: present
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost
'''

RETURN = r'''
smtp_server:
  description: The new C(smtp_server) value of the SMTP configuration.
  returned: changed
  type: str
  sample: mail.mydomain.com
smtp_server_port:
  description: The new C(smtp_server_port) value of the SMTP configuration.
  returned: changed
  type: int
  sample: 25
local_host_name:
  description: The new C(local_host_name) value of the SMTP configuration.
  returned: changed
  type: str
  sample: smtp.mydomain.com
from_address:
  description: The new C(from_address) value of the SMTP configuration.
  returned: changed
  type: str
  sample: no-reply@mydomain.com
encryption:
  description: The new C(encryption) value of the SMTP configuration.
  returned: changed
  type: str
  sample: tls
authentication:
  description: Whether the authentication parameters are active or not.
  returned: changed
  type: bool
  sample: true
'''
from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, is_valid_hostname
)
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'username': 'smtp_server_username',
        'passwordEncrypted': 'smtp_server_password',
        'localHostName': 'local_host_name',
        'smtpServerHostName': 'smtp_server',
        'smtpServerPort': 'smtp_server_port',
        'encryptedConnection': 'encryption',
        'authenticationEnabled': 'authentication_enabled',
        'authenticationDisabled': 'authentication_disabled',
        'fromAddress': 'from_address',
    }

    api_attributes = [
        'username',
        'passwordEncrypted',
        'localHostName',
        'smtpServerHostName',
        'smtpServerPort',
        'encryptedConnection',
        'authenticationEnabled',
        'authenticationDisabled',
        'fromAddress',
    ]

    returnables = [
        'smtp_server_username',
        'smtp_server_password',
        'local_host_name',
        'smtp_server',
        'smtp_server_port',
        'encryption',
        'authentication',
        'from_address',
    ]

    updatables = [
        'smtp_server_username',
        'smtp_server_password',
        'local_host_name',
        'smtp_server',
        'smtp_server_port',
        'encryption',
        'authentication',
        'from_address',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def local_host_name(self):
        if self._values['local_host_name'] is None:
            return None
        if is_valid_ip(self._values['local_host_name']):
            return self._values['local_host_name']
        elif is_valid_hostname(self._values['local_host_name']):
            # else fallback to checking reasonably well formatted hostnames
            return str(self._values['local_host_name'])
        raise F5ModuleError(
            "The provided 'local_host_name' value {0} is not a valid IP or hostname".format(
                str(self._values['local_host_name'])
            )
        )

    @property
    def authentication_enabled(self):
        if self._values['authentication'] is None:
            return None
        if self._values['authentication']:
            return True

    @property
    def authentication_disabled(self):
        if self._values['authentication'] is None:
            return None
        if not self._values['authentication']:
            return True

    @property
    def smtp_server_port(self):
        if self._values['smtp_server_port'] is None:
            return None
        return int(self._values['smtp_server_port'])


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
    def smtp_server_password(self):
        return None

    @property
    def smtp_server_username(self):
        return None


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
    def smtp_server_password(self):
        if self.want.update_password == 'on_create':
            return None
        return self.want.smtp_server_password

    @property
    def authentication(self):
        if self.want.authentication_enabled:
            if self.want.authentication_enabled != self.have.authentication_enabled:
                return dict(
                    authentication_enabled=self.want.authentication_enabled
                )
        if self.want.authentication_disabled:
            if self.want.authentication_disabled != self.have.authentication_disabled:
                return dict(
                    authentication_disable=self.want.authentication_disabled
                )


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

    def absent(self):
        if self.exists():
            return self.remove()
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
        uri = "https://{0}:{1}/mgmt/tm/sys/smtp-server/{2}".format(
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
        params = self.want.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/smtp-server/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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
        params = self.want.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/smtp-server/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/sys/smtp-server/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/smtp-server/{2}".format(
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
            smtp_server=dict(),
            smtp_server_port=dict(type='int'),
            smtp_server_username=dict(no_log=True),
            smtp_server_password=dict(no_log=True),
            local_host_name=dict(),
            encryption=dict(choices=['none', 'ssl', 'tls']),
            update_password=dict(
                default='always',
                choices=['always', 'on_create'],
                no_log=False
            ),
            from_address=dict(),
            authentication=dict(type='bool'),
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
