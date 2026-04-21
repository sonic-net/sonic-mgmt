#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_snmp_trap
short_description: Manipulate SNMP trap information on a BIG-IP
description:
  - Manipulate SNMP trap information on a BIG-IP system.
version_added: "1.0.0"
options:
  name:
    description:
      - Name of the SNMP configuration endpoint.
    type: str
    required: True
  snmp_version:
    description:
      - Specifies to which Simple Network Management Protocol (SNMP) version
        the trap destination applies.
    type: str
    choices:
      - '1'
      - '2c'
      - '3'
  community:
    description:
      - Specifies the community name for the trap destination.
    type: str
  destination:
    description:
      - Specifies the address for the trap destination. This can be either an
        IP address or a hostname.
    type: str
  port:
    description:
      - Specifies the port for the trap destination.
    type: str
  network:
    description:
      - Specifies the name of the trap network. This option is not supported in
        versions of BIG-IP prior to 12.1.0, and is simply ignored on those versions.
      - The value C(default) was removed in BIG-IP version 13.1.0. Specifying this
        value when configuring a BIG-IP causes the module to stop and report
        an error. In this case, choose one of the other options, such as
        C(management).
    type: str
    choices:
      - other
      - management
      - default
  security_name:
    description:
      - Specifies the security name to used for v3 snmp trap
      - Required for the C(snmp_version) matches C(v3).
    type: str
    version_added: "1.16.0"
  security_level:
    description:
      - Specifies the port for the trap destination.
      - Required for the C(snmp_version) matches C(v3).
    type: str
    choices:
      - auth-no-privacy
      - auth-privacy
    version_added: "1.16.0"
  auth_protocol:
    description:
      - Specifies the Authentication protocol to be used for snmp v3 traps
      - Required for the C(security_level)
    type: str
    choices:
      - sha
      - md5
    version_added: "1.16.0"
  auth_password:
    description:
      - Specifies the Authentication protocol password to be used for snmp v3 traps
      - Required for the C(snmp_version) matches C(v3) and for the C(security_level)
    type: str
    version_added: "1.16.0"
  privacy_protocol:
    description:
      - Specifies the Privacy protocol to be used for snmp v3 traps
      - Required for the C(security_level) matches c(auth-privacy)
    type: str
    choices:
      - aes
      - des
    version_added: "1.16.0"
  privacy_password:
    description:
      - Specifies the Privacy protocol password to be used for snmp v3 traps
      - Required for the C(security_level) matches c(auth-privacy)
    type: str
    version_added: "1.16.0"
  state:
    description:
      - When C(present), ensures the resource exists.
      - When C(absent), ensures the resource does not exist.
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
notes:
  - This module only supports version v1 and v2c of SNMP.
  - The C(network) option is not supported on versions of BIG-IP prior to 12.1.0 because
    the platform did not support that option until 12.1.0. If used on versions
    prior to 12.1.0, it is simply be ignored.
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create snmp v1 trap
  bigip_snmp_trap:
    community: general
    destination: 1.2.3.4
    name: my-trap1
    network: management
    port: 9000
    snmp_version: 1
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create snmp v2 trap
  bigip_snmp_trap:
    community: general
    destination: 5.6.7.8
    name: my-trap2
    network: default
    port: 7000
    snmp_version: 2c
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create snmp v3 trap
  bigip_snmp_trap:
    community: general
    destination: 5.6.7.9
    name: my-trap3
    network: management
    port: 7001
    snmp_version: 3
    auth_protocol: 'sha'
    auth_password: 'test12345'
    security_name: "testsec2"
    security_level: "auth-no-privacy"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
    state: absent
  delegate_to: localhost

- name: Create snmp v3 trap-2
  bigip_snmp_trap:
    community: general
    destination: 5.6.7.10
    name: my-trap4
    network: management
    port: 7002
    snmp_version: 3
    auth_protocol: 'sha'
    auth_password: 'test123456'
    security_name: "testsec3"
    security_level: "auth-privacy"
    privacy_protocol: "des"
    privacy_password: 'test@12345'
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
    state: absent
  delegate_to: localhost
'''

RETURN = r'''
snmp_version:
  description: The new C(snmp_version) configured on the remote device.
  returned: changed and success
  type: str
  sample: 2c
community:
  description: The new C(community) name for the trap destination.
  returned: changed and success
  type: list
  sample: secret
destination:
  description: The new address for the trap destination in either IP or hostname form.
  returned: changed and success
  type: str
  sample: 1.2.3.4
port:
  description: The new C(port) of the trap destination.
  returned: changed and success
  type: str
  sample: 900
network:
  description: The new name of the network the SNMP trap is on.
  returned: changed and success
  type: str
  sample: management
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

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'version': 'snmp_version',
        'community': 'community',
        'host': 'destination',
        'securityName': 'security_name',
        'authProtocol': 'auth_protocol',
        'authPassword': 'auth_password',
        'securityLevel': 'security_level',
        'privacyProtocol': 'privacy_protocol',
        'privacyPassword': 'privacy_password',
    }

    @property
    def snmp_version(self):
        if self._values['snmp_version'] is None:
            return None
        return str(self._values['snmp_version'])

    @property
    def port(self):
        if self._values['port'] is None:
            return None
        return int(self._values['port'])

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result


class V3Parameters(Parameters):
    updatables = [
        'snmp_version',
        'community',
        'destination',
        'port',
        'network',
        'security_name',
        'auth_protocol',
        'security_level',
        'privacy_protocol',
    ]

    returnables = [
        'snmp_version',
        'community',
        'destination',
        'port',
        'network',
        'security_name',
        'auth_protocol',
        'auth_password',
        'security_level',
        'privacy_protocol',
        'privacy_password',
    ]

    api_attributes = [
        'version',
        'community',
        'host',
        'port',
        'network',
        'securityName',
        'authProtocol',
        'authPassword',
        'securityLevel',
        'privacyProtocol',
        'privacyPassword',
    ]

    @property
    def network(self):
        if self._values['network'] is None:
            return None
        network = str(self._values['network'])
        if network == 'management':
            return 'mgmt'
        elif network == 'default':
            raise F5ModuleError(
                "'default' is not a valid option for this version of BIG-IP. "
                "Use either 'management', 'or 'other' instead."
            )
        else:
            return network


class V2Parameters(Parameters):
    updatables = [
        'snmp_version',
        'community',
        'destination',
        'port',
        'network',
    ]

    returnables = [
        'snmp_version',
        'community',
        'destination',
        'port',
        'network',
    ]

    api_attributes = [
        'version',
        'community',
        'host',
        'port',
        'network',
    ]

    @property
    def network(self):
        if self._values['network'] is None:
            return None
        network = str(self._values['network'])
        if network == 'management':
            return 'mgmt'
        elif network == 'default':
            return ''
        else:
            return network


class V1Parameters(Parameters):
    updatables = [
        'snmp_version',
        'community',
        'destination',
        'port',
    ]

    returnables = [
        'snmp_version',
        'community',
        'destination',
        'port',
    ]

    api_attributes = [
        'version',
        'community',
        'host',
        'port',
    ]

    @property
    def network(self):
        return None


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.kwargs = kwargs

    def exec_module(self):
        if self.is_version_without_network():
            manager = V1Manager(**self.kwargs)
        elif self.is_version_with_default_network():
            manager = V2Manager(**self.kwargs)
        else:
            manager = V3Manager(**self.kwargs)

        return manager.exec_module()

    def is_version_without_network(self):
        """Is current BIG-IP version missing "network" value support

        Returns:
            bool: True when it is missing. False otherwise.
        """
        version = tmos_version(self.client)
        if Version(version) < Version('12.1.0'):
            return True
        else:
            return False

    def is_version_with_default_network(self):
        """Is current BIG-IP version missing "default" network value support

        Returns:
            bool: True when it is missing. False otherwise.
        """
        version = tmos_version(self.client)
        if Version(version) < Version('13.1.0'):
            return True
        else:
            return False


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.have = None

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

        changes = self.changes.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
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

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the snmp trap")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if all(getattr(self.want, v) is None for v in self.required_resources):
            raise F5ModuleError(
                "You must specify at least one of "
                ', '.join(self.required_resources)
            )
        self.create_on_device()
        return True

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

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/{2}".format(
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

    def update_on_device(self):
        params = self.want.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/{2}".format(
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
        params = self.want.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/".format(
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True


class V3Manager(BaseManager):
    def __init__(self, *args, **kwargs):
        super(V3Manager, self).__init__(**kwargs)
        self.required_resources = [
            'version', 'community', 'destination', 'port', 'network', 'security_name', 'auth_protocol', 'auth_password',
            'security_level', 'privacy_protocol', 'privacy_password'
        ]
        self.want = V3Parameters(params=self.module.params)
        self.changes = V3Parameters()

    def _set_changed_options(self):
        changed = {}
        for key in V3Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = V3Parameters(params=changed)

    def _update_changed_options(self):
        changed = {}
        for key in V3Parameters.updatables:
            if getattr(self.want, key) is not None:
                attr1 = getattr(self.want, key)
                attr2 = getattr(self.have, key)
                if attr1 != attr2:
                    changed[key] = attr1
        if changed:
            self.changes = V3Parameters(params=changed)
            return True
        return False

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/{2}".format(
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
        return V3Parameters(params=response)


class V2Manager(BaseManager):
    def __init__(self, *args, **kwargs):
        super(V2Manager, self).__init__(**kwargs)
        self.required_resources = [
            'version', 'community', 'destination', 'port', 'network'
        ]
        self.want = V2Parameters(params=self.module.params)
        self.changes = V2Parameters()

    def _set_changed_options(self):
        changed = {}
        for key in V2Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = V2Parameters(params=changed)

    def _update_changed_options(self):
        changed = {}
        for key in V2Parameters.updatables:
            if getattr(self.want, key) is not None:
                attr1 = getattr(self.want, key)
                attr2 = getattr(self.have, key)
                if attr1 != attr2:
                    changed[key] = attr1
        if changed:
            self.changes = V2Parameters(params=changed)
            return True
        return False

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/{2}".format(
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
        self._ensure_network(response)
        return V2Parameters(params=response)

    def _ensure_network(self, result):
        # BIG-IP's value for "default" is that the key does not
        # exist. This conflicts with our purpose of having a key
        # not exist (which we equate to "i dont want to change that"
        # therefore, if we load the information from BIG-IP and
        # find that there is no 'network' key, that is BIG-IP's
        # way of saying that the network value is "default"
        if 'network' not in result:
            result['network'] = 'default'


class V1Manager(BaseManager):
    def __init__(self, *args, **kwargs):
        super(V1Manager, self).__init__(**kwargs)
        self.required_resources = [
            'version', 'community', 'destination', 'port'
        ]
        self.want = V1Parameters(params=self.module.params)
        self.changes = V1Parameters()

    def _set_changed_options(self):
        changed = {}
        for key in V1Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = V1Parameters(params=changed)

    def _update_changed_options(self):
        changed = {}
        for key in V1Parameters.updatables:
            if getattr(self.want, key) is not None:
                attr1 = getattr(self.want, key)
                attr2 = getattr(self.have, key)
                if attr1 != attr2:
                    changed[key] = attr1
        if changed:
            self.changes = V1Parameters(params=changed)
            return True
        return False

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/snmp/traps/{2}".format(
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
        return V1Parameters(params=response)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True
            ),
            snmp_version=dict(
                choices=['1', '2c', '3']
            ),
            community=dict(no_log=True),
            destination=dict(),
            security_name=dict(),
            security_level=dict(
                choices=['auth-no-privacy', 'auth-privacy']
            ),
            auth_protocol=dict(
                choices=['sha', 'md5']
            ),
            auth_password=dict(no_log=True),
            privacy_protocol=dict(
                choices=['aes', 'des']
            ),
            privacy_password=dict(no_log=True),
            port=dict(),
            network=dict(
                choices=['other', 'management', 'default']
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )

        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['snmp_version', '3', ['security_name']],
            ['snmp_version', '3', ['security_level']],
            ['security_level', 'auth-no-privacy', ['auth_protocol']],
            ['security_level', 'auth-no-privacy', ['auth_password']],
            ['security_level', 'auth-privacy', ['auth_protocol']],
            ['security_level', 'auth-privacy', ['auth_password']],
            ['security_level', 'auth-privacy', ['privacy_protocol']],
            ['security_level', 'auth-privacy', ['privacy_password']]
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if
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
