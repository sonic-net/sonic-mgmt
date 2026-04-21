#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_device_trust
short_description: Manage the trust relationships between BIG-IPs
description:
  - Manage the trust relationships between BIG-IP systems. Devices, once peered, cannot
    be updated. If updating is needed, the peer must first be removed before it
    can be re-added to the trust.
version_added: "1.0.0"
options:
  peer_server:
    description:
      - The peer address to connect to and trust for synchronizing the configuration.
        This is typically the management address of the remote device, but may
        also be a Self IP address.
    type: str
    required: True
  peer_hostname:
    description:
      - The hostname you want to associate with the device. This value is
        used to easily distinguish this device in BIG-IP configuration.
      - When trusting a new device, if this parameter is not specified, the value
        of C(peer_server) is used as a default.
    type: str
  peer_user:
    description:
      - The API username of the remote peer device you are trusting. Note
        that the CLI user cannot be used unless it too has an API account. If this
        value is not specified, then the value of C(user), or the environment
        variable C(F5_USER) is used.
    type: str
  peer_password:
    description:
      - The password of the API username of the remote peer device you are
        trusting. If this value is not specified, then the value of C(password),
        or the environment variable C(F5_PASSWORD) is used.
    type: str
  type:
    description:
      - Specifies whether the device you are adding is a Peer or a Subordinate.
        The default is C(peer).
      - The difference between the two is a matter of mitigating risk of
        compromise.
      - A subordinate device cannot sign a certificate for another device.
      - In the case where the security of an authority device in a trust domain
        is compromised, the risk of compromise is minimized for any subordinate
        device.
      - Designating devices as subordinate devices is recommended for device
        groups with a large number of member devices, where the risk of compromise
        is high.
    type: str
    choices:
      - peer
      - subordinate
    default: peer
  state:
    description:
      - When C(present), ensures the specified devices are trusted.
      - When C(absent), removes the device trusts.
    type: str
    choices:
      - absent
      - present
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
'''

EXAMPLES = r'''
- name: Add trusts for all peer devices to Active device
  bigip_device_trust:
    peer_server: "{{ item.ansible_host }}"
    peer_hostname: "{{ item.inventory_hostname }}"
    peer_user: "{{ item.bigip_username }}"
    peer_password: "{{ item.bigip_password }}"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  loop: hostvars
  when: inventory_hostname in groups['master']
  delegate_to: localhost
'''

RETURN = r'''
peer_server:
  description: The remote IP address of the trusted peer.
  returned: changed
  type: str
  sample: 10.0.2.15
peer_hostname:
  description: The remote hostname used to identify the trusted peer.
  returned: changed
  type: str
  sample: test-bigip-02.localhost.localdomain
'''

import re
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'deviceName': 'peer_hostname',
        'caDevice': 'type',
        'device': 'peer_server',
        'username': 'peer_user',
        'password': 'peer_password'
    }

    api_attributes = [
        'name',
        'caDevice',
        'device',
        'deviceName',
        'username',
        'password'
    ]

    returnables = [
        'peer_server', 'peer_hostname'
    ]

    updatables = []

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result

    @property
    def peer_server(self):
        if self._values['peer_server'] is None:
            return None
        if is_valid_ip(self._values['peer_server']):
            return self._values['peer_server']
        raise F5ModuleError(
            "The provided 'peer_server' parameter is not an IP address."
        )

    @property
    def peer_hostname(self):
        if self._values['peer_hostname'] is None:
            return self.peer_server
        regex = re.compile(r'[^a-zA-Z0-9.\-_]')
        result = regex.sub('_', self._values['peer_hostname'])
        return result

    @property
    def type(self):
        if self._values['type'] == 'peer':
            return True
        return False


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.have = None
        self.want = Parameters(params=self.module.params)
        self.changes = Parameters()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = Parameters(params=changed)

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

    def provided_password(self):
        if self.want.password:
            return self.password
        if self.want.provider.get('password', None):
            return self.want.provider.get('password')
        if self.module.params.get('password', None):
            return self.module.params.get('password')

    def provided_username(self):
        if self.want.username:
            return self.username
        if self.want.provider.get('user', None):
            return self.provider.get('user')
        if self.module.params.get('user', None):
            return self.module.params.get('user')

    def present(self):
        if self.exists():
            return False
        else:
            return self.create()

    def create(self):
        self._set_changed_options()
        if self.want.peer_user is None:
            self.want.update({'peer_user': self.provided_username()})
        if self.want.peer_password is None:
            self.want.update({'peer_password': self.provided_password()})
        if self.want.peer_hostname is None:
            self.want.update({'peer_hostname': self.want.peer_server})
        if self.module.check_mode:
            return True

        self.create_on_device()
        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        if self.want.peer_hostname is None:
            self.want.update({'peer_hostname': self.want.peer_server})
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to remove the trusted peer.")
        return True

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/cm/device".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        for device in response['items']:
            try:
                if device['managementIp'] == self.want.peer_server:
                    return True
            except KeyError:
                pass
        return False

    def create_on_device(self):
        params = self.want.api_params()
        params.update({
            "command": "run",
            "name": 'Root',
        })
        uri = "https://{0}:{1}/mgmt/tm/cm/add-to-trust/".format(
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

    def remove_from_device(self):
        params = self.want.api_params()
        params.update({
            "command": "run",
            "deviceName": self.want.peer_hostname,
            "name": self.want.peer_hostname,
        })
        uri = "https://{0}:{1}/mgmt/tm/cm/remove-from-trust/".format(
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


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            peer_server=dict(required=True),
            peer_hostname=dict(),
            peer_user=dict(),
            peer_password=dict(no_log=True),
            type=dict(
                choices=['peer', 'subordinate'],
                default='peer'
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
