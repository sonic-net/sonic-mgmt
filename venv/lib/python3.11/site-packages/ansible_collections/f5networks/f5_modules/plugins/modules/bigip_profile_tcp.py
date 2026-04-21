#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_profile_tcp
short_description: Manage TCP profiles on a BIG-IP
description:
  - Manage TCP profiles on a BIG-IP system. There are many TCP profiles, each with their
    own adjustments to the standard C(tcp) profile. Users of this module should be aware
    that many of the available options have no module default. Instead, the default is
    assigned by the BIG-IP system itself which, in most cases, is acceptable.
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
        is the system-supplied C(tcp) profile.
    type: str
  idle_timeout:
    description:
      - Specifies the length of time a connection is idle (has no traffic) before
        the connection is eligible for deletion.
      - When creating a new profile, if this parameter is not specified, the remote
        device will choose a default value appropriate for the profile, based on its
        C(parent) profile.
      - When a number is specified, indicates the number of seconds the TCP
        connection can remain idle before the system deletes it.
      - When C(0), or C(indefinite), specifies the system does not delete TCP connections
        regardless of how long they remain idle.
    type: str
  keep_alive_interval:
    description:
      - Specifies how frequently the system sends data over an idle TCP connection,
        to determine whether the connection is still valid.
      - When creating a new profile, if this parameter is not specified, the remote
        device will choose a default value appropriate for the profile, based on its
        C(parent) profile.
      - When C(0), or C(indefinite), specifies that the system does not send keep-alive communication.
    type: str
    version_added: "1.22.0"
  time_wait_recycle:
    description:
      - Specifies connections in a TIME-WAIT state are reused if a SYN packet (indicating a request
        for a new connection) is received.
      - When C(false), connections in a TIME-WAIT state remain unused for a specified length of time.
      - When creating a new profile, if this parameter is not specified, the default
        is provided by the parent profile.
    type: bool
  nagle:
    description:
      - When C(enabled) the system applies Nagle's algorithm to reduce the number of short segments on the network.
      - When C(auto), the use of Nagle's algorithm is decided based on network conditions.
      - For interactive protocols such as Telnet, rlogin, or SSH, F5 recommends disabling this setting on
        high-latency networks, to improve application responsiveness.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: str
    choices:
      - auto
      - enabled
      - disabled
  early_retransmit:
    description:
      - When C(true), the system uses early fast retransmits to reduce the recovery time for connections that are
        receive-buffer or user-data limited.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: bool
  proxy_options:
    description:
      - When C(true), the system advertises an option, such as a time-stamp, to the server only if it was negotiated
        with the client.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: bool
  initial_congestion_window_size:
    description:
      - Specifies the initial congestion window size for connections to this destination. The actual window size is
        this value multiplied by the MSS for the same connection.
      - When set to C(0), the system uses the values specified in RFC2414.
      - The valid value range is 0 - 16 inclusive.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: int
  initial_receive_window_size:
    description:
      - Specifies the initial receive window size for connections to this destination. The actual window size is
        this value multiplied by the MSS for the same connection.
      - When set to C(0), the system uses the Slow Start value.
      - The valid value range is 0 - 16 inclusive.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: int
  syn_rto_base:
    description:
      - Specifies the initial RTO C(Retransmission TimeOut) base multiplier for SYN retransmission, in C(milliseconds).
      - This value is modified by the exponential backoff table to select the interval for subsequent retransmissions.
      - The valid value range is 0 - 5000 inclusive.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: int
  delayed_acks:
    description:
      - When C(true), the system sends fewer than one ACK segment per data segment received.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: bool
  ip_tos_to_client:
    description:
      - Specifies the L3 Type of Service level the system inserts in TCP packets destined for clients.
      - When C(pass-through), the IP ToS setting remains unchanged.
      - When C(mimic), the system sets the ToS level of outgoing packets to the same ToS level of the most-recently
        received incoming packet.
      - When set as a number, the number indicates the IP ToS setting the system inserts in the IP packet header.
        Valid number range is 0 - 255 inclusive.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: str
  time_wait_timeout:
    description:
      - Specifies the number of milliseconds a connection is in the TIME-WAIT state before closing.
      - When C(immediate), the system closes the connection immediately after the connection enters the TIME-WAIT state.
      - When C(indefinite) or C(0), the system does not close TCP connections regardless of how long they remain in the
        TIME-WAIT state.
      - The valid number range is from 0 to 600000 milliseconds.
      - When creating a new profile, if this parameter is not specified, the default is provided by the parent profile.
    type: str
    version_added: "1.3.0"
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
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create a TCP profile
  bigip_profile_tcp:
    name: foo
    parent: f5-tcp-progressive
    time_wait_recycle: false
    idle_timeout: 300
    state: present
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost
'''

RETURN = r'''
parent:
  description: The new parent of the resource.
  returned: changed
  type: str
  sample: f5-tcp-optimized
idle_timeout:
  description: The new idle timeout of the resource.
  returned: changed
  type: int
  sample: 100
time_wait_recycle:
  description: Reuse connections in TIME-WAIT state.
  returned: changed
  type: bool
  sample: true
nagle:
  description: Specifies the use of Nagle's algorithm.
  returned: changed
  type: str
  sample: auto
early_retransmit:
  description: Specifies the use of early fast retransmits.
  returned: changed
  type: bool
  sample: true
proxy_options:
  description: Specifies if the system advertises negotiated options to the server.
  returned: changed
  type: bool
  sample: false
initial_congestion_window_size:
  description: Specifies the initial congestion window size for connections to this destination.
  returned: changed
  type: int
  sample: 5
initial_receive_window_size:
  description: Specifies the initial receive window size for connections to this destination.
  returned: changed
  type: int
  sample: 10
syn_rto_base:
  description: Specifies the initial Retransmission TimeOut base multiplier for SYN retransmission.
  returned: changed
  type: int
  sample: 2000
delayed_acks:
  description: Specifies if the system sends fewer than one ACK segment per data segment received.
  returned: changed
  type: bool
  sample: true
ip_tos_to_client:
  description: Specifies the L3 Type of Service level that the system inserts in TCP packets destined for clients.
  returned: changed
  type: str
  sample: mimic
time_wait_timeout:
  description: Specifies the number of milliseconds that a connection is in the TIME-WAIT state before closing.
  returned: changed
  type: str
  sample: immediate
keep_alive_interval:
  description: Specifies how frequently the system sends data over an idle TCP connection.
  returned: changed
  type: str
  sample: indefinite
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
        'idleTimeout': 'idle_timeout',
        'defaultsFrom': 'parent',
        'timeWaitRecycle': 'time_wait_recycle',
        'earlyRetransmit': 'early_retransmit',
        'proxyOptions': 'proxy_options',
        'initCwnd': 'initial_congestion_window_size',
        'initRwnd': 'initial_receive_window_size',
        'synRtoBase': 'syn_rto_base',
        'delayedAcks': 'delayed_acks',
        'ipTosToClient': 'ip_tos_to_client',
        'timeWaitTimeout': 'time_wait_timeout',
        'keepAliveInterval': 'keep_alive_interval',
    }

    api_attributes = [
        'idleTimeout',
        'defaultsFrom',
        'timeWaitRecycle',
        'nagle',
        'earlyRetransmit',
        'proxyOptions',
        'initCwnd',
        'initRwnd',
        'synRtoBase',
        'delayedAcks',
        'ipTosToClient',
        'timeWaitTimeout',
        'keepAliveInterval',
    ]

    returnables = [
        'idle_timeout',
        'parent',
        'time_wait_recycle',
        'nagle',
        'early_retransmit',
        'proxy_options',
        'initial_congestion_window_size',
        'initial_receive_window_size',
        'syn_rto_base',
        'delayed_acks',
        'ip_tos_to_client',
        'time_wait_timeout',
        'keep_alive_interval',
    ]

    updatables = [
        'idle_timeout',
        'parent',
        'time_wait_recycle',
        'nagle',
        'early_retransmit',
        'proxy_options',
        'initial_congestion_window_size',
        'initial_receive_window_size',
        'syn_rto_base',
        'delayed_acks',
        'ip_tos_to_client',
        'time_wait_timeout',
        'keep_alive_interval',
    ]


class ApiParameters(Parameters):
    @property
    def ip_tos_to_client(self):
        if self._values['ip_tos_to_client'] is None:
            return None
        if self._values['ip_tos_to_client'] in ['pass-through', 'mimic']:
            return self._values['ip_tos_to_client']
        return int(self._values['ip_tos_to_client'])

    @property
    def time_wait_timeout(self):
        if self._values['time_wait_timeout'] is None:
            return None
        if self._values['time_wait_timeout'] == '0':
            return 'immediate'
        return self._values['time_wait_timeout']


class ModuleParameters(Parameters):
    @property
    def time_wait_timeout(self):
        if self._values['time_wait_timeout'] is None:
            return None
        if self._values['time_wait_timeout'] == '0':
            return 'immediate'
        if self._values['time_wait_timeout'] in ['indefinite', 'immediate']:
            return self._values['time_wait_timeout']
        if 0 <= int(self._values['time_wait_timeout']) <= 600000:
            return self._values['time_wait_timeout']
        raise F5ModuleError(
            "Valid 'time_wait_timeout' must be in range 0 - 600000 milliseconds or 'immediate', 'indefinite'."
        )

    @property
    def parent(self):
        if self._values['parent'] is None:
            return None
        result = fq_name(self.partition, self._values['parent'])
        return result

    @property
    def idle_timeout(self):
        if self._values['idle_timeout'] is None:
            return None
        if self._values['idle_timeout'] == 'indefinite':
            return 4294967295
        return int(self._values['idle_timeout'])

    @property
    def keep_alive_interval(self):
        if self._values['keep_alive_interval'] is None:
            return None
        if self._values['keep_alive_interval'] == 'indefinite':
            return 0
        if 0 <= int(self._values['keep_alive_interval']) <= 4294967295:
            return int(self._values['keep_alive_interval'])
        raise F5ModuleError(
            "Valid 'keep_alive_interval' must be in range 0 - 4294967295 or 'indefinite'."
        )

    @property
    def time_wait_recycle(self):
        result = flatten_boolean(self._values['time_wait_recycle'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def early_retransmit(self):
        result = flatten_boolean(self._values['early_retransmit'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def proxy_options(self):
        result = flatten_boolean(self._values['proxy_options'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def initial_congestion_window_size(self):
        if self._values['initial_congestion_window_size'] is None:
            return None
        if 0 <= self._values['initial_congestion_window_size'] <= 16:
            return self._values['initial_congestion_window_size']
        raise F5ModuleError(
            "Valid 'initial_congestion_window_size' must be in range 0 - 16 MSS unit."
        )

    @property
    def initial_receive_window_size(self):
        if self._values['initial_receive_window_size'] is None:
            return None
        if 0 <= self._values['initial_receive_window_size'] <= 16:
            return self._values['initial_receive_window_size']
        raise F5ModuleError(
            "Valid 'initial_receive_window_size' must be in range 0 - 16 MSS unit."
        )

    @property
    def syn_rto_base(self):
        if self._values['syn_rto_base'] is None:
            return None
        if 0 <= self._values['syn_rto_base'] <= 5000:
            return self._values['syn_rto_base']
        raise F5ModuleError(
            "Valid 'syn_rto_base' must be in range 0 - 5000 milliseconds."
        )

    @property
    def delayed_acks(self):
        result = flatten_boolean(self._values['delayed_acks'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def ip_tos_to_client(self):
        if self._values['ip_tos_to_client'] is None:
            return None
        if self._values['ip_tos_to_client'] in ['pass-through', 'mimic']:
            return self._values['ip_tos_to_client']
        if 0 <= int(self._values['ip_tos_to_client']) <= 255:
            return int(self._values['ip_tos_to_client'])
        raise F5ModuleError(
            "Valid 'ip_tos_to_client' must be in range 0 - 255 or 'pass-through', 'mimic'."
        )


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
    def idle_timeout(self):
        if self._values['idle_timeout'] is None:
            return None
        if 0 <= self._values['idle_timeout'] <= 4294967295:
            return self._values['idle_timeout']
        raise F5ModuleError(
            "Valid 'idle_timeout' must be in range 1 - 4294967295, or 'indefinite'."
        )

    @property
    def time_wait_timeout(self):
        if self._values['time_wait_timeout'] is None:
            return None
        if self._values['time_wait_timeout'] == 'immediate':
            return '0'
        return self._values['time_wait_timeout']


class ReportableChanges(Changes):
    @property
    def idle_timeout(self):
        if self._values['idle_timeout'] is None:
            return None
        if self._values['idle_timeout'] == 4294967295:
            return 'indefinite'
        return int(self._values['idle_timeout'])

    @property
    def keep_alive_interval(self):
        if self._values['keep_alive_interval'] is None:
            return None
        if self._values['keep_alive_interval'] == 0:
            return 'indefinite'
        return str(self._values['keep_alive_interval'])

    @property
    def time_wait_recycle(self):
        if self._values['time_wait_recycle'] is None:
            return None
        elif self._values['time_wait_recycle'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def early_retransmit(self):
        result = flatten_boolean(self._values['early_retransmit'])
        return result

    @property
    def proxy_options(self):
        result = flatten_boolean(self._values['proxy_options'])
        return result

    @property
    def time_wait_timeout(self):
        if self._values['time_wait_timeout'] is None:
            return None
        if self._values['time_wait_timeout'] == '0':
            return 'immediate'
        return self._values['time_wait_timeout']


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
    def ip_tos_to_client(self):
        if self.want.ip_tos_to_client is None:
            return None
        if self.want.ip_tos_to_client in ['pass-through', 'mimic']:
            if isinstance(self.have.ip_tos_to_client, int):
                return self.want.ip_tos_to_client
        if self.have.ip_tos_to_client in ['pass-through', 'mimic']:
            if isinstance(self.want.ip_tos_to_client, int):
                return self.want.ip_tos_to_client
        if self.want.ip_tos_to_client != self.have.ip_tos_to_client:
            return self.want.ip_tos_to_client


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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/tcp/{2}".format(
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
        if self.want.parent is None:
            self.want.update({'parent': fq_name(self.want.partition, 'tcp')})
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/tcp/".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/tcp/{2}".format(
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

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/tcp/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/tcp/{2}".format(
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
            parent=dict(),
            idle_timeout=dict(),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            time_wait_recycle=dict(type='bool'),
            nagle=dict(
                choices=['enabled', 'disabled', 'auto']
            ),
            early_retransmit=dict(type='bool'),
            proxy_options=dict(type='bool'),
            initial_congestion_window_size=dict(type='int'),
            initial_receive_window_size=dict(type='int'),
            syn_rto_base=dict(type='int'),
            delayed_acks=dict(type='bool'),
            ip_tos_to_client=dict(),
            time_wait_timeout=dict(),
            keep_alive_interval=dict(),
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
