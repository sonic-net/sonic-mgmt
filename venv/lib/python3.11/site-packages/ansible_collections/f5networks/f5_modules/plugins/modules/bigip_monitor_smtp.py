#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_monitor_smtp
short_description: Manage SMTP monitors on a BIG-IP
description:
  - Manage SMTP monitors on a BIG-IP.
version_added: "1.1.0"
options:
  name:
    description:
      - Specifies the name of the monitor.
    type: str
    required: True
  app_service:
    description:
      - The iApp service to be associated with this profile. When no service is
        specified, the default is None.
    type: str
  parent:
    description:
      - The parent template of this monitor template. Once this value has
        been set, it cannot be changed.
      - When creating a new monitor, if this parameter is not specified, the default
        is the system-supplied C(smtp) monitor.
    type: str
  description:
    description:
      - The description of the monitor.
    type: str
  debug:
    description:
      - Specifies whether the monitor sends error messages and additional information to a log file created and
        labeled specifically for this monitor.
      - "When C(true) the system redirects error messages and additional information to the
        C(/var/log/monitors/<monitor_name>-<node_name>-<port>.log) file."
    type: bool
  domain:
    description:
      - Specifies the domain name to check.
    type: str
  ip:
    description:
      - IP address part of the IP/port definition. If this parameter is not
        provided when creating a new monitor, the default value is '*'.
    type: str
  port:
    description:
      - Port address part of the IP/port definition. If this parameter is not
        provided when creating a new monitor, the default value is '*'.
        If specifying an IP address, you must specify a value between 1 and 65535.
    type: str
  interval:
    description:
      - The interval specifying how frequently the monitor instance of this
        template will run.
      - This value B(must) be less than the C(timeout) value.
      - When creating a new monitor, if this parameter is not provided, the
        default C(5) will be used.
    type: int
  up_interval:
    description:
      - Specifies the interval for the system to use to perform the health check
        when a resource is up.
      - When C(0), specifies the system uses the interval specified in
        C(interval) to check the health of the resource.
      - When any other number, enables you to specify a different interval to
        use when checking the health of a resource that is up.
      - When creating a new monitor, if this parameter is not provided, the
        default C(0) will be used.
    type: int
  timeout:
    description:
      - The number of seconds in which the node or service must respond to
        the monitor request.
      - If the target responds within the set time period, it is considered up.
      - If the target does not respond within the set time period, it is considered down.
      - You can change this to any number, however, it should be 3 times the
        interval number of seconds plus 1 second.
      - If this parameter is not provided when creating a new monitor, the default
        value will be C(31).
    type: int
  manual_resume:
    description:
      - Specifies whether the system automatically changes the status of a resource
        to B(enabled) at the next successful monitor check.
      - If you set this option to C(true), you must manually re-enable the resource
        before the system can use it for load balancing connections.
      - When creating a new monitor, if this parameter is not specified, the default
        value is C(false).
      - When C(true), specifies you must manually re-enable the resource after an
        unsuccessful monitor check.
      - When C(false), specifies the system automatically changes the status of a
        resource to B(enabled) at the next successful monitor check.
    type: bool
  time_until_up:
    description:
      - Specifies the amount of time in seconds after the first successful
        response before a node will be marked up.
      - A value of C(0) will cause a node to be marked up immediately after a valid
        response is received from the node.
      - If this parameter is not provided when creating a new monitor, then the default
        value will be C(0).
    type: int
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the monitor exists.
      - When C(absent), ensures the monitor is removed.
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
- name: Create SMTP Monitor
  bigip_monitor_smtp:
    state: present
    ip: 10.10.10.10
    name: my_smtp_monitor
    domain: foo.com
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Remove SMTP Monitor
  bigip_monitor_smtp:
    state: absent
    name: my_smtp_monitor
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
app_service:
  description: The iApp service associated with this monitor.
  returned: changed
  type: str
  sample: /Common/good_service.app/good_service
parent:
  description: The parent monitor.
  returned: changed
  type: str
  sample: /Common/foo_smtp
description:
  description: The description of the monitor.
  returned: changed
  type: str
  sample: Important Monitor
debug:
  description:
    - Whether the monitor sends error messages and additional information to a log file created and
      labeled specifically for this monitor.
  returned: changed
  type: bool
  sample: false
domain:
  description: Specifies the domain name to check.
  returned: changed
  type: str
  sample: bigipinternal.com
ip:
  description: The new IP of IP/port definition.
  returned: changed
  type: str
  sample: 10.12.13.14
port:
  description:
    - Alias port or service for the monitor to check, on behalf of the pools or pool
      members with which the monitor is associated.
  returned: changed
  type: str
  sample: 80
interval:
  description: The new interval in which to run the monitor check.
  returned: changed
  type: int
  sample: 2
up_interval:
  description: Interval for the system to use to perform the health check when a resource is up.
  returned: changed
  type: int
  sample: 0
timeout:
  description: The new timeout in which the remote system must respond to the monitor.
  returned: changed
  type: int
  sample: 10
manual_resume:
  description:
    - Specifies whether the system automatically changes the status of a
      resource to up at the next successful monitor check.
  returned: changed
  type: bool
  sample: true
time_until_up:
  description: The new time in which to mark a system as up after first successful response.
  returned: changed
  type: int
  sample: 2
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'appService': 'app_service',
        'defaultsFrom': 'parent',
        'timeUntilUp': 'time_until_up',
        'manualResume': 'manual_resume',
        'upInterval': 'up_interval',
    }

    api_attributes = [
        'defaultsFrom',
        'debug',
        'description',
        'destination',
        'domain',
        'interval',
        'upInterval',
        'timeout',
        'manualResume',
        'timeUntilUp',
    ]

    returnables = [
        'app_service',
        'parent',
        'description',
        'destination',
        'debug',
        'domain',
        'ip',
        'port',
        'interval',
        'up_interval',
        'timeout',
        'manual_resume',
        'time_until_up',

    ]

    updatables = [
        'app_service',
        'description',
        'debug',
        'destination',
        'domain',
        'ip',
        'port',
        'interval',
        'up_interval',
        'timeout',
        'manual_resume',
        'time_until_up',
    ]


class ApiParameters(Parameters):
    @property
    def ip(self):
        des = self._values['destination']
        ip, d, port = des.rpartition('.')
        if not is_valid_ip(ip) and ip != '*':
            ip, d, port = des.rpartition(':')
        return ip

    @property
    def port(self):
        des = self._values['destination']
        ip, d, port = des.rpartition('.')
        if not is_valid_ip(ip) and ip != '*':
            ip, d, port = des.rpartition(':')
        return int(port) if port.isnumeric() else port

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def domain(self):
        if self._values['domain'] in [None, 'none']:
            return None
        return self._values['domain']


class ModuleParameters(Parameters):
    @property
    def description(self):
        if self._values['description'] is None:
            return None
        elif self._values['description'] in ['none', '']:
            return ''
        return self._values['description']

    @property
    def domain(self):
        if self._values['domain'] is None:
            return None
        elif self._values['domain'] in ['none', '']:
            return ''
        return self._values['domain']

    @property
    def parent(self):
        if self._values['parent'] is None:
            return None
        result = fq_name(self.partition, self._values['parent'])
        return result

    @property
    def interval(self):
        if self._values['interval'] is None:
            return None
        if 1 > self._values['interval'] > 86400:
            raise F5ModuleError(
                "Interval value must be between 1 and 86400."
            )
        return self._values['interval']

    @property
    def timeout(self):
        if self._values['timeout'] is None:
            return None
        if self._values['timeout'] is None:
            return None
        if 1 > self._values['timeout'] > 86400:
            raise F5ModuleError(
                "Timeout value must be between 1 and 86400."
            )
        return self._values['timeout']

    @property
    def ip(self):
        if self._values['ip'] is None:
            return None
        if self._values['ip'] in ['*', '0.0.0.0']:
            return '*'
        elif is_valid_ip(self._values['ip']) or is_valid_ip(self._values['ip'].split("%")[0]):
            return self._values['ip']
        else:
            raise F5ModuleError(
                "The provided 'ip' parameter is not an IP address."
            )

    @property
    def port(self):
        if self._values['port'] is None:
            return None
        elif self._values['port'] == '*':
            return '*'
        return int(self._values['port'])

    @property
    def destination(self):
        if self.ip is None and self.port is None:
            return None
        destination = '{0}:{1}'.format(self.ip, self.port)
        return destination

    @destination.setter
    def destination(self, value):
        ip, port = value.split(':')
        self._values['ip'] = ip
        self._values['port'] = port

    @property
    def time_until_up(self):
        if self._values['time_until_up'] is None:
            return None
        if self._values['time_until_up'] is None:
            return None
        if 0 > self._values['time_until_up'] > 86400:
            raise F5ModuleError(
                "Time_until_up value must be between 0 and 86400."
            )
        return self._values['time_until_up']

    @property
    def manual_resume(self):
        result = flatten_boolean(self._values['manual_resume'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def debug(self):
        result = flatten_boolean(self._values['debug'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'


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
    def debug(self):
        return flatten_boolean(self._values['debug'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])


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
    def destination(self):
        if self.want.ip is None and self.want.port is None:
            return None
        if self.want.port is None:
            self.want.update({'port': self.have.port})
        if self.want.ip is None:
            self.want.update({'ip': self.have.ip})

        if self.want.port in [None, '*'] and self.want.ip != '*':
            raise F5ModuleError(
                "Specifying an IP address requires that a port number be specified."
            )
        if self.want.destination != self.have.destination:
            return self.want.destination

    @property
    def description(self):
        return cmp_str_with_none(self.want.description, self.have.description)

    @property
    def domain(self):
        return cmp_str_with_none(self.want.domain, self.have.domain)

    @property
    def interval(self):
        if self.want.timeout is not None and self.want.interval is not None:
            if self.want.interval >= self.want.timeout:
                raise F5ModuleError(
                    "Parameter 'interval' must be less than 'timeout'."
                )
        elif self.want.timeout is not None:
            if self.have.interval >= self.want.timeout:
                raise F5ModuleError(
                    "Parameter 'interval' must be less than 'timeout'."
                )
        elif self.want.interval is not None:
            if self.want.interval >= self.have.timeout:
                raise F5ModuleError(
                    "Parameter 'interval' must be less than 'timeout'."
                )
        if self.want.interval != self.have.interval:
            return self.want.interval


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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/smtp/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/smtp/".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/smtp/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/smtp/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/smtp/{2}".format(
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
            app_service=dict(),
            parent=dict(),
            description=dict(),
            debug=dict(type='bool'),
            domain=dict(),
            ip=dict(),
            port=dict(),
            interval=dict(type='int'),
            up_interval=dict(type='int'),
            timeout=dict(type='int'),
            manual_resume=dict(type='bool'),
            time_until_up=dict(type='int'),
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
