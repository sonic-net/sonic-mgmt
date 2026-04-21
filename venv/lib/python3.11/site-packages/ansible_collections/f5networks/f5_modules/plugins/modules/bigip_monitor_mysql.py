#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_monitor_mysql
short_description: Manages BIG-IP MySQL monitors
description:
  - Manages BIG-IP MySQL monitors.
version_added: "1.3.0"
options:
  name:
    description:
      - Monitor name.
    type: str
    required: True
  app_service:
    description:
      - The iApp service to be associated with this profile. When no service is
        specified, the default is None.
    type: str
  description:
    description:
      - Specifies descriptive text that identifies the monitor.
    type: str
  parent:
    description:
      - The parent template of this monitor template. Once this value has
        been set, it cannot be changed.
      - By default, this value is the C(mysql) parent on the C(Common) partition.
    type: str
  count:
    description:
      - Specifies the number of monitor probes after which the connection to the database is terminated.
    type: int
  database:
    description:
      - Specifies the name of the database that the monitor tries to access.
    type: str
  debug:
    description:
      - Specifies whether the monitor sends error messages
        and additional information to a log file created and labeled specifically for this monitor.
    type: bool
  ip:
    description:
      - IP address part of the IP/port definition. If this parameter is not
        provided when creating a new monitor, then the default value is '*'.
    type: str
  port:
    description:
      - Port address part of the IP/port definition. If this parameter is not
        provided when creating a new monitor, the default value is '*'.
      - If specifying an IP address, you must specify a value between 1 and 65535.
    type: str
  target_password:
    description:
      - Specifies the password if the monitored target requires authentication.
    type: str
  target_username:
    description:
      - Specifies the user name if the monitored target requires authentication.
    type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  interval:
    description:
      - Specifies the frequency at which the system issues the monitor check.
    type: int
  timeout:
    description:
      - Specifies the number of seconds the target has in which to respond to
        the monitor request.
      - If the target responds within the set time period, it is considered 'up'.
        If the target does not respond within the set time period, it is considered
        'down'. When this value is set to 0 (zero), the system uses the interval
        from the parent monitor.
      - Note that C(timeout) and C(time_until_up) combine to control when a
        resource is set to up.
    type: int
  time_until_up:
    description:
      - Specifies the number of seconds to wait after a resource first responds
        correctly to the monitor before setting the resource to 'up'.
      - During the interval, all responses from the resource must be correct.
      - When the interval expires, the resource is marked 'up'.
      - A value of 0, means that the resource is marked up immediately upon
        receipt of the first correct response.
    type: int
  up_interval:
    description:
      - Specifies the interval for the system to use to perform the health check
        when a resource is up.
      - When C(0), specifies the system uses the interval specified in
        C(interval) to check the health of the resource.
      - When any other number, enables you to specify a different interval to
        use when checking the health of a resource that is up.
    type: int
  manual_resume:
    description:
      - Specifies whether the system automatically changes the status of a resource
        to B(enabled) at the next successful monitor check.
      - If you set this option to C(true), you must manually re-enable the resource
        before the system can use it for load balancing connections.
      - When C(true), specifies you must manually re-enable the resource after an
        unsuccessful monitor check.
      - When C(false), specifies the system automatically changes the status of a
        resource to B(enabled) at the next successful monitor check.
    type: bool
  recv:
    description:
      - Specifies the text string the monitor looks for in the returned resource.
      - The most common receive expressions contain a text string
        that is included in a field in your database.
      - If you do not specify both a Send String and a Receive String,
        the monitor performs a simple service check and connect only.
    type: str
  recv_column:
    description:
      - Specifies the column in the database where the system expects
        the specified Receive String to be located.
      - This is an optional setting, and is applicable only
        if you configure the C(send) and C(recv) options.
    type: str
  recv_row:
    description:
      - Specifies the row in the database where the system expects the specified Receive String to be located.
      - This is an optional setting, and is applicable only if you configure the C(send) and C(recv) options.
    type: str
  send:
    description:
      - Specifies the SQL query the monitor sends to the target object.
      - Because the string may have special characters, the system may require the string be enclosed with single
        quotation marks. If this value is C(none), then a valid connection suffices to determine that the service is up.
        In this case, the system does not need the recv, recv-row, and recv-column options and ignores them
        even if not C(none).
    type: str
  update_password:
    description:
      - C(always) will update passwords if the C(target_password) is specified.
      - C(on_create) will only set the password for newly created monitors.
    type: str
    choices:
      - always
      - on_create
    default: always
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
  - Andrey Kashcheev (@andreykashcheev)
'''

EXAMPLES = r'''
- name: Create an mysql monitor
  bigip_monitor_mysql:
    ip: 10.10.10.10
    port: 10923
    name: my_mysql_monitor
    send: "SELECT status FROM v$instance"
    recv: OPEN
    recv_column: 2
    recv_row: 1
    database: primary1
    target_username: bigip
    target_password: secret
    update_password: on_create
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Modify an mysql monitor
  bigip_monitor_mysql:
    name: my_mysql_monitor
    recv_column: 4
    recv_row: 3
    database: primary2
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Remove mysql monitor
  bigip_monitor_mysql:
    state: absent
    name: my_mysql_monitor
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
  sample: /Common/foo_mysql
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
  description: The new interval at which to run the monitor check.
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
recv:
  description: The text string the monitor looks for in the returned resource.
  returned: changed
  type: str
  sample: OPEN
send:
  description: The SQL query the monitor sends to the target object.
  returned: changed
  type: str
  sample: "SELECT status FROM v$instance"
database:
  description: The name of the database the monitor tries to access.
  returned: changed
  type: str
  sample: primary1
target_username:
  description: The user name for the the monitored target.
  returned: changed
  type: str
  sample: bigip
recv_column:
  description: The column in the database where the specified string should be located.
  returned: changed
  type: str
  sample: 2
recv_row:
  description: The row in the database where the specified string should be located.
  returned: changed
  type: str
  sample: 1
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'appService': 'app_service',
        'upInterval': 'up_interval',
        'timeUntilUp': 'time_until_up',
        'password': 'target_password',
        'username': 'target_username',
        'defaultsFrom': 'parent',
        'manualResume': 'manual_resume',
        'recvColumn': 'recv_column',
        'recvRow': 'recv_row'
    }

    api_attributes = [
        'recvColumn',
        'recvRow',
        'timeUntilUp',
        'username',
        'count',
        'password',
        'timeout',
        'destination',
        'send',
        'recv',
        'debug',
        'interval',
        'upInterval',
        'manualResume',
        'database'
    ]

    returnables = [
        'app_service',
        'count',
        'timeout',
        'debug',
        'ip',
        'port',
        'destination',
        'time_until_up',
        'up_interval',
        'interval',
        'upInterval',
        'manual_resume',
        'target_username',
        'target_password',
        'description',
        'send',
        'recv',
        'recv_column',
        'recv_row',
        'database'
    ]

    updatables = [
        'app_service',
        'destination',
        'count',
        'timeout',
        'debug',
        'time_until_up',
        'up_interval',
        'manual_resume',
        'interval',
        'upInterval',
        'target_username',
        'target_password',
        'send',
        'recv',
        'recv_column',
        'recv_row',
        'database'
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
        return port

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def count(self):
        if self._values['count'] is None:
            return None
        result = int(self._values['count'])
        return result


class ModuleParameters(Parameters):
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
    def manual_resume(self):
        result = flatten_boolean(self._values['manual_resume'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def debug(self):
        return flatten_boolean(self._values['debug'])

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
    def interval(self):
        if self._values['interval'] is None:
            return None
        if 1 > int(self._values['interval']) > 86400:
            raise F5ModuleError(
                "Interval value must be between 1 and 86400"
            )
        return int(self._values['interval'])

    @property
    def description(self):
        if self._values['description'] is None:
            return None
        elif self._values['description'] in ['none', '']:
            return ''
        return self._values['description']

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
    def count(self):
        if self._values['count'] is None:
            return None
        result = str(self._values['count'])
        return result


class ReportableChanges(Changes):
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
        return int(port)

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def count(self):
        if self._values['count'] is None:
            return None
        result = int(self._values['count'])
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
        return cmp_str_with_none(self.want.description, self.have.description)

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
                "Specifying an IP address requires that a port number be specified"
            )

        if self.want.destination != self.have.destination:
            return self.want.destination

    @property
    def target_password(self):
        if self.want.target_password != self.have.target_password:
            if self.want.update_password == 'always':
                result = self.want.target_password
                return result

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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/mysql/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/mysql/".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/mysql/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/mysql/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/mysql/{2}".format(
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
            count=dict(type='int'),
            app_service=dict(),
            name=dict(required=True),
            parent=dict(),
            ip=dict(),
            description=dict(),
            port=dict(),
            database=dict(),
            interval=dict(type='int'),
            timeout=dict(type='int'),
            target_username=dict(),
            target_password=dict(no_log=True),
            debug=dict(type='bool'),
            time_until_up=dict(type='int'),
            up_interval=dict(type='int'),
            manual_resume=dict(type='bool'),
            send=dict(),
            recv=dict(),
            recv_row=dict(),
            recv_column=dict(),
            update_password=dict(
                default='always',
                choices=['always', 'on_create'],
                no_log=False
            ),
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
