#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_configsync_action
short_description: Perform different actions related to config-sync
description:
  - Allows running different config-sync actions. These actions allow
    you to manually sync your configuration across multiple BIG-IPs when
    those devices are in an HA pair.
version_added: "1.0.0"
options:
  device_group:
    description:
      - The device group on which you want to perform config-sync actions.
    type: str
    required: True
  sync_device_to_group:
    description:
      - Specifies the system synchronizes configuration data from this
        device to other members of the device group. In this case, the device
        performs a "push" to all the other devices in the group. This option
        is mutually exclusive with the C(sync_group_to_device) option.
    type: bool
  sync_group_to_device:
    description:
      - Specifies the system synchronizes configuration data from the
        device with the most recent configuration. In this case, the device
        performs a "pull" from the most recently updated device. This option
        is mutually exclusive with the C(sync_device_to_group) options.
    type: bool
  overwrite_config:
    description:
      - Indicates the sync operation overwrites the configuration on
        the target.
    type: bool
    default: false
notes:
  - Requires the objectpath Python package on the host. This is as easy as
    running C(pip install objectpath).
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Sync configuration from device to group
  bigip_configsync_action:
    device_group: foo-group
    sync_device_to_group: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Sync configuration from most recent device to the current host
  bigip_configsync_action:
    device_group: foo-group
    sync_group_to_device: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Perform an initial sync of a device to a new device group
  bigip_configsync_action:
    device_group: new-device-group
    sync_device_to_group: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
# only common fields returned
'''

import re
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule


from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem

try:
    from objectpath import Tree
    HAS_OBJPATH = True
except ImportError:
    HAS_OBJPATH = False


class Parameters(AnsibleF5Parameters):
    api_attributes = []
    returnables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def direction(self):
        if self.sync_device_to_group:
            return 'to-group'
        else:
            return 'from-group'

    @property
    def sync_device_to_group(self):
        result = flatten_boolean(self._values['sync_device_to_group'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def sync_group_to_device(self):
        result = flatten_boolean(self._values['sync_group_to_device'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def force_full_push(self):
        if self.overwrite_config:
            return 'force-full-load-push'
        else:
            return ''

    @property
    def overwrite_config(self):
        result = flatten_boolean(self._values['overwrite_config'])
        if result == 'yes':
            return True
        if result == 'no':
            return False


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
    pass


class Difference(object):
    pass


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

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
        result = dict()

        changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if not self._device_group_exists():
            raise F5ModuleError(
                "The specified 'device_group' not not exist."
            )
        if self._sync_to_group_required():
            raise F5ModuleError(
                "This device group needs an initial sync. Please use "
                "'sync_device_to_group'"
            )
        if self.exists():
            return False
        else:
            return self.execute()

    def _sync_to_group_required(self):
        status = self._get_status_from_resource()
        if status == 'Awaiting Initial Sync' and self.want.sync_group_to_device:
            return True
        return False

    def _device_group_exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/cm/device-group/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.device_group
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

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def execute(self):
        self.execute_on_device()
        self._wait_for_sync()
        return True

    def exists(self):
        status = self._get_status_from_resource()
        if status == 'In Sync':
            return True
        else:
            return False

    def execute_on_device(self):
        sync_cmd = 'config-sync {0} {1} {2}'.format(
            self.want.direction,
            self.want.device_group,
            self.want.force_full_push
        )
        uri = "https://{0}:{1}/mgmt/tm/cm".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        args = dict(
            command='run',
            utilCmdArgs=sync_cmd
        )
        resp = self.client.api.post(uri, json=args)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def _wait_for_sync(self):
        # Wait no more than half an hour
        for x in range(1, 180):
            time.sleep(3)
            status = self._get_status_from_resource()

            # Changes Pending:
            #     The existing device has changes made to it that
            #     need to be sync'd to the group.
            #
            # Awaiting Initial Sync:
            #     This is a new device group and has not had any sync
            #     done yet. You _must_ `sync_device_to_group` in this
            #     case.
            #
            # Not All Devices Synced:
            #     A device group will go into this state immediately
            #     after starting the sync and stay until all devices finish.
            #
            if status in ['Changes Pending']:
                details = self._get_details_from_resource()
                self._validate_pending_status(details)
            elif status in ['Awaiting Initial Sync', 'Not All Devices Synced']:
                pass
            elif status == 'In Sync':
                return
            elif status == 'Disconnected':
                raise F5ModuleError(
                    "One or more devices are unreachable (disconnected). "
                    "Resolve any communication problems before attempting to sync."
                )
            else:
                raise F5ModuleError(status)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/cm/sync-status/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response
        raise F5ModuleError(resp.content)

    def _get_status_from_resource(self):
        resource = self.read_current_from_device()
        entries = resource['entries'].copy()
        k, v = entries.popitem()
        status = v['nestedStats']['entries']['status']['description']
        return status

    def _get_details_from_resource(self):
        resource = self.read_current_from_device()
        stats = resource['entries'].copy()
        if HAS_OBJPATH:
            tree = Tree(stats)
        else:
            raise F5ModuleError(
                "objectpath module required, install objectpath module to continue. "
            )
        details = list(tree.execute('$..*["details"]["description"]'))
        result = details[::-1]
        return result

    def _validate_pending_status(self, details):
        """Validate the content of a pending sync operation

        This is a hack. The REST API is not consistent with its 'status' values
        so this method is here to check the returned strings from the operation
        and see if it reported any of these inconsistencies.

        :param details:
        :raises F5ModuleError:
        """
        pattern1 = r'.*(?P<msg>Recommended\s+action.*)'
        for detail in details:
            matches = re.search(pattern1, detail)
            if matches:
                raise F5ModuleError(matches.group('msg'))


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = False

        argument_spec = dict(
            sync_device_to_group=dict(
                type='bool'
            ),
            sync_group_to_device=dict(
                type='bool'
            ),
            overwrite_config=dict(
                type='bool',
                default='no'
            ),
            device_group=dict(
                required=True
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)

        self.required_one_of = [
            ['sync_device_to_group', 'sync_group_to_device']
        ]
        self.mutually_exclusive = [
            ['sync_device_to_group', 'sync_group_to_device']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
