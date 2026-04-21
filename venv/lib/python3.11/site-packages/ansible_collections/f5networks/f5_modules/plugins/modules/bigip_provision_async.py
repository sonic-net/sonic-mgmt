#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_provision_async
short_description: Manage BIG-IP module provisioning
description:
  - Manages BIG-IP module provisioning. This module will perform provisioning operations in an asynchronous way. See the Notes
    section for more information.
version_added: "1.25.0"
options:
  module:
    description:
      - The module to provision in BIG-IP.
    type: str
    required: True
    choices:
      - am
      - afm
      - apm
      - asm
      - avr
      - cgnat
      - fps
      - gtm
      - ilx
      - lc
      - ltm
      - mgmt
      - pem
      - sam
      - sslo
      - swg
      - urldb
      - vcmp
    aliases:
      - name
  level:
    description:
      - Sets the provisioning level for the requested modules. Changing the
        level for one module may require modifying the level of another module.
        For example, changing one module to C(dedicated) requires setting all
        others to C(none). Setting the level of a module to C(none) means
        the module is not activated.
      - Use a C(state) if B(absent) to set c(level) to none and de-provision the module.
      - This parameter is not relevant to C(cgnat - pre tmos 15.0) or C(mgmt) and will not be
        applied to the C(cgnat - pre tmos 15.0) or the C(mgmt) module.
    type: str
    choices:
      - dedicated
      - nominal
      - minimum
    default: nominal
  memory:
    description:
      - Sets additional memory for the management module. This is in addition to
        the minimum allocated RAM of 1264MB.
      - The accepted value range is C(0 - 8192). Maximum value is restricted by
        the available RAM in the system.
      - Specifying C(large) reserves an additional 500MB for the mgmt module.
      - Specifying C(medium) reserves an additional 200MB for the mgmt module.
      - Specifying C(small) reserves no additional RAM for the mgmt module.
      - Use C(large) for configurations containing more than 2000 objects, or
        more specifically, for any configuration that exceeds 1000 objects
        per 2 GB of installed memory. Changing the Management C(mgmt) size
        after initial provisioning causes a re-provision operation.
    type: str
  check_status:
    description:
      - If C(true), then the module will run to check provisioning progress.
      - Required parameter, if using the C(module) parameter.
    type: bool
    default: false
  status_timeout:
    description:
      - The amount of time in seconds to wait for provisioning process to finish.
      - The accepted value range is between C(150) and C(3600) seconds.
      - If the device needs to restart the module, then it will return with no change and an appropriate message. In such cases,
        you must pause the playbook execution, until the device is ready (see the C(EXAMPLES) section).
    type: int
    default: 300
  state:
    description:
      - The state of the provisioned module on the system. If C(present), then that
        guarantees the specified module is provisioned at the requested
        level, provided there are sufficient resources on the device (such
        as physical RAM) to support the module.
      - If C(absent), then that de-provisions the module.
      - C(absent), is not an option for the C(mgmt) module, as it cannot be de-provisioned.
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
notes:
  - Checking for provisioning status with the C(check_status) parameter is not idempotent (see the C(EXAMPLES) section).
  - The module allows the same provisioning operations as bigip_provision with the difference being that it will
    not wait through the service restarts or device reboots. This is to fix the edge cases, when using this module in
    certain environments that can cause a timeout or be stuck in infinite loops, despite the provisioning operation being
    successful.
  - Use the module in conjunction with the C(bigip_wait) module, for best results.
  - This module requires TMOS version of 15.x and above.
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Provision GTM on the device
  bigip_provision_async:
    module: "gtm"
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin

- name: Check for provision progress
  bigip_provision_async:
    module: "gtm"
    check_status: true
    status_timeout: 900
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  register: status

- name: Wait for 3 minutes if device is restarting services
  bigip_wait:
    timeout: 180
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  when:
    - result.message == "Device is restarting services, unable to check provisioning status."

- name: Re-check for provision progress
  bigip_provision_async:
    module: "gtm"
    check_status: true
    status_timeout: 900
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  register: status
  when:
    - status.message == "Device is restarting services, unable to check provisioning status."

- name: Provision GTM on the device - Idempotent Check
  bigip_provision_async:
    module: "gtm"
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  register: result
  when:
    - status.message == "Device has finished provisioning the requested module."

- name: Assert Provision GTM on the device - Idempotent Check
  assert:
    that:
      - result is not changed
  when:
    - status.message == "Device has finished provisioning the requested module."

- name: Provision VCMP on the device
  bigip_provision_async:
    module: "vcmp"
    level: "dedicated"
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost

- name: Check for provision progress
  bigip_provision_async:
    module: "vcmp"
    level: "dedicated"
    check_status: true
    status_timeout: 900
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  register: status

- name: Wait for 10 minutes if device is restarting services
  bigip_wait:
    timeout: 600
    type: vcmp
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  when:
    - result.message == "Device is restarting services, unable to check provisioning status."

- name: Re-check for provision progress
  bigip_provision_async:
    module: "vcmp"
    level: "dedicated"
    check_status: true
    status_timeout: 900
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  delegate_to: localhost
  register: status
  when:
    - status.message == "Device is restarting services, unable to check provisioning status."

- name: Provision VCMP on the device - Idempotent Check
  bigip_provision_async:
    module: "vcmp"
    level: "dedicated"
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  register: result
  delegate_to: localhost
  when:
    - status.message == "Device has finished provisioning the requested module."

- name: Assert Provision VCMP on the device - Idempotent Check
  assert:
    that:
      - result is not changed
  when:
    - status.message == "Device has finished provisioning the requested module."

- name: De-provision VCMP on the device
  bigip_provision_async:
    module: "vcmp"
    state: "absent"
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin

- name: Check for de-provision progress
  bigip_provision_async:
    module: "vcmp"
    state: "absent"
    check_status: true
    status_timeout: 900
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  register: status

- name: Wait for 10 minutes if device is restarting services
  bigip_wait:
    timeout: 600
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  when:
    - result.message == "Device is restarting services, unable to check provisioning status."

- name: Re-check for de-provision progress
  bigip_provision_async:
    module: "vcmp"
    state: "absent"
    check_status: true
    status_timeout: 900
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  register: status
  when:
    - status.message == "Device is restarting services, unable to check provisioning status."

- name: De-provision VCMP on the device - Idempotent Check
  bigip_provision_async:
    module: "vcmp"
    state: "absent"
    provider:
      server: lb.mydomain.com
      password: secret
      user: admin
  register: result
  when:
    - status.message == "Device has finished de-provisioning the requested module."

- name: Assert Provision VCMP on the device - Idempotent Check
  assert:
    that:
      - result is not changed
  when:
    - status.message == "Device has finished de-provisioning the requested module."
'''

RETURN = r'''
level:
  description: The new provisioning level of the module.
  returned: changed
  type: str
  sample: minimum
memory:
  description: The new provisioned amount of memory for the mgmt module.
  returned: changed
  type: str
  sample: large
message:
  description: Informative message of the ansible task status.
  returned: changed
  type: dict
  sample: hash/dictionary of values
'''
import time
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
    AnsibleModule, missing_required_lib
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec,
)
from ..module_utils.icontrol import (
    TransactionContextManager, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'value': 'memory',
    }

    api_attributes = [
        'level',
        'value',
    ]

    returnables = [
        'level',
        'memory',
        'message',
    ]

    updatables = [
        'level',
        'cgnat',
        'memory',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):

    def _validate_memory_limit(self, limit):
        if self._values['memory'] == 'small':
            return '0'
        if self._values['memory'] == 'medium':
            return '200'
        if self._values['memory'] == 'large':
            return '500'
        if 0 <= int(limit) <= 8192:
            return str(limit)
        raise F5ModuleError(
            "Valid 'memory' must be in range 0 - 8192, 'small', 'medium', or 'large'."
        )

    @property
    def level(self):
        if self._values['level'] is None:
            return None
        if self._values['module'] == 'mgmt':
            return None
        if self.state == 'absent':
            return 'none'
        return str(self._values['level'])

    @property
    def memory(self):
        if self._values['memory'] is None:
            return None
        if self._values['module'] != 'mgmt':
            return None
        return int(self._validate_memory_limit(self._values['memory']))

    @property
    def status_timeout(self):
        divisor = 100
        timeout = self._values['status_timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / divisor

        return delay, divisor


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
            return result
        except Exception:
            return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    @property
    def memory(self):
        if self._values['memory'] is None:
            return None
        if self._values['memory'] == '0':
            return 'small'
        if self._values['memory'] == '200':
            return 'medium'
        if self._values['memory'] == '500':
            return 'large'
        return str(self._values['memory'])


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            result = self.__default(param)
            return result

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def cgnat(self):
        if self.want.module == 'cgnat':
            if self.want.state == 'absent' and self.have.enabled is True:
                return True
            if self.want.state == 'present' and self.have.disabled is True:
                return True


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.have = None
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

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

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)

        if Version(version) < Version('15.0.0'):
            raise F5ModuleError("This module can only be used on BIG-IP with TMOS version 15.x and above.")

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
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if self.want.check_status is True:
            return self.check_progress()
        if self.exists():
            return False
        return self.update()

    def mgmt_exists(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/db/provision.extramb/".format(
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
        if int(response['value']) != 0 and self.want.memory == 0:
            return False
        if int(response['value']) == 0 and self.want.memory == 0:
            return True
        if int(response['value']) == self.want.memory:
            return True
        return False

    def exists(self):
        if self.want.module == 'mgmt':
            return self.mgmt_exists()

        uri = "https://{0}:{1}/mgmt/tm/sys/provision/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        for module in response['items']:
            if module['name'] == self.want.module:
                if module['level'] != 'none' and self.want.level == 'none':
                    return True
                if module['level'] == 'none' and self.want.level == 'none':
                    return False
                if module['level'] == self.want.level:
                    return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        if self._device_is_rebooting():
            self.changes.update(
                {'message': "Device goes down for a reboot and will start provisioning requested module: {0}, "
                            "recheck the status by re-running the module with 'check_status' parameter.".format(self.want.module)}
            )
        else:
            self.changes.update(
                {'message': "Device will start provisioning requested module: {0}, "
                            "recheck the status by re-running the module with 'check_status' parameter.".format(self.want.module)}
            )
        return True

    def check_progress(self):
        if self._device_is_rebooting():
            self.changes.update(
                {'message': 'Device is rebooting, unable to check provisioning status.'}
            )
        if not self.device_is_ready():
            self.changes.update(
                {'message': 'Device is restarting services, unable to check provisioning status.'}
            )
            return False
        return self.wait_for_provisioning()

    def device_is_ready(self):
        try:
            if self._is_rest_available():
                return True
        except Exception as ex:
            # This can be caused by services restarting, we only want to raise on SSL errors if there are
            # any, otherwise there is a good chance device is rebooting or restarting
            if 'Failed to validate the SSL' in str(ex):
                raise F5ModuleError(str(ex))
            pass
        return False

    def wait_for_provisioning(self):
        delay, period = self.want.status_timeout
        checks = 0
        for x in range(0, period):
            # we check again to ensure device did not start to restart services in between API calls
            if not self.device_is_ready():
                self.changes.update(
                    {'message': 'Device is restarting services, unable to check provisioning status.'}
                )
                return False
            if not self._is_mprov_running_on_device():
                checks += 1
            if checks > 2:
                if self.want.state == 'absent':
                    self.changes.update(
                        {'message': 'Device has finished de-provisioning the requested module.'}
                    )

                else:
                    self.changes.update(
                        {'message': 'Device has finished provisioning the requested module.'}
                    )
                return True
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the status_timeout parameter for long lived actions."
        )

    def _is_rest_available(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/available".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError:
            return False

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        return False

    def _is_mprov_running_on_device(self):
        # /usr/libexec/qemu-kvm is added here to prevent vcmp provisioning
        # from never allowing the mprov provisioning to succeed.
        #
        # It turns out that the 'mprov' string is found when enabling vcmp. The
        # qemu-kvm command that is run includes it.
        #
        # For example,
        #   /usr/libexec/qemu-kvm -rt-usecs 880 ... -mem-path /dev/mprov/vcmp -f5-tracing ...
        #

        command = "ps aux | grep \'[m]prov\' | grep -v /usr/libexec/qemu-kvm"
        params = dict(
            command="run",
            utilCmdArgs='-c "{0}"'.format(command)
        )
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError:
            return False

        if 'code' in response and response['code'] in [400, 403]:
            return False
        if 'commandResult' in response:
            return True
        return False

    def _device_is_rebooting(self):
        params = {
            "command": "run",
            "utilCmdArgs": '-c "runlevel"'
        }
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError:
            # Sometimes when deamons are restarting earlier and we get an invalid json in response, this does not
            # mean device is rebooting so we are returning False here.
            return False

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'commandResult' in response and '6' in response['commandResult']:
            return True
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update_on_device(self):
        if self.want.level == 'dedicated' and self.want.module != 'mgmt':
            self.provision_dedicated_on_device()
        else:
            self.provision_non_dedicated_on_device()

    def _read_other_modules_from_device(self, uri):
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return [x['name'] for x in response['items'] if x['name'] != self.want.module]

    def provision_dedicated_on_device(self):
        params = self.want.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/provision/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )

        resources = self._read_other_modules_from_device(uri)

        with TransactionContextManager(self.client) as transact:
            for resource in resources:
                target = uri + resource
                resp = transact.api.patch(target, json=dict(level='none'))
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if 'code' in response and response['code'] in [400, 404]:
                    if 'message' in response:
                        raise F5ModuleError(response['message'])
                    else:
                        raise F5ModuleError(resp.content)

            target = uri + self.want.module
            resp = transact.api.patch(target, json=params)
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if 'code' in response and response['code'] in [400, 404]:
                if 'message' in response:
                    raise F5ModuleError(response['message'])
                else:
                    raise F5ModuleError(resp.content)

    def provision_mgmt_on_device(self, params):
        uri = "https://{0}:{1}/mgmt/tm/sys/db/provision.extramb/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def provision_non_dedicated_on_device(self):
        params = self.want.api_params()

        if self.want.module == 'mgmt':
            return self.provision_mgmt_on_device(params)

        uri = "https://{0}:{1}/mgmt/tm/sys/provision/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.module
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def read_mgmt_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/db/provision.extramb/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)

    def read_current_from_device(self):
        if self.want.module == 'mgmt':
            return self.read_mgmt_from_device()

        uri = "https://{0}:{1}/mgmt/tm/sys/provision/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.module
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)

    def absent(self):
        if self.want.check_status is True:
            return self.check_removal_progress()
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self._device_is_rebooting():
            self.changes.update(
                {'message': "Device goes down for a reboot and will start de-provisioning requested module: {0}, "
                            "recheck the status by re-running the module with 'check_status' parameter.".format(self.want.module)}
            )
        else:
            self.changes.update(
                {'message': "Device will start de-provisioning requested module: {0}, "
                            "recheck the status by re-running the module with 'check_status' parameter.".format(self.want.module)}
            )
        return True

    def check_removal_progress(self):
        done = self.check_progress()
        if done:
            if self.should_reboot():
                self.save_on_device()
                self.changes.update(
                    {'message': "Device finished de-provisioning requested module: {0} "
                                "and configuration has been saved, a reboot is required.".format(self.want.module)}
                )
            return True
        return False

    def should_reboot(self):
        # we do a quick check if another reboot is required
        for x in range(0, 3):
            uri = "https://{0}:{1}/mgmt/tm/sys/db/{2}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                'provision.action'
            )
            resp = self.client.api.get(uri)
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if 'code' in response and response['code'] in [400, 404]:
                if 'message' in response:
                    raise F5ModuleError(response['message'])
                else:
                    raise F5ModuleError(resp.content)

            if response['value'] == 'reboot':
                return True
            elif response['value'] == 'none':
                time.sleep(5)
        return False

    def save_on_device(self):
        command = 'tmsh save sys config'
        params = dict(
            command="run",
            utilCmdArgs='-c "{0}"'.format(command)
        )
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port']
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
        uri = "https://{0}:{1}/mgmt/tm/sys/provision/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.module
        )
        resp = self.client.api.patch(uri, json=dict(level='none'))

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            module=dict(
                required=True,
                choices=[
                    'afm', 'am', 'apm', 'asm', 'avr', 'cgnat',
                    'fps', 'gtm', 'ilx', 'lc', 'ltm', 'mgmt',
                    'pem', 'sam', 'sslo', 'swg', 'urldb', 'vcmp'
                ],
                aliases=['name']
            ),
            check_status=dict(
                type='bool',
                default='no'
            ),
            status_timeout=dict(
                type='int',
                default=300
            ),
            level=dict(
                default='nominal',
                choices=['nominal', 'dedicated', 'minimum']
            ),
            memory=dict(),
            state=dict(
                default='present',
                choices=['present', 'absent']
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['check_status', 'yes', ['module']]
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,

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
