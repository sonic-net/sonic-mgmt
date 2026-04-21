#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ucs
short_description: Manage upload, installation, and removal of UCS files
description:
   - Manage the upload, installation, and removal of UCS files on a BIG-IP system.
     A user configuration set (UCS) is a backup file that contains BIG-IP configuration
     data that can be used to fully restore a BIG-IP system in the event of a
     failure or RMA replacement.
version_added: "1.0.0"
options:
  include_chassis_level_config:
    description:
      - During restoration of the UCS file, includes chassis level configuration
        that is shared among boot volume sets. For example, the cluster default
        configuration.
    type: bool
  ucs:
    description:
      - The path to the UCS file to install. The parameter must be
        provided if the C(state) is either C(installed) or C(activated).
        When C(state) is C(absent), the full path for this parameter is
        ignored and only the filename is used to select a UCS for removal.
        Therefore you could specify C(/foo/bar/test.ucs) and this module
        would only look for C(test.ucs).
    type: str
    required: True
  force:
    description:
      - If C(true), the system uploads the file every time and replaces the file on the
        device. If C(false), the file is only uploaded if it does not already
        exist. Generally should only be C(true) in cases where you believe
        the image was corrupted during upload.
    type: bool
    default: false
  no_license:
    description:
      - Performs a full restore of the UCS file and all the files it contains,
        with the exception of the license file. The option must be used to
        restore a UCS on RMA (Returned Materials Authorization) devices.
    type: bool
  no_platform_check:
    description:
      - Bypasses the platform check and allows installation of a UCS that was
        created using a different platform. By default (without this option),
        installation of a UCS created from a different platform is not allowed.
    type: bool
  passphrase:
    description:
      - Specifies the passphrase that is necessary to load the specified UCS file.
    type: str
  reset_trust:
    description:
      - When specified, the device and trust domain certs and keys are not
        loaded from the UCS. Instead, a new set is generated.
    type: bool
  state:
    description:
      - When C(installed), ensures the UCS is uploaded and installed
        on the system. When C(present), ensures the UCS is uploaded.
        When C(absent), the UCS is removed from the system. When
        C(installed), the uploading of the UCS is idempotent, however the
        installation of that configuration is not idempotent.
    type: str
    choices:
      - absent
      - installed
      - present
    default: present
notes:
   - Only the most basic checks are performed by this module. Other checks and
     considerations need to be taken into account. See
     https://support.f5.com/kb/en-us/solutions/public/11000/300/sol11318.html
   - This module does not handle devices with the FIPS 140 HSM.
   - This module does not handle BIG-IPs systems on the 6400, 6800, 8400, or
     8800 hardware platforms.
   - This module does not verify the new or replaced SSH keys from the
     UCS file are synchronized between the BIG-IP system and the SCCP.
   - This module does not support the 'rma' option.
   - This module does not support restoring a UCS archive on a BIG-IP 1500,
     3400, 4100, 6400, 6800, or 8400 hardware platforms other than the system
     from which the backup was created.
   - The UCS restore operation restores the full configuration only if the
     hostname of the target system matches the hostname on which the UCS
     archive was created. If the hostname does not match, only the shared
     configuration is restored. You can ensure hostnames match by using
     the C(bigip_hostname) Ansible module in a task before using this module.
   - This module does not support re-licensing a BIG-IP restored from a UCS.
   - This module does not support restoring encrypted archives on replacement
     RMA unit.
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Upload UCS
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Install (upload, install) UCS.
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Install (upload, install) UCS without installing the license portion
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    no_license: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Install (upload, install) UCS except the license, and bypassing the platform check
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    no_license: true
    no_platform_check: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Install (upload, install) UCS using a passphrase necessary to load the UCS
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    passphrase: MyPassphrase1234
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Remove uploaded UCS file
  bigip_ucs:
    ucs: bigip.localhost.localdomain.ucs
    state: absent
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
# only common fields returned
'''

import os
import re
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
from ansible.module_utils.six import iteritems

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.icontrol import (
    upload_file, tmos_version
)
from ..module_utils.teem import send_teem

try:
    from collections import OrderedDict
except ImportError:
    try:
        from ordereddict import OrderedDict
    except ImportError:
        pass


class Parameters(AnsibleF5Parameters):
    api_map = {}
    updatables = []
    returnables = []
    api_attributes = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    def _check_required_if(self, parameter):
        if self._values[parameter] is not True:
            return self._values[parameter]
        if self.state != 'installed':
            raise F5ModuleError(
                '"{0}" parameters requires "installed" state'.format(parameter)
            )

    @property
    def basename(self):
        return os.path.basename(self.ucs)

    @property
    def options(self):
        return {
            'include-chassis-level-config': self.include_chassis_level_config,
            'no-license': self.no_license,
            'no-platform-check': self.no_platform_check,
            'passphrase': self.passphrase,
            'reset-trust': self.reset_trust
        }

    @property
    def reset_trust(self):
        self._check_required_if('reset_trust')
        return self._values['reset_trust']

    @property
    def passphrase(self):
        self._check_required_if('passphrase')
        return self._values['passphrase']

    @property
    def no_platform_check(self):
        self._check_required_if('no_platform_check')
        return self._values['no_platform_check']

    @property
    def no_license(self):
        self._check_required_if('no_license')
        return self._values['no_license']

    @property
    def include_chassis_level_config(self):
        self._check_required_if('include_chassis_level_config')
        return self._values['include_chassis_level_config']

    @property
    def install_command(self):
        cmd = 'tmsh load sys ucs /var/local/ucs/{0}'.format(self.basename)
        # Append any options that might be specified
        options = OrderedDict(sorted(self.options.items(), key=lambda t: t[0]))
        for k, v in iteritems(options):
            if v is False or v is None:
                continue
            elif k == 'passphrase':
                cmd += ' %s %s' % (k, v)
            else:
                cmd += ' %s' % (k)
        return cmd


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


class ReportableChanges(Changes):
    pass


class UsableChanges(Changes):
    pass


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)

    def exec_module(self):
        if self.is_version_v1():
            manager = V1Manager(**self.kwargs)
        else:
            manager = V2Manager(**self.kwargs)

        return manager.exec_module()

    def is_version_v1(self):
        """Checks to see if the TMOS version is less than 12.1.0

        Versions prior to 12.1.0 have a bug which prevents the REST
        API from properly listing any UCS files when you query the
        /mgmt/tm/sys/ucs endpoint. Therefore you need to do everything
        through tmsh over REST.

        :return: Bool
        """
        version = tmos_version(self.client)
        if Version(version) < Version('12.1.0'):
            return True
        else:
            return False


class Difference(object):
    pass


class BaseManager(object):
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
        changed = False
        result = dict()
        state = self.want.state

        if state in ['present', 'installed']:
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

    def update(self):
        if self.module.check_mode:
            if self.want.force:
                return True
            return False
        elif self.want.force:
            self.remove()
            return self.create()
        elif self.want.state == 'installed':
            return self.install_on_device()
        else:
            return False

    def create(self):
        if self.module.check_mode:
            return True
        self.create_on_device()
        if not self.exists():
            raise F5ModuleError("Failed to upload the UCS file")
        if self.want.state == 'installed':
            self.install_on_device()
        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the UCS file")
        return True

    def wait_for_rest_api_restart(self):
        time.sleep(5)
        for x in range(0, 60):
            try:
                self.client.reconnect()
                break
            except Exception:
                time.sleep(3)

    def wait_for_configuration_reload(self):
        noops = 0
        while noops < 4:
            time.sleep(3)
            try:
                params = dict(command="run",
                              utilCmdArgs='-c "tmsh show sys mcp-state"'
                              )
                uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=params)
                try:
                    output = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))
                if 'code' in output and output['code'] in [400, 403]:
                    if 'message' in output:
                        raise F5ModuleError(output['message'])
                    else:
                        raise F5ModuleError(resp.content)
            except Exception:
                # This can be caused by restjavad restarting.
                continue

            if 'commandResult' not in output:
                continue

            # Need to re-connect here because the REST framework will be restarting
            # and thus be clearing its authorization cache
            result = output['commandResult']
            if self._is_config_reloading_failed_on_device(result):
                raise F5ModuleError(
                    "Failed to reload the configuration. This may be due "
                    "to a cross-version incompatibility. {0}".format(result)
                )
            if self._is_config_reloading_success_on_device(result):
                if self._is_config_reloading_running_on_device(result):
                    noops += 1
                    continue
            noops = 0

    def _is_config_reloading_success_on_device(self, output):
        succeed = r'Last Configuration Load Status\s+full-config-load-succeed'
        matches = re.search(succeed, output)
        if matches:
            return True
        return False

    def _is_config_reloading_running_on_device(self, output):
        running = r'Running Phase\s+running'
        matches = re.search(running, output)
        if matches:
            return True
        return False

    def _is_config_reloading_failed_on_device(self, output):
        failed = r'Last Configuration Load Status\s+base-config-load-failed'
        matches = re.search(failed, output)
        if matches:
            return True
        return False


class V1Manager(BaseManager):
    """Manager class for V1 product

    V1 products include versions of BIG-IP < 12.1.0, but >= 12.0.0.

    These versions had a number of API deficiencies. These include, but
    are not limited to,

      * UCS collection endpoint listed no items
      * No API to upload UCS files

    """

    def _set_mode_and_ownership(self):
        url = 'https://{0}:{1}/mgmt/tm/util/bash'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        ownership = 'root:root'
        ucs_path = '/var/local/ucs/{0}'.format(self.want.basename)
        file_mode = oct(os.stat(self.want.ucs).st_mode)[-3:]
        args = dict(
            command='run',
            utilCmdArgs='-c "chown {0} {1};chmod {2} {1}"'.format(ownership, ucs_path, file_mode)
        )

        self.client.api.post(url, json=args)

    def upload_file_to_device(self, content, name):
        url = 'https://{0}:{1}/mgmt/shared/file-transfer/uploads'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        try:
            upload_file(self.client, url, content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def create_on_device(self):
        remote_path = "/var/local/ucs"
        tpath_name = '/var/config/rest/downloads'

        self.upload_file_to_device(self.want.ucs, self.want.basename)

        uri = "https://{0}:{1}/mgmt/tm/util/unix-mv/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        args = dict(
            command='run',
            utilCmdArgs='{0}/{2} {1}/{2}'.format(
                tpath_name, remote_path, self.want.basename
            )
        )
        resp = self.client.api.post(uri, json=args)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        self._set_mode_and_ownership()
        return True

    def read_current_from_device(self):
        result = []
        params = dict(command="run",
                      utilCmdArgs='-c "tmsh list sys ucs"'
                      )
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            output = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if 'code' in output and output['code'] in [400, 403]:
            if 'message' in output:
                raise F5ModuleError(output['message'])
            else:
                raise F5ModuleError(resp.content)
        if 'commandResult' in output:
            lines = output['commandResult'].split("\n")
            result = [x.strip() for x in lines]
            result = list(set(result))
        return result

    def exists(self):
        collection = self.read_current_from_device()
        if self.want.basename in collection:
            return True
        return False

    def remove_from_device(self):
        params = dict(command="run",
                      utilCmdArgs='-c "tmsh delete sys ucs {0}"'.format(self.want.basename)
                      )
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            output = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if 'code' in output and output['code'] in [400, 403]:
            if 'message' in output:
                raise F5ModuleError(output['message'])
            else:
                raise F5ModuleError(resp.content)
        if 'commandResult' in output:
            if '{0} is deleted'.format(self.want.basename) in output['commandResult']:
                return True
        return False

    def install_on_device(self):
        try:
            params = dict(command="run",
                          utilCmdArgs='-c "{0}"'.format(self.want.install_command)
                          )
            uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            resp = self.client.api.post(uri, json=params)
            try:
                output = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))
            if 'code' in output and output['code'] in [400, 403]:
                if 'message' in output:
                    raise F5ModuleError(output['message'])
                else:
                    raise F5ModuleError(resp.content)
        except Exception as ex:
            # Reloading a UCS configuration will cause restjavad to restart,
            # aborting the connection.
            if 'Connection aborted' in str(ex):
                pass
            elif 'TimeoutException' in str(ex):
                # Timeouts appear to be able to happen in 12.1.2
                pass
            elif 'remoteSender' in str(ex):
                # catching some edge cases where API becomes unstable after installation
                pass
            elif 'Proxy Error' in str(ex):
                # catching some edge cases where API becomes unstable after installation
                pass
            elif 'object has no attribute' in str(ex):
                pass
            elif 'Expecting value' in str(ex):
                pass
            else:
                raise F5ModuleError(str(ex))
        self.wait_for_rest_api_restart()
        self.wait_for_configuration_reload()
        return True


class V2Manager(V1Manager):
    """Manager class for V2 product

    V2 products include versions of BIG-IP >= 12.1.0 but < 13.0.0.

    These versions fixed the collection bug in V1, but had yet to add the
    ability to upload files using a dedicated UCS upload API.

    """

    def read_current_from_device(self):
        result = []
        uri = "https://{0}:{1}/mgmt/tm/sys/ucs/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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
        items = response.get('items', [])
        for item in items:
            result.append(os.path.basename(item['apiRawValues']['filename']))
        return result

    def exists(self):
        collection = self.read_current_from_device()
        if self.want.basename in collection:
            return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            force=dict(
                type='bool',
                default='no'
            ),
            include_chassis_level_config=dict(
                type='bool'
            ),
            no_license=dict(
                type='bool'
            ),
            no_platform_check=dict(
                type='bool'
            ),
            passphrase=dict(no_log=True),
            reset_trust=dict(type='bool'),
            state=dict(
                default='present',
                choices=['absent', 'installed', 'present']
            ),
            ucs=dict(required=True)
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
