#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ucs_fetch
short_description: Fetches a UCS file from remote nodes
description:
   - This module is used for fetching UCS files from remote machines and
     storing them locally in a file tree, organized by hostname. This module
     was written to create and transfer UCS files that might not be present,
     it does not require UCS file to be pre-created. So a missing remote UCS
     is not an error unless C(fail_on_missing) is set to 'yes'.
version_added: "1.0.0"
options:
  backup:
    description:
      - Creates a backup file including the timestamp information so you can
        get the original file back if you overwrote it incorrectly.
    type: bool
    default: false
  create_on_missing:
    description:
      - Creates the UCS based on the value of C(src), if the file does not already
        exist on the remote system.
      - When set to C(false), with C(fail_on_missing) set to C(false) the module will return no change
        if the ucs file is missing on device.
    type: bool
    default: true
  dest:
    description:
      - A directory to save the UCS file into.
      - This option is mandatory when C(only_create_file) is set to C(false).
    type: path
  encryption_password:
    description:
      - Password to use to encrypt the UCS file if desired.
    type: str
  fail_on_missing:
    description:
      - Make the module fail if the UCS file on the remote system is missing.
      - This option always takes precedence over C(create_on_missing), hence when set to C(true), the module will
        always fail if the UCS is missing, even if C(create_on_missing) option is set to C(true).
      - When set to C(false), with C(create_on_missing) set to C(false) the module will return no change
        if the ucs file is missing on device.
    type: bool
    default: false
  force:
    description:
      - If C(false), the file is only transferred if the destination does not
        exist.
    type: bool
    default: true
  src:
    description:
      - The name of the UCS file to create on the remote server for downloading.
      - The file is retrieved or created in /var/local/ucs/.
      - This option is mandatory when C(only_create_file) is set to C(true).
    type: str
  async_timeout:
    description:
      - Parameter used when creating new UCS file on a device.
      - The number of seconds to wait for the API async interface to complete its task.
      - The accepted value range is between C(150) and C(1800) seconds.
    type: int
    default: 150
  only_create_file:
    description:
      - If C(true), the file is created on the device and not downloaded. If the UCS archive exists on the device,
        no change is made and the file is not downloaded.
      - To recreate UCS files left on the device, remove them with the C(bigip_ucs) module before running this
        module with C(only_create_file) set to C(true).
    type: bool
    default: false
    version_added: "1.12.0"
notes:
  - BIG-IP provides no way to get a checksum of the UCS files on the system
    via any interface with the possible exception of logging in directly to the box (which
    would not support appliance mode). Therefore, the best this module can
    do is check for the existence of the file on disk; no check-summing.
  - If you are using this module with either Ansible Tower or Ansible AWX, you
    should be aware of how these Ansible products execute jobs in restricted
    environments. More information can be found here
    https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/module-usage-with-tower.html
  - Some longer running tasks might cause the REST interface on BIG-IP to time out, to avoid this adjust the timers as
    per this KB article https://support.f5.com/csp/article/K94602685
extends_documentation_fragment:
  - f5networks.f5_modules.f5
  - ansible.builtin.files
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Download a new UCS
  bigip_ucs_fetch:
    src: cs_backup.ucs
    dest: /tmp/cs_backup.ucs
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Only create new UCS, no download
  bigip_ucs_fetch:
    src: cs_backup.ucs
    only_create_file: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Recreate UCS file left on device - remove file first
  bigip_ucs:
    ucs: cs_backup.ucs
    state: absent
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Recreate UCS file left on device - create new file
  bigip_ucs_fetch:
    src: cs_backup.ucs
    only_create_file: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
checksum:
  description: The SHA1 checksum of the downloaded file.
  returned: success or changed
  type: str
  sample: 7b46bbe4f8ebfee64761b5313855618f64c64109
dest:
  description: Location on the Ansible host the UCS was saved to.
  returned: success
  type: str
  sample: /path/to/file.txt
src:
  description:
    - Name of the UCS file on the remote BIG-IP to download. If not
      specified, this is a randomly generated filename.
  returned: changed
  type: str
  sample: cs_backup.ucs
backup_file:
  description: Name of the backup file.
  returned: changed and if backup=yes
  type: str
  sample: /path/to/file.txt.2015-02-12@22:09~
gid:
  description: Group ID of the UCS file, after execution.
  returned: success
  type: int
  sample: 100
group:
  description: Group of the UCS file, after execution.
  returned: success
  type: str
  sample: httpd
owner:
  description: Owner of the UCS file, after execution.
  returned: success
  type: str
  sample: httpd
uid:
  description: Owner ID of the UCS file, after execution.
  returned: success
  type: int
  sample: 100
md5sum:
  description: The MD5 checksum of the downloaded file.
  returned: changed or success
  type: str
  sample: 96cacab4c259c4598727d7cf2ceb3b45
mode:
  description: Permissions of the target UCS, after execution.
  returned: success
  type: str
  sample: 0644
size:
  description: Size of the target UCS, after execution.
  returned: success
  type: int
  sample: 1220
'''

import os
import re
import tempfile
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
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.icontrol import (
    tmos_version, download_file
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    updatables = []
    returnables = [
        'dest',
        'src',
        'md5sum',
        'checksum',
        'backup_file'
    ]
    api_attributes = []
    api_map = {}


class ModuleParameters(Parameters):
    @property
    def options(self):
        result = []
        if self.passphrase:
            result.append(dict(
                passphrase=self.want.passphrase
            ))
        return result

    @property
    def src(self):
        if self._values['src'] is not None:
            return self._values['src']
        result = next(tempfile._get_candidate_names()) + '.ucs'
        self._values['src'] = result
        return result

    @property
    def fulldest(self):
        result = None
        if os.path.isdir(self.dest):
            result = os.path.join(self.dest, self.src)
        else:
            if os.path.exists(os.path.dirname(self.dest)):
                result = self.dest
            else:
                try:
                    # os.path.exists() can return false in some
                    # circumstances where the directory does not have
                    # the execute bit for the current user set, in
                    # which case the stat() call will raise an OSError
                    os.stat(os.path.dirname(self.dest))
                except OSError as e:
                    if "permission denied" in str(e).lower():
                        raise F5ModuleError(
                            "Destination directory {0} is not accessible".format(os.path.dirname(self.dest))
                        )
                    raise F5ModuleError(
                        "Destination directory {0} does not exist".format(os.path.dirname(self.dest))
                    )

        if not os.access(os.path.dirname(result), os.W_OK):
            raise F5ModuleError(
                "Destination {0} not writable".format(os.path.dirname(result))
            )
        return result

    @property
    def async_timeout(self):
        divisor = 100
        timeout = self._values['async_timeout']
        if timeout < 150 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 150 and 1800 seconds."
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
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)

    def exec_module(self):
        if self.is_version_v1():
            manager = self.get_manager('v1')
        else:
            manager = self.get_manager('v2')
        return manager.exec_module()

    def get_manager(self, type):
        if type == 'v1':
            return V1Manager(**self.kwargs)
        elif type == 'v2':
            return V2Manager(**self.kwargs)

    def is_version_v1(self):
        """Checks to see if the TMOS version is less than 12.1.0

        Versions prior to 12.1.0 have a bug which prevents the REST
        API from properly listing any UCS files when you query the
        /mgmt/tm/sys/ucs endpoint. Therefore you need to do everything
        through tmsh over REST.

        :return: bool
        """
        version = tmos_version(self.client)
        if Version(version) < Version('12.1.0'):
            return True
        else:
            return False


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        result = dict()

        self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=True))
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if self.exists():
            if not self.want.only_create_file:
                self.update()
        else:
            self.create()

    def update(self):
        if os.path.exists(self.want.fulldest):
            if not self.want.force:
                raise F5ModuleError(
                    "File '{0}' already exists".format(self.want.fulldest)
                )
        self.execute()

    def _get_backup_file(self):
        return self.module.backup_local(self.want.fulldest)

    def execute(self):
        try:
            if self.want.backup:
                if os.path.exists(self.want.fulldest):
                    backup_file = self._get_backup_file()
                    self.changes.update({'backup_file': backup_file})
            self.download()
        except IOError:
            raise F5ModuleError(
                "Failed to copy: {0} to {1}".format(self.want.src, self.want.fulldest)
            )
        self._set_checksum()
        self._set_md5sum()
        self.changes.update({'src': self.want.src})
        self.changes.update({'md5sum': self.want.md5sum})
        self.changes.update({'checksum': self.want.checksum})
        file_args = self.module.load_file_common_arguments(self.module.params)
        return self.module.set_fs_attributes_if_different(file_args, True)

    def _set_checksum(self):
        try:
            result = self.module.sha1(self.want.fulldest)
            self.want.update({'checksum': result})
        except ValueError:
            pass

    def _set_md5sum(self):
        try:
            result = self.module.md5(self.want.fulldest)
            self.want.update({'md5sum': result})
        except ValueError:
            pass

    def create(self):
        if self.want.fail_on_missing:
            raise F5ModuleError(
                "UCS '{0}' was not found".format(self.want.src)
            )

        if not self.want.create_on_missing:
            raise F5ModuleError(
                "UCS '{0}' was not found".format(self.want.src)
            )

        if self.module.check_mode:
            return True
        if self.want.create_on_missing:
            self.create_on_device()
        if not self.want.only_create_file:
            self.execute()
        return True

    def create_on_device(self):
        task = self.create_async_task_on_device()
        self._start_task_on_device(task)
        self.async_wait(task)

    def create_async_task_on_device(self):
        if self.want.encryption_password:
            params = dict(
                command='save',
                name=self.want.src,
                options=[{'passphrase': self.want.encryption_password}]
            )
        else:
            params = dict(
                command='save',
                name=self.want.src,
            )

        uri = "https://{0}:{1}/mgmt/tm/task/sys/ucs".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response['_taskId']
        raise F5ModuleError(resp.content)

    def _start_task_on_device(self, task):
        payload = {"_taskState": "VALIDATING"}
        uri = "https://{0}:{1}/mgmt/tm/task/sys/ucs/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            task
        )
        resp = self.client.api.put(uri, json=payload)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201, 202] or 'code' in response and response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(resp.content)

    def async_wait(self, task):
        delay, period = self.want.async_timeout
        uri = "https://{0}:{1}/mgmt/tm/task/sys/ucs/{2}/result".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            task
        )
        for x in range(0, period):
            resp = self.client.api.get(uri)
            try:
                response = resp.json()
            except ValueError:
                # It is possible that the API call can return invalid JSON.
                # This invalid JSON appears to be just empty strings.
                continue
            if resp.status in [200, 201, 202] or 'code' in response and response['code'] in [200, 201, 202]:
                if response['_taskState'] == 'FAILED':
                    raise F5ModuleError("Task failed unexpectedly.")
                if response['_taskState'] == 'COMPLETED':
                    return True

            time.sleep(delay)
        # at times we time out waiting on task as sometimes task is gone from async queue after services reboot
        # we are adding existence check here to catch where the file is created but async task is removed.
        if not self.exists():
            raise F5ModuleError(
                "Module timeout reached, state change is unknown, "
                "please increase the async_timeout parameter for long lived actions."
            )

    def download(self):
        self.download_from_device(self.want.dest)
        if os.path.exists(self.want.dest):
            return True
        raise F5ModuleError(
            "Failed to download the remote file"
        )


class V1Manager(BaseManager):
    def __init__(self, *args, **kwargs):
        super(V1Manager, self).__init__(**kwargs)
        self.remote_dir = '/var/config/rest/madm'

    def read_current(self):
        result = None
        output = self.read_current_from_device()
        if 'commandResult' in output:
            result = self._read_ucs_files_from_output(output['commandResult'])
        return result

    def read_current_from_device(self):
        params = dict(
            command='run',
            utilCmdArgs='-c "tmsh list sys ucs"'
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
        return response

    def _read_ucs_files_from_output(self, output):
        search = re.compile(r'filename\s+(.*)').search
        lines = output.split("\n")
        result = [m.group(1) for m in map(search, lines) if m]
        return result

    def exists(self):
        collection = self.read_current()
        base = os.path.basename(self.want.src)
        if any(base == os.path.basename(x) for x in collection):
            return True
        return False

    def download_from_device(self, dest):
        url = 'https://{0}:{1}/mgmt/shared/file-transfer/madm/{2}'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.filename
        )
        try:
            download_file(self.client, url, dest)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to download the file."
            )
        if os.path.exists(self.want.dest):
            return True
        return False

    def _move_to_download(self):
        move_path = '/var/local/ucs/{0} {1}/{0}'.format(
            self.want.filename, self.remote_dir
        )
        params = dict(
            command='run',
            utilCmdArgs=move_path
        )

        uri = "https://{0}:{1}/mgmt/tm/util/unix-mv/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )

        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
            if 'commandResult' in response:
                if 'cannot stat' in response['commandResult']:
                    raise F5ModuleError(response['commandResult'])
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        return True


class V2Manager(BaseManager):
    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/ucs".format(
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

        return response

    def read_current(self):
        collection = self.read_current_from_device()
        if 'items' not in collection:
            return []
        resources = collection['items']
        result = [x['apiRawValues']['filename'] for x in resources]
        return result

    def exists(self):
        collection = self.read_current()
        base = os.path.basename(self.want.src)
        if any(base == os.path.basename(x) for x in collection):
            return True
        return False

    def download_from_device(self, dest):
        url = 'https://{0}:{1}/mgmt/shared/file-transfer/ucs-downloads/{2}'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.src
        )
        try:
            download_file(self.client, url, dest)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to download the file."
            )
        if os.path.exists(self.want.dest):
            return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            backup=dict(
                default='no',
                type='bool'
            ),
            create_on_missing=dict(
                default='yes',
                type='bool'
            ),
            encryption_password=dict(no_log=True),
            dest=dict(
                type='path'
            ),
            force=dict(
                default='yes',
                type='bool'
            ),
            fail_on_missing=dict(
                default='no',
                type='bool'
            ),
            src=dict(),
            only_create_file=dict(
                default='no',
                type='bool'
            ),
            async_timeout=dict(
                type='int',
                default=150
            ),
        )
        self.required_if = [
            ['only_create_file', 'no', ['dest']],
            ['only_create_file', 'yes', ['src']]
        ]
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.add_file_common_args = True


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
        add_file_common_args=spec.add_file_common_args
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
