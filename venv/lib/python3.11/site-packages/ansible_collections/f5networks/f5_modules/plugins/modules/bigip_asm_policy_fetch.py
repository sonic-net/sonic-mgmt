#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_policy_fetch
short_description: Exports the ASM policy from remote nodes.
description:
  - Exports the ASM policy from remote nodes.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the policy exported to create a file on the remote device for downloading.
    type: str
    required: True
  dest:
    description:
      - A directory to save the policy file into.
      - This option is ignored when C(inline) is set to C(true).
    type: path
  file:
    description:
      - The name of the file to be created on the remote device for downloading.
      - When C(binary) is set to C(false) the ASM policy is in XML format.
    type: str
  inline:
    description:
      - If C(true), the ASM policy is exported C(inline) as a string instead of a file.
      - The policy can be be retrieved in the playbook C(result) dictionary under the C(inline_policy) key.
    type: bool
  compact:
    description:
      - If C(true), only the ASM policy custom settings is exported.
      - Only applies to XML type ASM policy exports.
    type: bool
  base64:
    description:
      - If C(true), the returned C(inline) ASM policy content is Base64 encoded.
      - Only applies to C(inline) ASM policy exports.
    type: bool
  binary:
    description:
      - If C(true), the exported ASM policy is in binary format.
      - Only applies to C(file) ASM policy exports.
    type: bool
  force:
    description:
      - If C(false), the file will only be transferred if it does not exist in the the destination.
    default: true
    type: bool
  partition:
    description:
      - Device partition which contains the ASM policy to export.
    type: str
    default: Common
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
  - Nitin Khanna (@nitinthewiz)
'''

EXAMPLES = r'''
- name: Export policy in binary format
  bigip_asm_policy_fetch:
    name: foobar
    file: export_foo
    dest: /root/download
    binary: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Export policy inline base64 encoded format
  bigip_asm_policy_fetch:
    name: foobar
    inline: true
    base64: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Export policy in XML format
  bigip_asm_policy_fetch:
    name: foobar
    file: export_foo
    dest: /root/download
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Export compact policy in XML format
  bigip_asm_policy_fetch:
    name: foobar
    file: export_foo.xml
    dest: /root/download/
    compact: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Export policy in binary format, autogenerate name
  bigip_asm_policy_fetch:
    name: foobar
    dest: /root/download/
    binary: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
name:
  description: Name of the ASM policy to be exported.
  returned: changed
  type: str
  sample: Asm_APP1_Transparent
dest:
  description: Local path to download the exported ASM policy.
  returned: changed
  type: str
  sample: /root/downloads/foobar.xml
file:
  description:
    - Name of the policy file on the remote BIG-IP to download. If not
      specified, then this is a randomly generated filename.
  returned: changed
  type: str
  sample: foobar.xml
inline:
  description: Set when the ASM policy to be exported is inline
  returned: changed
  type: bool
  sample: true
compact:
  description: Set only to export custom ASM policy settings.
  returned: changed
  type: bool
  sample: false
base64:
  description: Set to encode inline export in Base64 format.
  returned: changed
  type: bool
  sample: false
binary:
  description: Set to export the ASM policy in binary format.
  returned: changed
  type: bool
  sample: true
'''

import os
import time
import tempfile
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.icontrol import (
    module_provisioned, download_asm_file, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'filename': 'file',
        'minimal': 'compact',
        'isBase64': 'base64',
    }

    api_attributes = [
        'inline',
        'minimal',
        'isBase64',
        'policyReference',
        'filename',
    ]

    returnables = [
        'file',
        'compact',
        'base64',
        'inline',
        'force',
        'binary',
        'dest',
        'name',
        'inline_policy',
    ]

    updatables = [

    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def file(self):
        if self._values['file'] is not None:
            return self._values['file']
        if self.binary:
            result = next(tempfile._get_candidate_names()) + '.plc'
        else:
            result = next(tempfile._get_candidate_names()) + '.xml'
        self._values['file'] = result
        return result

    @property
    def fulldest(self):
        if os.path.isdir(self.dest):
            result = os.path.join(self.dest, self.file)
        else:
            if os.path.exists(os.path.dirname(self.dest)):
                result = self.dest
            else:
                try:
                    # os.path.exists() can return false in some
                    # circumstances where the directory does not have
                    # the execute bit for the current user set, in
                    # which case the stat() call will raise an OSError
                    result = self.dest
                    os.stat(os.path.dirname(result))
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
    def inline(self):
        result = flatten_boolean(self._values['inline'])
        if result == 'yes':
            return True
        elif result == 'no':
            return False

    @property
    def compact(self):
        result = flatten_boolean(self._values['compact'])
        if result == 'yes':
            return True
        elif result == 'no':
            return False

    @property
    def base64(self):
        result = flatten_boolean(self._values['base64'])
        if result == 'yes':
            return True
        elif result == 'no':
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


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

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
        if not module_provisioned(self.client, 'asm'):
            raise F5ModuleError(
                "ASM must be provisioned to use this module."
            )
        result = dict()

        self.export()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=True))
        send_teem(start, self.client, self.module, version)
        return result

    def export(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def update(self):
        if not self.want.force:
            raise F5ModuleError(
                "File '{0}' already exists.".format(self.want.fulldest)
            )
        self.create()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.want.binary:
            self.export_binary()
            return True
        self.create_on_device()
        if not self.want.inline:
            self.execute()
        return True

    def export_binary(self):
        self.export_binary_on_device()
        self.execute()
        return True

    def download(self):
        self.download_from_device(self.want.fulldest)
        if os.path.exists(self.want.fulldest):
            return True
        raise F5ModuleError(
            "Failed to download the remote file."
        )

    def execute(self):
        self.download()
        self.remove_temp_policy_from_device()
        return True

    def exists(self):
        self.policy_exists()
        if not self.want.inline:
            if os.path.exists(self.want.fulldest):
                return True
        return False

    def policy_exists(self):
        uri = 'https://{0}:{1}/mgmt/tm/asm/policies/'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$filter=contains(name,'{0}')+and+contains(partition,'{1}')&$select=name,partition".format(
            self.want.name, self.want.partition
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' in response and response['items'] != []:
            # because api filter on ASM is broken when names that contain numbers at the end we need to work around it
            for policy in response['items']:
                if policy['name'] == self.want.name and policy['partition'] == self.want.partition:
                    return True
        raise F5ModuleError(
            "The specified ASM policy {0} on partition {1} does not exist on device.".format(
                self.want.name, self.want.partition
            )
        )

    def create_on_device(self):
        self._set_policy_link()
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/asm/tasks/export-policy/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result, output, file_size = self.wait_for_task(response['id'])
        if result and output:
            if 'file' in output:
                self.changes.update(dict(inline_policy=output['file']))
        if result:
            self.want.file_size = file_size
            return True

    def wait_for_task(self, task_id):
        uri = "https://{0}:{1}/mgmt/tm/asm/tasks/export-policy/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            task_id
        )
        while True:
            resp = self.client.api.get(uri)

            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
                raise F5ModuleError(resp.content)

            if response['status'] in ['COMPLETED', 'FAILURE']:
                break
            time.sleep(1)

        if response['status'] == 'FAILURE':
            raise F5ModuleError(
                'Failed to export ASM policy.'
            )
        if response['status'] == 'COMPLETED':
            if not self.want.inline:
                return True, None, response['result']['fileSize']
            else:
                return True, response['result'], response['result']['fileSize']

    def _set_policy_link(self):
        policy_link = None
        uri = 'https://{0}:{1}/mgmt/tm/asm/policies/'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$filter=contains(name,'{0}')+and+contains(partition,'{1}')&$select=name,partition".format(
            self.want.name, self.want.partition
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if 'items' in response and response['items'] != []:
            # because api filter on ASM is broken when names that contain numbers at the end we need to work around it
            for policy in response['items']:
                if policy['name'] == self.want.name and policy['partition'] == self.want.partition:
                    policy_link = policy['selfLink']

        if not policy_link:
            raise F5ModuleError("The policy was not found")

        self.changes.update(dict(policyReference={'link': policy_link}))
        return True

    def export_binary_on_device(self):
        full_name = fq_name(self.want.partition, self.want.name)
        cmd = 'tmsh save asm policy {0} bin-file {1}'.format(full_name, self.want.file)
        uri = "https://{0}:{1}/mgmt/tm/util/bash/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        args = dict(
            command='run',
            utilCmdArgs='-c "{0}"'.format(cmd)
        )
        resp = self.client.api.post(uri, json=args)

        try:
            response = resp.json()
            if 'commandResult' in response:
                if 'Error' in response['commandResult'] or 'error' in response['commandResult']:
                    raise F5ModuleError(response['commandResult'])
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        self._stat_binary_on_device()
        self._move_binary_to_download()

        return True

    def _stat_binary_on_device(self):
        params = dict(
            command='run',
            utilCmdArgs='/var/tmp/{0} -l'.format(self.want.file)
        )

        uri = "https://{0}:{1}/mgmt/tm/util/unix-ls/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'commandResult' not in response:
            raise F5ModuleError("Failed to obtain file information, aborting.")

        if 'Error' in response['commandResult'] or 'error' in response['commandResult']:
            raise F5ModuleError(response['commandResult'])

        if '/var/tmp/{0}'.format(self.want.file) not in response['commandResult']:
            raise F5ModuleError("Cannot get size of exported binary file, aborting")

        size = response['commandResult']

        self.want.file_size = int(size.split()[4])
        return True

    def _move_binary_to_download(self):
        name = '{0}~{1}'.format(self.client.provider['user'], self.want.file)
        move_path = '/var/tmp/{0} {1}/{2}'.format(
            self.want.file,
            '/ts/var/rest',
            name
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

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def download_from_device(self, dest):
        url = 'https://{0}:{1}/mgmt/tm/asm/file-transfer/downloads/{2}'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.file
        )
        try:
            download_asm_file(self.client, url, dest, self.want.file_size)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to download the file."
            )
        if os.path.exists(self.want.dest):
            return True
        return False

    def remove_temp_policy_from_device(self):
        name = '{0}~{1}'.format(self.client.provider['user'], self.want.file)
        tpath_name = '/ts/var/rest/{0}'.format(name)
        uri = "https://{0}:{1}/mgmt/tm/util/unix-rm/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        args = dict(
            command='run',
            utilCmdArgs=tpath_name
        )
        resp = self.client.api.post(uri, json=args)
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
            name=dict(
                required=True,
            ),
            dest=dict(
                type='path'
            ),
            file=dict(),
            inline=dict(
                type='bool'
            ),
            compact=dict(
                type='bool'
            ),
            base64=dict(
                type='bool'
            ),
            binary=dict(
                type='bool'
            ),
            force=dict(
                default='yes',
                type='bool'
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['binary', 'inline'],
            ['binary', 'compact'],
            ['dest', 'inline'],
            ['file', 'inline']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
