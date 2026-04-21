#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_policy_import
short_description: Manage BIG-IP ASM policy imports
description:
   - Manage the policy imports for BIG-IP ASM policies.
version_added: "1.0.0"
options:
  name:
    description:
      - The ASM policy to create or override.
    type: str
    required: True
  policy_type:
    description:
      - The type of the policy to import.
      - When C(policy_type) is C(security), the policy is imported as an application security policy that you can apply
        to a virtual server.
      - When C(policy_type) is C(parent), the policy becomes a parent to which other Security policies attach,
        inheriting its attributes. This policy type cannot be applied to Virtual Servers.
      - This parameter is available on TMOS version 13.x and later and only takes effect when the C(inline) import method
        is used.
    type: str
    default: security
    choices:
      - security
      - parent
  retain_inheritance_settings:
    description:
      - Indicates if an imported security type policy should retain settings when attached to parent policy.
      - This parameter is available on TMOS version 13.x and later and only takes effect when the C(inline) import method
        is used.
    type: bool
  parent_policy:
    description:
      - The parent policy to which the newly imported policy should be attached as child.
      - When C(parent_policy) is specified, the imported C(policy_type) must not be C(parent).
      - This parameter is available on TMOS version 13.x and later and only takes effect when C(inline) import method
        is used.
    type: str
  base64:
    description:
      - Indicates if the imported policy string is encoded in Base64.
      - This parameter only takes effect when using the C(inline) method of import.
    type: bool
  inline:
    description:
      - When specified, the ASM policy is created from a provided string.
      - Content needs to be provided in a valid XML format, otherwise the operation will fail.
    type: str
  encoding:
    description:
      - Specifies the desired application language of the imported policy.
      - The imported policy cannot be a C(parent) type or attached to a C(parent) policy when C(auto-detect)
        encoding is set.
      - When importing a policy to attach to a C(parent) policy, the C(encoding) of the imported policy, if different,
        must be set to be the same value as C(parent_policy), otherwise import will fail.
      - This parameter is available on TMOS version 13.x and later and only takes effect when the C(inline) import method
        is used.
    type: str
    choices:
      - windows-874
      - utf-8
      - koi8-r
      - windows-1253
      - iso-8859-10
      - gbk
      - windows-1256
      - windows-1250
      - iso-8859-13
      - iso-8859-9
      - windows-1251
      - iso-8859-6
      - big5
      - gb2312
      - iso-8859-1
      - windows-1252
      - iso-8859-4
      - iso-8859-2
      - iso-8859-3
      - gb18030
      - shift_jis
      - iso-8859-8
      - euc-kr
      - iso-8859-5
      - iso-8859-7
      - windows-1255
      - euc-jp
      - iso-8859-15
      - windows-1257
      - iso-8859-16
      - auto-detect
  source:
    description:
      - Full path to a policy file to be imported into the BIG-IP ASM.
      - Policy files exported from newer versions of BIG-IP cannot be imported into older
        versions of BIG-IP. However, policy files from older versions of BIG-IP can be
        imported into newer versions of BIG-IP.
      - The file format can be binary or XML.
    type: path
  force:
    description:
      - When set to C(true), any existing policy with the same name will be overwritten by the new import.
      - This works for both inline and file imports, if the policy does not exist this setting is ignored.
    default: false
    type: bool
  partition:
    description:
      - Device partition on which to create the policy.
      - This parameter is also applied to indicate the partition of the C(parent) policy.
    type: str
    default: Common
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
  - Nitin Khanna (@nitinthewiz)
'''

EXAMPLES = r'''
- name: Import ASM policy
  bigip_asm_policy_import:
    name: new_asm_policy
    file: /root/asm_policy.xml
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Import ASM policy inline
  bigip_asm_policy_import:
    name: foo-policy4
    inline: <xml>content</xml>
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Override existing ASM policy
  bigip_asm_policy:
    name: new_asm_policy
    source: /root/asm_policy_new.xml
    force: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
policy_type:
  description: The type of the policy to import.
  returned: changed
  type: str
  sample: security
retain_inheritance_settings:
  description: Indicate if an imported security type policy should retain settings when attached to the parent policy.
  returned: changed
  type: bool
  sample: true
parent_policy:
  description: The parent policy to which the newly imported policy should be attached as child.
  returned: changed
  type: str
  sample: /Common/parent
base64:
  description: Indicates if the imported policy string is encoded in Base64.
  returned: changed
  type: bool
  sample: true
encoding:
  description: The desired application language of the imported policy.
  returned: changed
  type: str
  sample: utf-8
source:
  description: Local path to an ASM policy file.
  returned: changed
  type: str
  sample: /root/some_policy.xml
inline:
  description: Contents of a policy as an inline string.
  returned: changed
  type: str
  sample: <xml>foobar contents</xml>
name:
  description: Name of the ASM policy to be created/overwritten.
  returned: changed
  type: str
  sample: Asm_APP1_Transparent
force:
  description: Set when overwriting an existing policy.
  returned: changed
  type: bool
  sample: true
'''

import os
import time
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.icontrol import (
    module_provisioned, upload_file, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    updatables = []

    returnables = [
        'name',
        'inline',
        'source',
        'force',
        'policy_type',
        'retain_inheritance_settings',
        'parent_policy',
        'base64',
        'encoding',
    ]

    api_attributes = [
        'file',
        'name',
        'policyType',
        'retainInheritanceSettings',
        'parentPolicy',
        'isBase64',
        'applicationLanguage',
    ]

    api_map = {
        'file': 'inline',
        'filename': 'source',
        'policyType': 'policy_type',
        'retainInheritanceSettings': 'retain_inheritance_settings',
        'parentPolicy': 'parent_policy',
        'isBase64': 'base64',
        'applicationLanguage': 'encoding',
    }


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def parent_policy(self):
        if self._values['parent_policy'] is None:
            return None
        if self._values['policy_type'] == 'parent':
            raise F5ModuleError(
                "The 'policy_type' cannot be 'parent' if 'parent_policy' is defined."
            )
        result = dict(fullPath=fq_name(self.partition, self._values['parent_policy']))
        return result

    @property
    def base64(self):
        result = flatten_boolean(self._values['base64'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def retain_inheritance_settings(self):
        result = flatten_boolean(self._values['retain_inheritance_settings'])
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
    @property
    def parent_policy(self):
        if self._values['parent_policy'] is None:
            return None
        result = self._values['parent_policy']['fullPath']
        return result

    @property
    def retain_inheritance_settings(self):
        result = flatten_boolean(self._values['retain_inheritance_settings'])
        return result

    @property
    def base64(self):
        result = flatten_boolean(self._values['base64'])
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

        changed = self.policy_import()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def _clear_changes(self):
        redundant = [
            'policy_type',
            'retain_inheritance_settings',
            'parent_policy',
            'base64',
            'encoding',
        ]
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None and key not in redundant:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def policy_import(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.exists():
            if self.want.force is False:
                return False
        if not self.exists() and self.want.force is True:
            self.want.update({'force': None})
        if self.want.inline:
            task = self.inline_import()
            self.wait_for_task(task)
            return True
        self._clear_changes()
        self.import_file_to_device()
        return True

    def exists(self):
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
        return False

    def upload_file_to_device(self, content, name):
        url = 'https://{0}:{1}/mgmt/tm/asm/file-transfer/uploads'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        try:
            upload_file(self.client, url, content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def _get_policy_link(self):
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
                    policy_link = policy['selfLink']
                    return policy_link
        raise F5ModuleError(
            'Unable to retrieve policy link for policy {0}.'.format(self.want.name)
        )

    def inline_import(self):
        params = self.changes.api_params()
        params['name'] = fq_name(self.want.partition, self.want.name)
        if self.want.source:
            params['filename'] = os.path.split(self.want.source)[1]
        uri = "https://{0}:{1}/mgmt/tm/asm/tasks/import-policy/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        if self.want.force:
            params.update(dict(policyReference={'link': self._get_policy_link()}))
            params.pop('name')

        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        return response['id']

    def wait_for_task(self, task_id):
        uri = "https://{0}:{1}/mgmt/tm/asm/tasks/import-policy/{2}".format(
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
                'Failed to import ASM policy.'
            )
        if response['status'] == 'COMPLETED':
            return True

    def import_file_to_device(self):
        name = os.path.split(self.want.source)[1]
        self.upload_file_to_device(self.want.source, name)
        time.sleep(2)

        task = self.inline_import()
        self.wait_for_task(task)
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.choices = [
            'windows-874',
            'utf-8',
            'koi8-r',
            'windows-1253',
            'iso-8859-10',
            'gbk',
            'windows-1256',
            'windows-1250',
            'iso-8859-13',
            'iso-8859-9',
            'windows-1251',
            'iso-8859-6',
            'big5',
            'gb2312',
            'iso-8859-1',
            'windows-1252',
            'iso-8859-4',
            'iso-8859-2',
            'iso-8859-3',
            'gb18030',
            'shift_jis',
            'iso-8859-8',
            'euc-kr',
            'iso-8859-5',
            'iso-8859-7',
            'windows-1255',
            'euc-jp',
            'iso-8859-15',
            'windows-1257',
            'iso-8859-16',
            'auto-detect'
        ]
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            source=dict(type='path'),
            inline=dict(),
            policy_type=dict(
                default='security',
                choices=['security', 'parent']
            ),
            retain_inheritance_settings=dict(type='bool'),
            base64=dict(type='bool'),
            parent_policy=dict(),
            encoding=dict(choices=self.choices),
            force=dict(
                type='bool',
                default='no'
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
            ['source', 'inline']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
