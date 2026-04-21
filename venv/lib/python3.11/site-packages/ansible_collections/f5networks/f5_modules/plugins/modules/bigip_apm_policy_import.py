#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_apm_policy_import
short_description: Manage BIG-IP APM policy or APM access profile imports
description:
   - Manage BIG-IP APM policy or APM access profile imports.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the APM policy or APM access profile to create or override.
    type: str
    required: True
  type:
    description:
      - Specifies the type of item to export from the device.
    type: str
    choices:
      - profile_access
      - access_policy
      - profile_api_protection
    default: profile_access
  source:
    description:
      - Full path to a file to be imported into the BIG-IP APM.
    type: path
  force:
    description:
      - When set to C(true) any existing policy with the same name will be overwritten by the new import.
      - If a policy does not exist, this setting is ignored.
    default: false
    type: bool
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  reuse_objects:
    description:
      - When set to C(true) and objects referred within the policy exist on the BIG-IP,
        those will be used instead of the objects defined in the policy.
      - Reusing existing objects reduces configuration size.
      - The configuration of existing objects might differ to the configuration of the objects defined in the policy!
    default: true
    type: bool
notes:
  - Due to ID685681 it is not possible to execute ng_* tools via REST API on v12.x and 13.x, once this is fixed
    this restriction will be removed.
  - Requires BIG-IP >= 14.0.0
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Import APM profile
  bigip_apm_policy_import:
    name: new_apm_profile
    source: /root/apm_profile.tar.gz
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Import APM policy
  bigip_apm_policy_import:
    name: new_apm_policy
    source: /root/apm_policy.tar.gz
    type: access_policy
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Override existing APM policy
  bigip_asm_policy:
    name: new_apm_policy
    source: /root/apm_policy.tar.gz
    force: true
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Import APM profile without re-using existing configuration objects
  bigip_apm_policy_import:
    name: new_apm_profile
    source: /root/apm_profile.tar.gz
    reuse_objects: false
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
source:
  description: Local path to APM policy file.
  returned: changed
  type: str
  sample: /root/some_policy.tar.gz
name:
  description: Name of the APM policy or APM access profile to be created/overwritten.
  returned: changed
  type: str
  sample: APM_policy_global
type:
  description: Set to specify type of item to export.
  returned: changed
  type: str
  sample: access_policy
force:
  description: Set when overwriting an existing policy or profile.
  returned: changed
  type: bool
  sample: true
reuse_objects:
  description: Set when reusing existing objects on the BIG-IP.
  returned: changed
  type: bool
  sample: true
'''

import os
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
    AnsibleModule, missing_required_lib, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version, upload_file
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [

    ]

    returnables = [
        'name',
        'source',
        'type',

    ]

    updatables = [

    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    pass


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
        if not module_provisioned(self.client, 'apm'):
            raise F5ModuleError(
                "APM must be provisioned to use this module."
            )

        if self.version_less_than_14():
            raise F5ModuleError('Due to bug ID685681 it is not possible to use this module on TMOS version below 14.x')

        result = dict()

        changed = self.policy_import()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def version_less_than_14(self):
        version = tmos_version(self.client)
        if Version(version) < Version('14.0.0'):
            return True
        return False

    def policy_import(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.exists():
            if self.want.force is False:
                return False

        self.import_file_to_device()
        self.remove_temp_file_from_device()
        return True

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        if self.want.type == 'access_policy':
            uri = "https://{0}:{1}/mgmt/tm/apm/policy/access-policy/{2}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self.want.partition, self.want.name)
            )
        else:
            uri = "https://{0}:{1}/mgmt/tm/apm/profile/access/{2}".format(
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

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

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

    def import_file_to_device(self):
        name = os.path.split(self.want.source)[1]
        self.upload_file_to_device(self.want.source, name)

        if self.want.reuse_objects is True:
            reuse_objects = "-s"
        else:
            reuse_objects = ""

        cmd = 'ng_import {0} /var/config/rest/downloads/{1} {2} -p {3} -t {4}'.format(
            reuse_objects, name, self.want.name, self.want.partition, self.want.type
        )

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
                raise F5ModuleError(response['commandResult'])
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def remove_temp_file_from_device(self):
        name = os.path.split(self.want.source)[1]
        tpath_name = '/var/config/rest/downloads/{0}'.format(name)
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
            source=dict(type='path'),
            force=dict(
                type='bool',
                default='no'
            ),
            type=dict(
                default='profile_access',
                choices=['profile_access', 'access_policy', 'profile_api_protection']
            ),
            reuse_objects=dict(
                type='bool',
                default='yes'
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
