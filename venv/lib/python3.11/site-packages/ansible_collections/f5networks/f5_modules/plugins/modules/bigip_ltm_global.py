#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_ltm_global
short_description: Manages global LTM settings
description:
  - Manages global BIG-IP LTM settings. These settings include connection related settings.
version_added: "1.16.0"
options:
  connection:
    description:
      - Specifies the connection related general LTM settings.
    type: dict
    required: True
    suboptions:
      default_vs_syn_challenge_tresh:
        description:
          - Specifies the default value of per-virtual server SYN Cookie activation threshold.
          - "The valid range is 128 - 1048576, or infinite (encoded as 0)."
        type: int
      global_syn_challenge_tresh:
        description:
          -  Specifies the default value of the global SYN Cookie activation threshold.
          - "The valid range is 2048 - 4194304, or infinite (encoded as 0)."
        type: int
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Modify ltm global settings
  bigip_ltm_global:
    connection:
      default_vs_syn_challenge_tresh: 9123
      global_syn_challenge_tresh: 20000
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
default_vs_syn_challenge_tresh:
  description: The default value of per-virtual server SYN Cookie activation threshold.
  returned: changed
  type: int
  sample: 0
global_syn_challenge_tresh:
  description: The default value of the global SYN Cookie activation threshold.
  returned: changed
  type: int
  sample: 64000
'''
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'defaultVsSynChallengeThreshold': 'default_vs_syn_challenge_tresh',
        'globalSynChallengeThreshold': 'global_syn_challenge_tresh',
    }

    api_attributes = [
        'defaultVsSynChallengeThreshold',
        'globalSynChallengeThreshold',
    ]

    returnables = [
        'default_vs_syn_challenge_tresh',
        'global_syn_challenge_tresh'
    ]

    updatables = [
        'default_vs_syn_challenge_tresh',
        'global_syn_challenge_tresh'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def default_vs_syn_challenge_tresh(self):
        if self._values['connection'] is None:
            return None
        value = self._values['connection']['default_vs_syn_challenge_tresh']
        if value is None:
            return None
        if value == 0:
            return 'infinite'
        if 128 < value > 1048576:
            raise F5ModuleError(
                "Specified number is out of valid range, correct range is between 128 and 1048576, or 0 for infinite."
            )
        return str(value)

    @property
    def global_syn_challenge_tresh(self):
        if self._values['connection'] is None:
            return None
        value = self._values['connection']['global_syn_challenge_tresh']
        if value is None:
            return None
        if value == 0:
            return 'infinite'
        if 2048 < value > 4194304:
            raise F5ModuleError(
                "Specified number is out of valid range, correct range is between 2048 and 4194304, or 0 for infinite."
            )
        return str(value)


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
    def default_vs_syn_challenge_tresh(self):
        if self._values['default_vs_syn_challenge_tresh'] is None:
            return None
        value = self._values['default_vs_syn_challenge_tresh']
        if value is None:
            return None
        if value == 'infinite':
            return 0
        return int(value)

    @property
    def global_syn_challenge_tresh(self):
        value = self._values['global_syn_challenge_tresh']
        if value is None:
            return None
        if value == 'infinite':
            return 0
        return int(value)


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
        self.have = ApiParameters()
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
        return self.update()

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/global-settings/connection".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/global-settings/connection".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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
            connection=dict(
                type='dict',
                required=True,
                options=dict(
                    default_vs_syn_challenge_tresh=dict(type='int'),
                    global_syn_challenge_tresh=dict(type='int')
                ),
                required_one_of=[
                    ['default_vs_syn_challenge_tresh', 'global_syn_challenge_tresh']
                ]
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
