#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_policy_server_technology
short_description: Manages Server Technology on an ASM policy
description:
  - Manages Server Technology on ASM policies.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the server technology to apply on, or remove from, the ASM policy.
    type: str
    required: True
    choices:
      - jQuery
      - Java Servlets/JSP
      - ASP
      - WebDAV
      - IIS
      - Front Page Server Extensions (FPSE)
      - ASP.NET
      - Microsoft Windows
      - Unix/Linux
      - Macromedia ColdFusion
      - WordPress
      - Apache Tomcat
      - Apache/NCSA HTTP Server
      - Outlook Web Access
      - PHP
      - Microsoft SQL Server
      - Oracle
      - MySQL
      - Lotus Domino
      - BEA Systems WebLogic Server
      - Macromedia JRun
      - Novell
      - Cisco
      - SSI (Server Side Includes)
      - Proxy Servers
      - CGI
      - Sybase/ASE
      - IBM DB2
      - PostgreSQL
      - XML
      - Apache Struts
      - Elasticsearch
      - JBoss
      - Citrix
      - Node.js
      - Django
      - MongoDB
      - Ruby
      - JavaServer Faces (JSF)
      - Joomla
      - Jetty
  policy_name:
    description:
      - Specifies the name of an existing ASM policy to add or remove a server technology to.
    type: str
    required: True
  state:
    description:
      - When C(present), ensures the resource exists.
      - When C(absent), ensures the resource is removed.
    type: str
    default: present
    choices:
      - present
      - absent
  partition:
    description:
      - This parameter is only used when identifying an ASM policy.
    type: str
    default: Common
notes:
  - This module is primarily used as a component of configuring an ASM policy in the Ansible Galaxy ASM Policy Role.
  - Requires BIG-IP >= 13.0.0
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Add Server Technology to ASM Policy
  bigip_asm_policy_server_technology:
    name: Joomla
    policy_name: FooPolicy
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
- name: Remove Server Technology from ASM Policy
  bigip_asm_policy_server_technology:
    name: Joomla
    policy_name: FooPolicy
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
policy_name:
  description: The name of the ASM policy
  returned: changed
  type: str
  sample: FooPolicy
name:
  description: The name of Server Technology added/removed on the ASM policy.
  returned: changed
  type: str
  sample: Joomla
'''
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
    AnsibleModule, env_fallback, missing_required_lib
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [

    ]

    returnables = [
        'policy_name',
        'name'

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


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = Changes(params=changed)

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        if not module_provisioned(self.client, 'asm'):
            raise F5ModuleError(
                "ASM must be provisioned to use this module."
            )
        if self.version_is_less_than_13():
            raise F5ModuleError(
                "This module requires TMOS version 13.x and above."
            )

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

    def version_is_less_than_13(self):
        version = tmos_version(self.client)
        if Version(version) < Version('13.0.0'):
            return True
        else:
            return False

    def present(self):
        if self.exists():
            return False
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

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
        policy_id = self._get_policy_id()
        server_link = self._get_server_tech_link()
        uri = 'https://{0}:{1}/mgmt/tm/asm/policies/{2}/server-technologies/'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id,
        )
        resp = self.client.api.get(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        if 'items' in response and response['items'] != []:
            for st in response['items']:
                if st['serverTechnologyReference']['link'] == server_link:
                    self.want.tech_id = st['id']
                    return True
        return False

    def _get_policy_id(self):
        policy_id = None
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$filter=contains(name,'{0}')+and+contains(partition,'{1}')&$select=name,id,partition".format(
            self.want.policy_name, self.want.partition
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
                if policy['name'] == self.want.policy_name and policy['partition'] == self.want.partition:
                    policy_id = policy['id']

        if not policy_id:
            raise F5ModuleError(
                "The policy with the name {0} was not found.".format(self.want.policy_name)
            )
        return policy_id

    def _get_server_tech_link(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/server-technologies/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        name = self.want.name.replace(' ', '%20')
        query = "?$filter=contains(serverTechnologyName,'{0}')".format(name)
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' in response and response['items'] != []:
            for item in response['items']:
                if item['serverTechnologyName'] == self.want.name:
                    return item['selfLink']
        raise F5ModuleError("The following server technology: {0} was not found on the device.".format(self.want.name))

    def create_on_device(self):
        policy_id = self._get_policy_id()

        uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}/server-technologies/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id
        )

        params = dict(serverTechnologyReference={'link': self._get_server_tech_link()})
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def remove_from_device(self):
        policy_id = self._get_policy_id()
        tech_id = self.want.tech_id
        uri = 'https://{0}:{1}/mgmt/tm/asm/policies/{2}/server-technologies/{3}'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id,
            tech_id,
        )
        response = self.client.api.delete(uri)
        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.tech = [
            'jQuery',
            'Java Servlets/JSP',
            'ASP',
            'WebDAV',
            'IIS',
            'Front Page Server Extensions (FPSE)',
            'ASP.NET',
            'Microsoft Windows',
            'Unix/Linux',
            'Macromedia ColdFusion',
            'WordPress',
            'Apache Tomcat',
            'Apache/NCSA HTTP Server',
            'Outlook Web Access',
            'PHP',
            'Microsoft SQL Server',
            'Oracle',
            'MySQL',
            'Lotus Domino',
            'BEA Systems WebLogic Server',
            'Macromedia JRun',
            'Novell',
            'Cisco',
            'SSI (Server Side Includes)',
            'Proxy Servers',
            'CGI',
            'Sybase/ASE',
            'IBM DB2',
            'PostgreSQL',
            'XML',
            'Apache Struts',
            'Elasticsearch',
            'JBoss',
            'Citrix',
            'Node.js',
            'Django',
            'MongoDB',
            'Ruby',
            'JavaServer Faces (JSF)',
            'Joomla',
            'Jetty'
        ]
        argument_spec = dict(
            policy_name=dict(
                required=True
            ),
            name=dict(
                choices=self.tech,
                required=True
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
