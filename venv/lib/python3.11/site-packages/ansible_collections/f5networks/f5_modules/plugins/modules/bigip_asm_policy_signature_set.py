#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_policy_signature_set
short_description: Manages Signature Sets on an ASM policy
description:
  - Manages Signature Sets on an ASM policy.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the signature sets to apply to, or remove from, the ASM policy.
      - Apart from built-in signature sets that ship with the device, you can create and use
        custom signature sets.
      - When C(All Response Signatures), configures all signatures in the attack signature
        pool that can review responses.
      - When C(All Signatures), configures all attack signatures in the attack signature pool.
      - When C(Apache Struts Signatures), configures signatures that target attacks against
        the Apache Struts web servers. Only available in version 13.x and later.
      - When C(Apache Tomcat Signatures), configures signatures that target attacks against
        the Apache Tomcat web servers. Only available in version 13.x and later.
      - When C(Cisco Signatures), configures signatures that target attacks against Cisco systems.
        Only available in version 13.x and later.
      - When C(Command Execution Signatures), configures signatures involving attacks perpetrated by executing commands.
      - When C(Cross Site Scripting Signatures), configures signatures that target attacks caused
        by cross-site scripting techniques.
      - When C(Directory Indexing Signatures), configures signatures targeting attacks that browse directory listings.
      - When C(Generic Detection Signatures), configures signatures targeting well-known
        or common web and application attacks.
      - When C(HTTP Response Splitting Signatures), configures signatures targeting attacks that
        take advantage of responses for which input values have not been sanitized.
      - When C(High Accuracy Detection Evasion Signatures), configures signatures with a high level of accuracy
        that produce few false positives when identifying evasion attacks. Only available in version 13.x and later.
      - When C(High Accuracy Signatures), configures signatures with a high level of accuracy
        that produce few false positives when identifying evasion attacks.
      - When C(IIS and Windows Signatures), configures signatures that target attacks against Microsoft IIS
        and Windows-based systems. Only available in version 13.x and later.
      - When C(Information Leakage Signatures), configures signatures targeting attacks that are looking for system data
        or debugging information that shows where the system is vulnerable to attack.
      - When C(Java Servlets/JSP Signatures), configures signatures that target attacks against Java Servlets
        and Java Server Pages (JSP) based applications. Only available in version 13.x and later.
      - When C(Low Accuracy Signatures), configures signatures that may result in more false positives
        when identifying attacks.
      - When C(Medium Accuracy Signatures), configures signatures with a medium level of accuracy
        when identifying attacks.
      - When C(OS Command Injection Signatures), configures signatures targeting attacks
        that attempt to run system level commands through a vulnerable application.
      - When C(OWA Signatures), configures signatures that target attacks against
        the Microsoft Outlook Web Access (OWA) application.
      - When C(Other Application Attacks Signatures), configures signatures targeting miscellaneous attacks,
        including session fixation, local file access, injection attempts, header tampering
        and so on, affecting many applications.
      - When C(Path Traversal Signatures), configures signatures targeting attacks that attempt to access files
        and directories that are stored outside the web root folder.
      - When C(Predictable Resource Location Signatures), configures signatures targeting attacks that attempt
        to uncover hidden website content and functionality by forceful browsing, or by directory and file enumeration.
      - When C(Remote File Include Signatures), configures signatures targeting attacks that attempt to exploit
        a remote file include vulnerability that could enable a remote attacker to execute arbitrary commands
        on the server hosting the application.
      - When C(SQL Injection Signatures), configures signatures targeting attacks that attempt to insert (inject)
        a SQL query using the input data from a client to an application.
      - When C(Server Side Code Injection Signatures), configures signatures targeting code injection attacks
        on the server side.
      - When C(WebSphere signatures), configures signatures targeting attacks on many computing platforms
        that are integrated using WebSphere, including general database, Microsoft Windows, IIS,
        Microsoft SQL Server, Apache, Oracle, Unix/Linux, IBM DB2, PostgreSQL, and XML.
      - When C(XPath Injection Signatures), configures signatures targeting attacks that attempt to gain access
        to data structures or bypass permissions when a web site uses user-supplied information
        to construct XPath queries for XML data.
    type: str
    required: True
  policy_name:
    description:
      - Specifies the name of an existing ASM policy to add or remove signature sets to.
    type: str
    required: True
  alarm:
    description:
      - Specifies if the security policy logs the request data in the Statistics screen
        when a request matches a signature that is included in the signature set.
    type: bool
  block:
    description:
      - Effective when the security policy enforcement mode is Blocking.
      - Determines how the system treats requests that match a signature included in the signature set.
      - When C(true), the system blocks all requests that match a signature,
        and provides the client with a support ID number.
      - When C(false), the system accepts those requests.
    type: bool
  learn:
    description:
      - Specifies if the security policy learns all requests that match a signature
        that is included in the signature set.
    type: bool
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
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Add Signature Set to ASM Policy
  bigip_asm_policy_signature_set:
    name: IIS and Windows Signatures
    policy_name: FooPolicy
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove Signature Set to ASM Policy
  bigip_asm_policy_signature_set:
    name: IIS and Windows Signatures
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
  description: The name of the ASM policy.
  returned: changed
  type: str
  sample: FooPolicy
name:
  description: The name of the Signature Set added/removed on an ASM policy.
  returned: changed
  type: str
  sample: Cisco Signatures
alarm:
  description: Specifies whether the security policy logs the request data in the Statistics screen.
  returned: changed
  type: bool
  sample: true
block:
  description: Determines how the system treats requests that match a signature included in the signature set.
  returned: changed
  type: bool
  sample: false
learn:
  description: Specifies if the policy learns all requests that match a signature that is included in the signature set.
  returned: changed
  type: bool
  sample: true
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
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        'alarm',
        'block',
        'learn',

    ]

    returnables = [
        'policy_name',
        'name',
        'alarm',
        'block',
        'learn',

    ]

    updatables = [
        'alarm',
        'block',
        'learn',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def alarm(self):
        result = flatten_boolean(self._values['alarm'])
        if result:
            if result == 'yes':
                return True
            return False

    @property
    def block(self):
        result = flatten_boolean(self._values['block'])
        if result:
            if result == 'yes':
                return True
            return False

    @property
    def learn(self):
        result = flatten_boolean(self._values['learn'])
        if result:
            if result == 'yes':
                return True
            return False

    def _signature_set_exists_on_device(self, name):
        uri = "https://{0}:{1}/mgmt/tm/asm/signature-sets".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )

        query = "?$select=name"
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)
        if any(p['name'] == name for p in response['items']):
            return True
        return False

    @property
    def name(self):
        if self._values['name'] is None:
            return None

        version = tmos_version(self.client)

        if Version(version) < Version('13.0.0'):
            name_list = [
                'All Response Signatures',
                'All Signatures',
                'Command Execution Signatures',
                'Cross Site Scripting Signatures',
                'Directory Indexing Signatures',
                'Generic Detection Signatures',
                'HTTP Response Splitting Signatures',
                'High Accuracy Signatures',
                'Information Leakage Signatures',
                'Low Accuracy Signatures',
                'Medium Accuracy Signatures',
                'OS Command Injection Signatures',
                'OWA Signatures',
                'Other Application Attacks Signatures',
                'Path Traversal Signatures',
                'Predictable Resource Location Signatures',
                'Remote File Include Signatures',
                'SQL Injection Signatures',
                'Server Side Code Injection Signatures',
                'WebSphere signatures',
                'XPath Injection Signatures'
            ]
        else:
            name_list = [
                'All Response Signatures',
                'All Signatures',
                'Apache Struts Signatures',
                'Apache Tomcat Signatures',
                'Cisco Signatures',
                'Command Execution Signatures',
                'Cross Site Scripting Signatures',
                'Directory Indexing Signatures',
                'Generic Detection Signatures',
                'HTTP Response Splitting Signatures',
                'High Accuracy Detection Evasion Signatures',
                'High Accuracy Signatures',
                'IIS and Windows Signatures',
                'Information Leakage Signatures',
                'Java Servlets/JSP Signatures',
                'Low Accuracy Signatures',
                'Medium Accuracy Signatures',
                'OS Command Injection Signatures',
                'OWA Signatures',
                'Other Application Attacks Signatures',
                'Path Traversal Signatures',
                'Predictable Resource Location Signatures',
                'Remote File Include Signatures',
                'SQL Injection Signatures',
                'Server Side Code Injection Signatures',
                'WebSphere signatures',
                'XPath Injection Signatures'
            ]

        if self._values['name'] in name_list:
            return self._values['name']

        if self._signature_set_exists_on_device(self._values['name']):
            return self._values['name']

        raise F5ModuleError(
            "The specified signature {0} set does not exist.".format(
                self._values['name']
            )
        )


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
    def alarm(self):
        return flatten_boolean(self._values['alarm'])

    @property
    def learn(self):
        return flatten_boolean(self._values['learn'])

    @property
    def block(self):
        return flatten_boolean(self._values['block'])


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
        self.want = ModuleParameters(params=self.module.params, client=self.client)
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
        if not module_provisioned(self.client, 'asm'):
            raise F5ModuleError(
                "ASM must be provisioned to use this module."
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
        policy_id = self._get_policy_id()
        set_link = self._get_signature_set_link()
        uri = 'https://{0}:{1}/mgmt/tm/asm/policies/{2}/signature-sets/'.format(
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
                if st['signatureSetReference']['link'] == set_link['link']:
                    self.want.ss_id = st['id']
                    return True
        return False

    def _get_signature_set_link(self):
        result = None
        signature_set = self.want.name
        uri = "https://{0}:{1}/mgmt/tm/asm/signature-sets".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )

        query = "?$select=name"
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)
        if 'items' in response and response['items'] != []:
            for item in response['items']:
                if item['name'] == signature_set:
                    result = dict(link=item['selfLink'])
        if result:
            return result
        raise F5ModuleError("The following signature set: {0} was not found on the device. "
                            "Possibly name has changed in your TMOS version.".format(self.want.name))

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

    def create_on_device(self):
        policy_id = self._get_policy_id()
        params = self.changes.api_params()
        params['signatureSetReference'] = self._get_signature_set_link()
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}/signature-sets/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id
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
        policy_id = self._get_policy_id()
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}/signature-sets/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id,
            self.want.ss_id
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
        policy_id = self._get_policy_id()
        uri = 'https://{0}:{1}/mgmt/tm/asm/policies/{2}/signature-sets/{3}'.format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id,
            self.want.ss_id
        )
        response = self.client.api.delete(uri)
        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        policy_id = self._get_policy_id()
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}/signature-sets/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id,
            self.want.ss_id
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
            policy_name=dict(
                required=True
            ),
            name=dict(
                required=True
            ),
            alarm=dict(
                type='bool'
            ),
            block=dict(
                type='bool'
            ),
            learn=dict(
                type='bool'
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
