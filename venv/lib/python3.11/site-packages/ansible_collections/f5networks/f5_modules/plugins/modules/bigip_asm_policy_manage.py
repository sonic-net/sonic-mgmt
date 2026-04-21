#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_policy_manage
short_description: Manage BIG-IP ASM policies
description:
   - Manage BIG-IP ASM policies, create policies from templates, and manage global policy settings.
version_added: "1.0.0"
options:
  active:
    description:
      - If C(true), applies and activates the existing inactive policy. If C(false), it
        deactivates the existing active policy. Generally should be C(true) only in cases where
        you want to activate new or existing policy.
      - In TMOS v14 and later, deactivating the policy causes it to be detached from any other associated objects,
        therefore the default option of C(false) has been removed in order to prevent accidental disassociation.
    type: bool
  apply:
    description:
      - If C(true) applies the policy if the policy has pending changes.
      - This parameter supported on TMOS C(v14.x) and above.
    type: bool
    version_added: "1.4.0"
  name:
    description:
      - The ASM policy to manage or create.
    type: str
    required: True
  state:
    description:
      - When C(state) is C(present), and the C(template) parameter is provided,
        a new ASM policy is created from the template with the given policy C(name).
      - When C(state) is C(present) and no C(template) parameter is provided, a
        new blank ASM policy is created with the given policy C(name).
      - When C(state) is C(absent), ensures the policy is removed, even if it is
        currently active.
    type: str
    choices:
      - present
      - absent
    default: present
  template:
    description:
      - An ASM policy built-in template. If the template does not exist, an error is raised.
      - Once the policy has been created, this value cannot change.
      - The C(Comprehensive), C(Drupal), C(Fundamental), C(Joomla),
        C(Vulnerability Assessment Baseline), and C(Wordpress) templates are only available
        on BIG-IP versions >= 13.
    type: str
    choices:
      - ActiveSync v1.0 v2.0 (http)
      - ActiveSync v1.0 v2.0 (https)
      - Comprehensive
      - Drupal
      - Fundamental
      - Joomla
      - LotusDomino 6.5 (http)
      - LotusDomino 6.5 (https)
      - OWA Exchange 2003 (http)
      - OWA Exchange 2003 (https)
      - OWA Exchange 2003 with ActiveSync (http)
      - OWA Exchange 2003 with ActiveSync (https)
      - OWA Exchange 2007 (http)
      - OWA Exchange 2007 (https)
      - OWA Exchange 2007 with ActiveSync (http)
      - OWA Exchange 2007 with ActiveSync (https)
      - OWA Exchange 2010 (http)
      - OWA Exchange 2010 (https)
      - Oracle 10g Portal (http)
      - Oracle 10g Portal (https)
      - Oracle Applications 11i (http)
      - Oracle Applications 11i (https)
      - PeopleSoft Portal 9 (http)
      - PeopleSoft Portal 9 (https)
      - Rapid Deployment Policy
      - SAP NetWeaver 7 (http)
      - SAP NetWeaver 7 (https)
      - SharePoint 2003 (http)
      - SharePoint 2003 (https)
      - SharePoint 2007 (http)
      - SharePoint 2007 (https)
      - SharePoint 2010 (http)
      - SharePoint 2010 (https)
      - Vulnerability Assessment Baseline
      - Wordpress
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create ASM policy from template
  bigip_asm_policy:
    name: new_sharepoint_policy
    template: SharePoint 2007 (http)
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create blank ASM policy
  bigip_asm_policy:
    name: new_blank_policy
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create blank ASM policy and activate
  bigip_asm_policy_manage:
    name: new_blank_policy
    active: true
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Activate ASM policy
  bigip_asm_policy_manage:
    name: inactive_policy
    active: true
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Deactivate ASM policy
  bigip_asm_policy_manage:
    name: active_policy
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
active:
  description: Set when activating/deactivating an ASM policy.
  returned: changed
  type: bool
  sample: true
apply:
  description: Set when applying pending changes to an ASM policy.
  returned: changed when target policy has changes pending
  type: bool
  sample: true
state:
  description: Action performed on the target device.
  returned: changed
  type: str
  sample: absent
template:
  description: Name of the built-in ASM policy template.
  returned: changed
  type: str
  sample: OWA Exchange 2007 (https)
name:
  description: Name of the ASM policy to be managed/created.
  returned: changed
  type: str
  sample: Asm_APP1_Transparent
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
    AnsibleModule, env_fallback, missing_required_lib
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    updatables = [
        'active',
        'apply',
    ]

    returnables = [
        'name',
        'template',
        'active',
        'apply',
    ]

    api_attributes = []
    api_map = {
        'isModified': 'apply'
    }

    @property
    def template_link(self):
        if self._values['template_link'] is not None:
            return self._values['template_link']

        result = None

        uri = "https://{0}:{1}/mgmt/tm/asm/policy-templates/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )

        query = "?$filter=name+eq+{0}".format(self.template.upper())
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' in response and response['items'] != []:
            result = dict(link=response['items'][0]['selfLink'])

        return result

    @property
    def active(self):
        result = flatten_boolean(self._values['active'])
        if result is None:
            return None
        if result == 'yes':
            return True
        return False


class V1ModuleParameters(Parameters):
    @property
    def template(self):
        if self._values['template'] is None:
            return None
        template_map = {
            'ActiveSync v1.0 v2.0 (http)': 'POLICY_TEMPLATE_ACTIVESYNC_V1_0_V2_0_HTTP',
            'ActiveSync v1.0 v2.0 (https)': 'POLICY_TEMPLATE_ACTIVESYNC_V1_0_V2_0_HTTPS',
            'LotusDomino 6.5 (http)': 'POLICY_TEMPLATE_LOTUSDOMINO_6_5_HTTP',
            'LotusDomino 6.5 (https)': 'POLICY_TEMPLATE_LOTUSDOMINO_6_5_HTTPS',
            'OWA Exchange 2003 (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_HTTP',
            'OWA Exchange 2003 (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_HTTPS',
            'OWA Exchange 2003 with ActiveSync (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_WITH_ACTIVESYNC_HTTP',
            'OWA Exchange 2003 with ActiveSync (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_WITH_ACTIVESYNC_HTTPS',
            'OWA Exchange 2007 (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_HTTP',
            'OWA Exchange 2007 (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_HTTPS',
            'OWA Exchange 2007 with ActiveSync (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_WITH_ACTIVESYNC_HTTP',
            'OWA Exchange 2007 with ActiveSync (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_WITH_ACTIVESYNC_HTTPS',
            'OWA Exchange 2010 (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2010_HTTP',
            'OWA Exchange 2010 (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2010_HTTPS',
            'Oracle 10g Portal (http)': 'POLICY_TEMPLATE_ORACLE_10G_PORTAL_HTTP',
            'Oracle 10g Portal (https)': 'POLICY_TEMPLATE_ORACLE_10G_PORTAL_HTTPS',
            'Oracle Applications 11i (http)': 'POLICY_TEMPLATE_ORACLE_APPLICATIONS_11I_HTTP',
            'Oracle Applications 11i (https)': 'POLICY_TEMPLATE_ORACLE_APPLICATIONS_11I_HTTPS',
            'PeopleSoft Portal 9 (http)': 'POLICY_TEMPLATE_PEOPLESOFT_PORTAL_9_HTTP',
            'PeopleSoft Portal 9 (https)': 'POLICY_TEMPLATE_PEOPLESOFT_PORTAL_9_HTTPS',
            'Rapid Deployment Policy': 'POLICY_TEMPLATE_RAPID_DEPLOYMENT',
            'SAP NetWeaver 7 (http)': 'POLICY_TEMPLATE_SAP_NETWEAVER_7_HTTP',
            'SAP NetWeaver 7 (https)': 'POLICY_TEMPLATE_SAP_NETWEAVER_7_HTTPS',
            'SharePoint 2003 (http)': 'POLICY_TEMPLATE_SHAREPOINT_2003_HTTP',
            'SharePoint 2003 (https)': 'POLICY_TEMPLATE_SHAREPOINT_2003_HTTPS',
            'SharePoint 2007 (http)': 'POLICY_TEMPLATE_SHAREPOINT_2007_HTTP',
            'SharePoint 2007 (https)': 'POLICY_TEMPLATE_SHAREPOINT_2007_HTTPS',
            'SharePoint 2010 (http)': 'POLICY_TEMPLATE_SHAREPOINT_2010_HTTP',
            'SharePoint 2010 (https)': 'POLICY_TEMPLATE_SHAREPOINT_2010_HTTPS'
        }
        if self._values['template'] in template_map:
            return template_map[self._values['template']]
        else:
            raise F5ModuleError(
                "The specified template is not valid for this version of BIG-IP."
            )

    @property
    def apply(self):
        result = flatten_boolean(self._values['apply'])
        if result is None:
            return None
        if result == 'yes':
            return True
        return False


class V2ModuleParameters(Parameters):
    @property
    def template(self):
        if self._values['template'] is None:
            return None
        template_map = {
            'ActiveSync v1.0 v2.0 (http)': 'POLICY_TEMPLATE_ACTIVESYNC_V1_0_V2_0_HTTP',
            'ActiveSync v1.0 v2.0 (https)': 'POLICY_TEMPLATE_ACTIVESYNC_V1_0_V2_0_HTTPS',
            'Comprehensive': 'POLICY_TEMPLATE_COMPREHENSIVE',  # v13
            'Drupal': 'POLICY_TEMPLATE_DRUPAL',  # v13
            'Fundamental': 'POLICY_TEMPLATE_FUNDAMENTAL',  # v13
            'Joomla': 'POLICY_TEMPLATE_JOOMLA',  # v13
            'LotusDomino 6.5 (http)': 'POLICY_TEMPLATE_LOTUSDOMINO_6_5_HTTP',
            'LotusDomino 6.5 (https)': 'POLICY_TEMPLATE_LOTUSDOMINO_6_5_HTTPS',
            'OWA Exchange 2003 (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_HTTP',
            'OWA Exchange 2003 (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_HTTPS',
            'OWA Exchange 2003 with ActiveSync (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_WITH_ACTIVESYNC_HTTP',
            'OWA Exchange 2003 with ActiveSync (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2003_WITH_ACTIVESYNC_HTTPS',
            'OWA Exchange 2007 (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_HTTP',
            'OWA Exchange 2007 (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_HTTPS',
            'OWA Exchange 2007 with ActiveSync (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_WITH_ACTIVESYNC_HTTP',
            'OWA Exchange 2007 with ActiveSync (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2007_WITH_ACTIVESYNC_HTTPS',
            'OWA Exchange 2010 (http)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2010_HTTP',
            'OWA Exchange 2010 (https)': 'POLICY_TEMPLATE_OWA_EXCHANGE_2010_HTTPS',
            'Oracle 10g Portal (http)': 'POLICY_TEMPLATE_ORACLE_10G_PORTAL_HTTP',
            'Oracle 10g Portal (https)': 'POLICY_TEMPLATE_ORACLE_10G_PORTAL_HTTPS',
            'Oracle Applications 11i (http)': 'POLICY_TEMPLATE_ORACLE_APPLICATIONS_11I_HTTP',
            'Oracle Applications 11i (https)': 'POLICY_TEMPLATE_ORACLE_APPLICATIONS_11I_HTTPS',
            'PeopleSoft Portal 9 (http)': 'POLICY_TEMPLATE_PEOPLESOFT_PORTAL_9_HTTP',
            'PeopleSoft Portal 9 (https)': 'POLICY_TEMPLATE_PEOPLESOFT_PORTAL_9_HTTPS',
            'Rapid Deployment Policy': 'POLICY_TEMPLATE_RAPID_DEPLOYMENT',
            'SAP NetWeaver 7 (http)': 'POLICY_TEMPLATE_SAP_NETWEAVER_7_HTTP',
            'SAP NetWeaver 7 (https)': 'POLICY_TEMPLATE_SAP_NETWEAVER_7_HTTPS',
            'SharePoint 2003 (http)': 'POLICY_TEMPLATE_SHAREPOINT_2003_HTTP',
            'SharePoint 2003 (https)': 'POLICY_TEMPLATE_SHAREPOINT_2003_HTTPS',
            'SharePoint 2007 (http)': 'POLICY_TEMPLATE_SHAREPOINT_2007_HTTP',
            'SharePoint 2007 (https)': 'POLICY_TEMPLATE_SHAREPOINT_2007_HTTPS',
            'SharePoint 2010 (http)': 'POLICY_TEMPLATE_SHAREPOINT_2010_HTTP',
            'SharePoint 2010 (https)': 'POLICY_TEMPLATE_SHAREPOINT_2010_HTTPS',
            'Vulnerability Assessment Baseline': 'POLICY_TEMPLATE_VULNERABILITY_ASSESSMENT',  # v13
            'Wordpress': 'POLICY_TEMPLATE_WORDPRESS'  # v13
        }
        return template_map[self._values['template']]

    @property
    def apply(self):
        result = flatten_boolean(self._values['apply'])
        if result is None:
            return None
        if result == 'yes':
            return True
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
    def template(self):
        if self._values['template'] is None:
            return None
        template_map = {
            'POLICY_TEMPLATE_ACTIVESYNC_V1_0_V2_0_HTTP': 'ActiveSync v1.0 v2.0 (http)',
            'POLICY_TEMPLATE_ACTIVESYNC_V1_0_V2_0_HTTPS': 'ActiveSync v1.0 v2.0 (https)',
            'POLICY_TEMPLATE_COMPREHENSIVE': 'Comprehensive',
            'POLICY_TEMPLATE_DRUPAL': 'Drupal',
            'POLICY_TEMPLATE_FUNDAMENTAL': 'Fundamental',
            'POLICY_TEMPLATE_JOOMLA': 'Joomla',
            'POLICY_TEMPLATE_LOTUSDOMINO_6_5_HTTP': 'LotusDomino 6.5 (http)',
            'POLICY_TEMPLATE_LOTUSDOMINO_6_5_HTTPS': 'LotusDomino 6.5 (https)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2003_HTTP': 'OWA Exchange 2003 (http)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2003_HTTPS': 'OWA Exchange 2003 (https)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2003_WITH_ACTIVESYNC_HTTP': 'OWA Exchange 2003 with ActiveSync (http)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2003_WITH_ACTIVESYNC_HTTPS': 'OWA Exchange 2003 with ActiveSync (https)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2007_HTTP': 'OWA Exchange 2007 (http)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2007_HTTPS': 'OWA Exchange 2007 (https)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2007_WITH_ACTIVESYNC_HTTP': 'OWA Exchange 2007 with ActiveSync (http)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2007_WITH_ACTIVESYNC_HTTPS': 'OWA Exchange 2007 with ActiveSync (https)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2010_HTTP': 'OWA Exchange 2010 (http)',
            'POLICY_TEMPLATE_OWA_EXCHANGE_2010_HTTPS': 'OWA Exchange 2010 (https)',
            'POLICY_TEMPLATE_ORACLE_10G_PORTAL_HTTP': 'Oracle 10g Portal (http)',
            'POLICY_TEMPLATE_ORACLE_10G_PORTAL_HTTPS': 'Oracle 10g Portal (https)',
            'POLICY_TEMPLATE_ORACLE_APPLICATIONS_11I_HTTP': 'Oracle Applications 11i (http)',
            'POLICY_TEMPLATE_ORACLE_APPLICATIONS_11I_HTTPS': 'Oracle Applications 11i (https)',
            'POLICY_TEMPLATE_PEOPLESOFT_PORTAL_9_HTTP': 'PeopleSoft Portal 9 (http)',
            'POLICY_TEMPLATE_PEOPLESOFT_PORTAL_9_HTTPS': 'PeopleSoft Portal 9 (https)',
            'POLICY_TEMPLATE_RAPID_DEPLOYMENT': 'Rapid Deployment Policy',
            'POLICY_TEMPLATE_SAP_NETWEAVER_7_HTTP': 'SAP NetWeaver 7 (http)',
            'POLICY_TEMPLATE_SAP_NETWEAVER_7_HTTPS': 'SAP NetWeaver 7 (https)',
            'POLICY_TEMPLATE_SHAREPOINT_2003_HTTP': 'SharePoint 2003 (http)',
            'POLICY_TEMPLATE_SHAREPOINT_2003_HTTPS': 'SharePoint 2003 (https)',
            'POLICY_TEMPLATE_SHAREPOINT_2007_HTTP': 'SharePoint 2007 (http)',
            'POLICY_TEMPLATE_SHAREPOINT_2007_HTTPS': 'SharePoint 2007 (https)',
            'POLICY_TEMPLATE_SHAREPOINT_2010_HTTP': 'SharePoint 2010 (http)',
            'POLICY_TEMPLATE_SHAREPOINT_2010_HTTPS': 'SharePoint 2010 (https)',
            'POLICY_TEMPLATE_VULNERABILITY_ASSESSMENT': 'Vulnerability Assessment Baseline',
            'POLICY_TEMPLATE_WORDPRESS': 'Wordpress',
        }
        return template_map[self._values['template']]

    @property
    def apply(self):
        result = flatten_boolean(self._values['apply'])
        return result

    @property
    def active(self):
        result = flatten_boolean(self._values['active'])
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

    @property
    def active(self):
        if self.want.active is None:
            return None
        if self.want.active is True and self.have.active is False:
            return True
        if self.want.active is False and self.have.active is True:
            return False

    @property
    def apply(self):
        if self.want.apply is True and self.have.apply is True:
            return True


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        self.have = None
        self.changes = UsableChanges()

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
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
            self.changes = UsableChanges(params=changed)

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

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

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if not self.exists():
            return False
        else:
            return self.remove()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.want.template is not None:
            self.create_from_template()
        if self.want.template is None:
            self.create_blank()
        if self.want.active:
            self.activate()
            return True
        else:
            return True

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        if self.changes.active or self.changes.apply:
            self.activate()
        return True

    def activate(self):
        if not self.have:
            self.have = self.read_current_from_device()
        task_id = self.apply_on_device()
        if self.wait_for_task(task_id):
            self.wait_for_policy_apply()
            return True
        else:
            raise F5ModuleError('Apply policy task failed.')

    def create_blank(self):
        self.create_on_device()
        if self.exists():
            return True
        else:
            raise F5ModuleError(
                'Failed to create ASM policy: {0}'.format(self.want.name)
            )

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError(
                'Failed to delete ASM policy: {0}'.format(self.want.name)
            )
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

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        if 'items' in response and response['items'] != []:
            # because api filter on ASM is broken when names that contain numbers at the end we need to work around it
            for policy in response['items']:
                if policy['name'] == self.want.name and policy['partition'] == self.want.partition:
                    return True
        return False

    def wait_for_policy_apply(self):
        """
        As the API is quite buggy and unstable there are cases where the policy still indicates pending changes
        even after the apply-policy task has finished. Such state usually goes away after few seconds,
        this function waits for the policy to achieve such a state for
        maximum of 60 seconds.

        """
        # timer is required so that the api updates isModified state to a correct value.
        time.sleep(3)
        for x in range(0, 30):
            self.have = self.read_current_from_device()
            if self.have.apply is False:
                break
            time.sleep(2)
        return True

    def wait_for_task(self, task_id):
        uri = "https://{0}:{1}/mgmt/tm/asm/tasks/apply-policy/{2}".format(
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
            return False
        if response['status'] == 'COMPLETED':
            return True

    def _get_policy_id(self):
        policy_id = None
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$filter=contains(name,'{0}')+and+contains(partition,'{1}')&$select=name,id,partition".format(
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
                    policy_id = policy['id']

        if not policy_id:
            raise F5ModuleError(
                "The policy with the name {0} was not found.".format(self.want.name)
            )
        return policy_id

    def update_on_device(self):
        params = self.changes.api_params()
        # we need to remove active or apply from params as API will raise an error if the active or apply is set to yes,
        # policies can only be activated or applied via apply-policy task endpoint.

        params.pop('active', None)
        params.pop('isModified', None)

        if params:
            policy_id = self._get_policy_id()
            uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                policy_id
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
        policy_id = self._get_policy_id()
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id
        )
        resp = self.client.api.get(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response.update((dict(self_link=response['selfLink'])))
            return Parameters(params=response)
        raise F5ModuleError(resp.content)

    def apply_on_device(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/tasks/apply-policy/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        params = dict(policyReference={'link': self.have.self_link})
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response['id']
        raise F5ModuleError(resp.content)

    def create_from_template_on_device(self):
        full_name = fq_name(self.want.partition, self.want.name)
        cmd = 'tmsh create asm policy {0} policy-template {1} encoding utf-8'.format(full_name, self.want.template)
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

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        # we need to remove active or apply from params as API will raise an error if the active or apply is set to yes,
        # policies can only be activated or applied via apply-policy task endpoint.
        params.pop('active', None)
        params.pop('isModified', None)
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            time.sleep(2)
            return True
        raise F5ModuleError(resp.content)

    def remove_from_device(self):
        policy_id = self._get_policy_id()
        uri = "https://{0}:{1}/mgmt/tm/asm/policies/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            policy_id
        )
        response = self.client.api.delete(uri)
        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.kwargs = kwargs

    def exec_module(self):
        if not module_provisioned(self.client, 'asm'):
            raise F5ModuleError(
                "ASM must be provisioned to use this module."
            )
        if self.version_is_less_than_13():
            manager = self.get_manager('v1')
        else:
            manager = self.get_manager('v2')
        return manager.exec_module()

    def get_manager(self, type):
        if type == 'v1':
            return V1Manager(**self.kwargs)
        elif type == 'v2':
            return V2Manager(**self.kwargs)

    def version_is_less_than_13(self):
        version = tmos_version(self.client)
        if Version(version) < Version('13.0.0'):
            return True
        else:
            return False


class V1Manager(BaseManager):
    def __init__(self, *args, **kwargs):
        module = kwargs.get('module', None)
        client = F5RestClient(**module.params)
        super(V1Manager, self).__init__(client=client, module=module)
        self.want = V1ModuleParameters(params=module.params, client=client)

    def create_from_template(self):
        self.create_from_template_on_device()


class V2Manager(BaseManager):
    def __init__(self, *args, **kwargs):
        module = kwargs.get('module', None)
        client = F5RestClient(**module.params)
        super(V2Manager, self).__init__(client=client, module=module)
        self.want = V2ModuleParameters(params=module.params, client=client)

    # TODO Include creating ASM policies from custom templates in v13

    def create_from_template(self):
        if not self.create_from_template_on_device():
            return False


class ArgumentSpec(object):
    def __init__(self):
        self.template_map = [
            'ActiveSync v1.0 v2.0 (http)',
            'ActiveSync v1.0 v2.0 (https)',
            'Comprehensive',
            'Drupal',
            'Fundamental',
            'Joomla',
            'LotusDomino 6.5 (http)',
            'LotusDomino 6.5 (https)',
            'OWA Exchange 2003 (http)',
            'OWA Exchange 2003 (https)',
            'OWA Exchange 2003 with ActiveSync (http)',
            'OWA Exchange 2003 with ActiveSync (https)',
            'OWA Exchange 2007 (http)',
            'OWA Exchange 2007 (https)',
            'OWA Exchange 2007 with ActiveSync (http)',
            'OWA Exchange 2007 with ActiveSync (https)',
            'OWA Exchange 2010 (http)',
            'OWA Exchange 2010 (https)',
            'Oracle 10g Portal (http)',
            'Oracle 10g Portal (https)',
            'Oracle Applications 11i (http)',
            'Oracle Applications 11i (https)',
            'PeopleSoft Portal 9 (http)',
            'PeopleSoft Portal 9 (https)',
            'Rapid Deployment Policy',
            'SAP NetWeaver 7 (http)',
            'SAP NetWeaver 7 (https)',
            'SharePoint 2003 (http)',
            'SharePoint 2003 (https)',
            'SharePoint 2007 (http)',
            'SharePoint 2007 (https)',
            'SharePoint 2010 (http)',
            'SharePoint 2010 (https)',
            'Vulnerability Assessment Baseline',
            'Wordpress',
        ]
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            template=dict(
                choices=self.template_map
            ),
            active=dict(
                type='bool'
            ),
            apply=dict(
                type='bool',
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
