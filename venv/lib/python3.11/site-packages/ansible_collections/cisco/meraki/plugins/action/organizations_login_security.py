#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.plugins.action import ActionBase
try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.meraki.plugins.plugin_utils.meraki import (
    MERAKI,
    meraki_argument_spec,
    meraki_compare_equality2,
)
from ansible_collections.cisco.meraki.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = meraki_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present"]),
    accountLockoutAttempts=dict(type="int"),
    apiAuthentication=dict(type="dict"),
    enforceAccountLockout=dict(type="bool"),
    enforceDifferentPasswords=dict(type="bool"),
    enforceIdleTimeout=dict(type="bool"),
    enforceLoginIpRanges=dict(type="bool"),
    enforcePasswordExpiration=dict(type="bool"),
    enforceStrongPasswords=dict(type="bool"),
    enforceTwoFactorAuth=dict(type="bool"),
    idleTimeoutMinutes=dict(type="int"),
    loginIpRanges=dict(type="list"),
    minimumPasswordLength=dict(type="int"),
    numDifferentPasswords=dict(type="int"),
    passwordExpirationDays=dict(type="int"),
    organizationId=dict(type="str"),
))

required_if = [
    ("state", "present", ["organizationId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class OrganizationsLoginSecurity(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            accountLockoutAttempts=params.get("accountLockoutAttempts"),
            apiAuthentication=params.get("apiAuthentication"),
            enforceAccountLockout=params.get("enforceAccountLockout"),
            enforceDifferentPasswords=params.get("enforceDifferentPasswords"),
            enforceIdleTimeout=params.get("enforceIdleTimeout"),
            enforceLoginIpRanges=params.get("enforceLoginIpRanges"),
            enforcePasswordExpiration=params.get("enforcePasswordExpiration"),
            enforceStrongPasswords=params.get("enforceStrongPasswords"),
            enforceTwoFactorAuth=params.get("enforceTwoFactorAuth"),
            idleTimeoutMinutes=params.get("idleTimeoutMinutes"),
            loginIpRanges=params.get("loginIpRanges"),
            minimumPasswordLength=params.get("minimumPasswordLength"),
            numDifferentPasswords=params.get("numDifferentPasswords"),
            passwordExpirationDays=params.get("passwordExpirationDays"),
            organization_id=params.get("organizationId"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('organizationId') is not None or self.new_object.get('organization_id') is not None:
            new_object_params['organizationId'] = self.new_object.get('organizationId') or \
                self.new_object.get('organization_id')
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        if self.new_object.get('accountLockoutAttempts') is not None or self.new_object.get('account_lockout_attempts') is not None:
            new_object_params['accountLockoutAttempts'] = self.new_object.get('accountLockoutAttempts') or \
                self.new_object.get('account_lockout_attempts')
        if self.new_object.get('apiAuthentication') is not None or self.new_object.get('api_authentication') is not None:
            new_object_params['apiAuthentication'] = self.new_object.get('apiAuthentication') or \
                self.new_object.get('api_authentication')
        if self.new_object.get('enforceAccountLockout') is not None or self.new_object.get('enforce_account_lockout') is not None:
            new_object_params['enforceAccountLockout'] = self.new_object.get(
                'enforceAccountLockout')
        if self.new_object.get('enforceDifferentPasswords') is not None or self.new_object.get('enforce_different_passwords') is not None:
            new_object_params['enforceDifferentPasswords'] = self.new_object.get(
                'enforceDifferentPasswords')
        if self.new_object.get('enforceIdleTimeout') is not None or self.new_object.get('enforce_idle_timeout') is not None:
            new_object_params['enforceIdleTimeout'] = self.new_object.get(
                'enforceIdleTimeout')
        if self.new_object.get('enforceLoginIpRanges') is not None or self.new_object.get('enforce_login_ip_ranges') is not None:
            new_object_params['enforceLoginIpRanges'] = self.new_object.get(
                'enforceLoginIpRanges')
        if self.new_object.get('enforcePasswordExpiration') is not None or self.new_object.get('enforce_password_expiration') is not None:
            new_object_params['enforcePasswordExpiration'] = self.new_object.get(
                'enforcePasswordExpiration')
        if self.new_object.get('enforceStrongPasswords') is not None or self.new_object.get('enforce_strong_passwords') is not None:
            new_object_params['enforceStrongPasswords'] = self.new_object.get(
                'enforceStrongPasswords')
        if self.new_object.get('enforceTwoFactorAuth') is not None or self.new_object.get('enforce_two_factor_auth') is not None:
            new_object_params['enforceTwoFactorAuth'] = self.new_object.get(
                'enforceTwoFactorAuth')
        if self.new_object.get('idleTimeoutMinutes') is not None or self.new_object.get('idle_timeout_minutes') is not None:
            new_object_params['idleTimeoutMinutes'] = self.new_object.get('idleTimeoutMinutes') or \
                self.new_object.get('idle_timeout_minutes')
        if self.new_object.get('loginIpRanges') is not None or self.new_object.get('login_ip_ranges') is not None:
            new_object_params['loginIpRanges'] = self.new_object.get('loginIpRanges') or \
                self.new_object.get('login_ip_ranges')
        if self.new_object.get('minimumPasswordLength') is not None or self.new_object.get('minimum_password_length') is not None:
            new_object_params['minimumPasswordLength'] = self.new_object.get('minimumPasswordLength') or \
                self.new_object.get('minimum_password_length')
        if self.new_object.get('numDifferentPasswords') is not None or self.new_object.get('num_different_passwords') is not None:
            new_object_params['numDifferentPasswords'] = self.new_object.get('numDifferentPasswords') or \
                self.new_object.get('num_different_passwords')
        if self.new_object.get('passwordExpirationDays') is not None or self.new_object.get('password_expiration_days') is not None:
            new_object_params['passwordExpirationDays'] = self.new_object.get('passwordExpirationDays') or \
                self.new_object.get('password_expiration_days')
        if self.new_object.get('organizationId') is not None or self.new_object.get('organization_id') is not None:
            new_object_params['organizationId'] = self.new_object.get('organizationId') or \
                self.new_object.get('organization_id')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.meraki.exec_meraki(
                family="organizations",
                function="getOrganizationLoginSecurity",
                params=self.get_all_params(name=name),
            )
            # if isinstance(items, dict):
            #     if 'response' in items:
            #         items = items.get('response')
            # result = get_dict_result(items, 'name', name)
            if result is None:
                result = items
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object
        name = self.new_object
        if o_id:
            prev_obj = self.get_object_by_name(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("accountLockoutAttempts", "accountLockoutAttempts"),
            ("apiAuthentication", "apiAuthentication"),
            ("enforceAccountLockout", "enforceAccountLockout"),
            ("enforceDifferentPasswords", "enforceDifferentPasswords"),
            ("enforceIdleTimeout", "enforceIdleTimeout"),
            ("enforceLoginIpRanges", "enforceLoginIpRanges"),
            ("enforcePasswordExpiration", "enforcePasswordExpiration"),
            ("enforceStrongPasswords", "enforceStrongPasswords"),
            ("enforceTwoFactorAuth", "enforceTwoFactorAuth"),
            ("idleTimeoutMinutes", "idleTimeoutMinutes"),
            ("loginIpRanges", "loginIpRanges"),
            ("minimumPasswordLength", "minimumPasswordLength"),
            ("numDifferentPasswords", "numDifferentPasswords"),
            ("organizationId", "organizationId"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.meraki.exec_meraki(
            family="organizations",
            function="updateOrganizationLoginSecurity",
            params=self.update_all_params(),
            op_modifies=True,
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        meraki = MERAKI(self._task.args)
        obj = OrganizationsLoginSecurity(self._task.args, meraki)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = obj.update()
                    meraki.object_updated()
                else:
                    response = prev_obj
                    meraki.object_already_present()
            else:
                meraki.fail_json(
                    "Object does not exists, plugin only has update")

        self._result.update(dict(meraki_response=response))
        self._result.update(meraki.exit_json())
        return self._result
