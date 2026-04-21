#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

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
from ansible_collections.cisco.dnac.plugins.plugin_utils.dnac import (
    DNACSDK,
    dnac_argument_spec,
    dnac_compare_equality,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present"]),
        _id=dict(type="str"),
        aaaCredentials=dict(type="dict"),
        acceptEula=dict(type="bool"),
        defaultProfile=dict(type="dict"),
        savaMappingList=dict(type="list"),
        taskTimeOuts=dict(type="dict"),
        tenantId=dict(type="str"),
        version=dict(type="int"),
    )
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class PnpGlobalSettings(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            _id=params.get("_id"),
            aaaCredentials=params.get("aaaCredentials"),
            acceptEula=params.get("acceptEula"),
            defaultProfile=params.get("defaultProfile"),
            savaMappingList=params.get("savaMappingList"),
            taskTimeOuts=params.get("taskTimeOuts"),
            tenantId=params.get("tenantId"),
            version=params.get("version"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["_id"] = self.new_object.get("_id")
        new_object_params["aaaCredentials"] = self.new_object.get("aaaCredentials")
        new_object_params["acceptEula"] = self.new_object.get("acceptEula")
        new_object_params["defaultProfile"] = self.new_object.get("defaultProfile")
        new_object_params["savaMappingList"] = self.new_object.get("savaMappingList")
        new_object_params["taskTimeOuts"] = self.new_object.get("taskTimeOuts")
        new_object_params["tenantId"] = self.new_object.get("tenantId")
        new_object_params["version"] = self.new_object.get("version")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        result = self.dnac.exec(
            family="device_onboarding_pnp",
            function="get_pnp_global_settings",
            params=self.get_all_params(name=name),
        )
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        return result

    def exists(self):
        prev_obj = None
        name = None
        prev_obj = self.get_object_by_name(name)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("_id", "_id"),
            ("aaaCredentials", "aaaCredentials"),
            ("acceptEula", "acceptEula"),
            ("defaultProfile", "defaultProfile"),
            ("savaMappingList", "savaMappingList"),
            ("taskTimeOuts", "taskTimeOuts"),
            ("tenantId", "tenantId"),
            ("version", "version"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def update(self):
        result = None
        result = self.dnac.exec(
            family="device_onboarding_pnp",
            function="update_pnp_global_settings",
            params=self.update_all_params(),
            op_modifies=True,
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'"
            )
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

        dnac = DNACSDK(self._task.args)
        obj = PnpGlobalSettings(self._task.args, dnac)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = obj.update()
                    dnac.object_updated()
                else:
                    response = prev_obj
                    dnac.object_already_present()
            else:
                dnac.fail_json("Object does not exists, plugin only has update")

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
