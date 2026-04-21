#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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
    get_dict_result,
)
from ansible_collections.cisco.dnac.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)


# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present"]),
        comments=dict(type="str"),
        credentialType=dict(type="str"),
        description=dict(type="str"),
        enablePassword=dict(type="str", no_log=True),
        id=dict(type="str"),
        instanceTenantId=dict(type="str"),
        instanceUuid=dict(type="str"),
        password=dict(type="str", no_log=True),
        username=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["description", "id", "username"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class CliCredential(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            comments=params.get("comments"),
            credentialType=params.get("credentialType"),
            description=params.get("description"),
            enablePassword=params.get("enablePassword"),
            id=params.get("id"),
            instanceTenantId=params.get("instanceTenantId"),
            instanceUuid=params.get("instanceUuid"),
            password=params.get("password"),
            username=params.get("username"),
        )

    def create_params(self):
        new_object_params = {}
        payload = {}
        keys = [
            "comments",
            "credentialType",
            "description",
            "enablePassword",
            "id",
            "instanceTenantId",
            "instanceUuid",
            "password",
            "username",
        ]
        for key in keys:
            if self.new_object.get(key) is not None:
                payload[key] = self.new_object.get(key)
        new_object_params["payload"] = [payload]
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["comments"] = self.new_object.get("comments")
        new_object_params["credentialType"] = self.new_object.get("credentialType")
        new_object_params["description"] = self.new_object.get("description")
        new_object_params["enablePassword"] = self.new_object.get("enablePassword")
        new_object_params["id"] = self.new_object.get("id")
        new_object_params["instanceTenantId"] = self.new_object.get("instanceTenantId")
        new_object_params["instanceUuid"] = self.new_object.get("instanceUuid")
        new_object_params["password"] = self.new_object.get("password")
        new_object_params["username"] = self.new_object.get("username")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        try:
            items = self.dnac.exec(
                family="discovery",
                function="get_global_credentials",
                params={"credential_sub_type": "CLI"},
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "description", name) or get_dict_result(
                items, "username", name
            )
        except Exception:
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.dnac.exec(
                family="discovery",
                function="get_global_credentials",
                params={"credential_sub_type": "CLI"},
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "id", id)
        except Exception:
            result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get("id")
        name = self.new_object.get("description") or self.new_object.get("username")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object"
                )
            if _id:
                self.new_object.update(dict(id=_id))
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object
        obj_params = [
            ("comments", "comments"),
            ("credentialType", "credentialType"),
            ("description", "description"),
            ("id", "id"),
            ("instanceTenantId", "instanceTenantId"),
            ("instanceUuid", "instanceUuid"),
            ("username", "username"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def create(self):
        result = self.dnac.exec(
            family="discovery",
            function="create_cli_credentials",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="discovery",
            function="update_cli_credentials",
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
        obj = CliCredential(self._task.args, dnac)

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
                response = obj.create()
                dnac.object_created()

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
