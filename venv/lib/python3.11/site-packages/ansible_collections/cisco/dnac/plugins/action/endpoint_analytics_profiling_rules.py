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
        state=dict(type="str", default="present", choices=["present", "absent"]),
        ruleId=dict(type="str"),
        ruleName=dict(type="str"),
        ruleType=dict(type="str"),
        ruleVersion=dict(type="int"),
        rulePriority=dict(type="int"),
        sourcePriority=dict(type="int"),
        isDeleted=dict(type="bool"),
        lastModifiedBy=dict(type="str"),
        lastModifiedOn=dict(type="int"),
        pluginId=dict(type="str"),
        clusterId=dict(type="str"),
        rejected=dict(type="bool"),
        result=dict(type="dict"),
        conditionGroups=dict(type="dict"),
        usedAttributes=dict(type="list"),
    )
)

required_if = [
    ("state", "present", ["ruleId"], True),
    ("state", "absent", ["ruleId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class EndpointAnalyticsProfilingRules(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            ruleId=params.get("ruleId"),
            ruleName=params.get("ruleName"),
            ruleType=params.get("ruleType"),
            ruleVersion=params.get("ruleVersion"),
            rulePriority=params.get("rulePriority"),
            sourcePriority=params.get("sourcePriority"),
            isDeleted=params.get("isDeleted"),
            lastModifiedBy=params.get("lastModifiedBy"),
            lastModifiedOn=params.get("lastModifiedOn"),
            pluginId=params.get("pluginId"),
            clusterId=params.get("clusterId"),
            rejected=params.get("rejected"),
            result=params.get("result"),
            conditionGroups=params.get("conditionGroups"),
            usedAttributes=params.get("usedAttributes"),
            rule_id=params.get("ruleId"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["rule_type"] = self.new_object.get(
            "ruleType"
        ) or self.new_object.get("rule_type")
        new_object_params["include_deleted"] = self.new_object.get(
            "includeDeleted"
        ) or self.new_object.get("include_deleted")
        new_object_params["limit"] = self.new_object.get("limit")
        new_object_params["offset"] = self.new_object.get("offset")
        new_object_params["sort_by"] = self.new_object.get(
            "sortBy"
        ) or self.new_object.get("sort_by")
        new_object_params["order"] = self.new_object.get("order")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["ruleId"] = self.new_object.get("ruleId")
        new_object_params["ruleName"] = self.new_object.get("ruleName")
        new_object_params["ruleType"] = self.new_object.get("ruleType")
        new_object_params["ruleVersion"] = self.new_object.get("ruleVersion")
        new_object_params["rulePriority"] = self.new_object.get("rulePriority")
        new_object_params["sourcePriority"] = self.new_object.get("sourcePriority")
        new_object_params["isDeleted"] = self.new_object.get("isDeleted")
        new_object_params["lastModifiedBy"] = self.new_object.get("lastModifiedBy")
        new_object_params["lastModifiedOn"] = self.new_object.get("lastModifiedOn")
        new_object_params["pluginId"] = self.new_object.get("pluginId")
        new_object_params["clusterId"] = self.new_object.get("clusterId")
        new_object_params["rejected"] = self.new_object.get("rejected")
        new_object_params["result"] = self.new_object.get("result")
        new_object_params["conditionGroups"] = self.new_object.get("conditionGroups")
        new_object_params["usedAttributes"] = self.new_object.get("usedAttributes")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["rule_id"] = self.new_object.get("rule_id")
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        new_object_params["ruleId"] = self.new_object.get("ruleId")
        new_object_params["ruleName"] = self.new_object.get("ruleName")
        new_object_params["ruleType"] = self.new_object.get("ruleType")
        new_object_params["ruleVersion"] = self.new_object.get("ruleVersion")
        new_object_params["rulePriority"] = self.new_object.get("rulePriority")
        new_object_params["sourcePriority"] = self.new_object.get("sourcePriority")
        new_object_params["isDeleted"] = self.new_object.get("isDeleted")
        new_object_params["lastModifiedBy"] = self.new_object.get("lastModifiedBy")
        new_object_params["lastModifiedOn"] = self.new_object.get("lastModifiedOn")
        new_object_params["pluginId"] = self.new_object.get("pluginId")
        new_object_params["clusterId"] = self.new_object.get("clusterId")
        new_object_params["rejected"] = self.new_object.get("rejected")
        new_object_params["result"] = self.new_object.get("result")
        new_object_params["conditionGroups"] = self.new_object.get("conditionGroups")
        new_object_params["usedAttributes"] = self.new_object.get("usedAttributes")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.dnac.exec(
                family="ai_endpoint_analytics",
                function="get_list_of_profiling_rules",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if "profilingRules" in items:
                    items = items.get("profilingRules")
            result = get_dict_result(items, "name", name)
        except Exception:
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.dnac.exec(
                family="ai_endpoint_analytics",
                function="get_details_of_a_single_profiling_rule",
                params={"rule_id": id},
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "ruleId", id)
        except Exception:
            result = None
        return result

    def exists(self):
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("id")
        o_id = o_id or self.new_object.get("rule_id")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("ruleId")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object"
                )
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(rule_id=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("ruleId", "ruleId"),
            ("ruleName", "ruleName"),
            ("ruleType", "ruleType"),
            ("ruleVersion", "ruleVersion"),
            ("rulePriority", "rulePriority"),
            ("sourcePriority", "sourcePriority"),
            ("isDeleted", "isDeleted"),
            ("lastModifiedBy", "lastModifiedBy"),
            ("lastModifiedOn", "lastModifiedOn"),
            ("pluginId", "pluginId"),
            ("clusterId", "clusterId"),
            ("rejected", "rejected"),
            ("result", "result"),
            ("conditionGroups", "conditionGroups"),
            ("usedAttributes", "usedAttributes"),
            ("ruleId", "rule_id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (DNAC) params
        # If any does not have eq params, it requires update
        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def create(self):
        result = self.dnac.exec(
            family="ai_endpoint_analytics",
            function="create_a_profiling_rule",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("rule_id")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("ruleId")
            if id_:
                self.new_object.update(dict(rule_id=id_))
        result = self.dnac.exec(
            family="ai_endpoint_analytics",
            function="update_an_existing_profiling_rule",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("rule_id")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("ruleId")
            if id_:
                self.new_object.update(dict(rule_id=id_))
        result = self.dnac.exec(
            family="ai_endpoint_analytics",
            function="delete_an_existing_profiling_rule",
            params=self.delete_by_id_params(),
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
        obj = EndpointAnalyticsProfilingRules(self._task.args, dnac)

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

        elif state == "absent":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                response = obj.delete()
                dnac.object_deleted()
            else:
                dnac.object_already_absent()

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
