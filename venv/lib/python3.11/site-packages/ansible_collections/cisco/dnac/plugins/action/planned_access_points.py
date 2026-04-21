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
        attributes=dict(type="dict"),
        isSensor=dict(type="bool"),
        location=dict(type="dict"),
        position=dict(type="dict"),
        radioCount=dict(type="int"),
        radios=dict(type="list"),
        floorId=dict(type="str"),
        plannedAccessPointUuid=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["floorId", "plannedAccessPointUuid"], True),
    ("state", "absent", ["floorId", "plannedAccessPointUuid"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class PlannedAccessPoints(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            attributes=params.get("attributes"),
            isSensor=params.get("isSensor"),
            location=params.get("location"),
            position=params.get("position"),
            radioCount=params.get("radioCount"),
            radios=params.get("radios"),
            floor_id=params.get("floorId"),
            planned_access_point_uuid=params.get("plannedAccessPointUuid"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["limit"] = self.new_object.get("limit")
        new_object_params["offset"] = self.new_object.get("offset")
        new_object_params["radios"] = self.new_object.get("radios")
        new_object_params["floor_id"] = self.new_object.get(
            "floorId"
        ) or self.new_object.get("floor_id")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["attributes"] = self.new_object.get("attributes")
        new_object_params["isSensor"] = self.new_object.get("isSensor")
        new_object_params["location"] = self.new_object.get("location")
        new_object_params["position"] = self.new_object.get("position")
        new_object_params["radioCount"] = self.new_object.get("radioCount")
        new_object_params["radios"] = self.new_object.get("radios")
        new_object_params["floorId"] = self.new_object.get("floorId")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["floor_id"] = self.new_object.get("floor_id")
        new_object_params["planned_access_point_uuid"] = self.new_object.get(
            "planned_access_point_uuid"
        )
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["attributes"] = self.new_object.get("attributes")
        new_object_params["isSensor"] = self.new_object.get("isSensor")
        new_object_params["location"] = self.new_object.get("location")
        new_object_params["position"] = self.new_object.get("position")
        new_object_params["radioCount"] = self.new_object.get("radioCount")
        new_object_params["radios"] = self.new_object.get("radios")
        new_object_params["floorId"] = self.new_object.get("floorId")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.dnac.exec(
                family="devices",
                function="get_planned_access_points_for_floor",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "name", name)
        except Exception:
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        try:
            items = self.dnac.exec(
                family="devices",
                function="get_planned_access_points_for_floor",
                params=self.get_all_params(id=id),
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "id", id)
        except Exception:
            result = None
        return result

    def exists(self):
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("id")
        o_id = o_id or self.new_object.get("planned_access_point_uuid")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("plannedAccessPointUuid")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object"
                )
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(planned_access_point_uuid=_id))
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("attributes", "attributes"),
            ("isSensor", "isSensor"),
            ("location", "location"),
            ("position", "position"),
            ("radioCount", "radioCount"),
            ("radios", "radios"),
            ("floorId", "floor_id"),
            ("plannedAccessPointUuid", "planned_access_point_uuid"),
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
            family="devices",
            function="create_planned_access_point_for_floor",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="devices",
            function="update_planned_access_point_for_floor",
            params=self.update_all_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("planned_access_point_uuid")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("plannedAccessPointUuid")
            if id_:
                self.new_object.update(dict(planned_access_point_uuid=id_))
        result = self.dnac.exec(
            family="devices",
            function="delete_planned_access_point_for_floor",
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
        obj = PlannedAccessPoints(self._task.args, dnac)

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
