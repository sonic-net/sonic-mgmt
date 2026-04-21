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
        macAddress=dict(type="str"),
        deviceType=dict(type="str"),
        hardwareManufacturer=dict(type="str"),
        hardwareModel=dict(type="str"),
        epId=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["epId"], True),
    ("state", "absent", ["epId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class EndpointAnalyticsEndpoints(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            macAddress=params.get("macAddress"),
            deviceType=params.get("deviceType"),
            hardwareManufacturer=params.get("hardwareManufacturer"),
            hardwareModel=params.get("hardwareModel"),
            ep_id=params.get("epId"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["profiling_status"] = self.new_object.get(
            "profilingStatus"
        ) or self.new_object.get("profiling_status")
        new_object_params["mac_address"] = self.new_object.get(
            "macAddress"
        ) or self.new_object.get("mac_address")
        new_object_params["mac_addresses"] = self.new_object.get(
            "macAddresses"
        ) or self.new_object.get("mac_addresses")
        new_object_params["ip"] = self.new_object.get("ip")
        new_object_params["device_type"] = self.new_object.get(
            "deviceType"
        ) or self.new_object.get("device_type")
        new_object_params["hardware_manufacturer"] = self.new_object.get(
            "hardwareManufacturer"
        ) or self.new_object.get("hardware_manufacturer")
        new_object_params["hardware_model"] = self.new_object.get(
            "hardwareModel"
        ) or self.new_object.get("hardware_model")
        new_object_params["operating_system"] = self.new_object.get(
            "operatingSystem"
        ) or self.new_object.get("operating_system")
        new_object_params["registered"] = self.new_object.get("registered")
        new_object_params["random_mac"] = self.new_object.get(
            "randomMac"
        ) or self.new_object.get("random_mac")
        new_object_params["trust_score"] = self.new_object.get(
            "trustScore"
        ) or self.new_object.get("trust_score")
        new_object_params["auth_method"] = self.new_object.get(
            "authMethod"
        ) or self.new_object.get("auth_method")
        new_object_params["posture_status"] = self.new_object.get(
            "postureStatus"
        ) or self.new_object.get("posture_status")
        new_object_params["ai_spoofing_trust_level"] = self.new_object.get(
            "aiSpoofingTrustLevel"
        ) or self.new_object.get("ai_spoofing_trust_level")
        new_object_params["changed_profile_trust_level"] = self.new_object.get(
            "changedProfileTrustLevel"
        ) or self.new_object.get("changed_profile_trust_level")
        new_object_params["nat_trust_level"] = self.new_object.get(
            "natTrustLevel"
        ) or self.new_object.get("nat_trust_level")
        new_object_params["concurrent_mac_trust_level"] = self.new_object.get(
            "concurrentMacTrustLevel"
        ) or self.new_object.get("concurrent_mac_trust_level")
        new_object_params["ip_blocklist_detected"] = self.new_object.get(
            "ipBlocklistDetected"
        ) or self.new_object.get("ip_blocklist_detected")
        new_object_params["unauth_port_detected"] = self.new_object.get(
            "unauthPortDetected"
        ) or self.new_object.get("unauth_port_detected")
        new_object_params["weak_cred_detected"] = self.new_object.get(
            "weakCredDetected"
        ) or self.new_object.get("weak_cred_detected")
        new_object_params["anc_policy"] = self.new_object.get(
            "ancPolicy"
        ) or self.new_object.get("anc_policy")
        new_object_params["limit"] = self.new_object.get("limit")
        new_object_params["offset"] = self.new_object.get("offset")
        new_object_params["sort_by"] = self.new_object.get(
            "sortBy"
        ) or self.new_object.get("sort_by")
        new_object_params["order"] = self.new_object.get("order")
        new_object_params["include"] = self.new_object.get("include")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["macAddress"] = self.new_object.get("macAddress")
        new_object_params["deviceType"] = self.new_object.get("deviceType")
        new_object_params["hardwareManufacturer"] = self.new_object.get(
            "hardwareManufacturer"
        )
        new_object_params["hardwareModel"] = self.new_object.get("hardwareModel")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["ep_id"] = self.new_object.get("ep_id")
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        new_object_params["deviceType"] = self.new_object.get("deviceType")
        new_object_params["hardwareManufacturer"] = self.new_object.get(
            "hardwareManufacturer"
        )
        new_object_params["hardwareModel"] = self.new_object.get("hardwareModel")
        new_object_params["epId"] = self.new_object.get("epId")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.dnac.exec(
                family="ai_endpoint_analytics",
                function="query_the_endpoints",
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
        try:
            items = self.dnac.exec(
                family="ai_endpoint_analytics",
                function="get_endpoint_details",
                params={"ep_id": id},
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "epId", id)
        except Exception:
            result = None
        return result

    def exists(self):
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("id")
        o_id = o_id or self.new_object.get("ep_id")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("epId")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object"
                )
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(ep_id=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("macAddress", "macAddress"),
            ("deviceType", "deviceType"),
            ("hardwareManufacturer", "hardwareManufacturer"),
            ("hardwareModel", "hardwareModel"),
            ("epId", "ep_id"),
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
            function="register_an_endpoint",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("ep_id")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("epId")
            if id_:
                self.new_object.update(dict(ep_id=id_))
        result = self.dnac.exec(
            family="ai_endpoint_analytics",
            function="update_a_registered_endpoint",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("ep_id")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("epId")
            if id_:
                self.new_object.update(dict(ep_id=id_))
        result = self.dnac.exec(
            family="ai_endpoint_analytics",
            function="delete_an_endpoint",
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
        obj = EndpointAnalyticsEndpoints(self._task.args, dnac)

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
