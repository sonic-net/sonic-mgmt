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
    dnac_compare_equality2,
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
        wiredDataCollection=dict(type="dict"),
        wirelessTelemetry=dict(type="dict"),
        snmpTraps=dict(type="dict"),
        syslogs=dict(type="dict"),
        applicationVisibility=dict(type="dict"),
        id=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["id"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class SitesTelemetrySettings(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            wiredDataCollection=params.get("wiredDataCollection"),
            wirelessTelemetry=params.get("wirelessTelemetry"),
            snmpTraps=params.get("snmpTraps"),
            syslogs=params.get("syslogs"),
            applicationVisibility=params.get("applicationVisibility"),
            id=params.get("id"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["inherited"] = self.new_object.get(
            "_inherited"
        ) or self.new_object.get("inherited")
        new_object_params["id"] = id or self.new_object.get("id")
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["wiredDataCollection"] = self.new_object.get(
            "wiredDataCollection"
        )
        new_object_params["wirelessTelemetry"] = self.new_object.get(
            "wirelessTelemetry"
        )
        new_object_params["snmpTraps"] = self.new_object.get("snmpTraps")
        new_object_params["syslogs"] = self.new_object.get("syslogs")
        new_object_params["applicationVisibility"] = self.new_object.get(
            "applicationVisibility"
        )
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.dnac.exec(
                family="network_settings",
                function="retrieve_telemetry_settings_for_a_site",
                params=self.get_all_params(id=id),
            )
            if isinstance(items, dict):
                if "response" in items:
                    result = items.get("response")
        except Exception:
            result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get("id")
        name = self.new_object.get("name")
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
            ("wiredDataCollection", "wiredDataCollection"),
            ("wirelessTelemetry", "wirelessTelemetry"),
            ("snmpTraps", "snmpTraps"),
            ("syslogs", "syslogs"),
            ("applicationVisibility", "applicationVisibility"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(
            not dnac_compare_equality2(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="network_settings",
            function="set_telemetry_settings_for_a_site",
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
        obj = SitesTelemetrySettings(self._task.args, dnac)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    # response = obj.update()
                    dnac.object_updated()
                else:
                    response = prev_obj
                    dnac.object_already_present()
            else:
                dnac.fail_json("Object does not exists, plugin only has update")

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
