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
        apProfileName=dict(type="str"),
        description=dict(type="str"),
        remoteWorkerEnabled=dict(type="bool"),
        managementSetting=dict(type="dict"),
        awipsEnabled=dict(type="bool"),
        awipsForensicEnabled=dict(type="bool"),
        rogueDetectionSetting=dict(type="dict"),
        pmfDenialEnabled=dict(type="bool"),
        meshEnabled=dict(type="bool"),
        meshSetting=dict(type="dict"),
        apPowerProfileName=dict(type="str"),
        calendarPowerProfiles=dict(type="dict"),
        countryCode=dict(type="str"),
        timeZone=dict(type="str"),
        timeZoneOffsetHour=dict(type="int"),
        timeZoneOffsetMinutes=dict(type="int"),
        clientLimit=dict(type="int"),
        id=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["id"], True),
    ("state", "absent", ["id"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class WirelessSettingsApProfilesId(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            apProfileName=params.get("apProfileName"),
            description=params.get("description"),
            remoteWorkerEnabled=params.get("remoteWorkerEnabled"),
            managementSetting=params.get("managementSetting"),
            awipsEnabled=params.get("awipsEnabled"),
            awipsForensicEnabled=params.get("awipsForensicEnabled"),
            rogueDetectionSetting=params.get("rogueDetectionSetting"),
            pmfDenialEnabled=params.get("pmfDenialEnabled"),
            meshEnabled=params.get("meshEnabled"),
            meshSetting=params.get("meshSetting"),
            apPowerProfileName=params.get("apPowerProfileName"),
            calendarPowerProfiles=params.get("calendarPowerProfiles"),
            countryCode=params.get("countryCode"),
            timeZone=params.get("timeZone"),
            timeZoneOffsetHour=params.get("timeZoneOffsetHour"),
            timeZoneOffsetMinutes=params.get("timeZoneOffsetMinutes"),
            clientLimit=params.get("clientLimit"),
            id=params.get("id"),
        )

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        new_object_params["apProfileName"] = self.new_object.get("apProfileName")
        new_object_params["description"] = self.new_object.get("description")
        new_object_params["remoteWorkerEnabled"] = self.new_object.get(
            "remoteWorkerEnabled"
        )
        new_object_params["managementSetting"] = self.new_object.get(
            "managementSetting"
        )
        new_object_params["awipsEnabled"] = self.new_object.get("awipsEnabled")
        new_object_params["awipsForensicEnabled"] = self.new_object.get(
            "awipsForensicEnabled"
        )
        new_object_params["rogueDetectionSetting"] = self.new_object.get(
            "rogueDetectionSetting"
        )
        new_object_params["pmfDenialEnabled"] = self.new_object.get("pmfDenialEnabled")
        new_object_params["meshEnabled"] = self.new_object.get("meshEnabled")
        new_object_params["meshSetting"] = self.new_object.get("meshSetting")
        new_object_params["apPowerProfileName"] = self.new_object.get(
            "apPowerProfileName"
        )
        new_object_params["calendarPowerProfiles"] = self.new_object.get(
            "calendarPowerProfiles"
        )
        new_object_params["countryCode"] = self.new_object.get("countryCode")
        new_object_params["timeZone"] = self.new_object.get("timeZone")
        new_object_params["timeZoneOffsetHour"] = self.new_object.get(
            "timeZoneOffsetHour"
        )
        new_object_params["timeZoneOffsetMinutes"] = self.new_object.get(
            "timeZoneOffsetMinutes"
        )
        new_object_params["clientLimit"] = self.new_object.get("clientLimit")
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name and get all
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.dnac.exec(
                family="wireless", function="get_ap_profile_by_id", params={"id": id}
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
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("apProfileName", "apProfileName"),
            ("description", "description"),
            ("remoteWorkerEnabled", "remoteWorkerEnabled"),
            ("managementSetting", "managementSetting"),
            ("awipsEnabled", "awipsEnabled"),
            ("awipsForensicEnabled", "awipsForensicEnabled"),
            ("rogueDetectionSetting", "rogueDetectionSetting"),
            ("pmfDenialEnabled", "pmfDenialEnabled"),
            ("meshEnabled", "meshEnabled"),
            ("meshSetting", "meshSetting"),
            ("apPowerProfileName", "apPowerProfileName"),
            ("calendarPowerProfiles", "calendarPowerProfiles"),
            ("countryCode", "countryCode"),
            ("timeZone", "timeZone"),
            ("timeZoneOffsetHour", "timeZoneOffsetHour"),
            ("timeZoneOffsetMinutes", "timeZoneOffsetMinutes"),
            ("clientLimit", "clientLimit"),
            ("id", "id"),
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
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
            if id_:
                self.new_object.update(dict(id=id_))
        result = self.dnac.exec(
            family="wireless",
            function="update_ap_profile_by_id",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
            if id_:
                self.new_object.update(dict(id=id_))
        result = self.dnac.exec(
            family="wireless",
            function="delete_ap_profile_by_id",
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
        obj = WirelessSettingsApProfilesId(self._task.args, dnac)

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
