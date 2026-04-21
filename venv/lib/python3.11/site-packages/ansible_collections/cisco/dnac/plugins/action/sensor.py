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
        name=dict(type="str"),
        version=dict(type="int"),
        modelVersion=dict(type="int"),
        connection=dict(type="str"),
        ssids=dict(type="list"),
        profiles=dict(type="list"),
        encryptionMode=dict(type="str"),
        runNow=dict(type="str"),
        locationInfoList=dict(type="list"),
        sensors=dict(type="list"),
        apCoverage=dict(type="list"),
        templateName=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["name"], True),
    ("state", "absent", ["name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class Sensor(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            name=params.get("name"),
            version=params.get("version"),
            modelVersion=params.get("modelVersion"),
            connection=params.get("connection"),
            ssids=params.get("ssids"),
            profiles=params.get("profiles"),
            encryptionMode=params.get("encryptionMode"),
            runNow=params.get("runNow"),
            locationInfoList=params.get("locationInfoList"),
            sensors=params.get("sensors"),
            apCoverage=params.get("apCoverage"),
            template_name=params.get("templateName"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["site_id"] = self.new_object.get(
            "siteId"
        ) or self.new_object.get("site_id")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["version"] = self.new_object.get("version")
        new_object_params["modelVersion"] = self.new_object.get("modelVersion")
        new_object_params["connection"] = self.new_object.get("connection")
        new_object_params["ssids"] = self.new_object.get("ssids")
        new_object_params["profiles"] = self.new_object.get("profiles")
        new_object_params["encryptionMode"] = self.new_object.get("encryptionMode")
        new_object_params["runNow"] = self.new_object.get("runNow")
        new_object_params["locationInfoList"] = self.new_object.get("locationInfoList")
        new_object_params["sensors"] = self.new_object.get("sensors")
        new_object_params["apCoverage"] = self.new_object.get("apCoverage")
        return new_object_params

    def delete_all_params(self):
        new_object_params = {}
        new_object_params["template_name"] = self.new_object.get("template_name")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.dnac.exec(
                family="sensors",
                function="sensors",
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
            ("name", "name"),
            ("version", "version"),
            ("modelVersion", "modelVersion"),
            ("connection", "connection"),
            ("ssids", "ssids"),
            ("profiles", "profiles"),
            ("encryptionMode", "encryptionMode"),
            ("runNow", "runNow"),
            ("locationInfoList", "locationInfoList"),
            ("sensors", "sensors"),
            ("apCoverage", "apCoverage"),
            ("templateName", "template_name"),
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
            family="sensors",
            function="create_sensor_test_template",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="sensors",
            function="delete_sensor_test",
            params=self.delete_all_params(),
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
        obj = Sensor(self._task.args, dnac)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = prev_obj
                    dnac.object_present_and_different()
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
