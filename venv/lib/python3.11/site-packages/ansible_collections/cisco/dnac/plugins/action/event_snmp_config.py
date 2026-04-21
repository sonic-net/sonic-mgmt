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
from ansible_collections.cisco.dnac.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present"]),
        name=dict(type="str"),
        description=dict(type="str"),
        ipAddress=dict(type="str"),
        port=dict(type="str"),
        snmpVersion=dict(type="str"),
        community=dict(type="str"),
        userName=dict(type="str"),
        snmpMode=dict(type="str"),
        snmpAuthType=dict(type="str"),
        authPassword=dict(type="str", no_log=True),
        snmpPrivacyType=dict(type="str"),
        privacyPassword=dict(type="str", no_log=True),
        configId=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class EventSnmpConfig(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            name=params.get("name"),
            description=params.get("description"),
            ipAddress=params.get("ipAddress"),
            port=params.get("port"),
            snmpVersion=params.get("snmpVersion"),
            community=params.get("community"),
            userName=params.get("userName"),
            snmpMode=params.get("snmpMode"),
            snmpAuthType=params.get("snmpAuthType"),
            authPassword=params.get("authPassword"),
            snmpPrivacyType=params.get("snmpPrivacyType"),
            privacyPassword=params.get("privacyPassword"),
            configId=params.get("configId"),
        )

    def create_params(self):
        new_object_params = {}
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["description"] = self.new_object.get("description")
        new_object_params["ipAddress"] = self.new_object.get("ipAddress")
        new_object_params["port"] = self.new_object.get("port")
        new_object_params["snmpVersion"] = self.new_object.get("snmpVersion")
        new_object_params["community"] = self.new_object.get("community")
        new_object_params["userName"] = self.new_object.get("userName")
        new_object_params["snmpMode"] = self.new_object.get("snmpMode")
        new_object_params["snmpAuthType"] = self.new_object.get("snmpAuthType")
        new_object_params["authPassword"] = self.new_object.get("authPassword")
        new_object_params["snmpPrivacyType"] = self.new_object.get("snmpPrivacyType")
        new_object_params["privacyPassword"] = self.new_object.get("privacyPassword")
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["configId"] = self.new_object.get("configId")
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["description"] = self.new_object.get("description")
        new_object_params["ipAddress"] = self.new_object.get("ipAddress")
        new_object_params["port"] = self.new_object.get("port")
        new_object_params["snmpVersion"] = self.new_object.get("snmpVersion")
        new_object_params["community"] = self.new_object.get("community")
        new_object_params["userName"] = self.new_object.get("userName")
        new_object_params["snmpMode"] = self.new_object.get("snmpMode")
        new_object_params["snmpAuthType"] = self.new_object.get("snmpAuthType")
        new_object_params["authPassword"] = self.new_object.get("authPassword")
        new_object_params["snmpPrivacyType"] = self.new_object.get("snmpPrivacyType")
        new_object_params["privacyPassword"] = self.new_object.get("privacyPassword")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name and get all
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
            ("description", "description"),
            ("ipAddress", "ipAddress"),
            ("port", "port"),
            ("snmpVersion", "snmpVersion"),
            ("community", "community"),
            ("userName", "userName"),
            ("snmpMode", "snmpMode"),
            ("snmpAuthType", "snmpAuthType"),
            ("authPassword", "authPassword"),
            ("snmpPrivacyType", "snmpPrivacyType"),
            ("privacyPassword", "privacyPassword"),
            ("configId", "configId"),
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
            family="event_management",
            function="create_snmp_destination",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="event_management",
            function="update_snmp_destination",
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
        obj = EventSnmpConfig(self._task.args, dnac)

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
