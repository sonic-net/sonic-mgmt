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
    AnsibleSDAException,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        siteNameHierarchy=dict(type="str"),
        deviceManagementIpAddress=dict(type="str"),
        interfaceName=dict(type="str"),
        interfaceNames=dict(type="list"),
        dataIpAddressPoolName=dict(type="str"),
        voiceIpAddressPoolName=dict(type="str"),
        authenticateTemplateName=dict(type="str"),
        scalableGroupName=dict(type="str"),
        interfaceDescription=dict(type="str"),
    )
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class SdaPortAssignmentForUserDevice(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            siteNameHierarchy=params.get("siteNameHierarchy"),
            deviceManagementIpAddress=params.get("deviceManagementIpAddress"),
            interfaceName=params.get("interfaceName"),
            interfaceNames=params.get("interfaceNames"),
            dataIpAddressPoolName=params.get("dataIpAddressPoolName"),
            voiceIpAddressPoolName=params.get("voiceIpAddressPoolName"),
            authenticateTemplateName=params.get("authenticateTemplateName"),
            scalableGroupName=params.get("scalableGroupName"),
            interfaceDescription=params.get("interfaceDescription"),
            device_management_ip_address=params.get("deviceManagementIpAddress"),
            interface_name=params.get("interfaceName"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["device_management_ip_address"] = self.new_object.get(
            "deviceManagementIpAddress"
        ) or self.new_object.get("device_management_ip_address")
        new_object_params["interface_name"] = self.new_object.get(
            "interfaceName"
        ) or self.new_object.get("interface_name")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["siteNameHierarchy"] = self.new_object.get(
            "siteNameHierarchy"
        )
        new_object_params["deviceManagementIpAddress"] = self.new_object.get(
            "deviceManagementIpAddress"
        )
        new_object_params["interfaceName"] = self.new_object.get("interfaceName")
        new_object_params["interfaceNames"] = self.new_object.get("interfaceNames")
        new_object_params["dataIpAddressPoolName"] = self.new_object.get(
            "dataIpAddressPoolName"
        )
        new_object_params["voiceIpAddressPoolName"] = self.new_object.get(
            "voiceIpAddressPoolName"
        )
        new_object_params["authenticateTemplateName"] = self.new_object.get(
            "authenticateTemplateName"
        )
        new_object_params["scalableGroupName"] = self.new_object.get(
            "scalableGroupName"
        )
        new_object_params["interfaceDescription"] = self.new_object.get(
            "interfaceDescription"
        )
        return new_object_params

    def delete_all_params(self):
        new_object_params = {}
        new_object_params["device_management_ip_address"] = self.new_object.get(
            "device_management_ip_address"
        )
        new_object_params["interface_name"] = self.new_object.get("interface_name")
        return new_object_params

    def get_object_by_name(self, name, is_absent=False):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.dnac.exec(
                family="sda",
                function="get_port_assignment_for_user_device",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
                if isinstance(items, dict) and items.get("status") == "failed":
                    if is_absent:
                        raise AnsibleSDAException(response=items)
                    result = None
                    return result
            result = get_dict_result(items, "name", name)
        except Exception:
            if is_absent:
                raise
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        return result

    def exists(self, is_absent=False):
        name = self.new_object.get("name")
        prev_obj = self.get_object_by_name(name, is_absent=is_absent)
        it_exists = (
            prev_obj is not None
            and isinstance(prev_obj, dict)
            and prev_obj.get("status") != "failed"
        )
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("siteNameHierarchy", "siteNameHierarchy"),
            ("deviceManagementIpAddress", "deviceManagementIpAddress"),
            ("interfaceName", "interfaceName"),
            ("interfaceNames", "interfaceNames"),
            ("dataIpAddressPoolName", "dataIpAddressPoolName"),
            ("voiceIpAddressPoolName", "voiceIpAddressPoolName"),
            ("authenticateTemplateName", "authenticateTemplateName"),
            ("scalableGroupName", "scalableGroupName"),
            ("interfaceDescription", "interfaceDescription"),
            ("deviceManagementIpAddress", "device_management_ip_address"),
            ("interfaceName", "interface_name"),
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
            family="sda",
            function="add_port_assignment_for_user_device",
            params=self.create_params(),
            op_modifies=True,
        )
        if isinstance(result, dict):
            if "response" in result:
                result = result.get("response")
            if isinstance(result, dict) and result.get("status") == "failed":
                raise AnsibleSDAException(response=result)
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="sda",
            function="delete_port_assignment_for_user_device",
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
        obj = SdaPortAssignmentForUserDevice(self._task.args, dnac)

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
                try:
                    response = obj.create()
                    dnac.object_created()
                except AnsibleSDAException as e:
                    dnac.fail_json("Could not create object {e}".format(e=e._response))
        elif state == "absent":
            try:
                (obj_exists, prev_obj) = obj.exists(is_absent=True)
                if obj_exists:
                    response = obj.delete()
                    dnac.object_deleted()
                else:
                    dnac.object_already_absent()
            except AnsibleSDAException as e:
                dnac.fail_json(
                    "Could not get object to be delete {e}".format(e=e._response)
                )

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
