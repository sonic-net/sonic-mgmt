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
        cliTransport=dict(type="str"),
        computeDevice=dict(type="bool"),
        enablePassword=dict(type="str", no_log=True),
        extendedDiscoveryInfo=dict(type="str"),
        httpPassword=dict(type="str"),
        httpPort=dict(type="str"),
        httpSecure=dict(type="bool"),
        httpUserName=dict(type="str"),
        ipAddress=dict(type="list"),
        merakiOrgId=dict(type="list"),
        netconfPort=dict(type="str"),
        password=dict(type="str", no_log=True),
        serialNumber=dict(type="str"),
        snmpAuthPassphrase=dict(type="str"),
        snmpAuthProtocol=dict(type="str"),
        snmpMode=dict(type="str"),
        snmpPrivPassphrase=dict(type="str"),
        snmpPrivProtocol=dict(type="str"),
        snmpROCommunity=dict(type="str"),
        snmpRwCommunity=dict(type="str"),
        snmpRetry=dict(type="int"),
        snmpTimeout=dict(type="int"),
        snmpUserName=dict(type="str"),
        snmpVersion=dict(type="str"),
        type=dict(type="str"),
        userName=dict(type="str"),
        id=dict(type="str"),
        updateMgmtIPaddressList=dict(type="list"),
        cleanConfig=dict(type="bool"),
    )
)

required_if = [
    ("state", "present", ["id", "ipAddress"], True),
    ("state", "absent", ["id", "ipAddress"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworkDevice(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            cliTransport=params.get("cliTransport"),
            computeDevice=params.get("computeDevice"),
            enablePassword=params.get("enablePassword"),
            extendedDiscoveryInfo=params.get("extendedDiscoveryInfo"),
            httpPassword=params.get("httpPassword"),
            httpPort=params.get("httpPort"),
            httpSecure=params.get("httpSecure"),
            httpUserName=params.get("httpUserName"),
            ipAddress=params.get("ipAddress"),
            merakiOrgId=params.get("merakiOrgId"),
            netconfPort=params.get("netconfPort"),
            password=params.get("password"),
            serialNumber=params.get("serialNumber"),
            snmpAuthPassphrase=params.get("snmpAuthPassphrase"),
            snmpAuthProtocol=params.get("snmpAuthProtocol"),
            snmpMode=params.get("snmpMode"),
            snmpPrivPassphrase=params.get("snmpPrivPassphrase"),
            snmpPrivProtocol=params.get("snmpPrivProtocol"),
            snmpROCommunity=params.get("snmpROCommunity"),
            snmpRwCommunity=params.get("snmpRwCommunity"),
            snmpRetry=params.get("snmpRetry"),
            snmpTimeout=params.get("snmpTimeout"),
            snmpUserName=params.get("snmpUserName"),
            snmpVersion=params.get("snmpVersion"),
            type=params.get("type"),
            userName=params.get("userName"),
            id=params.get("id"),
            updateMgmtIPaddressList=params.get("updateMgmtIPaddressList"),
            clean_config=params.get("cleanConfig"),
            managementIpAddress=params.get("managementIpAddress"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["hostname"] = self.new_object.get("hostname")
        new_object_params["management_ip_address"] = self.new_object.get(
            "management_ip_address"
        ) or self.new_object.get("ipAddress")
        new_object_params["mac_address"] = self.new_object.get(
            "macAddress"
        ) or self.new_object.get("mac_address")
        new_object_params["location_name"] = self.new_object.get(
            "locationName"
        ) or self.new_object.get("location_name")
        new_object_params["serial_number"] = self.new_object.get(
            "serialNumber"
        ) or self.new_object.get("serial_number")
        new_object_params["location"] = self.new_object.get("location")
        new_object_params["family"] = self.new_object.get("family")
        # new_object_params['type'] = self.new_object.get('type')
        new_object_params["series"] = self.new_object.get("series")
        new_object_params["collection_status"] = self.new_object.get(
            "collectionStatus"
        ) or self.new_object.get("collection_status")
        new_object_params["collection_interval"] = self.new_object.get(
            "collectionInterval"
        ) or self.new_object.get("collection_interval")
        new_object_params["not_synced_for_minutes"] = self.new_object.get(
            "notSyncedForMinutes"
        ) or self.new_object.get("not_synced_for_minutes")
        new_object_params["error_code"] = self.new_object.get(
            "errorCode"
        ) or self.new_object.get("error_code")
        new_object_params["error_description"] = self.new_object.get(
            "errorDescription"
        ) or self.new_object.get("error_description")
        new_object_params["software_version"] = self.new_object.get(
            "softwareVersion"
        ) or self.new_object.get("software_version")
        new_object_params["software_type"] = self.new_object.get(
            "softwareType"
        ) or self.new_object.get("software_type")
        new_object_params["platform_id"] = self.new_object.get(
            "platformId"
        ) or self.new_object.get("platform_id")
        new_object_params["role"] = self.new_object.get("role")
        new_object_params["reachability_status"] = self.new_object.get(
            "reachabilityStatus"
        ) or self.new_object.get("reachability_status")
        new_object_params["up_time"] = self.new_object.get(
            "upTime"
        ) or self.new_object.get("up_time")
        new_object_params["associated_wlc_ip"] = self.new_object.get(
            "associatedWlcIp"
        ) or self.new_object.get("associated_wlc_ip")
        new_object_params["license_name"] = self.new_object.get("license_name")
        new_object_params["license_type"] = self.new_object.get("license_type")
        new_object_params["license_status"] = self.new_object.get("license_status")
        new_object_params["module_name"] = self.new_object.get("module_name")
        new_object_params["module_equpimenttype"] = self.new_object.get(
            "module_equpimenttype"
        )
        new_object_params["module_servicestate"] = self.new_object.get(
            "module_servicestate"
        )
        new_object_params["module_vendorequipmenttype"] = self.new_object.get(
            "module_vendorequipmenttype"
        )
        new_object_params["module_partnumber"] = self.new_object.get(
            "module_partnumber"
        )
        new_object_params["module_operationstatecode"] = self.new_object.get(
            "module_operationstatecode"
        )
        new_object_params["id"] = id or self.new_object.get("id")
        new_object_params["device_support_level"] = self.new_object.get(
            "deviceSupportLevel"
        ) or self.new_object.get("device_support_level")
        new_object_params["offset"] = self.new_object.get("offset")
        new_object_params["limit"] = self.new_object.get("limit")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["cliTransport"] = self.new_object.get("cliTransport")
        new_object_params["computeDevice"] = self.new_object.get("computeDevice")
        new_object_params["enablePassword"] = self.new_object.get("enablePassword")
        new_object_params["extendedDiscoveryInfo"] = self.new_object.get(
            "extendedDiscoveryInfo"
        )
        new_object_params["httpPassword"] = self.new_object.get("httpPassword")
        new_object_params["httpPort"] = self.new_object.get("httpPort")
        new_object_params["httpSecure"] = self.new_object.get("httpSecure")
        new_object_params["httpUserName"] = self.new_object.get("httpUserName")
        new_object_params["ipAddress"] = self.new_object.get("ipAddress")
        new_object_params["merakiOrgId"] = self.new_object.get("merakiOrgId")
        new_object_params["netconfPort"] = self.new_object.get("netconfPort")
        new_object_params["password"] = self.new_object.get("password")
        new_object_params["serialNumber"] = self.new_object.get("serialNumber")
        new_object_params["snmpAuthPassphrase"] = self.new_object.get(
            "snmpAuthPassphrase"
        )
        new_object_params["snmpAuthProtocol"] = self.new_object.get("snmpAuthProtocol")
        new_object_params["snmpMode"] = self.new_object.get("snmpMode")
        new_object_params["snmpPrivPassphrase"] = self.new_object.get(
            "snmpPrivPassphrase"
        )
        new_object_params["snmpPrivProtocol"] = self.new_object.get("snmpPrivProtocol")
        new_object_params["snmpROCommunity"] = self.new_object.get("snmpROCommunity")
        new_object_params["snmpRwCommunity"] = self.new_object.get("snmpRwCommunity")
        new_object_params["snmpRetry"] = self.new_object.get("snmpRetry")
        new_object_params["snmpTimeout"] = self.new_object.get("snmpTimeout")
        new_object_params["snmpUserName"] = self.new_object.get("snmpUserName")
        new_object_params["snmpVersion"] = self.new_object.get("snmpVersion")
        new_object_params["type"] = self.new_object.get("type")
        new_object_params["userName"] = self.new_object.get("userName")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["clean_config"] = self.new_object.get("clean_config")
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["cliTransport"] = self.new_object.get("cliTransport")
        new_object_params["computeDevice"] = self.new_object.get("computeDevice")
        new_object_params["enablePassword"] = self.new_object.get("enablePassword")
        new_object_params["extendedDiscoveryInfo"] = self.new_object.get(
            "extendedDiscoveryInfo"
        )
        new_object_params["httpPassword"] = self.new_object.get("httpPassword")
        new_object_params["httpPort"] = self.new_object.get("httpPort")
        new_object_params["httpSecure"] = self.new_object.get("httpSecure")
        new_object_params["httpUserName"] = self.new_object.get("httpUserName")
        new_object_params["ipAddress"] = self.new_object.get("ipAddress")
        new_object_params["merakiOrgId"] = self.new_object.get("merakiOrgId")
        new_object_params["netconfPort"] = self.new_object.get("netconfPort")
        new_object_params["password"] = self.new_object.get("password")
        new_object_params["serialNumber"] = self.new_object.get("serialNumber")
        new_object_params["snmpAuthPassphrase"] = self.new_object.get(
            "snmpAuthPassphrase"
        )
        new_object_params["snmpAuthProtocol"] = self.new_object.get("snmpAuthProtocol")
        new_object_params["snmpMode"] = self.new_object.get("snmpMode")
        new_object_params["snmpPrivPassphrase"] = self.new_object.get(
            "snmpPrivPassphrase"
        )
        new_object_params["snmpPrivProtocol"] = self.new_object.get("snmpPrivProtocol")
        new_object_params["snmpROCommunity"] = self.new_object.get("snmpROCommunity")
        new_object_params["snmpRwCommunity"] = self.new_object.get("snmpRwCommunity")
        new_object_params["snmpRetry"] = self.new_object.get("snmpRetry")
        new_object_params["snmpTimeout"] = self.new_object.get("snmpTimeout")
        new_object_params["snmpUserName"] = self.new_object.get("snmpUserName")
        new_object_params["snmpVersion"] = self.new_object.get("snmpVersion")
        new_object_params["type"] = self.new_object.get("type")
        new_object_params["updateMgmtIPaddressList"] = self.new_object.get(
            "updateMgmtIPaddressList"
        )
        new_object_params["userName"] = self.new_object.get("userName")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.dnac.exec(
                family="devices",
                function="get_device_list",
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
                family="devices", function="get_device_by_id", params={"id": id}
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
        name = self.new_object.get("name") or self.new_object.get("ipAddress")
        if isinstance(name, list) and len(name) > 0:
            name = name[0]
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
            ("cliTransport", "cliTransport"),
            ("computeDevice", "computeDevice"),
            ("enablePassword", "enablePassword"),
            ("extendedDiscoveryInfo", "extendedDiscoveryInfo"),
            ("httpPassword", "httpPassword"),
            ("httpPort", "httpPort"),
            ("httpSecure", "httpSecure"),
            ("httpUserName", "httpUserName"),
            ("ipAddress", "ipAddress"),
            ("merakiOrgId", "merakiOrgId"),
            ("netconfPort", "netconfPort"),
            ("serialNumber", "serialNumber"),
            ("snmpAuthPassphrase", "snmpAuthPassphrase"),
            ("snmpAuthProtocol", "snmpAuthProtocol"),
            ("snmpMode", "snmpMode"),
            ("snmpPrivPassphrase", "snmpPrivPassphrase"),
            ("snmpPrivProtocol", "snmpPrivProtocol"),
            ("snmpROCommunity", "snmpROCommunity"),
            ("snmpRwCommunity", "snmpRwCommunity"),
            ("snmpRetry", "snmpRetry"),
            ("snmpTimeout", "snmpTimeout"),
            ("snmpUserName", "snmpUserName"),
            ("snmpVersion", "snmpVersion"),
            ("type", "type"),
            ("userName", "userName"),
            ("id", "id"),
            ("updateMgmtIPaddressList", "updateMgmtIPaddressList"),
            ("cleanConfig", "clean_config"),
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
            function="add_device",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name") or self.new_object.get("ipAddress")
        if isinstance(name, list) and len(name) > 0:
            name = name[0]
        result = None
        result = self.dnac.exec(
            family="devices",
            function="sync_devices",
            params=self.update_all_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name") or self.new_object.get("ipAddress")
        if isinstance(name, list) and len(name) > 0:
            name = name[0]
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
            if id_:
                self.new_object.update(dict(id=id_))
        result = self.dnac.exec(
            family="devices",
            function="delete_device_by_id",
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
        obj = NetworkDevice(self._task.args, dnac)

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
