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
        cdpLevel=dict(type="int"),
        discoveryType=dict(type="str"),
        enablePasswordList=dict(type="list", no_log=True),
        globalCredentialIdList=dict(type="list"),
        httpReadCredential=dict(type="dict"),
        httpWriteCredential=dict(type="dict"),
        ipAddressList=dict(type="str"),
        ipFilterList=dict(type="list"),
        lldpLevel=dict(type="int"),
        name=dict(type="str"),
        netconfPort=dict(type="str"),
        passwordList=dict(type="list", no_log=True),
        preferredMgmtIPMethod=dict(type="str"),
        protocolOrder=dict(type="str"),
        retry=dict(type="int"),
        snmpAuthPassphrase=dict(type="str"),
        snmpAuthProtocol=dict(type="str"),
        snmpMode=dict(type="str"),
        snmpPrivPassphrase=dict(type="str"),
        snmpPrivProtocol=dict(type="str"),
        snmpROCommunity=dict(type="str"),
        snmpRoCommunityDesc=dict(type="str"),
        snmpRwCommunity=dict(type="str"),
        snmpRwCommunityDesc=dict(type="str"),
        snmpUserName=dict(type="str"),
        snmpVersion=dict(type="str"),
        timeout=dict(type="int"),
        userNameList=dict(type="list"),
        id=dict(type="str"),
        attributeInfo=dict(type="dict"),
        deviceIds=dict(type="str"),
        discoveryCondition=dict(type="str"),
        discoveryStatus=dict(type="str"),
        isAutoCdp=dict(type="bool"),
        numDevices=dict(type="int"),
        parentDiscoveryId=dict(type="str"),
        retryCount=dict(type="int"),
        updateMgmtIp=dict(type="bool"),
    )
)

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class Discovery(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            cdpLevel=params.get("cdpLevel"),
            discoveryType=params.get("discoveryType"),
            enablePasswordList=params.get("enablePasswordList"),
            globalCredentialIdList=params.get("globalCredentialIdList"),
            httpReadCredential=params.get("httpReadCredential"),
            httpWriteCredential=params.get("httpWriteCredential"),
            ipAddressList=params.get("ipAddressList"),
            ipFilterList=params.get("ipFilterList"),
            lldpLevel=params.get("lldpLevel"),
            name=params.get("name"),
            netconfPort=params.get("netconfPort"),
            passwordList=params.get("passwordList"),
            preferredMgmtIPMethod=params.get("preferredMgmtIPMethod"),
            protocolOrder=params.get("protocolOrder"),
            retry=params.get("retry"),
            snmpAuthPassphrase=params.get("snmpAuthPassphrase"),
            snmpAuthProtocol=params.get("snmpAuthProtocol"),
            snmpMode=params.get("snmpMode"),
            snmpPrivPassphrase=params.get("snmpPrivPassphrase"),
            snmpPrivProtocol=params.get("snmpPrivProtocol"),
            snmpROCommunity=params.get("snmpROCommunity"),
            snmpRoCommunityDesc=params.get("snmpRoCommunityDesc"),
            snmpRwCommunity=params.get("snmpRwCommunity"),
            snmpRwCommunityDesc=params.get("snmpRwCommunityDesc"),
            snmpUserName=params.get("snmpUserName"),
            snmpVersion=params.get("snmpVersion"),
            timeout=params.get("timeout"),
            userNameList=params.get("userNameList"),
            id=params.get("id"),
            attributeInfo=params.get("attributeInfo"),
            deviceIds=params.get("deviceIds"),
            discoveryCondition=params.get("discoveryCondition"),
            discoveryStatus=params.get("discoveryStatus"),
            isAutoCdp=params.get("isAutoCdp"),
            numDevices=params.get("numDevices"),
            parentDiscoveryId=params.get("parentDiscoveryId"),
            retryCount=params.get("retryCount"),
            updateMgmtIp=params.get("updateMgmtIp"),
        )

    def create_params(self):
        new_object_params = {}
        new_object_params["cdpLevel"] = self.new_object.get("cdpLevel")
        new_object_params["discoveryType"] = self.new_object.get("discoveryType")
        new_object_params["enablePasswordList"] = self.new_object.get(
            "enablePasswordList"
        )
        new_object_params["globalCredentialIdList"] = self.new_object.get(
            "globalCredentialIdList"
        )
        new_object_params["httpReadCredential"] = self.new_object.get(
            "httpReadCredential"
        )
        new_object_params["httpWriteCredential"] = self.new_object.get(
            "httpWriteCredential"
        )
        new_object_params["ipAddressList"] = self.new_object.get("ipAddressList")
        new_object_params["ipFilterList"] = self.new_object.get("ipFilterList")
        new_object_params["lldpLevel"] = self.new_object.get("lldpLevel")
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["netconfPort"] = self.new_object.get("netconfPort")
        new_object_params["passwordList"] = self.new_object.get("passwordList")
        new_object_params["preferredMgmtIPMethod"] = self.new_object.get(
            "preferredMgmtIPMethod"
        )
        new_object_params["protocolOrder"] = self.new_object.get("protocolOrder")
        new_object_params["retry"] = self.new_object.get("retry")
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
        new_object_params["snmpRoCommunityDesc"] = self.new_object.get(
            "snmpRoCommunityDesc"
        )
        new_object_params["snmpRwCommunity"] = self.new_object.get("snmpRwCommunity")
        new_object_params["snmpRwCommunityDesc"] = self.new_object.get(
            "snmpRwCommunityDesc"
        )
        new_object_params["snmpUserName"] = self.new_object.get("snmpUserName")
        new_object_params["snmpVersion"] = self.new_object.get("snmpVersion")
        new_object_params["timeout"] = self.new_object.get("timeout")
        new_object_params["userNameList"] = self.new_object.get("userNameList")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def convert_list_string(self, pList):
        if isinstance(pList, list):
            if len(pList) > 0:
                pList_str = list(map(str, pList))
                return ", ".join(pList_str)
            else:
                return ""
        else:
            return pList

    def update_all_params(self):
        new_object_params = {}
        new_object_params["attributeInfo"] = self.new_object.get("attributeInfo")
        new_object_params["cdpLevel"] = self.new_object.get("cdpLevel")
        new_object_params["deviceIds"] = self.new_object.get("deviceIds")
        new_object_params["discoveryCondition"] = self.new_object.get(
            "discoveryCondition"
        )
        new_object_params["discoveryStatus"] = self.new_object.get("discoveryStatus")
        new_object_params["discoveryType"] = self.new_object.get("discoveryType")
        new_object_params["enablePasswordList"] = self.convert_list_string(
            self.new_object.get("enablePasswordList")
        )
        new_object_params["globalCredentialIdList"] = self.new_object.get(
            "globalCredentialIdList"
        )
        new_object_params["httpReadCredential"] = self.new_object.get(
            "httpReadCredential"
        )
        new_object_params["httpWriteCredential"] = self.new_object.get(
            "httpWriteCredential"
        )
        new_object_params["id"] = self.new_object.get("id")
        new_object_params["ipAddressList"] = self.new_object.get("ipAddressList")
        new_object_params["ipFilterList"] = self.convert_list_string(
            self.new_object.get("ipFilterList")
        )
        new_object_params["isAutoCdp"] = self.new_object.get("isAutoCdp")
        new_object_params["lldpLevel"] = self.new_object.get("lldpLevel")
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["netconfPort"] = self.new_object.get("netconfPort")
        new_object_params["numDevices"] = self.new_object.get("numDevices")
        new_object_params["parentDiscoveryId"] = self.new_object.get(
            "parentDiscoveryId"
        )
        new_object_params["passwordList"] = self.convert_list_string(
            self.new_object.get("passwordList")
        )
        new_object_params["preferredMgmtIPMethod"] = self.new_object.get(
            "preferredMgmtIPMethod"
        )
        new_object_params["protocolOrder"] = self.new_object.get("protocolOrder")
        new_object_params["retryCount"] = self.new_object.get("retryCount")
        new_object_params["snmpAuthPassphrase"] = self.new_object.get(
            "snmpAuthPassphrase"
        )
        new_object_params["snmpAuthProtocol"] = self.new_object.get("snmpAuthProtocol")
        new_object_params["snmpMode"] = self.new_object.get("snmpMode")
        new_object_params["snmpPrivPassphrase"] = self.new_object.get(
            "snmpPrivPassphrase"
        )
        new_object_params["snmpPrivProtocol"] = self.new_object.get("snmpPrivProtocol")
        new_object_params["snmpRoCommunity"] = self.new_object.get("snmpRoCommunity")
        new_object_params["snmpRoCommunityDesc"] = self.new_object.get(
            "snmpRoCommunityDesc"
        )
        new_object_params["snmpRwCommunity"] = self.new_object.get("snmpRwCommunity")
        new_object_params["snmpRwCommunityDesc"] = self.new_object.get(
            "snmpRwCommunityDesc"
        )
        new_object_params["snmpUserName"] = self.new_object.get("snmpUserName")
        new_object_params["timeout"] = self.new_object.get("timeout")
        new_object_params["updateMgmtIp"] = self.new_object.get("updateMgmtIp")
        new_object_params["userNameList"] = self.convert_list_string(
            self.new_object.get("userNameList")
        )
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        # NOTE: Does not have get all
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.dnac.exec(
                family="discovery", function="get_discovery_by_id", params={"id": id}
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
        requested_obj = dict(self.new_object)

        for key in requested_obj.keys():
            if key in ["ipFilterList", "userNameList"]:
                requested_obj[key] = self.convert_list_string(requested_obj.get(key))

        obj_params = [
            ("cdpLevel", "cdpLevel"),
            ("discoveryType", "discoveryType"),
            ("globalCredentialIdList", "globalCredentialIdList"),
            ("httpReadCredential", "httpReadCredential"),
            ("httpWriteCredential", "httpWriteCredential"),
            ("ipAddressList", "ipAddressList"),
            ("ipFilterList", "ipFilterList"),
            ("lldpLevel", "lldpLevel"),
            ("name", "name"),
            ("netconfPort", "netconfPort"),
            ("preferredMgmtIPMethod", "preferredMgmtIPMethod"),
            ("protocolOrder", "protocolOrder"),
            ("retry", "retry"),
            ("snmpAuthPassphrase", "snmpAuthPassphrase"),
            ("snmpAuthProtocol", "snmpAuthProtocol"),
            ("snmpMode", "snmpMode"),
            ("snmpPrivPassphrase", "snmpPrivPassphrase"),
            ("snmpPrivProtocol", "snmpPrivProtocol"),
            ("snmpROCommunity", "snmpROCommunity"),
            ("snmpRoCommunityDesc", "snmpRoCommunityDesc"),
            ("snmpRwCommunity", "snmpRwCommunity"),
            ("snmpRwCommunityDesc", "snmpRwCommunityDesc"),
            ("snmpUserName", "snmpUserName"),
            ("snmpVersion", "snmpVersion"),
            ("timeout", "timeout"),
            ("userNameList", "userNameList"),
            ("id", "id"),
            ("attributeInfo", "attributeInfo"),
            ("deviceIds", "deviceIds"),
            ("discoveryCondition", "discoveryCondition"),
            ("discoveryStatus", "discoveryStatus"),
            ("isAutoCdp", "isAutoCdp"),
            ("numDevices", "numDevices"),
            ("parentDiscoveryId", "parentDiscoveryId"),
            ("retryCount", "retryCount"),
            ("updateMgmtIp", "updateMgmtIp"),
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
            family="discovery",
            function="start_discovery",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

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
            family="discovery",
            function="updates_discovery_by_id",
            params=self.update_all_params(),
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
            family="discovery",
            function="delete_discovery_by_id",
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
        obj = Discovery(self._task.args, dnac)

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
