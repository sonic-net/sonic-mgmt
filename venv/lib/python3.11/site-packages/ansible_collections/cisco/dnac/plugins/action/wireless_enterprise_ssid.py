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
        securityLevel=dict(type="str"),
        passphrase=dict(type="str"),
        enableFastLane=dict(type="bool"),
        enableMACFiltering=dict(type="bool"),
        trafficType=dict(type="str"),
        radioPolicy=dict(type="str"),
        enableBroadcastSSID=dict(type="bool"),
        fastTransition=dict(type="str"),
        enableSessionTimeOut=dict(type="bool"),
        sessionTimeOut=dict(type="int"),
        enableClientExclusion=dict(type="bool"),
        clientExclusionTimeout=dict(type="int"),
        enableBasicServiceSetMaxIdle=dict(type="bool"),
        basicServiceSetClientIdleTimeout=dict(type="int"),
        enableDirectedMulticastService=dict(type="bool"),
        enableNeighborList=dict(type="bool"),
        mfpClientProtection=dict(type="str"),
        nasOptions=dict(type="list"),
        profileName=dict(type="str"),
        policyProfileName=dict(type="str"),
        aaaOverride=dict(type="bool"),
        coverageHoleDetectionEnable=dict(type="bool"),
        protectedManagementFrame=dict(type="str"),
        multiPSKSettings=dict(type="list"),
        clientRateLimit=dict(type="float"),
        authKeyMgmt=dict(type="list"),
        rsnCipherSuiteGcmp256=dict(type="bool"),
        rsnCipherSuiteCcmp256=dict(type="bool"),
        rsnCipherSuiteGcmp128=dict(type="bool"),
        ghz6PolicyClientSteering=dict(type="bool"),
        ghz24Policy=dict(type="str"),
        ssidName=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["name", "ssidName"], True),
    ("state", "absent", ["name", "ssidName"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class WirelessEnterpriseSsid(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            name=params.get("name"),
            securityLevel=params.get("securityLevel"),
            passphrase=params.get("passphrase"),
            enableFastLane=params.get("enableFastLane"),
            enableMACFiltering=params.get("enableMACFiltering"),
            trafficType=params.get("trafficType"),
            radioPolicy=params.get("radioPolicy"),
            enableBroadcastSSID=params.get("enableBroadcastSSID"),
            fastTransition=params.get("fastTransition"),
            enableSessionTimeOut=params.get("enableSessionTimeOut"),
            sessionTimeOut=params.get("sessionTimeOut"),
            enableClientExclusion=params.get("enableClientExclusion"),
            clientExclusionTimeout=params.get("clientExclusionTimeout"),
            enableBasicServiceSetMaxIdle=params.get("enableBasicServiceSetMaxIdle"),
            basicServiceSetClientIdleTimeout=params.get(
                "basicServiceSetClientIdleTimeout"
            ),
            enableDirectedMulticastService=params.get("enableDirectedMulticastService"),
            enableNeighborList=params.get("enableNeighborList"),
            mfpClientProtection=params.get("mfpClientProtection"),
            nasOptions=params.get("nasOptions"),
            profileName=params.get("profileName"),
            policyProfileName=params.get("policyProfileName"),
            aaaOverride=params.get("aaaOverride"),
            coverageHoleDetectionEnable=params.get("coverageHoleDetectionEnable"),
            protectedManagementFrame=params.get("protectedManagementFrame"),
            multiPSKSettings=params.get("multiPSKSettings"),
            clientRateLimit=params.get("clientRateLimit"),
            authKeyMgmt=params.get("authKeyMgmt"),
            rsnCipherSuiteGcmp256=params.get("rsnCipherSuiteGcmp256"),
            rsnCipherSuiteCcmp256=params.get("rsnCipherSuiteCcmp256"),
            rsnCipherSuiteGcmp128=params.get("rsnCipherSuiteGcmp128"),
            ghz6PolicyClientSteering=params.get("ghz6PolicyClientSteering"),
            ghz24Policy=params.get("ghz24Policy"),
            ssid_name=params.get("ssidName"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["ssid_name"] = self.new_object.get(
            "ssidName"
        ) or self.new_object.get("ssid_name")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["securityLevel"] = self.new_object.get("securityLevel")
        new_object_params["passphrase"] = self.new_object.get("passphrase")
        new_object_params["enableFastLane"] = self.new_object.get("enableFastLane")
        new_object_params["enableMACFiltering"] = self.new_object.get(
            "enableMACFiltering"
        )
        new_object_params["trafficType"] = self.new_object.get("trafficType")
        new_object_params["radioPolicy"] = self.new_object.get("radioPolicy")
        new_object_params["enableBroadcastSSID"] = self.new_object.get(
            "enableBroadcastSSID"
        )
        new_object_params["fastTransition"] = self.new_object.get("fastTransition")
        new_object_params["enableSessionTimeOut"] = self.new_object.get(
            "enableSessionTimeOut"
        )
        new_object_params["sessionTimeOut"] = self.new_object.get("sessionTimeOut")
        new_object_params["enableClientExclusion"] = self.new_object.get(
            "enableClientExclusion"
        )
        new_object_params["clientExclusionTimeout"] = self.new_object.get(
            "clientExclusionTimeout"
        )
        new_object_params["enableBasicServiceSetMaxIdle"] = self.new_object.get(
            "enableBasicServiceSetMaxIdle"
        )
        new_object_params["basicServiceSetClientIdleTimeout"] = self.new_object.get(
            "basicServiceSetClientIdleTimeout"
        )
        new_object_params["enableDirectedMulticastService"] = self.new_object.get(
            "enableDirectedMulticastService"
        )
        new_object_params["enableNeighborList"] = self.new_object.get(
            "enableNeighborList"
        )
        new_object_params["mfpClientProtection"] = self.new_object.get(
            "mfpClientProtection"
        )
        new_object_params["nasOptions"] = self.new_object.get("nasOptions")
        new_object_params["profileName"] = self.new_object.get("profileName")
        new_object_params["policyProfileName"] = self.new_object.get(
            "policyProfileName"
        )
        new_object_params["aaaOverride"] = self.new_object.get("aaaOverride")
        new_object_params["coverageHoleDetectionEnable"] = self.new_object.get(
            "coverageHoleDetectionEnable"
        )
        new_object_params["protectedManagementFrame"] = self.new_object.get(
            "protectedManagementFrame"
        )
        new_object_params["multiPSKSettings"] = self.new_object.get("multiPSKSettings")
        new_object_params["clientRateLimit"] = self.new_object.get("clientRateLimit")
        new_object_params["authKeyMgmt"] = self.new_object.get("authKeyMgmt")
        new_object_params["rsnCipherSuiteGcmp256"] = self.new_object.get(
            "rsnCipherSuiteGcmp256"
        )
        new_object_params["rsnCipherSuiteCcmp256"] = self.new_object.get(
            "rsnCipherSuiteCcmp256"
        )
        new_object_params["rsnCipherSuiteGcmp128"] = self.new_object.get(
            "rsnCipherSuiteGcmp128"
        )
        new_object_params["ghz6PolicyClientSteering"] = self.new_object.get(
            "ghz6PolicyClientSteering"
        )
        new_object_params["ghz24Policy"] = self.new_object.get("ghz24Policy")
        return new_object_params

    def delete_by_name_params(self):
        new_object_params = {}
        new_object_params["ssid_name"] = self.new_object.get("ssid_name")
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        new_object_params["name"] = self.new_object.get("name")
        new_object_params["securityLevel"] = self.new_object.get("securityLevel")
        new_object_params["passphrase"] = self.new_object.get("passphrase")
        new_object_params["enableFastLane"] = self.new_object.get("enableFastLane")
        new_object_params["enableMACFiltering"] = self.new_object.get(
            "enableMACFiltering"
        )
        new_object_params["trafficType"] = self.new_object.get("trafficType")
        new_object_params["radioPolicy"] = self.new_object.get("radioPolicy")
        new_object_params["enableBroadcastSSID"] = self.new_object.get(
            "enableBroadcastSSID"
        )
        new_object_params["fastTransition"] = self.new_object.get("fastTransition")
        new_object_params["enableSessionTimeOut"] = self.new_object.get(
            "enableSessionTimeOut"
        )
        new_object_params["sessionTimeOut"] = self.new_object.get("sessionTimeOut")
        new_object_params["enableClientExclusion"] = self.new_object.get(
            "enableClientExclusion"
        )
        new_object_params["clientExclusionTimeout"] = self.new_object.get(
            "clientExclusionTimeout"
        )
        new_object_params["enableBasicServiceSetMaxIdle"] = self.new_object.get(
            "enableBasicServiceSetMaxIdle"
        )
        new_object_params["basicServiceSetClientIdleTimeout"] = self.new_object.get(
            "basicServiceSetClientIdleTimeout"
        )
        new_object_params["enableDirectedMulticastService"] = self.new_object.get(
            "enableDirectedMulticastService"
        )
        new_object_params["enableNeighborList"] = self.new_object.get(
            "enableNeighborList"
        )
        new_object_params["mfpClientProtection"] = self.new_object.get(
            "mfpClientProtection"
        )
        new_object_params["nasOptions"] = self.new_object.get("nasOptions")
        new_object_params["profileName"] = self.new_object.get("profileName")
        new_object_params["policyProfileName"] = self.new_object.get(
            "policyProfileName"
        )
        new_object_params["aaaOverride"] = self.new_object.get("aaaOverride")
        new_object_params["coverageHoleDetectionEnable"] = self.new_object.get(
            "coverageHoleDetectionEnable"
        )
        new_object_params["protectedManagementFrame"] = self.new_object.get(
            "protectedManagementFrame"
        )
        new_object_params["multiPSKSettings"] = self.new_object.get("multiPSKSettings")
        new_object_params["clientRateLimit"] = self.new_object.get("clientRateLimit")
        new_object_params["authKeyMgmt"] = self.new_object.get("authKeyMgmt")
        new_object_params["rsnCipherSuiteGcmp256"] = self.new_object.get(
            "rsnCipherSuiteGcmp256"
        )
        new_object_params["rsnCipherSuiteCcmp256"] = self.new_object.get(
            "rsnCipherSuiteCcmp256"
        )
        new_object_params["rsnCipherSuiteGcmp128"] = self.new_object.get(
            "rsnCipherSuiteGcmp128"
        )
        new_object_params["ghz6PolicyClientSteering"] = self.new_object.get(
            "ghz6PolicyClientSteering"
        )
        new_object_params["ghz24Policy"] = self.new_object.get("ghz24Policy")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.dnac.exec(
                family="wireless",
                function="get_enterprise_ssid",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        n_item = None
                        if "response" in item:
                            n_item = item.get("response")
                        if "ssidDetails" in item:
                            n_item = item.get("ssidDetails")
                        n_item = get_dict_result(n_item, "name", name)
                        if n_item is not None:
                            return n_item
                return result
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
                if "ssidDetails" in items:
                    items = items.get("ssidDetails")
            result = get_dict_result(items, "name", name)
        except Exception:
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        try:
            items = self.dnac.exec(
                family="wireless",
                function="get_enterprise_ssid",
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
        name = self.new_object.get("name")
        name = name or self.new_object.get("ssid_name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if id_exists:
            _name = prev_obj.get("name")
            _name = _name or prev_obj.get("ssidName")
            if _name:
                self.new_object.update(dict(ssid_name=_name))
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
            ("securityLevel", "securityLevel"),
            ("passphrase", "passphrase"),
            ("enableFastLane", "enableFastLane"),
            ("enableMACFiltering", "enableMACFiltering"),
            ("trafficType", "trafficType"),
            ("radioPolicy", "radioPolicy"),
            ("enableBroadcastSSID", "enableBroadcastSSID"),
            ("fastTransition", "fastTransition"),
            ("enableSessionTimeOut", "enableSessionTimeOut"),
            ("sessionTimeOut", "sessionTimeOut"),
            ("enableClientExclusion", "enableClientExclusion"),
            ("clientExclusionTimeout", "clientExclusionTimeout"),
            ("enableBasicServiceSetMaxIdle", "enableBasicServiceSetMaxIdle"),
            ("basicServiceSetClientIdleTimeout", "basicServiceSetClientIdleTimeout"),
            ("enableDirectedMulticastService", "enableDirectedMulticastService"),
            ("enableNeighborList", "enableNeighborList"),
            ("mfpClientProtection", "mfpClientProtection"),
            ("nasOptions", "nasOptions"),
            ("profileName", "profileName"),
            ("policyProfileName", "policyProfileName"),
            ("aaaOverride", "aaaOverride"),
            ("coverageHoleDetectionEnable", "coverageHoleDetectionEnable"),
            ("protectedManagementFrame", "protectedManagementFrame"),
            ("multiPSKSettings", "multiPSKSettings"),
            ("clientRateLimit", "clientRateLimit"),
            ("authKeyMgmt", "authKeyMgmt"),
            ("rsnCipherSuiteGcmp256", "rsnCipherSuiteGcmp256"),
            ("rsnCipherSuiteCcmp256", "rsnCipherSuiteCcmp256"),
            ("rsnCipherSuiteGcmp128", "rsnCipherSuiteGcmp128"),
            ("ghz6PolicyClientSteering", "ghz6PolicyClientSteering"),
            ("ghz24Policy", "ghz24Policy"),
            ("ssidName", "ssid_name"),
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
            family="wireless",
            function="create_enterprise_ssid",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="wireless",
            function="update_enterprise_ssid",
            params=self.update_all_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        name = name or self.new_object.get("ssid_name")
        result = None
        if not name:
            prev_obj_id = self.get_object_by_id(id)
            name_ = None
            if prev_obj_id:
                name_ = prev_obj_id.get("name")
                name_ = name_ or prev_obj_id.get("ssidName")
            if name_:
                self.new_object.update(dict(ssid_name=name_))
        result = self.dnac.exec(
            family="wireless",
            function="delete_enterprise_ssid",
            params=self.delete_by_name_params(),
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
        obj = WirelessEnterpriseSsid(self._task.args, dnac)

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
