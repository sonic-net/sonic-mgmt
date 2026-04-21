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
        ssid=dict(type="str"),
        authType=dict(type="str"),
        passphrase=dict(type="str"),
        isFastLaneEnabled=dict(type="bool"),
        isMacFilteringEnabled=dict(type="bool"),
        ssidRadioType=dict(type="str"),
        isBroadcastSSID=dict(type="bool"),
        fastTransition=dict(type="str"),
        sessionTimeOutEnable=dict(type="bool"),
        sessionTimeOut=dict(type="int"),
        clientExclusionEnable=dict(type="bool"),
        clientExclusionTimeout=dict(type="int"),
        basicServiceSetMaxIdleEnable=dict(type="bool"),
        basicServiceSetClientIdleTimeout=dict(type="int"),
        directedMulticastServiceEnable=dict(type="bool"),
        neighborListEnable=dict(type="bool"),
        managementFrameProtectionClientprotection=dict(type="str"),
        nasOptions=dict(type="list"),
        profileName=dict(type="str"),
        aaaOverride=dict(type="bool"),
        coverageHoleDetectionEnable=dict(type="bool"),
        protectedManagementFrame=dict(type="str"),
        multiPSKSettings=dict(type="list"),
        clientRateLimit=dict(type="int"),
        rsnCipherSuiteGcmp256=dict(type="bool"),
        rsnCipherSuiteCcmp256=dict(type="bool"),
        rsnCipherSuiteGcmp128=dict(type="bool"),
        rsnCipherSuiteCcmp128=dict(type="bool"),
        ghz6PolicyClientSteering=dict(type="bool"),
        isAuthKey8021x=dict(type="bool"),
        isAuthKey8021xPlusFT=dict(type="bool"),
        isAuthKey8021x_SHA256=dict(type="bool"),
        isAuthKeySae=dict(type="bool"),
        isAuthKeySaePlusFT=dict(type="bool"),
        isAuthKeyPSK=dict(type="bool"),
        isAuthKeyPSKPlusFT=dict(type="bool"),
        isAuthKeyOWE=dict(type="bool"),
        isAuthKeyEasyPSK=dict(type="bool"),
        isAuthKeyPSKSHA256=dict(type="bool"),
        openSsid=dict(type="str"),
        wlanBandSelectEnable=dict(type="bool"),
        isEnabled=dict(type="bool"),
        authServers=dict(type="list"),
        acctServers=dict(type="list"),
        egressQos=dict(type="str"),
        ingressQos=dict(type="str"),
        wlanType=dict(type="str"),
        l3AuthType=dict(type="str"),
        authServer=dict(type="str"),
        externalAuthIpAddress=dict(type="str"),
        webPassthrough=dict(type="bool"),
        sleepingClientEnable=dict(type="bool"),
        sleepingClientTimeout=dict(type="int"),
        aclName=dict(type="str"),
        isPosturingEnabled=dict(type="bool"),
        isAuthKeySuiteB1x=dict(type="bool"),
        isAuthKeySuiteB1921x=dict(type="bool"),
        isAuthKeySaeExt=dict(type="bool"),
        isAuthKeySaeExtPlusFT=dict(type="bool"),
        isApBeaconProtectionEnabled=dict(type="bool"),
        ghz24Policy=dict(type="str"),
        cckmTsfTolerance=dict(type="int"),
        isCckmEnabled=dict(type="bool"),
        isHex=dict(type="bool"),
        isRandomMacFilterEnabled=dict(type="bool"),
        fastTransitionOverTheDistributedSystemEnable=dict(type="bool"),
        isRadiusProfilingEnabled=dict(type="bool"),
        policyProfileName=dict(type="str"),
        siteId=dict(type="str"),
        id=dict(type="str"),
        removeOverrideInHierarchy=dict(type="bool"),
    )
)

required_if = [
    ("state", "present", ["id", "siteId"], True),
    ("state", "absent", ["id", "siteId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class SitesWirelessSettingsSsids(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            ssid=params.get("ssid"),
            authType=params.get("authType"),
            passphrase=params.get("passphrase"),
            isFastLaneEnabled=params.get("isFastLaneEnabled"),
            isMacFilteringEnabled=params.get("isMacFilteringEnabled"),
            ssidRadioType=params.get("ssidRadioType"),
            isBroadcastSSID=params.get("isBroadcastSSID"),
            fastTransition=params.get("fastTransition"),
            sessionTimeOutEnable=params.get("sessionTimeOutEnable"),
            sessionTimeOut=params.get("sessionTimeOut"),
            clientExclusionEnable=params.get("clientExclusionEnable"),
            clientExclusionTimeout=params.get("clientExclusionTimeout"),
            basicServiceSetMaxIdleEnable=params.get("basicServiceSetMaxIdleEnable"),
            basicServiceSetClientIdleTimeout=params.get(
                "basicServiceSetClientIdleTimeout"
            ),
            directedMulticastServiceEnable=params.get("directedMulticastServiceEnable"),
            neighborListEnable=params.get("neighborListEnable"),
            managementFrameProtectionClientprotection=params.get(
                "managementFrameProtectionClientprotection"
            ),
            nasOptions=params.get("nasOptions"),
            profileName=params.get("profileName"),
            aaaOverride=params.get("aaaOverride"),
            coverageHoleDetectionEnable=params.get("coverageHoleDetectionEnable"),
            protectedManagementFrame=params.get("protectedManagementFrame"),
            multiPSKSettings=params.get("multiPSKSettings"),
            clientRateLimit=params.get("clientRateLimit"),
            rsnCipherSuiteGcmp256=params.get("rsnCipherSuiteGcmp256"),
            rsnCipherSuiteCcmp256=params.get("rsnCipherSuiteCcmp256"),
            rsnCipherSuiteGcmp128=params.get("rsnCipherSuiteGcmp128"),
            rsnCipherSuiteCcmp128=params.get("rsnCipherSuiteCcmp128"),
            ghz6PolicyClientSteering=params.get("ghz6PolicyClientSteering"),
            isAuthKey8021x=params.get("isAuthKey8021x"),
            isAuthKey8021xPlusFT=params.get("isAuthKey8021xPlusFT"),
            isAuthKey8021x_SHA256=params.get("isAuthKey8021x_SHA256"),
            isAuthKeySae=params.get("isAuthKeySae"),
            isAuthKeySaePlusFT=params.get("isAuthKeySaePlusFT"),
            isAuthKeyPSK=params.get("isAuthKeyPSK"),
            isAuthKeyPSKPlusFT=params.get("isAuthKeyPSKPlusFT"),
            isAuthKeyOWE=params.get("isAuthKeyOWE"),
            isAuthKeyEasyPSK=params.get("isAuthKeyEasyPSK"),
            isAuthKeyPSKSHA256=params.get("isAuthKeyPSKSHA256"),
            openSsid=params.get("openSsid"),
            wlanBandSelectEnable=params.get("wlanBandSelectEnable"),
            isEnabled=params.get("isEnabled"),
            authServers=params.get("authServers"),
            acctServers=params.get("acctServers"),
            egressQos=params.get("egressQos"),
            ingressQos=params.get("ingressQos"),
            wlanType=params.get("wlanType"),
            l3AuthType=params.get("l3AuthType"),
            authServer=params.get("authServer"),
            externalAuthIpAddress=params.get("externalAuthIpAddress"),
            webPassthrough=params.get("webPassthrough"),
            sleepingClientEnable=params.get("sleepingClientEnable"),
            sleepingClientTimeout=params.get("sleepingClientTimeout"),
            aclName=params.get("aclName"),
            isPosturingEnabled=params.get("isPosturingEnabled"),
            isAuthKeySuiteB1x=params.get("isAuthKeySuiteB1x"),
            isAuthKeySuiteB1921x=params.get("isAuthKeySuiteB1921x"),
            isAuthKeySaeExt=params.get("isAuthKeySaeExt"),
            isAuthKeySaeExtPlusFT=params.get("isAuthKeySaeExtPlusFT"),
            isApBeaconProtectionEnabled=params.get("isApBeaconProtectionEnabled"),
            ghz24Policy=params.get("ghz24Policy"),
            cckmTsfTolerance=params.get("cckmTsfTolerance"),
            isCckmEnabled=params.get("isCckmEnabled"),
            isHex=params.get("isHex"),
            isRandomMacFilterEnabled=params.get("isRandomMacFilterEnabled"),
            fastTransitionOverTheDistributedSystemEnable=params.get(
                "fastTransitionOverTheDistributedSystemEnable"
            ),
            isRadiusProfilingEnabled=params.get("isRadiusProfilingEnabled"),
            policyProfileName=params.get("policyProfileName"),
            site_id=params.get("siteId"),
            id=params.get("id"),
            remove_override_in_hierarchy=params.get("removeOverrideInHierarchy"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["limit"] = self.new_object.get("limit")
        new_object_params["offset"] = self.new_object.get("offset")
        new_object_params["ssid"] = self.new_object.get("ssid")
        new_object_params["wlan_type"] = self.new_object.get(
            "wlanType"
        ) or self.new_object.get("wlan_type")
        new_object_params["auth_type"] = self.new_object.get(
            "authType"
        ) or self.new_object.get("auth_type")
        new_object_params["l3auth_type"] = self.new_object.get(
            "l3authType"
        ) or self.new_object.get("l3auth_type")
        new_object_params["site_id"] = self.new_object.get(
            "siteId"
        ) or self.new_object.get("site_id")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["ssid"] = self.new_object.get("ssid")
        new_object_params["authType"] = self.new_object.get("authType")
        new_object_params["passphrase"] = self.new_object.get("passphrase")
        new_object_params["isFastLaneEnabled"] = self.new_object.get(
            "isFastLaneEnabled"
        )
        new_object_params["isMacFilteringEnabled"] = self.new_object.get(
            "isMacFilteringEnabled"
        )
        new_object_params["ssidRadioType"] = self.new_object.get("ssidRadioType")
        new_object_params["isBroadcastSSID"] = self.new_object.get("isBroadcastSSID")
        new_object_params["fastTransition"] = self.new_object.get("fastTransition")
        new_object_params["sessionTimeOutEnable"] = self.new_object.get(
            "sessionTimeOutEnable"
        )
        new_object_params["sessionTimeOut"] = self.new_object.get("sessionTimeOut")
        new_object_params["clientExclusionEnable"] = self.new_object.get(
            "clientExclusionEnable"
        )
        new_object_params["clientExclusionTimeout"] = self.new_object.get(
            "clientExclusionTimeout"
        )
        new_object_params["basicServiceSetMaxIdleEnable"] = self.new_object.get(
            "basicServiceSetMaxIdleEnable"
        )
        new_object_params["basicServiceSetClientIdleTimeout"] = self.new_object.get(
            "basicServiceSetClientIdleTimeout"
        )
        new_object_params["directedMulticastServiceEnable"] = self.new_object.get(
            "directedMulticastServiceEnable"
        )
        new_object_params["neighborListEnable"] = self.new_object.get(
            "neighborListEnable"
        )
        new_object_params["managementFrameProtectionClientprotection"] = (
            self.new_object.get("managementFrameProtectionClientprotection")
        )
        new_object_params["nasOptions"] = self.new_object.get("nasOptions")
        new_object_params["profileName"] = self.new_object.get("profileName")
        new_object_params["aaaOverride"] = self.new_object.get("aaaOverride")
        new_object_params["coverageHoleDetectionEnable"] = self.new_object.get(
            "coverageHoleDetectionEnable"
        )
        new_object_params["protectedManagementFrame"] = self.new_object.get(
            "protectedManagementFrame"
        )
        new_object_params["multiPSKSettings"] = self.new_object.get("multiPSKSettings")
        new_object_params["clientRateLimit"] = self.new_object.get("clientRateLimit")
        new_object_params["rsnCipherSuiteGcmp256"] = self.new_object.get(
            "rsnCipherSuiteGcmp256"
        )
        new_object_params["rsnCipherSuiteCcmp256"] = self.new_object.get(
            "rsnCipherSuiteCcmp256"
        )
        new_object_params["rsnCipherSuiteGcmp128"] = self.new_object.get(
            "rsnCipherSuiteGcmp128"
        )
        new_object_params["rsnCipherSuiteCcmp128"] = self.new_object.get(
            "rsnCipherSuiteCcmp128"
        )
        new_object_params["ghz6PolicyClientSteering"] = self.new_object.get(
            "ghz6PolicyClientSteering"
        )
        new_object_params["isAuthKey8021x"] = self.new_object.get("isAuthKey8021x")
        new_object_params["isAuthKey8021xPlusFT"] = self.new_object.get(
            "isAuthKey8021xPlusFT"
        )
        new_object_params["isAuthKey8021x_SHA256"] = self.new_object.get(
            "isAuthKey8021x_SHA256"
        )
        new_object_params["isAuthKeySae"] = self.new_object.get("isAuthKeySae")
        new_object_params["isAuthKeySaePlusFT"] = self.new_object.get(
            "isAuthKeySaePlusFT"
        )
        new_object_params["isAuthKeyPSK"] = self.new_object.get("isAuthKeyPSK")
        new_object_params["isAuthKeyPSKPlusFT"] = self.new_object.get(
            "isAuthKeyPSKPlusFT"
        )
        new_object_params["isAuthKeyOWE"] = self.new_object.get("isAuthKeyOWE")
        new_object_params["isAuthKeyEasyPSK"] = self.new_object.get("isAuthKeyEasyPSK")
        new_object_params["isAuthKeyPSKSHA256"] = self.new_object.get(
            "isAuthKeyPSKSHA256"
        )
        new_object_params["openSsid"] = self.new_object.get("openSsid")
        new_object_params["wlanBandSelectEnable"] = self.new_object.get(
            "wlanBandSelectEnable"
        )
        new_object_params["isEnabled"] = self.new_object.get("isEnabled")
        new_object_params["authServers"] = self.new_object.get("authServers")
        new_object_params["acctServers"] = self.new_object.get("acctServers")
        new_object_params["egressQos"] = self.new_object.get("egressQos")
        new_object_params["ingressQos"] = self.new_object.get("ingressQos")
        new_object_params["wlanType"] = self.new_object.get("wlanType")
        new_object_params["l3AuthType"] = self.new_object.get("l3AuthType")
        new_object_params["authServer"] = self.new_object.get("authServer")
        new_object_params["externalAuthIpAddress"] = self.new_object.get(
            "externalAuthIpAddress"
        )
        new_object_params["webPassthrough"] = self.new_object.get("webPassthrough")
        new_object_params["sleepingClientEnable"] = self.new_object.get(
            "sleepingClientEnable"
        )
        new_object_params["sleepingClientTimeout"] = self.new_object.get(
            "sleepingClientTimeout"
        )
        new_object_params["aclName"] = self.new_object.get("aclName")
        new_object_params["isPosturingEnabled"] = self.new_object.get(
            "isPosturingEnabled"
        )
        new_object_params["isAuthKeySuiteB1x"] = self.new_object.get(
            "isAuthKeySuiteB1x"
        )
        new_object_params["isAuthKeySuiteB1921x"] = self.new_object.get(
            "isAuthKeySuiteB1921x"
        )
        new_object_params["isAuthKeySaeExt"] = self.new_object.get("isAuthKeySaeExt")
        new_object_params["isAuthKeySaeExtPlusFT"] = self.new_object.get(
            "isAuthKeySaeExtPlusFT"
        )
        new_object_params["isApBeaconProtectionEnabled"] = self.new_object.get(
            "isApBeaconProtectionEnabled"
        )
        new_object_params["ghz24Policy"] = self.new_object.get("ghz24Policy")
        new_object_params["cckmTsfTolerance"] = self.new_object.get("cckmTsfTolerance")
        new_object_params["isCckmEnabled"] = self.new_object.get("isCckmEnabled")
        new_object_params["isHex"] = self.new_object.get("isHex")
        new_object_params["isRandomMacFilterEnabled"] = self.new_object.get(
            "isRandomMacFilterEnabled"
        )
        new_object_params["fastTransitionOverTheDistributedSystemEnable"] = (
            self.new_object.get("fastTransitionOverTheDistributedSystemEnable")
        )
        new_object_params["isRadiusProfilingEnabled"] = self.new_object.get(
            "isRadiusProfilingEnabled"
        )
        new_object_params["policyProfileName"] = self.new_object.get(
            "policyProfileName"
        )
        new_object_params["siteId"] = self.new_object.get("siteId")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["remove_override_in_hierarchy"] = self.new_object.get(
            "remove_override_in_hierarchy"
        )
        new_object_params["site_id"] = self.new_object.get("site_id")
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        new_object_params["ssid"] = self.new_object.get("ssid")
        new_object_params["authType"] = self.new_object.get("authType")
        new_object_params["passphrase"] = self.new_object.get("passphrase")
        new_object_params["isFastLaneEnabled"] = self.new_object.get(
            "isFastLaneEnabled"
        )
        new_object_params["isMacFilteringEnabled"] = self.new_object.get(
            "isMacFilteringEnabled"
        )
        new_object_params["ssidRadioType"] = self.new_object.get("ssidRadioType")
        new_object_params["isBroadcastSSID"] = self.new_object.get("isBroadcastSSID")
        new_object_params["fastTransition"] = self.new_object.get("fastTransition")
        new_object_params["sessionTimeOutEnable"] = self.new_object.get(
            "sessionTimeOutEnable"
        )
        new_object_params["sessionTimeOut"] = self.new_object.get("sessionTimeOut")
        new_object_params["clientExclusionEnable"] = self.new_object.get(
            "clientExclusionEnable"
        )
        new_object_params["clientExclusionTimeout"] = self.new_object.get(
            "clientExclusionTimeout"
        )
        new_object_params["basicServiceSetMaxIdleEnable"] = self.new_object.get(
            "basicServiceSetMaxIdleEnable"
        )
        new_object_params["basicServiceSetClientIdleTimeout"] = self.new_object.get(
            "basicServiceSetClientIdleTimeout"
        )
        new_object_params["directedMulticastServiceEnable"] = self.new_object.get(
            "directedMulticastServiceEnable"
        )
        new_object_params["neighborListEnable"] = self.new_object.get(
            "neighborListEnable"
        )
        new_object_params["managementFrameProtectionClientprotection"] = (
            self.new_object.get("managementFrameProtectionClientprotection")
        )
        new_object_params["nasOptions"] = self.new_object.get("nasOptions")
        new_object_params["profileName"] = self.new_object.get("profileName")
        new_object_params["aaaOverride"] = self.new_object.get("aaaOverride")
        new_object_params["coverageHoleDetectionEnable"] = self.new_object.get(
            "coverageHoleDetectionEnable"
        )
        new_object_params["protectedManagementFrame"] = self.new_object.get(
            "protectedManagementFrame"
        )
        new_object_params["multiPSKSettings"] = self.new_object.get("multiPSKSettings")
        new_object_params["clientRateLimit"] = self.new_object.get("clientRateLimit")
        new_object_params["rsnCipherSuiteGcmp256"] = self.new_object.get(
            "rsnCipherSuiteGcmp256"
        )
        new_object_params["rsnCipherSuiteCcmp256"] = self.new_object.get(
            "rsnCipherSuiteCcmp256"
        )
        new_object_params["rsnCipherSuiteGcmp128"] = self.new_object.get(
            "rsnCipherSuiteGcmp128"
        )
        new_object_params["rsnCipherSuiteCcmp128"] = self.new_object.get(
            "rsnCipherSuiteCcmp128"
        )
        new_object_params["ghz6PolicyClientSteering"] = self.new_object.get(
            "ghz6PolicyClientSteering"
        )
        new_object_params["isAuthKey8021x"] = self.new_object.get("isAuthKey8021x")
        new_object_params["isAuthKey8021xPlusFT"] = self.new_object.get(
            "isAuthKey8021xPlusFT"
        )
        new_object_params["isAuthKey8021x_SHA256"] = self.new_object.get(
            "isAuthKey8021x_SHA256"
        )
        new_object_params["isAuthKeySae"] = self.new_object.get("isAuthKeySae")
        new_object_params["isAuthKeySaePlusFT"] = self.new_object.get(
            "isAuthKeySaePlusFT"
        )
        new_object_params["isAuthKeyPSK"] = self.new_object.get("isAuthKeyPSK")
        new_object_params["isAuthKeyPSKPlusFT"] = self.new_object.get(
            "isAuthKeyPSKPlusFT"
        )
        new_object_params["isAuthKeyOWE"] = self.new_object.get("isAuthKeyOWE")
        new_object_params["isAuthKeyEasyPSK"] = self.new_object.get("isAuthKeyEasyPSK")
        new_object_params["isAuthKeyPSKSHA256"] = self.new_object.get(
            "isAuthKeyPSKSHA256"
        )
        new_object_params["openSsid"] = self.new_object.get("openSsid")
        new_object_params["wlanBandSelectEnable"] = self.new_object.get(
            "wlanBandSelectEnable"
        )
        new_object_params["isEnabled"] = self.new_object.get("isEnabled")
        new_object_params["authServers"] = self.new_object.get("authServers")
        new_object_params["acctServers"] = self.new_object.get("acctServers")
        new_object_params["egressQos"] = self.new_object.get("egressQos")
        new_object_params["ingressQos"] = self.new_object.get("ingressQos")
        new_object_params["wlanType"] = self.new_object.get("wlanType")
        new_object_params["l3AuthType"] = self.new_object.get("l3AuthType")
        new_object_params["authServer"] = self.new_object.get("authServer")
        new_object_params["externalAuthIpAddress"] = self.new_object.get(
            "externalAuthIpAddress"
        )
        new_object_params["webPassthrough"] = self.new_object.get("webPassthrough")
        new_object_params["sleepingClientEnable"] = self.new_object.get(
            "sleepingClientEnable"
        )
        new_object_params["sleepingClientTimeout"] = self.new_object.get(
            "sleepingClientTimeout"
        )
        new_object_params["aclName"] = self.new_object.get("aclName")
        new_object_params["isPosturingEnabled"] = self.new_object.get(
            "isPosturingEnabled"
        )
        new_object_params["isAuthKeySuiteB1x"] = self.new_object.get(
            "isAuthKeySuiteB1x"
        )
        new_object_params["isAuthKeySuiteB1921x"] = self.new_object.get(
            "isAuthKeySuiteB1921x"
        )
        new_object_params["isAuthKeySaeExt"] = self.new_object.get("isAuthKeySaeExt")
        new_object_params["isAuthKeySaeExtPlusFT"] = self.new_object.get(
            "isAuthKeySaeExtPlusFT"
        )
        new_object_params["isApBeaconProtectionEnabled"] = self.new_object.get(
            "isApBeaconProtectionEnabled"
        )
        new_object_params["ghz24Policy"] = self.new_object.get("ghz24Policy")
        new_object_params["cckmTsfTolerance"] = self.new_object.get("cckmTsfTolerance")
        new_object_params["isCckmEnabled"] = self.new_object.get("isCckmEnabled")
        new_object_params["isHex"] = self.new_object.get("isHex")
        new_object_params["isRandomMacFilterEnabled"] = self.new_object.get(
            "isRandomMacFilterEnabled"
        )
        new_object_params["fastTransitionOverTheDistributedSystemEnable"] = (
            self.new_object.get("fastTransitionOverTheDistributedSystemEnable")
        )
        new_object_params["isRadiusProfilingEnabled"] = self.new_object.get(
            "isRadiusProfilingEnabled"
        )
        new_object_params["policyProfileName"] = self.new_object.get(
            "policyProfileName"
        )
        new_object_params["siteId"] = self.new_object.get("siteId")
        new_object_params["id"] = self.new_object.get("id")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.dnac.exec(
                family="wireless",
                function="get_ssid_by_site",
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
                family="wireless", function="get_ssid_by_id", params={"id": id}
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
        requested_obj = self.new_object

        obj_params = [
            ("ssid", "ssid"),
            ("authType", "authType"),
            ("passphrase", "passphrase"),
            ("isFastLaneEnabled", "isFastLaneEnabled"),
            ("isMacFilteringEnabled", "isMacFilteringEnabled"),
            ("ssidRadioType", "ssidRadioType"),
            ("isBroadcastSSID", "isBroadcastSSID"),
            ("fastTransition", "fastTransition"),
            ("sessionTimeOutEnable", "sessionTimeOutEnable"),
            ("sessionTimeOut", "sessionTimeOut"),
            ("clientExclusionEnable", "clientExclusionEnable"),
            ("clientExclusionTimeout", "clientExclusionTimeout"),
            ("basicServiceSetMaxIdleEnable", "basicServiceSetMaxIdleEnable"),
            ("basicServiceSetClientIdleTimeout", "basicServiceSetClientIdleTimeout"),
            ("directedMulticastServiceEnable", "directedMulticastServiceEnable"),
            ("neighborListEnable", "neighborListEnable"),
            (
                "managementFrameProtectionClientprotection",
                "managementFrameProtectionClientprotection",
            ),
            ("nasOptions", "nasOptions"),
            ("profileName", "profileName"),
            ("aaaOverride", "aaaOverride"),
            ("coverageHoleDetectionEnable", "coverageHoleDetectionEnable"),
            ("protectedManagementFrame", "protectedManagementFrame"),
            ("multiPSKSettings", "multiPSKSettings"),
            ("clientRateLimit", "clientRateLimit"),
            ("rsnCipherSuiteGcmp256", "rsnCipherSuiteGcmp256"),
            ("rsnCipherSuiteCcmp256", "rsnCipherSuiteCcmp256"),
            ("rsnCipherSuiteGcmp128", "rsnCipherSuiteGcmp128"),
            ("rsnCipherSuiteCcmp128", "rsnCipherSuiteCcmp128"),
            ("ghz6PolicyClientSteering", "ghz6PolicyClientSteering"),
            ("isAuthKey8021x", "isAuthKey8021x"),
            ("isAuthKey8021xPlusFT", "isAuthKey8021xPlusFT"),
            ("isAuthKey8021x_SHA256", "isAuthKey8021x_SHA256"),
            ("isAuthKeySae", "isAuthKeySae"),
            ("isAuthKeySaePlusFT", "isAuthKeySaePlusFT"),
            ("isAuthKeyPSK", "isAuthKeyPSK"),
            ("isAuthKeyPSKPlusFT", "isAuthKeyPSKPlusFT"),
            ("isAuthKeyOWE", "isAuthKeyOWE"),
            ("isAuthKeyEasyPSK", "isAuthKeyEasyPSK"),
            ("isAuthKeyPSKSHA256", "isAuthKeyPSKSHA256"),
            ("openSsid", "openSsid"),
            ("wlanBandSelectEnable", "wlanBandSelectEnable"),
            ("isEnabled", "isEnabled"),
            ("authServers", "authServers"),
            ("acctServers", "acctServers"),
            ("egressQos", "egressQos"),
            ("ingressQos", "ingressQos"),
            ("wlanType", "wlanType"),
            ("l3AuthType", "l3AuthType"),
            ("authServer", "authServer"),
            ("externalAuthIpAddress", "externalAuthIpAddress"),
            ("webPassthrough", "webPassthrough"),
            ("sleepingClientEnable", "sleepingClientEnable"),
            ("sleepingClientTimeout", "sleepingClientTimeout"),
            ("aclName", "aclName"),
            ("isPosturingEnabled", "isPosturingEnabled"),
            ("isAuthKeySuiteB1x", "isAuthKeySuiteB1x"),
            ("isAuthKeySuiteB1921x", "isAuthKeySuiteB1921x"),
            ("isAuthKeySaeExt", "isAuthKeySaeExt"),
            ("isAuthKeySaeExtPlusFT", "isAuthKeySaeExtPlusFT"),
            ("isApBeaconProtectionEnabled", "isApBeaconProtectionEnabled"),
            ("ghz24Policy", "ghz24Policy"),
            ("cckmTsfTolerance", "cckmTsfTolerance"),
            ("isCckmEnabled", "isCckmEnabled"),
            ("isHex", "isHex"),
            ("isRandomMacFilterEnabled", "isRandomMacFilterEnabled"),
            (
                "fastTransitionOverTheDistributedSystemEnable",
                "fastTransitionOverTheDistributedSystemEnable",
            ),
            ("isRadiusProfilingEnabled", "isRadiusProfilingEnabled"),
            ("policyProfileName", "policyProfileName"),
            ("siteId", "site_id"),
            ("id", "id"),
            ("removeOverrideInHierarchy", "remove_override_in_hierarchy"),
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
            function="create_ssid",
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
            family="wireless",
            function="update_ssid",
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
            function="delete_ssid",
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
        obj = SitesWirelessSettingsSsids(self._task.args, dnac)

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
