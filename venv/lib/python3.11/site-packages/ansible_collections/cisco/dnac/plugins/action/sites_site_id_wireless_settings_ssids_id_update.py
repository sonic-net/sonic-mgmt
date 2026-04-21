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
)

# Get common arguements specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
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
    )
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


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

    def get_object(self, params):
        new_object = dict(
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
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        dnac = DNACSDK(params=self._task.args)

        response = dnac.exec(
            family="wireless",
            function="update_or_overridessid",
            op_modifies=True,
            params=self.get_object(self._task.args),
        )
        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
