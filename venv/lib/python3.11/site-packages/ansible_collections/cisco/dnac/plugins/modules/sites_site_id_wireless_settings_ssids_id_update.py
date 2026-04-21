#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_site_id_wireless_settings_ssids_id_update
short_description: Resource module for Sites Site Id
  Wireless Settings Ssids Id Update
description:
  - Manage operation create of the resource Sites Site
    Id Wireless Settings Ssids Id Update.
  - This API allows to either update SSID at global
    'siteId' or override SSID at given non-global 'siteId'.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aaaOverride:
    description: Activate the AAA Override feature when
      set to true.
    type: bool
  acctServers:
    description: List of Accounting server IpAddresses.
    elements: str
    type: list
  aclName:
    description: Pre-Auth Access Control List (ACL)
      Name.
    type: str
  authServer:
    description: For Guest SSIDs ('wlanType' is 'Guest'
      and 'l3AuthType' is 'web_auth'), the Authentication
      Server('authServer') is mandatory. Otherwise,
      it defaults to 'auth_external'.
    type: str
  authServers:
    description: List of Authentication/Authorization
      server IpAddresses.
    elements: str
    type: list
  authType:
    description: L2 Authentication Type (If authType
      is not open , then atleast one RSN Cipher Suite
      and corresponding valid AKM must be enabled).
    type: str
  basicServiceSetClientIdleTimeout:
    description: This refers to the duration of inactivity,
      measured in seconds, before a client connected
      to the Basic Service Set is considered idle and
      timed out. Default is Basic ServiceSet ClientIdle
      Timeout if exists else 300. If it needs to be
      disabled , pass 0 as its value else valid range
      is 15 to 100000.
    type: int
  basicServiceSetMaxIdleEnable:
    description: Activate the maximum idle feature for
      the Basic Service Set.
    type: bool
  cckmTsfTolerance:
    description: The default value is the Cckm Timestamp
      Tolerance (in milliseconds, if specified); otherwise,
      it is 0.
    type: int
  clientExclusionEnable:
    description: Activate the feature that allows for
      the exclusion of clients.
    type: bool
  clientExclusionTimeout:
    description: This refers to the length of time,
      in seconds, a client is excluded or blocked from
      accessing the network after a specified number
      of unsuccessful attempts.
    type: int
  clientRateLimit:
    description: This pertains to the maximum data transfer
      rate, specified in bits per second, that a client
      is permitted to achieve.
    type: int
  coverageHoleDetectionEnable:
    description: Activate Coverage Hole Detection feature
      when set to true.
    type: bool
  directedMulticastServiceEnable:
    description: The Directed Multicast Service feature
      becomes operational when it is set to true.
    type: bool
  egressQos:
    description: Egress QOS.
    type: str
  externalAuthIpAddress:
    description: External WebAuth URL (Mandatory for
      Guest SSIDs with wlanType = Guest, l3AuthType
      = web_auth and authServer = auth_external).
    type: str
  fastTransition:
    description: Fast Transition.
    type: str
  fastTransitionOverTheDistributedSystemEnable:
    description: Enable Fast Transition over the Distributed
      System when set to true.
    type: bool
  ghz24Policy:
    description: 2.4 Ghz Band Policy value. Allowed
      only when 2.4 Radio Band is enabled in ssidRadioType.
    type: str
  ghz6PolicyClientSteering:
    description: True if 6 GHz Policy Client Steering
      is enabled, else False.
    type: bool
  id:
    description: Id path parameter. SSID ID.
    type: str
  ingressQos:
    description: Ingress QOS.
    type: str
  isApBeaconProtectionEnabled:
    description: When set to true, the Access Point
      (AP) Beacon Protection feature is activated, enhancing
      the security of the network.
    type: bool
  isAuthKey8021x:
    description: When set to true, the 802.1X authentication
      key is in use.
    type: bool
  isAuthKey8021xPlusFT:
    description: When set to true, the 802.1X-Plus-FT
      authentication key is in use.
    type: bool
  isAuthKey8021x_SHA256:
    description: When set to true, the feature that
      enables 802.1X authentication using the SHA256
      algorithm is turned on.
    type: bool
  isAuthKeyEasyPSK:
    description: When set to true, the feature that
      enables the use of Easy Pre-shared Key (PSK) authentication
      is activated.
    type: bool
  isAuthKeyOWE:
    description: When set to true, the Opportunistic
      Wireless Encryption (OWE) authentication key feature
      is turned on.
    type: bool
  isAuthKeyPSK:
    description: When set to true, the Pre-shared Key
      (PSK) authentication feature is enabled.
    type: bool
  isAuthKeyPSKPlusFT:
    description: When set to true, the feature that
      enables the combination of Pre-shared Key (PSK)
      and Fast Transition (FT) authentication keys is
      activated.
    type: bool
  isAuthKeyPSKSHA256:
    description: The feature that allows the use of
      Pre-shared Key (PSK) authentication with the SHA256
      algorithm is enabled when it is set to true.
    type: bool
  isAuthKeySae:
    description: When set to true, the feature enabling
      the Simultaneous Authentication of Equals (SAE)
      authentication key is activated.
    type: bool
  isAuthKeySaeExt:
    description: When set to true, the Simultaneous
      Authentication of Equals (SAE) Extended Authentication
      key feature is turned on.
    type: bool
  isAuthKeySaeExtPlusFT:
    description: When set to true, the Simultaneous
      Authentication of Equals (SAE) combined with Fast
      Transition (FT) Authentication Key feature is
      enabled.
    type: bool
  isAuthKeySaePlusFT:
    description: Activating this setting by switching
      it to true turns on the authentication key feature
      that supports both Simultaneous Authentication
      of Equals (SAE) and Fast Transition (FT).
    type: bool
  isAuthKeySuiteB1921x:
    description: When set to true, the SuiteB192-1x
      authentication key feature is enabled.
    type: bool
  isAuthKeySuiteB1x:
    description: When activated by setting it to true,
      the SuiteB-1x authentication key feature is engaged.
    type: bool
  isBroadcastSSID:
    description: When activated by setting it to true,
      the Broadcast SSID feature will make the SSID
      publicly visible to wireless devices searching
      for available networks.
    type: bool
  isCckmEnabled:
    description: True if CCKM is enabled, else False.
    type: bool
  isEnabled:
    description: Set SSID's admin status as 'Enabled'
      when set to true.
    type: bool
  isFastLaneEnabled:
    description: True if FastLane is enabled, else False.
    type: bool
  isHex:
    description: True if passphrase is in Hex format,
      else False.
    type: bool
  isMacFilteringEnabled:
    description: When set to true, MAC Filtering will
      be activated, allowing control over network access
      based on the MAC address of the device.
    type: bool
  isPosturingEnabled:
    description: Applicable only for Enterprise SSIDs.
      When set to True, Posturing will enabled. Required
      to be set to True if ACL needs to be mapped for
      Enterprise SSID.
    type: bool
  isRadiusProfilingEnabled:
    description: '''true'' if Radius profiling needs
      to be enabled, defaults to ''false'' if not specified.
      At least one AAA/PSN server is required to enable
      Radius Profiling.'
    type: bool
  isRandomMacFilterEnabled:
    description: Deny clients using randomized MAC addresses
      when set to true.
    type: bool
  l3AuthType:
    description: 'L3 Authentication Type. When *wlanType*
      is *Enterprise*, *l3AuthType* is optional and
      defaults to *open* if not specified. If *wlanType*
      is *Guest* then *l3AuthType* is mandatory.'
    type: str
  managementFrameProtectionClientprotection:
    description: Management Frame Protection Client.
    type: str
  multiPSKSettings:
    description: Sites Site Id Wireless Settings Ssids
      Id Update's multiPSKSettings.
    elements: dict
    suboptions:
      passphrase:
        description: Passphrase needs to be between
          8 and 63 characters for ASCII type. HEX passphrase
          needs to be 64 characters.
        type: str
      passphraseType:
        description: Passphrase Type(default ASCII).
        type: str
      priority:
        description: Priority.
        type: int
    type: list
  nasOptions:
    description: Pre-Defined NAS Options AP ETH Mac
      Address, AP IP address, AP Location , AP MAC Address,
      AP Name, AP Policy Tag, AP Site Tag, SSID, System
      IP Address, System MAC Address, System Name.
    elements: str
    type: list
  neighborListEnable:
    description: The Neighbor List feature is enabled
      when it is set to true.
    type: bool
  openSsid:
    description: Open SSID which is already created
      in the design and not associated to any other
      OPEN-SECURED SSID.
    type: str
  passphrase:
    description: Passphrase (Only applicable for SSID
      with PERSONAL security level). Passphrase needs
      to be between 8 and 63 characters for ASCII type.
      HEX passphrase needs to be 64 characters.
    type: str
  policyProfileName:
    description: Policy Profile Name.
    type: str
  profileName:
    description: WLAN Profile Name, if not passed autogenerated
      profile name will be assigned.
    type: str
  protectedManagementFrame:
    description: (REQUIRED is applicable for authType
      WPA3_PERSONAL, WPA3_ENTERPRISE, OPEN_SECURED)
      and (OPTIONAL/REQUIRED is applicable for authType
      WPA2_WPA3_PERSONAL and WPA2_WPA3_ENTERPRISE).
    type: str
  rsnCipherSuiteCcmp128:
    description: When set to true, the Robust Security
      Network (RSN) Cipher Suite CCMP128 encryption
      protocol is activated.
    type: bool
  rsnCipherSuiteCcmp256:
    description: When set to true, the Robust Security
      Network (RSN) Cipher Suite CCMP256 encryption
      protocol is activated.
    type: bool
  rsnCipherSuiteGcmp128:
    description: When set to true, the Robust Security
      Network (RSN) Cipher Suite GCMP128 encryption
      protocol is activated.
    type: bool
  rsnCipherSuiteGcmp256:
    description: When set to true, the Robust Security
      Network (RSN) Cipher Suite GCMP256 encryption
      protocol is activated.
    type: bool
  sessionTimeOut:
    description: This denotes the allotted time span,
      expressed in seconds, before a session is automatically
      terminated due to inactivity. Default sessionTimeOut
      is 1800.
    type: int
  sessionTimeOutEnable:
    description: Turn on the feature that imposes a
      time limit on user sessions.
    type: bool
  siteId:
    description: SiteId path parameter. Site UUID.
    type: str
  sleepingClientEnable:
    description: When set to true, this will activate
      the timeout settings that apply to clients in
      sleep mode.
    type: bool
  sleepingClientTimeout:
    description: This refers to the amount of time,
      measured in minutes, before a sleeping (inactive)
      client is timed out of the network.
    type: int
  ssid:
    description: Name of the SSID.
    type: str
  ssidRadioType:
    description: Radio Policy Enum (default Triple band
      operation(2.4GHz, 5GHz and 6GHz)).
    type: str
  webPassthrough:
    description: When set to true, the Web-Passthrough
      feature will be activated for the Guest SSID,
      allowing guests to bypass certain login requirements.
    type: bool
  wlanBandSelectEnable:
    description: Band select is allowed only when band
      options selected contains at least 2.4 GHz and
      5 GHz band.
    type: bool
  wlanType:
    description: Wlan Type.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      UpdateOrOverrideSSID
    description: Complete reference of the UpdateOrOverrideSSID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-or-override-ssid
notes:
  - SDK Method used are
    wireless.Wireless.update_or_overridessid,
  - Paths used are
    post /dna/intent/api/v1/sites/{siteId}/wirelessSettings/ssids/{id}/update,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sites_site_id_wireless_settings_ssids_id_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    aaaOverride: true
    acctServers:
      - string
    aclName: string
    authServer: string
    authServers:
      - string
    authType: string
    basicServiceSetClientIdleTimeout: 0
    basicServiceSetMaxIdleEnable: true
    cckmTsfTolerance: 0
    clientExclusionEnable: true
    clientExclusionTimeout: 0
    clientRateLimit: 0
    coverageHoleDetectionEnable: true
    directedMulticastServiceEnable: true
    egressQos: string
    externalAuthIpAddress: string
    fastTransition: string
    fastTransitionOverTheDistributedSystemEnable: true
    ghz24Policy: string
    ghz6PolicyClientSteering: true
    id: string
    ingressQos: string
    isApBeaconProtectionEnabled: true
    isAuthKey8021x: true
    isAuthKey8021xPlusFT: true
    isAuthKey8021x_SHA256: true
    isAuthKeyEasyPSK: true
    isAuthKeyOWE: true
    isAuthKeyPSK: true
    isAuthKeyPSKPlusFT: true
    isAuthKeyPSKSHA256: true
    isAuthKeySae: true
    isAuthKeySaeExt: true
    isAuthKeySaeExtPlusFT: true
    isAuthKeySaePlusFT: true
    isAuthKeySuiteB1921x: true
    isAuthKeySuiteB1x: true
    isBroadcastSSID: true
    isCckmEnabled: true
    isEnabled: true
    isFastLaneEnabled: true
    isHex: true
    isMacFilteringEnabled: true
    isPosturingEnabled: true
    isRadiusProfilingEnabled: true
    isRandomMacFilterEnabled: true
    l3AuthType: string
    managementFrameProtectionClientprotection: string
    multiPSKSettings:
      - passphrase: string
        passphraseType: string
        priority: 0
    nasOptions:
      - string
    neighborListEnable: true
    openSsid: string
    passphrase: string
    policyProfileName: string
    profileName: string
    protectedManagementFrame: string
    rsnCipherSuiteCcmp128: true
    rsnCipherSuiteCcmp256: true
    rsnCipherSuiteGcmp128: true
    rsnCipherSuiteGcmp256: true
    sessionTimeOut: 0
    sessionTimeOutEnable: true
    siteId: string
    sleepingClientEnable: true
    sleepingClientTimeout: 0
    ssid: string
    ssidRadioType: string
    webPassthrough: true
    wlanBandSelectEnable: true
    wlanType: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
