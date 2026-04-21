#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sensor_test_template_edit
short_description: Resource module for Sensor Test Template
  Edit
description:
  - Manage operation update of the resource Sensor Test
    Template Edit.
  - Intent API to deploy, schedule, or edit and existing
    SENSOR test template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  _id:
    description: The sensor test template unique identifier,
      generated at test creation time.
    type: str
  actionInProgress:
    description: Indication of inprogress action.
    type: str
  apCoverage:
    description: Sensor Test Template Edit's apCoverage.
    elements: dict
    suboptions:
      bands:
        description: The WIFI bands.
        type: str
      numberOfApsToTest:
        description: Number of APs to test.
        type: int
      rssiThreshold:
        description: RSSI threshold.
        type: int
    type: list
  connection:
    description: Connection type of test WIRED, WIRELESS,
      BOTH.
    type: str
  encryptionMode:
    description: Encryption mode.
    type: str
  frequency:
    description: Sensor Test Template Edit's frequency.
    suboptions:
      unit:
        description: Unit of the time value (NANOSECONDS,
          MICROSECONDS, MILLISECONDS, SECONDS, MINUTES,
          HOURS, DAYS).
        type: str
      value:
        description: Value of the unit.
        type: int
    type: dict
  lastModifiedTime:
    description: Last modify time.
    type: int
  location:
    description: Location string.
    type: str
  locationInfoList:
    description: Sensor Test Template Edit's locationInfoList.
    elements: dict
    suboptions:
      allSensors:
        description: Use all sensors in the site for
          test.
        type: bool
      customManagementVlan:
        description: Custom Management VLAN.
        type: bool
      locationId:
        description: Site UUID.
        type: str
      locationType:
        description: Site type.
        type: str
      macAddressList:
        description: MAC addresses.
        elements: str
        type: list
      managementVlan:
        description: Management VLAN.
        type: str
      siteHierarchy:
        description: Site name hierarhy.
        type: str
    type: list
  modelVersion:
    description: Test template object model version
      (must be 2).
    type: int
  name:
    description: The sensor test template name, which
      is the same as in 'templateName'.
    type: str
  numAssociatedSensor:
    description: Number of associated sensor.
    type: int
  numNeighborAPThreshold:
    description: Number of neighboring AP threshold.
    type: int
  profiles:
    description: Sensor Test Template Edit's profiles.
    elements: dict
    suboptions:
      authProtocol:
        description: Auth protocol.
        type: str
      authType:
        description: Authentication type OPEN, WPA2_PSK,
          WPA2_EAP, WEB_AUTH, MAB, DOT1X, OTHER.
        type: str
      certdownloadurl:
        description: Certificate download URL.
        type: str
      certfilename:
        description: Auth certificate file name.
        type: str
      certpassphrase:
        description: Certificate password phrase.
        type: str
      certstatus:
        description: Certificate status INACTIVE or
          ACTIVE.
        type: str
      certxferprotocol:
        description: Certificate transfering protocol
          HTTP or HTTPS.
        type: str
      deviceType:
        description: Device Type.
        type: str
      eapMethod:
        description: WPA2_EAP methods EAP-FAST, PEAP-MSCHAPv2,
          EAP-TLS, PEAP-TLS, EAP-TTLS-MSCHAPv2, EAP-TTLS-PAP,
          EAP-TTLS-CHAP, EAP-FAST-GTC, EAP-PEAP-GTC.
        type: str
      extWebAuth:
        description: Indication of using external WEB
          Auth.
        type: bool
      extWebAuthAccessUrl:
        description: External WEB Auth access URL.
        type: str
      extWebAuthHtmlTag:
        description: Sensor Test Template Edit's extWebAuthHtmlTag.
        elements: dict
        suboptions:
          label:
            description: Label.
            type: str
          tag:
            description: Tag.
            type: str
          value:
            description: Value.
            type: str
        type: list
      extWebAuthPortal:
        description: External authentication portal.
        type: str
      extWebAuthVirtualIp:
        description: External WEB Auth virtual IP.
        type: str
      locationVlanList:
        description: Sensor Test Template Edit's locationVlanList.
        elements: dict
        suboptions:
          locationId:
            description: Site UUID.
            type: str
          vlans:
            description: Array of VLANs.
            elements: str
            type: list
        type: list
      password:
        description: Password string for onboarding
          SSID.
        type: str
      passwordType:
        description: SSID password type ASCII or HEX.
        type: str
      profileName:
        description: Profile name.
        type: str
      psk:
        description: Password of SSID when passwordType
          is ASCII.
        type: str
      qosPolicy:
        description: QoS policy PlATINUM, GOLD, SILVER,
          BRONZE.
        type: str
      scep:
        description: Secure certificate enrollment protocol
          true or false or null for not applicable.
        type: bool
      tests:
        description: Sensor Test Template Edit's tests.
        elements: dict
        suboptions:
          config:
            description: Sensor Test Template Edit's
              config.
            elements: dict
            suboptions:
              direction:
                description: IPerf direction (UPLOAD,
                  DOWNLOAD, BOTH).
                type: str
              domains:
                description: DNS domain name.
                elements: str
                type: list
              downlinkTest:
                description: Downlink test.
                type: bool
              endPort:
                description: IPerf end port.
                type: int
              exitCommand:
                description: Exit command.
                type: str
              finalPrompt:
                description: Final prompt.
                type: str
              ndtServer:
                description: NDT server.
                type: str
              ndtServerPath:
                description: NDT server path.
                type: str
              ndtServerPort:
                description: NDT server port.
                type: str
              numPackets:
                description: Number of packets.
                type: int
              password:
                description: Password.
                type: str
              passwordPrompt:
                description: Password prompt.
                type: str
              pathToDownload:
                description: File path for file transfer.
                type: str
              port:
                description: Radius or WEB server port.
                type: int
              probeType:
                description: Probe type.
                type: str
              protocol:
                description: Protocol used by file transfer,
                  IPerf, mail server, and radius (TCP,
                  UDP, FTP, POP3, IMAP, CHAP, PAP).
                type: str
              proxyPassword:
                description: Proxy password.
                type: str
              proxyPort:
                description: Proxy port.
                type: str
              proxyServer:
                description: Proxy server.
                type: str
              proxyUserName:
                description: Proxy user name.
                type: str
              server:
                description: Ping, file transfer, mail,
                  radius, ssh, or telnet server.
                type: str
              servers:
                description: IPerf server list.
                elements: str
                type: list
              sharedSecret:
                description: Shared secret.
                type: str
              startPort:
                description: IPerf start port.
                type: int
              transferType:
                description: File transfer type (UPLOAD,
                  DOWNLOAD, BOTH).
                type: str
              udpBandwidth:
                description: IPerf UDP bandwidth.
                type: int
              uplinkTest:
                description: Uplink test.
                type: bool
              url:
                description: URL.
                type: str
              userName:
                description: User name.
                type: str
              userNamePrompt:
                description: User name prompt.
                type: str
            type: list
          name:
            description: Name of the test.
            type: str
        type: list
      username:
        description: User name string for onboarding
          SSID.
        type: str
      vlan:
        description: VLAN.
        type: str
      whiteList:
        description: Indication of being on allowed
          list.
        type: bool
    type: list
  radioAsSensorRemoved:
    description: Radio as sensor removed.
    type: bool
  rssiThreshold:
    description: RSSI threshold.
    type: int
  runNow:
    description: Run now (YES, NO).
    type: str
  scheduleInDays:
    description: Bit-wise value of scheduled test days.
    type: int
  sensors:
    description: Sensor Test Template Edit's sensors.
    elements: dict
    suboptions:
      allSensorAddition:
        description: Is all sensor addition.
        type: bool
      assigned:
        description: Is assigned.
        type: bool
      configUpdated:
        description: Configuration updated YES, NO.
        type: str
      hostName:
        description: Host name.
        type: str
      iPerfInfo:
        description: A string-stringList iPerf information.
        type: dict
      id:
        description: Sensor ID.
        type: str
      ipAddress:
        description: IP address.
        type: str
      locationId:
        description: Site UUID.
        type: str
      macAddress:
        description: MAC address.
        type: str
      markedForUninstall:
        description: Is marked for uninstall.
        type: bool
      name:
        description: Sensor name.
        type: str
      runNow:
        description: Run now YES, NO.
        type: str
      sensorType:
        description: Sensor type.
        type: str
      servicePolicy:
        description: Service policy.
        type: str
      status:
        description: Sensor device status UP, DOWN,
          REBOOT.
        type: str
      switchMac:
        description: Switch MAC address.
        type: str
      switchSerialNumber:
        description: Switch serial number.
        type: str
      switchUuid:
        description: Switch device UUID.
        type: str
      targetAPs:
        description: Array of target APs.
        elements: str
        type: list
      testMacAddresses:
        description: A string-string test MAC address.
        type: dict
      wiredApplicationMessage:
        description: Wired application message.
        type: str
      wiredApplicationStatus:
        description: Wired application status.
        type: str
      xorSensor:
        description: Is XOR sensor.
        type: bool
    type: list
  showWlcUpgradeBanner:
    description: Show WLC upgrade banner.
    type: bool
  siteHierarchy:
    description: Site hierarchy.
    type: str
  ssids:
    description: Sensor Test Template Edit's ssids.
    elements: dict
    suboptions:
      authProtocol:
        description: Auth protocol.
        type: str
      authType:
        description: Authentication type OPEN, WPA2_PSK,
          WPA2_EAP, WEB_AUTH, MAB, DOT1X, OTHER.
        type: str
      bands:
        description: WIFI bands 2.4GHz or 5GHz.
        type: str
      certdownloadurl:
        description: Certificate download URL.
        type: str
      certfilename:
        description: Auth certificate file name.
        type: str
      certpassphrase:
        description: Certificate password phrase.
        type: str
      certstatus:
        description: Certificate status INACTIVE or
          ACTIVE.
        type: str
      certxferprotocol:
        description: Certificate transfering protocol
          HTTP or HTTPS.
        type: str
      eapMethod:
        description: WPA2_EAP methods EAP-FAST, PEAP-MSCHAPv2,
          EAP-TLS, PEAP-TLS, EAP-TTLS-MSCHAPv2, EAP-TTLS-PAP,
          EAP-TTLS-CHAP, EAP-FAST-GTC, EAP-PEAP-GTC.
        type: str
      extWebAuth:
        description: Indication of using external WEB
          Auth.
        type: bool
      extWebAuthAccessUrl:
        description: External WEB Auth access URL.
        type: str
      extWebAuthHtmlTag:
        description: Sensor Test Template Edit's extWebAuthHtmlTag.
        elements: dict
        suboptions:
          label:
            description: Label.
            type: str
          tag:
            description: Tag.
            type: str
          value:
            description: Value.
            type: str
        type: list
      extWebAuthPortal:
        description: External authentication portal.
        type: str
      extWebAuthVirtualIp:
        description: External WEB Auth virtual IP.
        type: str
      id:
        description: Identification number.
        type: int
      layer3webAuthEmailAddress:
        description: Layer 3 WEB Auth email address.
        type: str
      layer3webAuthpassword:
        description: Layer 3 WEB Auth password.
        type: str
      layer3webAuthsecurity:
        description: Layer 3 WEB Auth security.
        type: str
      layer3webAuthuserName:
        description: Layer 3 WEB Auth user name.
        type: str
      numAps:
        description: Number of APs in the test.
        type: int
      numSensors:
        description: Number of Sensors in the test.
        type: int
      password:
        description: Password string for onboarding
          SSID.
        type: str
      passwordType:
        description: SSID password type ASCII or HEX.
        type: str
      profileName:
        description: The SSID profile name string.
        type: str
      proxyPassword:
        description: Proxy server password.
        type: str
      proxyPort:
        description: Proxy server port.
        type: str
      proxyServer:
        description: Proxy server for onboarding SSID.
        type: str
      proxyUserName:
        description: Proxy server user name.
        type: str
      psk:
        description: Password of SSID when passwordType
          is ASCII.
        type: str
      qosPolicy:
        description: QoS policy PlATINUM, GOLD, SILVER,
          BRONZE.
        type: str
      scep:
        description: Secure certificate enrollment protocol
          true or false or null for not applicable.
        type: bool
      ssid:
        description: The SSID string.
        type: str
      status:
        description: WLAN status ENABLED or DISABLED.
        type: str
      tests:
        description: Sensor Test Template Edit's tests.
        elements: dict
        suboptions:
          config:
            description: Sensor Test Template Edit's
              config.
            elements: dict
            suboptions:
              direction:
                description: IPerf direction (UPLOAD,
                  DOWNLOAD, BOTH).
                type: str
              domains:
                description: DNS domain name.
                elements: str
                type: list
              downlinkTest:
                description: Downlink test.
                type: bool
              endPort:
                description: IPerf end port.
                type: int
              exitCommand:
                description: Exit command.
                type: str
              finalPrompt:
                description: Final prompt.
                type: str
              ndtServer:
                description: NDT server.
                type: str
              ndtServerPath:
                description: NDT server path.
                type: str
              ndtServerPort:
                description: NDT server port.
                type: str
              numPackets:
                description: Number of packets.
                type: int
              password:
                description: Password.
                type: str
              passwordPrompt:
                description: Password prompt.
                type: str
              pathToDownload:
                description: File path for file transfer.
                type: str
              port:
                description: Radius or WEB server port.
                type: int
              probeType:
                description: Probe type.
                type: str
              protocol:
                description: Protocol used by file transfer,
                  IPerf, mail server, and radius (TCP,
                  UDP, FTP, POP3, IMAP, CHAP, PAP).
                type: str
              proxyPassword:
                description: Proxy password.
                type: str
              proxyPort:
                description: Proxy port.
                type: str
              proxyServer:
                description: Proxy server.
                type: str
              proxyUserName:
                description: Proxy user name.
                type: str
              server:
                description: Ping, file transfer, mail,
                  radius, ssh, or telnet server.
                type: str
              servers:
                description: IPerf server list.
                elements: str
                type: list
              sharedSecret:
                description: Shared secret.
                type: str
              startPort:
                description: IPerf start port.
                type: int
              transferType:
                description: File transfer type (UPLOAD,
                  DOWNLOAD, BOTH).
                type: str
              udpBandwidth:
                description: IPerf UDP bandwidth.
                type: int
              uplinkTest:
                description: Uplink test.
                type: bool
              url:
                description: URL.
                type: str
              userName:
                description: User name.
                type: str
              userNamePrompt:
                description: User name prompt.
                type: str
            type: list
          name:
            description: Name of the test.
            type: str
        type: list
      thirdParty:
        description: Sensor Test Template Edit's thirdParty.
        suboptions:
          selected:
            description: True the SSID is third party.
            type: bool
        type: dict
      username:
        description: User name string for onboarding
          SSID.
        type: str
      validFrom:
        description: Valid From UTC timestamp.
        type: int
      validTo:
        description: Valid To UTC timestamp.
        type: int
      whiteList:
        description: Indication of being on allowed
          list.
        type: bool
      wlanId:
        description: WLAN ID.
        type: int
      wlc:
        description: WLC IP addres.
        type: str
    type: list
  startTime:
    description: Start time.
    type: int
  status:
    description: Status of the test (RUNNING, NOTRUNNING).
    type: str
  templateName:
    description: The test template name that is to be
      edited.
    type: str
  testScheduleMode:
    description: Test schedule mode (ONDEMAND, DEDICATED,
      SCHEDULED, CONTINUOUS, RUNNOW).
    type: str
  version:
    description: The sensor test template version (must
      be 2).
    type: int
  wlans:
    description: WLANs list.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      EditSensorTestTemplate
    description: Complete reference of the EditSensorTestTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!edit-sensor-test-template
notes:
  - SDK Method used are
    sensors.Sensors.edit_sensor_test_template,
  - Paths used are
    put /dna/intent/api/v1/AssuranceScheduleSensorTest,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sensor_test_template_edit:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    _id: string
    actionInProgress: string
    apCoverage:
      - bands: string
        numberOfApsToTest: 0
        rssiThreshold: 0
    connection: string
    encryptionMode: string
    frequency:
      unit: string
      value: 0
    lastModifiedTime: 0
    location: string
    locationInfoList:
      - allSensors: true
        customManagementVlan: true
        locationId: string
        locationType: string
        macAddressList:
          - string
        managementVlan: string
        siteHierarchy: string
    modelVersion: 0
    name: string
    numAssociatedSensor: 0
    numNeighborAPThreshold: 0
    profiles:
      - authProtocol: string
        authType: string
        certdownloadurl: string
        certfilename: string
        certpassphrase: string
        certstatus: string
        certxferprotocol: string
        deviceType: string
        eapMethod: string
        extWebAuth: true
        extWebAuthAccessUrl: string
        extWebAuthHtmlTag:
          - label: string
            tag: string
            value: string
        extWebAuthPortal: string
        extWebAuthVirtualIp: string
        locationVlanList:
          - locationId: string
            vlans:
              - string
        password: string
        passwordType: string
        profileName: string
        psk: string
        qosPolicy: string
        scep: true
        tests:
          - config:
              - direction: string
                domains:
                  - string
                downlinkTest: true
                endPort: 0
                exitCommand: string
                finalPrompt: string
                ndtServer: string
                ndtServerPath: string
                ndtServerPort: string
                numPackets: 0
                password: string
                passwordPrompt: string
                pathToDownload: string
                port: 0
                probeType: string
                protocol: string
                proxyPassword: string
                proxyPort: string
                proxyServer: string
                proxyUserName: string
                server: string
                servers:
                  - string
                sharedSecret: string
                startPort: 0
                transferType: string
                udpBandwidth: 0
                uplinkTest: true
                url: string
                userName: string
                userNamePrompt: string
            name: string
        username: string
        vlan: string
        whiteList: true
    radioAsSensorRemoved: true
    rssiThreshold: 0
    runNow: string
    scheduleInDays: 0
    sensors:
      - allSensorAddition: true
        assigned: true
        configUpdated: string
        hostName: string
        iPerfInfo: {}
        id: string
        ipAddress: string
        locationId: string
        macAddress: string
        markedForUninstall: true
        name: string
        runNow: string
        sensorType: string
        servicePolicy: string
        status: string
        switchMac: string
        switchSerialNumber: string
        switchUuid: string
        targetAPs:
          - string
        testMacAddresses: {}
        wiredApplicationMessage: string
        wiredApplicationStatus: string
        xorSensor: true
    showWlcUpgradeBanner: true
    siteHierarchy: string
    ssids:
      - authProtocol: string
        authType: string
        bands: string
        certdownloadurl: string
        certfilename: string
        certpassphrase: string
        certstatus: string
        certxferprotocol: string
        eapMethod: string
        extWebAuth: true
        extWebAuthAccessUrl: string
        extWebAuthHtmlTag:
          - label: string
            tag: string
            value: string
        extWebAuthPortal: string
        extWebAuthVirtualIp: string
        id: 0
        layer3webAuthEmailAddress: string
        layer3webAuthpassword: string
        layer3webAuthsecurity: string
        layer3webAuthuserName: string
        numAps: 0
        numSensors: 0
        password: string
        passwordType: string
        profileName: string
        proxyPassword: string
        proxyPort: string
        proxyServer: string
        proxyUserName: string
        psk: string
        qosPolicy: string
        scep: true
        ssid: string
        status: string
        tests:
          - config:
              - direction: string
                domains:
                  - string
                downlinkTest: true
                endPort: 0
                exitCommand: string
                finalPrompt: string
                ndtServer: string
                ndtServerPath: string
                ndtServerPort: string
                numPackets: 0
                password: string
                passwordPrompt: string
                pathToDownload: string
                port: 0
                probeType: string
                protocol: string
                proxyPassword: string
                proxyPort: string
                proxyServer: string
                proxyUserName: string
                server: string
                servers:
                  - string
                sharedSecret: string
                startPort: 0
                transferType: string
                udpBandwidth: 0
                uplinkTest: true
                url: string
                userName: string
                userNamePrompt: string
            name: string
        thirdParty:
          selected: true
        username: string
        validFrom: 0
        validTo: 0
        whiteList: true
        wlanId: 0
        wlc: string
    startTime: 0
    status: string
    templateName: string
    testScheduleMode: string
    version: 0
    wlans:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "name": "string",
        "_id": "string",
        "version": 0,
        "modelVersion": 0,
        "startTime": 0,
        "lastModifiedTime": 0,
        "numAssociatedSensor": 0,
        "location": "string",
        "siteHierarchy": "string",
        "status": "string",
        "connection": "string",
        "actionInProgress": "string",
        "frequency": {
          "value": 0,
          "unit": "string"
        },
        "rssiThreshold": 0,
        "numNeighborAPThreshold": 0,
        "scheduleInDays": 0,
        "wlans": [
          "string"
        ],
        "ssids": [
          {
            "bands": "string",
            "ssid": "string",
            "profileName": "string",
            "numAps": 0,
            "numSensors": 0,
            "layer3webAuthsecurity": "string",
            "layer3webAuthuserName": "string",
            "layer3webAuthpassword": "string",
            "layer3webAuthEmailAddress": "string",
            "thirdParty": {
              "selected": true
            },
            "id": 0,
            "wlanId": 0,
            "wlc": "string",
            "validFrom": 0,
            "validTo": 0,
            "status": "string",
            "proxyServer": "string",
            "proxyPort": "string",
            "proxyUserName": "string",
            "proxyPassword": "string",
            "authType": "string",
            "psk": "string",
            "username": "string",
            "password": "string",
            "passwordType": "string",
            "eapMethod": "string",
            "scep": true,
            "authProtocol": "string",
            "certfilename": "string",
            "certxferprotocol": "string",
            "certstatus": "string",
            "certpassphrase": "string",
            "certdownloadurl": "string",
            "extWebAuthVirtualIp": "string",
            "extWebAuth": true,
            "whiteList": true,
            "extWebAuthPortal": "string",
            "extWebAuthAccessUrl": "string",
            "extWebAuthHtmlTag": [
              {
                "label": "string",
                "tag": "string",
                "value": "string"
              }
            ],
            "qosPolicy": "string",
            "tests": [
              {
                "name": "string",
                "config": [
                  {
                    "domains": [
                      "string"
                    ],
                    "server": "string",
                    "userName": "string",
                    "password": "string",
                    "url": "string",
                    "port": 0,
                    "protocol": "string",
                    "servers": [
                      "string"
                    ],
                    "direction": "string",
                    "startPort": 0,
                    "endPort": 0,
                    "udpBandwidth": 0,
                    "probeType": "string",
                    "numPackets": 0,
                    "pathToDownload": "string",
                    "transferType": "string",
                    "sharedSecret": "string",
                    "ndtServer": "string",
                    "ndtServerPort": "string",
                    "ndtServerPath": "string",
                    "uplinkTest": true,
                    "downlinkTest": true,
                    "proxyServer": "string",
                    "proxyPort": "string",
                    "proxyUserName": "string",
                    "proxyPassword": "string",
                    "userNamePrompt": "string",
                    "passwordPrompt": "string",
                    "exitCommand": "string",
                    "finalPrompt": "string"
                  }
                ]
              }
            ]
          }
        ],
        "profiles": [
          {
            "authType": "string",
            "psk": "string",
            "username": "string",
            "password": "string",
            "passwordType": "string",
            "eapMethod": "string",
            "scep": true,
            "authProtocol": "string",
            "certfilename": "string",
            "certxferprotocol": "string",
            "certstatus": "string",
            "certpassphrase": "string",
            "certdownloadurl": "string",
            "extWebAuthVirtualIp": "string",
            "extWebAuth": true,
            "whiteList": true,
            "extWebAuthPortal": "string",
            "extWebAuthAccessUrl": "string",
            "extWebAuthHtmlTag": [
              {
                "label": "string",
                "tag": "string",
                "value": "string"
              }
            ],
            "qosPolicy": "string",
            "tests": [
              {
                "name": "string",
                "config": [
                  {
                    "domains": [
                      "string"
                    ],
                    "server": "string",
                    "userName": "string",
                    "password": "string",
                    "url": "string",
                    "port": 0,
                    "protocol": "string",
                    "servers": [
                      "string"
                    ],
                    "direction": "string",
                    "startPort": 0,
                    "endPort": 0,
                    "udpBandwidth": 0,
                    "probeType": "string",
                    "numPackets": 0,
                    "pathToDownload": "string",
                    "transferType": "string",
                    "sharedSecret": "string",
                    "ndtServer": "string",
                    "ndtServerPort": "string",
                    "ndtServerPath": "string",
                    "uplinkTest": true,
                    "downlinkTest": true,
                    "proxyServer": "string",
                    "proxyPort": "string",
                    "proxyUserName": "string",
                    "proxyPassword": "string",
                    "userNamePrompt": "string",
                    "passwordPrompt": "string",
                    "exitCommand": "string",
                    "finalPrompt": "string"
                  }
                ]
              }
            ],
            "profileName": "string",
            "deviceType": "string",
            "vlan": "string",
            "locationVlanList": [
              {
                "locationId": "string",
                "vlans": [
                  "string"
                ]
              }
            ]
          }
        ],
        "testScheduleMode": "string",
        "showWlcUpgradeBanner": true,
        "radioAsSensorRemoved": true,
        "encryptionMode": "string",
        "runNow": "string",
        "locationInfoList": [
          {
            "locationId": "string",
            "locationType": "string",
            "allSensors": true,
            "siteHierarchy": "string",
            "macAddressList": [
              "string"
            ],
            "managementVlan": "string",
            "customManagementVlan": true
          }
        ],
        "sensors": [
          {
            "name": "string",
            "macAddress": "string",
            "switchMac": "string",
            "switchUuid": "string",
            "switchSerialNumber": "string",
            "markedForUninstall": true,
            "ipAddress": "string",
            "hostName": "string",
            "wiredApplicationStatus": "string",
            "wiredApplicationMessage": "string",
            "assigned": true,
            "status": "string",
            "xorSensor": true,
            "targetAPs": [
              "string"
            ],
            "runNow": "string",
            "locationId": "string",
            "allSensorAddition": true,
            "configUpdated": "string",
            "sensorType": "string",
            "testMacAddresses": {},
            "id": "string",
            "servicePolicy": "string",
            "iPerfInfo": {}
          }
        ],
        "apCoverage": [
          {
            "bands": "string",
            "numberOfApsToTest": 0,
            "rssiThreshold": 0
          }
        ]
      }
    }
"""
