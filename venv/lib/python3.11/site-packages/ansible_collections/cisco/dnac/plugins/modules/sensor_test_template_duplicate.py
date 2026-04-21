#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sensor_test_template_duplicate
short_description: Resource module for Sensor Test Template
  Duplicate
description:
  - Manage operation update of the resource Sensor Test
    Template Duplicate.
  - Intent API to duplicate an existing SENSOR test
    template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  newTemplateName:
    description: Destination test template name.
    type: str
  templateName:
    description: Source test template name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      DuplicateSensorTestTemplate
    description: Complete reference of the DuplicateSensorTestTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!duplicate-sensor-test-template
notes:
  - SDK Method used are
    sensors.Sensors.duplicate_sensor_test_template,
  - Paths used are
    put /dna/intent/api/v1/sensorTestTemplate,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sensor_test_template_duplicate:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    newTemplateName: string
    templateName: string
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
