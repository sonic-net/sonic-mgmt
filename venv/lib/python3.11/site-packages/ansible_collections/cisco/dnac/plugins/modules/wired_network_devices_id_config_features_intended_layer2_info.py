#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_id_config_features_intended_layer2_info
short_description: Information module for Wired Network
  Devices Id Config Features Intended Layer2
description:
  - Get all Wired Network Devices Id Config Features
    Intended Layer2. - > This API returns the configurations
    for the intended layer 2 features on a wired device.
    Even after the intended configurations are deployed
    using the API /intent/api/v1/networkDevices/{id}/configFeatures/intended/deploy,
    they continue to be a part of the intended features
    on the device.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Network device ID of the
        wired device to configure.
    type: str
  feature:
    description:
      - >
        Feature query parameter. Name of the feature
        to configure. The API /data/intent/api/wired/networkDevices/{id}/configFeatures/supported/layer2
        can be used to get the list of features supported
        on a device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired GetConfigurationsForIntendedLayer2FeaturesOnAWiredDevice
    description: Complete reference of the GetConfigurationsForIntendedLayer2FeaturesOnAWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-configurations-for-intended-layer-2-features-on-a-wired-device
notes:
  - SDK Method used are
    wired.Wired.get_configurations_for_intended_layer2_features_on_a_wired_device,
  - Paths used are
    get /dna/intent/api/v1/intent/api/v1/wired/networkDevices/{id}/configFeatures/intended/layer2,
"""

EXAMPLES = r"""
---
- name: Get all Wired Network Devices Id Config Features
    Intended Layer2
  cisco.dnac.wired_network_devices_id_config_features_intended_layer2_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    feature: string
    id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "features": {
          "cdpGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "timer": 0,
                  "isCdpEnabled": true,
                  "isLogDuplexMismatchEnabled": true,
                  "isAdvertiseV2Enabled": true,
                  "holdTime": 0
                }
              ]
            ]
          },
          "cdpInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "isCdpEnabled": true,
                  "isLogDuplexMismatchEnabled": true
                }
              ]
            ]
          },
          "dhcpSnoopingGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "isDhcpSnoopingEnabled": true,
                  "databaseAgent": {
                    "agentUrl": "string",
                    "timeout": 0,
                    "writeDelay": 0
                  },
                  "isGleaningEnabled": true,
                  "proxyBridgeVlans": "string"
                }
              ]
            ]
          },
          "dhcpSnoopingInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "isTrustedInterface": true,
                  "interfaceName": "string"
                }
              ]
            ]
          },
          "dot1xGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "authenticationConfigMode": "string",
                  "isDot1xEnabled": true
                }
              ]
            ]
          },
          "dot1xInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "authenticationOrder": {
                    "configType": "string",
                    "items": [
                      "string"
                    ]
                  },
                  "priority": {
                    "configType": "string",
                    "items": [
                      "string"
                    ]
                  },
                  "inactivityTimer": 0,
                  "authenticationMode": "string",
                  "isReauthEnabled": true,
                  "maxReauthRequests": 0,
                  "isInactivityTimerFromServerEnabled": true,
                  "isReauthTimerFromServerEnabled": true,
                  "reauthTimer": 0,
                  "txPeriod": 0
                }
              ]
            ]
          },
          "igmpSnoopingGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "isIgmpSnoopingEnabled": true,
                  "isQuerierEnabled": true,
                  "querierQueryInterval": 0,
                  "querierVersion": "string",
                  "igmpSnoopingVlanSettings": {
                    "configType": "string",
                    "items": [
                      {
                        "configType": "string",
                        "vlanId": 0,
                        "isIgmpSnoopingEnabled": true,
                        "isImmediateLeaveEnabled": true,
                        "isQuerierEnabled": true,
                        "querierQueryInterval": 0,
                        "igmpSnoopingVlanMrouters": {
                          "configType": "string",
                          "items": [
                            {
                              "configType": "string",
                              "interfaceName": "string"
                            }
                          ]
                        }
                      }
                    ]
                  }
                }
              ]
            ]
          },
          "lldpGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "timer": 0,
                  "isLldpEnabled": true,
                  "reinitializationDelay": 0,
                  "holdTime": 0
                }
              ]
            ]
          },
          "lldpInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "adminStatus": "string"
                }
              ]
            ]
          },
          "mabInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "isMabEnabled": true
                }
              ]
            ]
          },
          "mldSnoopingGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "isMldSnoopingEnabled": true,
                  "isQuerierEnabled": true,
                  "querierQueryInterval": 0,
                  "querierVersion": "string",
                  "mldSnoopingVlanSettings": {
                    "configType": "string",
                    "items": [
                      {
                        "configType": "string",
                        "vlanId": 0,
                        "isMldSnoopingEnabled": true,
                        "isImmediateLeaveEnabled": true,
                        "isQuerierEnabled": true,
                        "querierQueryInterval": 0,
                        "mldSnoopingVlanMrouters": {
                          "configType": "string",
                          "items": [
                            {}
                          ]
                        }
                      }
                    ]
                  }
                }
              ]
            ]
          },
          "portchannelConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "isAutoEnabled": true,
                  "loadBalancingMethod": "string",
                  "lacpSystemPriority": 0,
                  "portchannels": {
                    "configType": "string",
                    "items": [
                      {
                        "configType": "string",
                        "name": "string",
                        "isLayer2": true,
                        "memberPorts": {
                          "configType": "string",
                          "items": [
                            {}
                          ]
                        }
                      }
                    ]
                  }
                }
              ]
            ]
          },
          "stpGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "stpMode": "string",
                  "isBackboneFastEnabled": true,
                  "isEtherChannelGuardEnabled": true,
                  "isExtendedSystemIdEnabled": true,
                  "isLoggingEnabled": true,
                  "isLoopGuardEnabled": true,
                  "portFastMode": "string",
                  "isBpduFilterEnabled": true,
                  "isBpduGuardEnabled": true,
                  "isUplinkFastEnabled": true,
                  "transmitHoldCount": 0,
                  "uplinkFastMaxUpdateRate": 0,
                  "stpInstances": {
                    "configType": "string",
                    "items": [
                      {
                        "configType": "string",
                        "vlanId": 0,
                        "priority": 0,
                        "isStpEnabled": true
                      }
                    ]
                  }
                }
              ]
            ]
          },
          "stpInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "guardMode": "string",
                  "bpduFilter": "string",
                  "bpduGuard": "string",
                  "pathCost": 0,
                  "priority": 0,
                  "portVlanCostSettings": {
                    "configType": "string",
                    "items": [
                      {
                        "configType": "string",
                        "cost": 0,
                        "vlans": "string"
                      }
                    ]
                  },
                  "portVlanPrioritySettings": {
                    "configType": "string",
                    "items": [
                      {
                        "configType": "string",
                        "priority": 0,
                        "vlans": "string"
                      }
                    ]
                  }
                }
              ]
            ]
          },
          "switchportInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "description": "string",
                  "mode": "string",
                  "accessVlan": 0,
                  "adminStatus": "string",
                  "trunkAllowedVlans": "string",
                  "nativeVlan": 0
                }
              ]
            ]
          },
          "trunkInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "isProtected": true,
                  "isDtpNegotiationEnabled": true,
                  "pruneEligibleVlans": "string"
                }
              ]
            ]
          },
          "vlanConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "vlanId": 0,
                  "name": "string",
                  "isVlanEnabled": true
                }
              ]
            ]
          },
          "vtpGlobalConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "mode": "string",
                  "version": "string",
                  "isPruningEnabled": true,
                  "configurationFileName": "string",
                  "sourceInterface": "string"
                }
              ]
            ]
          },
          "vtpInterfaceConfig": {
            "items": [
              [
                {
                  "configType": "string",
                  "interfaceName": "string",
                  "isVtpEnabled": true
                }
              ]
            ]
          }
        }
      },
      "version": "string"
    }
"""
