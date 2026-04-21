#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_id_config_features_intended_layer2_feature_info
short_description: Information module for Wired Network
  Devices Id Config Features Intended Layer2 Feature
description:
  - Get Wired Network Devices Id Config Features Intended
    Layer2 Feature by id. - > This API returns the configurations
    for an intended layer 2 feature on a wired device.
    Even after the intended configurations are deployed
    using the API /dna/intent/api/v1/networkDevices/{id}/configFeatures/intended/deploy,
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
      - Feature path parameter. The name of the feature
        to be retrieved.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired GetConfigurationsForAnIntendedLayer2FeatureOnAWiredDevice
    description: Complete reference of the GetConfigurationsForAnIntendedLayer2FeatureOnAWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-configurations-for-an-intended-layer-2-feature-on-a-wired-device
notes:
  - SDK Method used are
    wired.Wired.get_configurations_for_an_intended_layer2_feature_on_a_wired_device,
  - Paths used are
    get /dna/intent/api/v1/wired/networkDevices/{id}/configFeatures/intended/layer2/{feature},
"""

EXAMPLES = r"""
---
- name: Get Wired Network Devices Id Config Features
    Intended Layer2 Feature by id
  cisco.dnac.wired_network_devices_id_config_features_intended_layer2_feature_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    feature: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
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
      "dhcpSnoopingInterfaceConfig": {
        "items": [
          [
            {
              "configType": "string",
              "interfaceName": "string",
              "isTrustedInterface": true,
              "messageRateLimit": 0
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
                "configType": "string",
                "agentUrl": "string",
                "timeout": 0,
                "writeDelay": 0
              },
              "isGleaningEnabled": true,
              "proxyBridgeVlans": "string",
              "dhcpSnoopingVlans": "string"
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
              }
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
              "isSuppressListenerMessagesEnabled": true,
              "isQuerierEnabled": true,
              "querierAddress": "string",
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
                    "querierAddress": "string",
                    "querierQueryInterval": 0,
                    "querierVersion": "string",
                    "mldSnoopingVlanMrouters": {
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
      "igmpSnoopingGlobalConfig": {
        "items": [
          [
            {
              "configType": "string",
              "isIgmpSnoopingEnabled": true,
              "isQuerierEnabled": true,
              "querierAddress": "string",
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
                    "querierAddress": "string",
                    "querierQueryInterval": 0,
                    "querierVersion": "string",
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
                    "timers": {
                      "configType": "string",
                      "forwardDelay": 0,
                      "helloInterval": 0,
                      "maxAge": 0,
                      "isStpEnabled": true
                    }
                  }
                ]
              }
            }
          ]
        ]
      },
      "stpInterfaceConfig": {
        "items": [
          {
            "configType": "string",
            "interfaceName": "string",
            "guardMode": "string",
            "bpduFilter": "string",
            "bpduGuard": "string",
            "pathCost": 0,
            "portFastMode": "string",
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
      "vtpGlobalConfig": {
        "items": [
          [
            {
              "configType": "string",
              "mode": "string",
              "version": "string",
              "domainName": "string",
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
      "portChannelConfig": {
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
                    "AnyOf": {
                      "EtherchannelConfig": {
                        "configType": "string",
                        "name": "string",
                        "minLinks": 0,
                        "memberPorts": {
                          "configType": "string",
                          "items": [
                            {
                              "configType": "string",
                              "interfaceName": "string",
                              "mode": "string"
                            }
                          ]
                        }
                      },
                      "LacpPortchannelConfig": {
                        "configType": "string",
                        "name": "string",
                        "minLinks": 0,
                        "memberPorts": {
                          "configType": "string",
                          "items": [
                            {
                              "configType": "string",
                              "interfaceName": "string",
                              "mode": "string",
                              "portPriority": 0,
                              "rate": 0
                            }
                          ]
                        }
                      },
                      "PagpPortchannelConfig": {
                        "configType": "string",
                        "name": "string",
                        "minLinks": 0,
                        "memberPorts": {
                          "configType": "string",
                          "items": [
                            {
                              "configType": "string",
                              "interfaceName": "string",
                              "mode": "string",
                              "portPriority": 0,
                              "learnMethod": "string"
                            }
                          ]
                        }
                      }
                    }
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
              "voiceVlan": 0,
              "adminStatus": "string",
              "trunkAllowedVlans": "string",
              "nativeVlan": 0
            }
          ]
        ]
      }
    }
"""
