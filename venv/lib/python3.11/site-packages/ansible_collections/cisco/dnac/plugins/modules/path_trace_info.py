#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: path_trace_info
short_description: Information module for Path Trace
description:
  - Get all Path Trace.
  - Get Path Trace by id.
  - Returns a summary of all flow analyses stored. Results
    can be filtered by specified parameters.
  - Returns result of a previously requested flow analysis
    by its Flow Analysis id.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  periodicRefresh:
    description:
      - PeriodicRefresh query parameter. Is analysis
        periodically refreshed?.
    type: bool
  sourceIP:
    description:
      - SourceIP query parameter. Source IP address.
    type: str
  destIP:
    description:
      - DestIP query parameter. Destination IP address.
    type: str
  sourcePort:
    description:
      - SourcePort query parameter. Source port.
    type: float
  destPort:
    description:
      - DestPort query parameter. Destination port.
    type: float
  gtCreateTime:
    description:
      - GtCreateTime query parameter. Analyses requested
        after this time.
    type: float
  ltCreateTime:
    description:
      - LtCreateTime query parameter. Analyses requested
        before this time.
    type: float
  protocol:
    description:
      - Protocol query parameter.
    type: str
  status:
    description:
      - Status query parameter.
    type: str
  taskId:
    description:
      - TaskId query parameter. Task ID.
    type: str
  lastUpdateTime:
    description:
      - LastUpdateTime query parameter. Last update
        time.
    type: float
  limit:
    description:
      - Limit query parameter. Number of resources returned.
    type: float
  offset:
    description:
      - Offset query parameter. Start index of resources
        returned (1-based).
    type: float
  order:
    description:
      - Order query parameter. Order by this field.
    type: str
  sortBy:
    description:
      - SortBy query parameter. Sort by this field.
    type: str
  flowAnalysisId:
    description:
      - FlowAnalysisId path parameter. Flow analysis
        request id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Path Trace
      RetrievesAllPreviousPathtracesSummary
    description: Complete reference of the RetrievesAllPreviousPathtracesSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-all-previous-pathtraces-summary
  - name: Cisco DNA Center documentation for Path Trace
      RetrievesPreviousPathtrace
    description: Complete reference of the RetrievesPreviousPathtrace
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-previous-pathtrace
notes:
  - SDK Method used are
    path_trace.PathTrace.retrieves_all_previous_pathtraces_summary,
    path_trace.PathTrace.retrieves_previous_pathtrace,
  - Paths used are
    get /dna/intent/api/v1/flow-analysis,
    get /dna/intent/api/v1/flow-analysis/{flowAnalysisId},
"""

EXAMPLES = r"""
---
- name: Get all Path Trace
  cisco.dnac.path_trace_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    periodicRefresh: true
    sourceIP: string
    destIP: string
    sourcePort: 0
    destPort: 0
    gtCreateTime: 0
    ltCreateTime: 0
    protocol: string
    status: string
    taskId: string
    lastUpdateTime: 0
    limit: 0
    offset: 0
    order: string
    sortBy: string
  register: result
- name: Get Path Trace by id
  cisco.dnac.path_trace_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    flowAnalysisId: string
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
        "detailedStatus": {
          "aclTraceCalculation": "string",
          "aclTraceCalculationFailureReason": "string"
        },
        "lastUpdate": "string",
        "networkElements": [
          {
            "accuracyList": [
              {
                "percent": 0,
                "reason": "string"
              }
            ],
            "detailedStatus": {
              "aclTraceCalculation": "string",
              "aclTraceCalculationFailureReason": "string"
            },
            "deviceStatistics": {
              "cpuStatistics": {
                "fiveMinUsageInPercentage": 0,
                "fiveSecsUsageInPercentage": 0,
                "oneMinUsageInPercentage": 0,
                "refreshedAt": 0
              },
              "memoryStatistics": {
                "memoryUsage": 0,
                "refreshedAt": 0,
                "totalMemory": 0
              }
            },
            "deviceStatsCollection": "string",
            "deviceStatsCollectionFailureReason": "string",
            "egressPhysicalInterface": {
              "aclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "id": "string",
              "interfaceStatistics": {
                "adminStatus": "string",
                "inputPackets": 0,
                "inputQueueCount": 0,
                "inputQueueDrops": 0,
                "inputQueueFlushes": 0,
                "inputQueueMaxDepth": 0,
                "inputRatebps": 0,
                "operationalStatus": "string",
                "outputDrop": 0,
                "outputPackets": 0,
                "outputQueueCount": 0,
                "outputQueueDepth": 0,
                "outputRatebps": 0,
                "refreshedAt": 0
              },
              "interfaceStatsCollection": "string",
              "interfaceStatsCollectionFailureReason": "string",
              "name": "string",
              "pathOverlayInfo": [
                {
                  "controlPlane": "string",
                  "dataPacketEncapsulation": "string",
                  "destIp": "string",
                  "destPort": "string",
                  "protocol": "string",
                  "sourceIp": "string",
                  "sourcePort": "string",
                  "vxlanInfo": {
                    "dscp": "string",
                    "vnid": "string"
                  }
                }
              ],
              "qosStatistics": [
                {
                  "classMapName": "string",
                  "dropRate": 0,
                  "numBytes": 0,
                  "numPackets": 0,
                  "offeredRate": 0,
                  "queueBandwidthbps": "string",
                  "queueDepth": 0,
                  "queueNoBufferDrops": 0,
                  "queueTotalDrops": 0,
                  "refreshedAt": 0
                }
              ],
              "qosStatsCollection": "string",
              "qosStatsCollectionFailureReason": "string",
              "usedVlan": "string",
              "vrfName": "string"
            },
            "egressVirtualInterface": {
              "aclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "id": "string",
              "interfaceStatistics": {
                "adminStatus": "string",
                "inputPackets": 0,
                "inputQueueCount": 0,
                "inputQueueDrops": 0,
                "inputQueueFlushes": 0,
                "inputQueueMaxDepth": 0,
                "inputRatebps": 0,
                "operationalStatus": "string",
                "outputDrop": 0,
                "outputPackets": 0,
                "outputQueueCount": 0,
                "outputQueueDepth": 0,
                "outputRatebps": 0,
                "refreshedAt": 0
              },
              "interfaceStatsCollection": "string",
              "interfaceStatsCollectionFailureReason": "string",
              "name": "string",
              "pathOverlayInfo": [
                {
                  "controlPlane": "string",
                  "dataPacketEncapsulation": "string",
                  "destIp": "string",
                  "destPort": "string",
                  "protocol": "string",
                  "sourceIp": "string",
                  "sourcePort": "string",
                  "vxlanInfo": {
                    "dscp": "string",
                    "vnid": "string"
                  }
                }
              ],
              "qosStatistics": [
                {
                  "classMapName": "string",
                  "dropRate": 0,
                  "numBytes": 0,
                  "numPackets": 0,
                  "offeredRate": 0,
                  "queueBandwidthbps": "string",
                  "queueDepth": 0,
                  "queueNoBufferDrops": 0,
                  "queueTotalDrops": 0,
                  "refreshedAt": 0
                }
              ],
              "qosStatsCollection": "string",
              "qosStatsCollectionFailureReason": "string",
              "usedVlan": "string",
              "vrfName": "string"
            },
            "flexConnect": {
              "authentication": "string",
              "dataSwitching": "string",
              "egressAclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "ingressAclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "wirelessLanControllerId": "string",
              "wirelessLanControllerName": "string"
            },
            "id": "string",
            "ingressPhysicalInterface": {
              "aclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "id": "string",
              "interfaceStatistics": {
                "adminStatus": "string",
                "inputPackets": 0,
                "inputQueueCount": 0,
                "inputQueueDrops": 0,
                "inputQueueFlushes": 0,
                "inputQueueMaxDepth": 0,
                "inputRatebps": 0,
                "operationalStatus": "string",
                "outputDrop": 0,
                "outputPackets": 0,
                "outputQueueCount": 0,
                "outputQueueDepth": 0,
                "outputRatebps": 0,
                "refreshedAt": 0
              },
              "interfaceStatsCollection": "string",
              "interfaceStatsCollectionFailureReason": "string",
              "name": "string",
              "pathOverlayInfo": [
                {
                  "controlPlane": "string",
                  "dataPacketEncapsulation": "string",
                  "destIp": "string",
                  "destPort": "string",
                  "protocol": "string",
                  "sourceIp": "string",
                  "sourcePort": "string",
                  "vxlanInfo": {
                    "dscp": "string",
                    "vnid": "string"
                  }
                }
              ],
              "qosStatistics": [
                {
                  "classMapName": "string",
                  "dropRate": 0,
                  "numBytes": 0,
                  "numPackets": 0,
                  "offeredRate": 0,
                  "queueBandwidthbps": "string",
                  "queueDepth": 0,
                  "queueNoBufferDrops": 0,
                  "queueTotalDrops": 0,
                  "refreshedAt": 0
                }
              ],
              "qosStatsCollection": "string",
              "qosStatsCollectionFailureReason": "string",
              "usedVlan": "string",
              "vrfName": "string"
            },
            "ingressVirtualInterface": {
              "aclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "id": "string",
              "interfaceStatistics": {
                "adminStatus": "string",
                "inputPackets": 0,
                "inputQueueCount": 0,
                "inputQueueDrops": 0,
                "inputQueueFlushes": 0,
                "inputQueueMaxDepth": 0,
                "inputRatebps": 0,
                "operationalStatus": "string",
                "outputDrop": 0,
                "outputPackets": 0,
                "outputQueueCount": 0,
                "outputQueueDepth": 0,
                "outputRatebps": 0,
                "refreshedAt": 0
              },
              "interfaceStatsCollection": "string",
              "interfaceStatsCollectionFailureReason": "string",
              "name": "string",
              "pathOverlayInfo": [
                {
                  "controlPlane": "string",
                  "dataPacketEncapsulation": "string",
                  "destIp": "string",
                  "destPort": "string",
                  "protocol": "string",
                  "sourceIp": "string",
                  "sourcePort": "string",
                  "vxlanInfo": {
                    "dscp": "string",
                    "vnid": "string"
                  }
                }
              ],
              "qosStatistics": [
                {
                  "classMapName": "string",
                  "dropRate": 0,
                  "numBytes": 0,
                  "numPackets": 0,
                  "offeredRate": 0,
                  "queueBandwidthbps": "string",
                  "queueDepth": 0,
                  "queueNoBufferDrops": 0,
                  "queueTotalDrops": 0,
                  "refreshedAt": 0
                }
              ],
              "qosStatsCollection": "string",
              "qosStatsCollectionFailureReason": "string",
              "usedVlan": "string",
              "vrfName": "string"
            },
            "ip": "string",
            "linkInformationSource": "string",
            "name": "string",
            "perfMonCollection": "string",
            "perfMonCollectionFailureReason": "string",
            "perfMonStatistics": [
              {
                "byteRate": 0,
                "destIpAddress": "string",
                "destPort": "string",
                "inputInterface": "string",
                "ipv4DSCP": "string",
                "ipv4TTL": 0,
                "outputInterface": "string",
                "packetBytes": 0,
                "packetCount": 0,
                "packetLoss": 0,
                "packetLossPercentage": 0,
                "protocol": "string",
                "refreshedAt": 0,
                "rtpJitterMax": 0,
                "rtpJitterMean": 0,
                "rtpJitterMin": 0,
                "sourceIpAddress": "string",
                "sourcePort": "string"
              }
            ],
            "role": "string",
            "ssid": "string",
            "tunnels": [
              "string"
            ],
            "type": "string",
            "wlanId": "string"
          }
        ],
        "networkElementsInfo": [
          {
            "accuracyList": [
              {
                "percent": 0,
                "reason": "string"
              }
            ],
            "detailedStatus": {
              "aclTraceCalculation": "string",
              "aclTraceCalculationFailureReason": "string"
            },
            "deviceStatistics": {
              "cpuStatistics": {
                "fiveMinUsageInPercentage": 0,
                "fiveSecsUsageInPercentage": 0,
                "oneMinUsageInPercentage": 0,
                "refreshedAt": 0
              },
              "memoryStatistics": {
                "memoryUsage": 0,
                "refreshedAt": 0,
                "totalMemory": 0
              }
            },
            "deviceStatsCollection": "string",
            "deviceStatsCollectionFailureReason": "string",
            "egressInterface": {
              "physicalInterface": {
                "aclAnalysis": {
                  "aclName": "string",
                  "matchingAces": [
                    {
                      "ace": "string",
                      "matchingPorts": [
                        {
                          "ports": [
                            {
                              "destPorts": [
                                "string"
                              ],
                              "sourcePorts": [
                                "string"
                              ]
                            }
                          ],
                          "protocol": "string"
                        }
                      ],
                      "result": "string"
                    }
                  ],
                  "result": "string"
                },
                "id": "string",
                "interfaceStatistics": {
                  "adminStatus": "string",
                  "inputPackets": 0,
                  "inputQueueCount": 0,
                  "inputQueueDrops": 0,
                  "inputQueueFlushes": 0,
                  "inputQueueMaxDepth": 0,
                  "inputRatebps": 0,
                  "operationalStatus": "string",
                  "outputDrop": 0,
                  "outputPackets": 0,
                  "outputQueueCount": 0,
                  "outputQueueDepth": 0,
                  "outputRatebps": 0,
                  "refreshedAt": 0
                },
                "interfaceStatsCollection": "string",
                "interfaceStatsCollectionFailureReason": "string",
                "name": "string",
                "pathOverlayInfo": [
                  {
                    "controlPlane": "string",
                    "dataPacketEncapsulation": "string",
                    "destIp": "string",
                    "destPort": "string",
                    "protocol": "string",
                    "sourceIp": "string",
                    "sourcePort": "string",
                    "vxlanInfo": {
                      "dscp": "string",
                      "vnid": "string"
                    }
                  }
                ],
                "qosStatistics": [
                  {
                    "classMapName": "string",
                    "dropRate": 0,
                    "numBytes": 0,
                    "numPackets": 0,
                    "offeredRate": 0,
                    "queueBandwidthbps": "string",
                    "queueDepth": 0,
                    "queueNoBufferDrops": 0,
                    "queueTotalDrops": 0,
                    "refreshedAt": 0
                  }
                ],
                "qosStatsCollection": "string",
                "qosStatsCollectionFailureReason": "string",
                "usedVlan": "string",
                "vrfName": "string"
              },
              "virtualInterface": [
                {
                  "aclAnalysis": {
                    "aclName": "string",
                    "matchingAces": [
                      {
                        "ace": "string",
                        "matchingPorts": [
                          {
                            "ports": [
                              {
                                "destPorts": [
                                  "string"
                                ],
                                "sourcePorts": [
                                  "string"
                                ]
                              }
                            ],
                            "protocol": "string"
                          }
                        ],
                        "result": "string"
                      }
                    ],
                    "result": "string"
                  },
                  "id": "string",
                  "interfaceStatistics": {
                    "adminStatus": "string",
                    "inputPackets": 0,
                    "inputQueueCount": 0,
                    "inputQueueDrops": 0,
                    "inputQueueFlushes": 0,
                    "inputQueueMaxDepth": 0,
                    "inputRatebps": 0,
                    "operationalStatus": "string",
                    "outputDrop": 0,
                    "outputPackets": 0,
                    "outputQueueCount": 0,
                    "outputQueueDepth": 0,
                    "outputRatebps": 0,
                    "refreshedAt": 0
                  },
                  "interfaceStatsCollection": "string",
                  "interfaceStatsCollectionFailureReason": "string",
                  "name": "string",
                  "pathOverlayInfo": [
                    {
                      "controlPlane": "string",
                      "dataPacketEncapsulation": "string",
                      "destIp": "string",
                      "destPort": "string",
                      "protocol": "string",
                      "sourceIp": "string",
                      "sourcePort": "string",
                      "vxlanInfo": {
                        "dscp": "string",
                        "vnid": "string"
                      }
                    }
                  ],
                  "qosStatistics": [
                    {
                      "classMapName": "string",
                      "dropRate": 0,
                      "numBytes": 0,
                      "numPackets": 0,
                      "offeredRate": 0,
                      "queueBandwidthbps": "string",
                      "queueDepth": 0,
                      "queueNoBufferDrops": 0,
                      "queueTotalDrops": 0,
                      "refreshedAt": 0
                    }
                  ],
                  "qosStatsCollection": "string",
                  "qosStatsCollectionFailureReason": "string",
                  "usedVlan": "string",
                  "vrfName": "string"
                }
              ]
            },
            "flexConnect": {
              "authentication": "string",
              "dataSwitching": "string",
              "egressAclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "ingressAclAnalysis": {
                "aclName": "string",
                "matchingAces": [
                  {
                    "ace": "string",
                    "matchingPorts": [
                      {
                        "ports": [
                          {
                            "destPorts": [
                              "string"
                            ],
                            "sourcePorts": [
                              "string"
                            ]
                          }
                        ],
                        "protocol": "string"
                      }
                    ],
                    "result": "string"
                  }
                ],
                "result": "string"
              },
              "wirelessLanControllerId": "string",
              "wirelessLanControllerName": "string"
            },
            "id": "string",
            "ingressInterface": {
              "physicalInterface": {
                "aclAnalysis": {
                  "aclName": "string",
                  "matchingAces": [
                    {
                      "ace": "string",
                      "matchingPorts": [
                        {
                          "ports": [
                            {
                              "destPorts": [
                                "string"
                              ],
                              "sourcePorts": [
                                "string"
                              ]
                            }
                          ],
                          "protocol": "string"
                        }
                      ],
                      "result": "string"
                    }
                  ],
                  "result": "string"
                },
                "id": "string",
                "interfaceStatistics": {
                  "adminStatus": "string",
                  "inputPackets": 0,
                  "inputQueueCount": 0,
                  "inputQueueDrops": 0,
                  "inputQueueFlushes": 0,
                  "inputQueueMaxDepth": 0,
                  "inputRatebps": 0,
                  "operationalStatus": "string",
                  "outputDrop": 0,
                  "outputPackets": 0,
                  "outputQueueCount": 0,
                  "outputQueueDepth": 0,
                  "outputRatebps": 0,
                  "refreshedAt": 0
                },
                "interfaceStatsCollection": "string",
                "interfaceStatsCollectionFailureReason": "string",
                "name": "string",
                "pathOverlayInfo": [
                  {
                    "controlPlane": "string",
                    "dataPacketEncapsulation": "string",
                    "destIp": "string",
                    "destPort": "string",
                    "protocol": "string",
                    "sourceIp": "string",
                    "sourcePort": "string",
                    "vxlanInfo": {
                      "dscp": "string",
                      "vnid": "string"
                    }
                  }
                ],
                "qosStatistics": [
                  {
                    "classMapName": "string",
                    "dropRate": 0,
                    "numBytes": 0,
                    "numPackets": 0,
                    "offeredRate": 0,
                    "queueBandwidthbps": "string",
                    "queueDepth": 0,
                    "queueNoBufferDrops": 0,
                    "queueTotalDrops": 0,
                    "refreshedAt": 0
                  }
                ],
                "qosStatsCollection": "string",
                "qosStatsCollectionFailureReason": "string",
                "usedVlan": "string",
                "vrfName": "string"
              },
              "virtualInterface": [
                {
                  "aclAnalysis": {
                    "aclName": "string",
                    "matchingAces": [
                      {
                        "ace": "string",
                        "matchingPorts": [
                          {
                            "ports": [
                              {
                                "destPorts": [
                                  "string"
                                ],
                                "sourcePorts": [
                                  "string"
                                ]
                              }
                            ],
                            "protocol": "string"
                          }
                        ],
                        "result": "string"
                      }
                    ],
                    "result": "string"
                  },
                  "id": "string",
                  "interfaceStatistics": {
                    "adminStatus": "string",
                    "inputPackets": 0,
                    "inputQueueCount": 0,
                    "inputQueueDrops": 0,
                    "inputQueueFlushes": 0,
                    "inputQueueMaxDepth": 0,
                    "inputRatebps": 0,
                    "operationalStatus": "string",
                    "outputDrop": 0,
                    "outputPackets": 0,
                    "outputQueueCount": 0,
                    "outputQueueDepth": 0,
                    "outputRatebps": 0,
                    "refreshedAt": 0
                  },
                  "interfaceStatsCollection": "string",
                  "interfaceStatsCollectionFailureReason": "string",
                  "name": "string",
                  "pathOverlayInfo": [
                    {
                      "controlPlane": "string",
                      "dataPacketEncapsulation": "string",
                      "destIp": "string",
                      "destPort": "string",
                      "protocol": "string",
                      "sourceIp": "string",
                      "sourcePort": "string",
                      "vxlanInfo": {
                        "dscp": "string",
                        "vnid": "string"
                      }
                    }
                  ],
                  "qosStatistics": [
                    {
                      "classMapName": "string",
                      "dropRate": 0,
                      "numBytes": 0,
                      "numPackets": 0,
                      "offeredRate": 0,
                      "queueBandwidthbps": "string",
                      "queueDepth": 0,
                      "queueNoBufferDrops": 0,
                      "queueTotalDrops": 0,
                      "refreshedAt": 0
                    }
                  ],
                  "qosStatsCollection": "string",
                  "qosStatsCollectionFailureReason": "string",
                  "usedVlan": "string",
                  "vrfName": "string"
                }
              ]
            },
            "ip": "string",
            "linkInformationSource": "string",
            "name": "string",
            "perfMonCollection": "string",
            "perfMonCollectionFailureReason": "string",
            "perfMonitorStatistics": [
              {
                "byteRate": 0,
                "destIpAddress": "string",
                "destPort": "string",
                "inputInterface": "string",
                "ipv4DSCP": "string",
                "ipv4TTL": 0,
                "outputInterface": "string",
                "packetBytes": 0,
                "packetCount": 0,
                "packetLoss": 0,
                "packetLossPercentage": 0,
                "protocol": "string",
                "refreshedAt": 0,
                "rtpJitterMax": 0,
                "rtpJitterMean": 0,
                "rtpJitterMin": 0,
                "sourceIpAddress": "string",
                "sourcePort": "string"
              }
            ],
            "role": "string",
            "ssid": "string",
            "tunnels": [
              "string"
            ],
            "type": "string",
            "wlanId": "string"
          }
        ],
        "properties": [
          "string"
        ],
        "request": {
          "controlPath": true,
          "createTime": 0,
          "destIP": "string",
          "destPort": "string",
          "failureReason": "string",
          "id": "string",
          "inclusions": [
            "string"
          ],
          "lastUpdateTime": 0,
          "periodicRefresh": true,
          "protocol": "string",
          "sourceIP": "string",
          "sourcePort": "string",
          "status": "string",
          "previousFlowAnalysisId": "string"
        }
      },
      "version": "string"
    }
"""
