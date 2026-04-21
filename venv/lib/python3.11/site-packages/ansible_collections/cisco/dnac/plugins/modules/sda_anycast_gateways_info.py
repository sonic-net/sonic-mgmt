#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_anycast_gateways_info
short_description: Information module for Sda Anycast
  Gateways
description:
  - Get all Sda Anycast Gateways.
  - Returns a list of anycast gateways that match the
    provided query parameters.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id query parameter. ID of the anycast gateway.
    type: str
  fabricId:
    description:
      - FabricId query parameter. ID of the fabric the
        anycast gateway is assigned to.
    type: str
  virtualNetworkName:
    description:
      - VirtualNetworkName query parameter. Name of
        the virtual network associated with the anycast
        gateways.
    type: str
  ipPoolName:
    description:
      - IpPoolName query parameter. Name of the IP pool
        associated with the anycast gateways.
    type: str
  vlanName:
    description:
      - VlanName query parameter. VLAN name of the anycast
        gateways.
    type: str
  vlanId:
    description:
      - >
        VlanId query parameter. VLAN ID of the anycast
        gateways. The allowed range for vlanId is 2-4093
        except for reserved VLANs 1002-1005, 2046, and
        4094.
    type: float
  offset:
    description:
      - Offset query parameter. Starting record for
        pagination. The value must be greater than or equal to 1.
    type: int
  limit:
    description:
      - >
        Limit query parameter. Maximum number of records
        to return. The maximum number of objects supported
        in a single request is 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetAnycastGateways
    description: Complete reference of the GetAnycastGateways
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-anycast-gateways
notes:
  - SDK Method used are
    sda.Sda.get_anycast_gateways,
  - Paths used are
    get /dna/intent/api/v1/sda/anycastGateways,
"""

EXAMPLES = r"""
---
- name: Get all Sda Anycast Gateways
  cisco.dnac.sda_anycast_gateways_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    fabricId: string
    virtualNetworkName: string
    ipPoolName: string
    vlanName: string
    vlanId: 0
    offset: 1      # Must be >= 1
    limit: 25     # Must be >= 1
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "fabricId": "string",
          "virtualNetworkName": "string",
          "ipPoolName": "string",
          "tcpMssAdjustment": 0,
          "vlanName": "string",
          "vlanId": 0,
          "trafficType": "string",
          "poolType": "string",
          "securityGroupName": "string",
          "isCriticalPool": true,
          "isLayer2FloodingEnabled": true,
          "layer2FloodingAddressAssignment": "string",
          "layer2FloodingAddress": "string",
          "isWirelessPool": true,
          "isWirelessFloodingEnabled": true,
          "isResourceGuardEnabled": true,
          "isIpDirectedBroadcast": true,
          "isIntraSubnetRoutingEnabled": true,
          "isMultipleIpToMacAddresses": true,
          "isSupplicantBasedExtendedNodeOnboarding": true,
          "isGroupBasedPolicyEnforcementEnabled": true
        }
      ],
      "version": "string"
    }
"""
