#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_controllers_wireless_mobility_groups_mobility_provision
short_description: Resource module for Wireless Controllers
  Wireless Mobility Groups Mobility Provision
description:
  - Manage operation create of the resource Wireless
    Controllers Wireless Mobility Groups Mobility Provision.
  - This API is used to provision/deploy wireless mobility
    into Cisco wireless controllers.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  dataLinkEncryption:
    description: A secure link in which data is encrypted
      using CAPWAP DTLS protocol can be established
      between two controllers. This value will be applied
      to all peers during POST operation.
    type: bool
  dtlsHighCipher:
    description: DTLS High Cipher.
    type: bool
  macAddress:
    description: Device mobility MAC Address. Allowed
      formats are 0a0b.0c01.0211, 0a0b0c010211, 0a 0b
      0c 01 02 11.
    type: str
  managementIp:
    description: Self device wireless Management IP.
    type: str
  mobilityGroupName:
    description: Self device Group Name. Must be alphanumeric
      without {!,<,space,?/'} and maximum of 31 characters.
    type: str
  mobilityPeers:
    description: Wireless Controllers Wireless Mobility
      Groups Mobility Provision's mobilityPeers.
    elements: dict
    suboptions:
      deviceSeries:
        description: Indicates peer device mobility
          belongs to AireOS or IOX-XE family. 0 - indicates
          AireOS and 1 - indicates C9800.
        type: str
      hashKey:
        description: SSC hash string must be 40 characters.
        type: str
      memberMacAddress:
        description: Peer device mobility MAC Address.
          Allowed formats are 0a0b.0c01.0211, 0a0b0c010211,
          0a 0b 0c 01 02 11.
        type: str
      mobilityGroupName:
        description: Peer Device mobility group Name.
          Must be alphanumeric without {!,<,space,?/'}
          and maximum of 31 characters.
        type: str
      peerDeviceName:
        description: Peer device Host Name.
        type: str
      peerIp:
        description: This indicates public ip address.
        type: str
      peerNetworkDeviceId:
        description: The possible values are UNKNOWN
          or valid UUID of Network device Id. UNKNOWN
          represents out of band device which is not
          managed internally. Valid UUID represents
          WLC network device id.
        type: str
      privateIpAddress:
        description: This indicates private/management
          ip address.
        type: str
    type: list
  networkDeviceId:
    description: Obtain the network device ID value
      by using the API call GET /dna/intent/api/v1/network-device/ip-...
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      MobilityProvision
    description: Complete reference of the MobilityProvision
      API.
    link: https://developer.cisco.com/docs/dna-center/#!mobility-provision
notes:
  - SDK Method used are
    wireless.Wireless.mobility_provision,
  - Paths used are
    post /dna/intent/api/v1/wirelessControllers/wirelessMobilityGroups/mobilityProvision,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_controllers_wireless_mobility_groups_mobility_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dataLinkEncryption: true
    dtlsHighCipher: true
    macAddress: string
    managementIp: string
    mobilityGroupName: string
    mobilityPeers:
      - deviceSeries: string
        hashKey: string
        memberMacAddress: string
        mobilityGroupName: string
        peerDeviceName: string
        peerIp: string
        peerNetworkDeviceId: string
        privateIpAddress: string
    networkDeviceId: string
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
