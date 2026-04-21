#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_controllers_provision
short_description: Resource module for Wireless Controllers
  Provision
description:
  - Manage operation create of the resource Wireless
    Controllers Provision.
  - This API is used to provision wireless controller.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  apAuthorizationListName:
    description: AP Authorization List name. 'Obtain
      the AP Authorization List names by using the API
      call GET /intent/api/v1/wirelessSettings/apAuthorizationLists.
      During re-provision, obtain the AP Authorization
      List configured for the given provisioned network
      device Id using the API call GET /intent/api/v1/wireless/apAuthorizationLists/{networkDev...
    type: str
  authorizeMeshAndNonMeshAccessPoints:
    description: True if AP Authorization List should
      authorize against All Mesh/Non-Mesh APs, else
      false if AP Authorization List should only authorize
      against Mesh APs (Applicable only when Mesh is
      enabled on sites).
    type: bool
  deviceId:
    description: DeviceId path parameter. Network Device
      ID. This value can be obtained by using the API
      call GET /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
    type: str
  featureTemplatesOverridenAttributes:
    description: Wireless Controllers Provision's featureTemplatesOverridenAttributes.
    suboptions:
      editFeatureTemplates:
        description: Wireless Controllers Provision's
          editFeatureTemplates.
        elements: dict
        suboptions:
          additionalIdentifiers:
            description: Wireless Controllers Provision's
              additionalIdentifiers.
            suboptions:
              siteUuid:
                description: Site UUID. This must be
                  provided if `featureTemplateId` belongs
                  to `Flex Configuration` feature template.
                type: str
              wlanProfileName:
                description: WLAN Profile Name. This
                  must be passed if `featureTemplateId`
                  belongs to `Advanced SSID Configuration`
                  Feature Template.
                type: str
            type: dict
          attributes:
            description: This dynamic map should contain
              attribute name and overridden value of
              respective Feature Template whose `featureTemplateId`.
              List of attributes applicable to given
              `featureTemplateId` can be retrieved from
              its GET API call /dna/intent/api/v1/featureTemplates/wireless/<featureTemplateName>/featureTemplateId.
            type: dict
          excludedAttributes:
            description: List of attributes which will
              NOT be provisioned.
            elements: str
            type: list
          featureTemplateId:
            description: Feature Template ID.
            type: str
        type: list
    type: dict
  interfaces:
    description: Wireless Controllers Provision's interfaces.
    elements: dict
    suboptions:
      interfaceGateway:
        description: Interface Gateway.
        type: str
      interfaceIPAddress:
        description: Interface IP Address.
        type: str
      interfaceName:
        description: Interface Name.
        type: str
      interfaceNetmaskInCIDR:
        description: Interface Netmask In CIDR, range
          is 1-30.
        type: int
      lagOrPortNumber:
        description: Lag Or Port Number.
        type: int
      vlanId:
        description: VLAN ID range is 1 - 4094.
        type: int
    type: list
  rollingApUpgrade:
    description: Wireless Controllers Provision's rollingApUpgrade.
    suboptions:
      apRebootPercentage:
        description: AP Reboot Percentage. Permissible
          values - 5, 15, 25.
        type: int
      enableRollingApUpgrade:
        description: True if Rolling AP Upgrade is enabled,
          else False.
        type: bool
    type: dict
  skipApProvision:
    description: True if Skip AP Provision is enabled,
      else False.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      WirelessControllerProvision
    description: Complete reference of the WirelessControllerProvision
      API.
    link: https://developer.cisco.com/docs/dna-center/#!wireless-controller-provision
notes:
  - SDK Method used are
    wireless.Wireless.wireless_controller_provision,
  - Paths used are
    post /dna/intent/api/v1/wirelessControllers/{deviceId}/provision,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_controllers_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    apAuthorizationListName: string
    authorizeMeshAndNonMeshAccessPoints: true
    deviceId: string
    featureTemplatesOverridenAttributes:
      editFeatureTemplates:
        - additionalIdentifiers:
            siteUuid: string
            wlanProfileName: string
          attributes: {}
          excludedAttributes:
            - string
          featureTemplateId: string
    interfaces:
      - interfaceGateway: string
        interfaceIPAddress: string
        interfaceName: string
        interfaceNetmaskInCIDR: 0
        lagOrPortNumber: 0
        vlanId: 0
    rollingApUpgrade:
      apRebootPercentage: 0
      enableRollingApUpgrade: true
    skipApProvision: true
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
