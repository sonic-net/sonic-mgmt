#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: fabric_site_health_summaries_id_info
short_description: Information module for Fabric Site
  Health Summaries Id
description:
  - Get Fabric Site Health Summaries Id by id.
  - Get Fabric site health summary for a specific fabric
    site by providing the unique fabric site id in the
    url path.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Unique fabric site id.
    type: str
  startTime:
    description:
      - >
        StartTime query parameter. Start time from which
        API queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive.
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive.
    type: float
  attribute:
    description:
      - >
        Attribute query parameter. The list of FabricSite
        health attributes. Please refer to ```fabricSiteAttributes```
        section in the Open API specification document
        mentioned in the description.
    type: str
  view:
    description:
      - >
        View query parameter. The specific summary view
        being requested. A maximum of 3 views can be
        queried at a time per request. Please refer
        to ```fabricSiteViews``` section in the Open
        API specification document mentioned in the
        description.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA ReadFabricSitesWithHealthSummaryFromId
    description: Complete reference of the ReadFabricSitesWithHealthSummaryFromId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!read-fabric-sites-with-health-summary-from-id
notes:
  - SDK Method used are
    sda.Sda.read_fabric_sites_with_health_summary_from_id,
  - Paths used are
    get /dna/data/api/v1/fabricSiteHealthSummaries/{id},
"""

EXAMPLES = r"""
---
- name: Get Fabric Site Health Summaries Id by id
  cisco.dnac.fabric_site_health_summaries_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    startTime: 0
    endTime: 0
    attribute: string
    view: string
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
        "id": "string",
        "name": "string",
        "totalDeviceCount": 0,
        "goodHealthPercentage": 0,
        "totalHealthDeviceCount": 0,
        "goodHealthDeviceCount": 0,
        "poorHealthDeviceCount": 0,
        "fairHealthDeviceCount": 0,
        "connectivityGoodHealthPercentage": 0,
        "connectivityTotalHealthDeviceCount": 0,
        "connectivityGoodHealthDeviceCount": 0,
        "connectivityPoorHealthDeviceCount": 0,
        "connectivityFairHealthDeviceCount": 0,
        "infraGoodHealthPercentage": 0,
        "infraTotalHealthDeviceCount": 0,
        "infraGoodHealthDeviceCount": 0,
        "infraFairHealthDeviceCount": 0,
        "infraPoorHealthDeviceCount": 0,
        "controlPlaneGoodHealthPercentage": 0,
        "controlPlaneTotalHealthDeviceCount": 0,
        "controlPlaneGoodHealthDeviceCount": 0,
        "controlPlanePoorHealthDeviceCount": 0,
        "controlPlaneFairHealthDeviceCount": 0,
        "pubsubInfraVnGoodHealthPercentage": 0,
        "pubsubInfraVnTotalHealthDeviceCount": 0,
        "pubsubInfraVnGoodHealthDeviceCount": 0,
        "pubsubInfraVnPoorHealthDeviceCount": 0,
        "pubsubInfraVnFairHealthDeviceCount": 0,
        "bgpEvpnGoodHealthPercentage": 0,
        "bgpEvpnTotalHealthDeviceCount": 0,
        "bgpEvpnGoodHealthDeviceCount": 0,
        "bgpEvpnPoorHealthDeviceCount": 0,
        "bgpEvpnFairHealthDeviceCount": 0,
        "ctsEnvDataDownloadGoodHealthPercentage": 0,
        "ctsEnvDataDownloadTotalHealthDeviceCount": 0,
        "ctsEnvDataDownloadGoodHealthDeviceCount": 0,
        "ctsEnvDataDownloadPoorHealthDeviceCount": 0,
        "ctsEnvDataDownloadFairHealthDeviceCount": 0,
        "aaaStatusGoodHealthPercentage": 0,
        "aaaStatusTotalHealthDeviceCount": 0,
        "aaaStatusGoodHealthDeviceCount": 0,
        "aaaStatusPoorHealthDeviceCount": 0,
        "aaaStatusFairHealthDeviceCount": 0,
        "portChannelGoodHealthPercentage": 0,
        "portChannelTotalHealthDeviceCount": 0,
        "portChannelGoodHealthDeviceCount": 0,
        "portChannelPoorHealthDeviceCount": 0,
        "portChannelFairHealthDeviceCount": 0,
        "peerScoreGoodHealthPercentage": 0,
        "peerScoreTotalHealthDeviceCount": 0,
        "peerScoreGoodHealthDeviceCount": 0,
        "peerScorePoorHealthDeviceCount": 0,
        "peerScoreFairHealthDeviceCount": 0,
        "lispSessionGoodHealthPercentage": 0,
        "lispSessionTotalHealthDeviceCount": 0,
        "lispSessionGoodHealthDeviceCount": 0,
        "lispSessionPoorHealthDeviceCount": 0,
        "lispSessionFairHealthDeviceCount": 0,
        "borderToControlPlaneGoodHealthPercentage": 0,
        "borderToControlPlaneTotalHealthDeviceCount": 0,
        "borderToControlPlaneGoodHealthDeviceCount": 0,
        "borderToControlPlanePoorHealthDeviceCount": 0,
        "borderToControlPlaneFairHealthDeviceCount": 0,
        "bgpBgpSiteGoodHealthPercentage": 0,
        "bgpBgpSiteTotalHealthDeviceCount": 0,
        "bgpBgpSiteGoodHealthDeviceCount": 0,
        "bgpBgpSitePoorHealthDeviceCount": 0,
        "bgpBgpSiteFairHealthDeviceCount": 0,
        "bgpPubsubSiteGoodHealthPercentage": 0,
        "bgpPubsubSiteTotalHealthDeviceCount": 0,
        "bgpPubsubSiteGoodHealthDeviceCount": 0,
        "bgpPubsubSitePoorHealthDeviceCount": 0,
        "bgpPubsubSiteFairHealthDeviceCount": 0,
        "bgpPeerInfraVnScoreGoodHealthPercentage": 0,
        "bgpPeerInfraVnTotalHealthDeviceCount": 0,
        "bgpPeerInfraVnGoodHealthDeviceCount": 0,
        "bgpPeerInfraVnPoorHealthDeviceCount": 0,
        "bgpPeerInfraVnFairHealthDeviceCount": 0,
        "associatedL2VnCount": 0,
        "associatedL3VnCount": 0,
        "networkProtocol": "string"
      },
      "version": "string"
    }
"""
