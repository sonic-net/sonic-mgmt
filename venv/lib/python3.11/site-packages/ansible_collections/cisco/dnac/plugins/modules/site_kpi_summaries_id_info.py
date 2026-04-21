#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_kpi_summaries_id_info
short_description: Information module for Site Kpi Summaries
  Id
description:
  - Get Site Kpi Summaries Id by id. - > Returns site
    analytics for the given site. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-SiteKpiSummaries-1.0.0-resolved.yaml.
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
      - Id path parameter. The Site UUID.
    type: str
  taskId:
    description:
      - >
        TaskId query parameter. Used to retrieve asynchronously
        processed & stored data. When this parameter
        is used, the rest of the request params will
        be ignored.
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
  ssid:
    description:
      - >
        Ssid query parameter. SSID is the name of wireless
        network to which client connects to. It is also
        referred to as WLAN ID - Wireless Local Area
        Network Identifier. Examples `ssid=Alpha` (single
        ssid requested) `ssid=Alpha&ssid=Guest` (multiple
        ssid requested).
    type: str
  band:
    description:
      - >
        Band query parameter. WiFi frequency band that
        client or Access Point operates. Band value
        is represented in Giga Hertz - GHz Examples
        `band=5` (single band requested) `band=2.4&band=6`
        (multiple band requested).
    type: str
  failureCategory:
    description:
      - >
        FailureCategory query parameter. Category of
        failure when a client fails to meet the threshold.
        Examples `failureCategory=AUTH` (single failure
        category requested) `failureCategory=AUTH&failureCategory=DHCP`
        (multiple failure categories requested).
    type: str
  failureReason:
    description:
      - >
        FailureReason query parameter. Reason for failure
        when a client fails to meet the threshold. Examples
        `failureReason=MOBILITY_FAILURE` (single ssid
        requested) `failureReason=REASON_IPLEARN_CONNECT_TIMEOUT&failureReason=ST_EAP_TIMEOUT`
        (multiple ssid requested).
    type: str
  view:
    description:
      - >
        View query parameter. <p>The name of the View.
        Each view represents a specific data set. Please
        refer to the <code>SiteAnalyticsView</code>
        Model for supported views. View is predefined
        set of attributes supported by the API. Only
        the attributes related to the given view will
        be part of the API response along with default
        attributes. If multiple views are provided,
        then response will contain attributes from all
        those views. If no views are specified, all
        attributes will be returned.</p><table><thead><tr><th>View
        Name</th><th>Included Attributes</th></tr></thead><tbody><tr><td><code>coverage</code></td><td>coverageAverage,
        coverageSuccessPercentage, coverageSuccessCount,
        coverageTotalCount, coverageFailureCount, coverageClientCount,
        coverageImpactedEntities, coverageFailureImpactedEntities,
        coverageFailureMetrics</ td></tr><tr><td><code>onboardingAttempts</code></td><td>onboardingAttemptsSuccessPercentage,
        onboardingAttemptsSuccessCount, onboardingAttemptsTotalCount,
        onboardingAttemptsFailureCount, onboardingAttemptsClientCount,
        onboardingAttemptsImpactedEntities, onboardingAttemptsFailureImpactedEntities,
        onboardingAttemptsFailureMetrics</td></tr><tr><td><code>onboa
        rdingDuration</code></td><td>onboardingDurationAverage,
        onboardingDurationSuccessPercentage, onboardingDurationSuccessCount,
        onboardingDurationTotalCount, onboardingDurationFailureCount,
        onboardingDurationClientCount, onboardingDurationImpactedEntities,
        onboardingDurationFailureImpactedEntities, onboardingDurationFailureMetrics</td></tr><tr><td><code>roami
        ngAttempts</code></td><td>roamingAttemptsSuccessPercentage,
        roamingAttemptsSuccessCount, roamingAttemptsTotalCount,
        roamingAttemptsFailureCount, roamingAttemptsClientCount,
        roamingAttemptsImpactedEntities, roamingAttemptsFailureImpactedEntities,
        roamingAttemptsFailureMetrics</ td></tr><tr><td><code>roamingDuration</code></td><td>roamingDurationAverage,
        roamingDurationSuccessPercentage, roamingDurationSuccessCount,
        roamingDurationTotalCount, roamingDurationFailureCount,
        roamingDurationClientCount, roamingDurationImpactedEntities,
        roamingDurationFailureImpactedEntities, roamingDurationFailureMetrics</td></tr><tr><td><code>connectionS
        peed</code></td><td>connectionSpeedAverage,
        connectionSpeedSuccessPercentage, connectionSpeedSuccessCount,
        connectionSpeedTotalCount, connectionSpeedFailureCount,
        connectionSpeedClientCount, connectionSpeedImpactedEntities,
        connectionSpeedFailureImpactedEntities, connectionSpeedFailureMetrics</td></tr></tbody></table><p>Examples
        <code>view=connectionSpeed</code> (single view
        requested) <code>view=roamingDuration&amp;view=roamingAttempts</code>
        (multiple views requested) </p>.
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes
        related to site analytics. If these are provided,
        then only those attributes will be part of response
        along with the default attributes. Examples
        `attribute=coverageAverage` (single attribute
        requested) `attribute=coverageFailureMetrics&attribute=coverageTotalCount`
        (multiple attributes requested).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites GetSiteAnalyticsForOneSite
    description: Complete reference of the GetSiteAnalyticsForOneSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-site-analytics-for-one-site
notes:
  - SDK Method used are
    sites.Sites.get_site_analytics_for_one_site,
  - Paths used are
    get /dna/data/api/v1/siteKpiSummaries/{id},
"""

EXAMPLES = r"""
---
- name: Get Site Kpi Summaries Id by id
  cisco.dnac.site_kpi_summaries_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    taskId: string
    startTime: 0
    endTime: 0
    ssid: string
    band: string
    failureCategory: string
    failureReason: string
    view: string
    attribute: string
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
        "siteId": "string",
        "siteHierarchyId": "string",
        "siteHierarchy": "string",
        "siteType": "string",
        "apCount": 0,
        "coverageAverage": 0,
        "coverageSuccessPercentage": 0,
        "coverageSuccessCount": 0,
        "coverageTotalCount": 0,
        "coverageFailureCount": 0,
        "coverageClientCount": 0,
        "coverageImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "coverageFailureImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "coverageFailureMetrics": {
          "failureApCount": 0,
          "failureClientCount": 0,
          "failurePercentage": 0
        },
        "onboardingAttemptsSuccessPercentage": 0,
        "onboardingAttemptsSuccessCount": 0,
        "onboardingAttemptsTotalCount": 0,
        "onboardingAttemptsFailureCount": 0,
        "onboardingAttemptsClientCount": 0,
        "onboardingAttemptsImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "onboardingAttemptsFailureImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "onboardingAttemptsFailureMetrics": {
          "failureApCount": 0,
          "failureClientCount": 0,
          "failurePercentage": 0
        },
        "onboardingDurationAverage": 0,
        "onboardingDurationSuccessPercentage": 0,
        "onboardingDurationSuccessCount": 0,
        "onboardingDurationTotalCount": 0,
        "onboardingDurationFailureCount": 0,
        "onboardingDurationClientCount": 0,
        "onboardingDurationImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "onboardingDurationFailureImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "onboardingDurationFailureMetrics": {
          "failureApCount": 0,
          "failureClientCount": 0,
          "failurePercentage": 0
        },
        "roamingAttemptsSuccessPercentage": 0,
        "roamingAttemptsSuccessCount": 0,
        "roamingAttemptsTotalCount": 0,
        "roamingAttemptsFailureCount": 0,
        "roamingAttemptsClientCount": 0,
        "roamingAttemptsImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "roamingAttemptsFailureImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "roamingAttemptsFailureMetrics": {
          "failureApCount": 0,
          "failureClientCount": 0,
          "failurePercentage": 0
        },
        "roamingDurationAverage": 0,
        "roamingDurationSuccessPercentage": 0,
        "roamingDurationSuccessCount": 0,
        "roamingDurationTotalCount": 0,
        "roamingDurationFailureCount": 0,
        "roamingDurationClientCount": 0,
        "roamingDurationImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "roamingDurationFailureImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "roamingDurationFailureMetrics": {
          "failureApCount": 0,
          "failureClientCount": 0,
          "failurePercentage": 0
        },
        "connectionSpeedAverage": 0,
        "connectionSpeedSuccessPercentage": 0,
        "connectionSpeedSuccessCount": 0,
        "connectionSpeedTotalCount": 0,
        "connectionSpeedFailureCount": 0,
        "connectionSpeedClientCount": 0,
        "connectionSpeedImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "connectionSpeedFailureImpactedEntities": {
          "buildingCount": 0,
          "floorCount": 0,
          "sitesCount": 0,
          "apCount": 0
        },
        "connectionSpeedFailureMetrics": {
          "failureApCount": 0,
          "failureClientCount": 0,
          "failurePercentage": 0
        }
      },
      "version": "string"
    }
"""
