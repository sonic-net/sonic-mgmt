#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_visibility_network_devices_count_info
short_description: Information module for Application
  Visibility Network Devices Count
description:
  - Get all Application Visibility Network Devices Count.
  - This API retrieves the count of network devices
    for the given application visibility status filters.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  ids:
    description:
      - >
        Ids query parameter. List of network devices
        ids. If this parameter is not provided, all
        network devices will be included in the response.
        Multiple network device IDs can be provided.
    type: str
  managementAddress:
    description:
      - >
        ManagementAddress query parameter. The management
        address for the network device. This is normally
        IP address of the device. But it could be hostname
        in some cases like Meraki devices. Partial search
        is supported. For example, searching for `25.`
        would include `10.25.1.1`, `25.5.10.1`, `225.225.1.0`,
        `10.10.10.125`, etc.
    type: str
  hostname:
    description:
      - >
        Hostname query parameter. The host name of the
        network device. Partial search is supported.
        For example, searching for `switch` will include
        `edge-switch1.domain.com`, `switch25`, etc.
    type: str
  siteId:
    description:
      - SiteId query parameter. The site ID where the
        network device is assigned.
    type: str
  appTelemetryDeploymentStatus:
    description:
      - >
        AppTelemetryDeploymentStatus query parameter.
        Status of the application telemetry deployment
        on the network device. Available values SCHEDULED,
        IN_PROGRESS, COMPLETED, FAILED, NOT_DEPLOYED.
    type: str
  appTelemetryReadinessStatus:
    description:
      - >
        AppTelemetryReadinessStatus query parameter.
        Indicates whether the network device is ready
        for application telemetry enablement or not.
        Available values ENABLED, READY, NOT_READY,
        NOT_SUPPORTED.
    type: str
  cbarDeploymentStatus:
    description:
      - >
        CbarDeploymentStatus query parameter. Status
        of the CBAR deployment on the network device.
        Available values SCHEDULED, IN_PROGRESS, COMPLETED,
        FAILED, NOT_DEPLOYED.
    type: str
  cbarReadinessStatus:
    description:
      - >
        CbarReadinessStatus query parameter. Indicates
        whether the network device is ready for CBAR
        enablement or not. Available values ENABLED,
        READY, NOT_READY, NOT_SUPPORTED.
    type: str
  protocolPackStatus:
    description:
      - >
        ProtocolPackStatus query parameter. Indicates
        whether the NBAR protocol pack is up-to-date
        or not on the network device. Available values
        LATEST, OUTDATED, UNKNOWN.
    type: str
  protocolPackUpdateStatus:
    description:
      - >
        ProtocolPackUpdateStatus query parameter. Status
        of the NBAR protocol pack update on the network
        device. Available values SCHEDULED, IN_PROGRESS,
        SUCCESS, FAILED, NONE.
    type: str
  applicationRegistrySyncStatus:
    description:
      - >
        ApplicationRegistrySyncStatus query parameter.
        Indicates whether the latest definitions from
        application registry have been synchronized
        with the network device or not. Available values
        SYNCING, IN_SYNC, OUT_OF_SYNC, NOT_APPLICABLE.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy RetrieveTheCountOfNetworkDevicesForTheGivenApplicationVisibilityStatusFilters
    description: Complete reference of the RetrieveTheCountOfNetworkDevicesForTheGivenApplicationVisibilityStatusFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-the-count-of-network-devices-for-the-given-application-visibility-status-filters
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.retrieve_the_count_of_network_devices_for_the_given_application_visibility_status_filters,
  - Paths used are
    get /dna/intent/api/v1/applicationVisibility/networkDevices/count,
"""

EXAMPLES = r"""
---
- name: Get all Application Visibility Network Devices
    Count
  cisco.dnac.application_visibility_network_devices_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    ids: string
    managementAddress: string
    hostname: string
    siteId: string
    appTelemetryDeploymentStatus: string
    appTelemetryReadinessStatus: string
    cbarDeploymentStatus: string
    cbarReadinessStatus: string
    protocolPackStatus: string
    protocolPackUpdateStatus: string
    applicationRegistrySyncStatus: string
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
        "count": 0
      },
      "version": "string"
    }
"""
