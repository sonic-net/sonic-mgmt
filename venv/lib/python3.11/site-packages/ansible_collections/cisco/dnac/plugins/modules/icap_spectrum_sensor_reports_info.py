#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_spectrum_sensor_reports_info
short_description: Information module for Icap Spectrum
  Sensor Reports
description:
  - Get all Icap Spectrum Sensor Reports. - > Retrieves
    the spectrum sensor reports sent by WLC for provided
    AP Mac. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-icap-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
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
  apMac:
    description:
      - ApMac query parameter. The base ethernet macAddress
        of the access point.
    type: str
  dataType:
    description:
      - >
        DataType query parameter. Data type reported
        by the sensor |Data Type | Description | | ---
        | --- | | `0` | Duty Cycle | | `1` | Max Power
        | | `2` | Average Power | | `3` | Max Power
        in dBm with adjusted base of +48 | | `4` | Average
        Power in dBm with adjusted base of +48 |.
    type: float
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: int
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: int
  timeSortOrder:
    description:
      - TimeSortOrder query parameter. The sort order
        of the field ascending or descending.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      RetrievesTheSpectrumSensorReportsSentByWLCForProvidedAPMac
    description: Complete reference of the RetrievesTheSpectrumSensorReportsSentByWLCForProvidedAPMac
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-spectrum-sensor-reports-sent-by-wlc-for-provided-ap-mac
notes:
  - SDK Method used are
    sensors.Sensors.retrieves_the_spectrum_sensor_reports_sent_by_w_l_c_for_provided_ap_mac,
  - Paths used are
    get /dna/data/api/v1/icap/spectrumSensorReports,
"""

EXAMPLES = r"""
---
- name: Get all Icap Spectrum Sensor Reports
  cisco.dnac.icap_spectrum_sensor_reports_info:
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
    apMac: string
    dataType: 0
    limit: 0
    offset: 0
    timeSortOrder: string
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
          "spanKHz": 0,
          "dataType": 0,
          "apMac": "string",
          "dataAvg": 0,
          "dataMin": 0,
          "dataMax": 0,
          "dataUnits": "string",
          "centralFrequencyKHz": 0,
          "band": "string",
          "timestamp": 0,
          "data": [
            0
          ],
          "dataSize": 0,
          "channels": [
            0
          ]
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "timeSortOrder": "string"
      },
      "version": "string"
    }
"""
