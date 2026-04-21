#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_get_sensor_test_results_info
short_description: Information module for Assurance
  Get Sensor Test Results
description:
  - Get all Assurance Get Sensor Test Results.
  - Intent API to get SENSOR test result summary.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId query parameter. Assurance site UUID.
    type: str
  startTime:
    description:
      - StartTime query parameter. The epoch time in
        milliseconds.
    type: float
  endTime:
    description:
      - EndTime query parameter. The epoch time in milliseconds.
    type: float
  testFailureBy:
    description:
      - >
        TestFailureBy query parameter. Obtain failure
        statistics group by "area", "building", or "floor"
        (case insensitive).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      SensorTestResults
    description: Complete reference of the SensorTestResults
      API.
    link: https://developer.cisco.com/docs/dna-center/#!sensor-test-results
notes:
  - SDK Method used are
    wireless.Wireless.sensor_test_results,
  - Paths used are
    get /dna/intent/api/v1/AssuranceGetSensorTestResults,
"""

EXAMPLES = r"""
---
- name: Get all Assurance Get Sensor Test Results
  cisco.dnac.assurance_get_sensor_test_results_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    startTime: 0
    endTime: 0
    testFailureBy: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "summary": {
          "totalTestCount": 0,
          "ONBOARDING": {
            "AUTH": {
              "passCount": 0,
              "failCount": 0
            },
            "DHCP": {
              "passCount": 0,
              "failCount": 0
            },
            "ASSOC": {
              "passCount": 0,
              "failCount": 0
            }
          },
          "PERFORMANCE": {
            "IPSLASENDER": {
              "passCount": 0,
              "failCount": 0
            }
          },
          "NETWORK_SERVICES": {
            "DNS": {
              "passCount": 0,
              "failCount": 0
            }
          },
          "APP_CONNECTIVITY": {
            "HOST_REACHABILITY": {
              "passCount": 0,
              "failCount": 0
            },
            "WEBSERVER": {
              "passCount": 0,
              "failCount": 0
            },
            "FILETRANSFER": {
              "passCount": 0,
              "failCount": 0
            }
          },
          "RF_ASSESSMENT": {
            "DATA_RATE": {
              "passCount": 0,
              "failCount": 0
            },
            "SNR": {
              "passCount": 0,
              "failCount": 0
            }
          },
          "EMAIL": {
            "MAILSERVER": {
              "passCount": 0,
              "failCount": 0
            }
          }
        },
        "failureStats": [
          {
            "errorCode": 0,
            "errorTitle": "string",
            "testType": "string",
            "testCategory": "string"
          }
        ]
      }
    }
"""
