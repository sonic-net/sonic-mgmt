#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_subscription_info
short_description: Information module for Event Subscription
description:
  - Get all Event Subscription. - > Gets the list of
    Subscriptions's based on provided offset and limit.
    Deprecated since Guardian release. Alternative GET
    /intent/api/v1/event/subscription/rest.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  eventIds:
    description:
      - EventIds query parameter. List of subscriptions
        related to the respective eventIds.
    type: str
  offset:
    description:
      - Offset query parameter. The number of Subscriptions's
        to offset in the resultset whose default value
        0.
    type: int
  limit:
    description:
      - Limit query parameter. The number of Subscriptions's
        to limit in the resultset whose default value
        10.
    type: int
  sortBy:
    description:
      - SortBy query parameter. SortBy field name.
    type: str
  order:
    description:
      - Order query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      GetEventSubscriptions
    description: Complete reference of the GetEventSubscriptions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-event-subscriptions
notes:
  - SDK Method used are
    event_management.EventManagement.get_event_subscriptions,
  - Paths used are
    get /dna/intent/api/v1/event/subscription,
"""

EXAMPLES = r"""
---
- name: Get all Event Subscription
  cisco.dnac.event_subscription_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    eventIds: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "version": "string",
        "subscriptionId": "string",
        "name": "string",
        "description": "string",
        "subscriptionEndpoints": [
          {
            "instanceId": "string",
            "subscriptionDetails": {
              "connectorType": "string",
              "instanceId": "string",
              "name": "string",
              "description": "string",
              "url": "string",
              "basePath": "string",
              "resource": "string",
              "method": "string",
              "trustCert": true,
              "headers": [
                {
                  "string": "string"
                }
              ],
              "queryParams": [
                {
                  "string": "string"
                }
              ],
              "pathParams": [
                {
                  "string": "string"
                }
              ],
              "body": "string",
              "connectTimeout": 0,
              "readTimeout": 0
            },
            "connectorType": "string"
          }
        ],
        "filter": {
          "eventIds": [
            "string"
          ],
          "others": [
            "string"
          ],
          "domainsSubdomains": [
            {
              "domain": "string",
              "subDomains": [
                "string"
              ]
            }
          ],
          "types": [
            "string"
          ],
          "categories": [
            "string"
          ],
          "severities": [
            "string"
          ],
          "sources": [
            "string"
          ],
          "siteIds": [
            "string"
          ]
        },
        "isPrivate": true,
        "tenantId": "string"
      }
    ]
"""
