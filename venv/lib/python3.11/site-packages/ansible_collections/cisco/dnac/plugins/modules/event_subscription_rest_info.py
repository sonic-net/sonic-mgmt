#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_subscription_rest_info
short_description: Information module for Event Subscription
  Rest
description:
  - Get all Event Subscription Rest.
  - Gets the list of Rest/Webhook Subscriptions's based
    on provided query params.
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
        related to the respective eventIds (Comma separated
        event ids).
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
  domain:
    description:
      - Domain query parameter. List of subscriptions
        related to the respective domain.
    type: str
  subDomain:
    description:
      - SubDomain query parameter. List of subscriptions
        related to the respective sub-domain.
    type: str
  category:
    description:
      - Category query parameter. List of subscriptions
        related to the respective category.
    type: str
  type:
    description:
      - Type query parameter. List of subscriptions
        related to the respective type.
    type: str
  name:
    description:
      - Name query parameter. List of subscriptions
        related to the respective name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      GetRestWebhookEventSubscriptions
    description: Complete reference of the GetRestWebhookEventSubscriptions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-rest-webhook-event-subscriptions
notes:
  - SDK Method used are
    event_management.EventManagement.get_rest_webhook_event_subscriptions,
  - Paths used are
    get /dna/intent/api/v1/event/subscription/rest,
"""

EXAMPLES = r"""
---
- name: Get all Event Subscription Rest
  cisco.dnac.event_subscription_rest_info:
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
    domain: string
    subDomain: string
    category: string
    type: string
    name: string
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
              "trustCert": "string",
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
              "connectTimeout": "string",
              "readTimeout": "string"
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
        "isPrivate": "string",
        "tenantId": "string"
      }
    ]
"""
