#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_subscription
short_description: Resource module for Event Subscription
description:
  - Manage operations create, update and delete of the
    resource Event Subscription. - > Subscribe SubscriptionEndpoint
    to list of registered events. Deprecated since Guardian
    release. Alternative POST /intent/api/v1/event/subscription/rest.
  - Delete EventSubscriptions. - > Update SubscriptionEndpoint
    to list of registered events. Deprecated since Guardian
    release. Alternative PUT /intent/api/v1/event/subscription/rest.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Event Subscription's payload.
    elements: dict
    suboptions:
      description:
        description: Description.
        type: str
      filter:
        description: Event Subscription's filter.
        suboptions:
          categories:
            description: Categories.
            elements: str
            type: list
          domainsSubdomains:
            description: Event Subscription's domainsSubdomains.
            elements: dict
            suboptions:
              domain:
                description: Domain.
                type: str
              subDomains:
                description: Sub Domains.
                elements: str
                type: list
            type: list
          eventIds:
            description: Event Ids (Comma separated
              event ids).
            elements: str
            type: list
          severities:
            description: Severities.
            elements: str
            type: list
          siteIds:
            description: Site Ids.
            elements: str
            type: list
          sources:
            description: Sources.
            elements: str
            type: list
          types:
            description: Types.
            elements: str
            type: list
        type: dict
      name:
        description: Name.
        type: str
      subscriptionEndpoints:
        description: Event Subscription's subscriptionEndpoints.
        elements: dict
        suboptions:
          instanceId:
            description: (From Get Rest/Webhook Subscription
              Details --> pick instanceId).
            type: str
          subscriptionDetails:
            description: Event Subscription's subscriptionDetails.
            suboptions:
              connectorType:
                description: Connector Type (Must be
                  REST).
                type: str
            type: dict
        type: list
      subscriptionId:
        description: Subscription Id (Unique UUID).
        type: str
      version:
        description: Version.
        type: str
    type: list
  subscriptions:
    description: Subscriptions query parameter. List
      of EventSubscriptionId's for removal.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      CreateEventSubscriptions
    description: Complete reference of the CreateEventSubscriptions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-event-subscriptions
  - name: Cisco DNA Center documentation for Event Management
      DeleteEventSubscriptions
    description: Complete reference of the DeleteEventSubscriptions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-event-subscriptions
  - name: Cisco DNA Center documentation for Event Management
      UpdateEventSubscriptions
    description: Complete reference of the UpdateEventSubscriptions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-event-subscriptions
notes:
  - SDK Method used are
    event_management.EventManagement.create_event_subscriptions,
    event_management.EventManagement.delete_event_subscriptions,
    event_management.EventManagement.update_event_subscriptions,
  - Paths used are
    post /dna/intent/api/v1/event/subscription,
    delete /dna/intent/api/v1/event/subscription,
    put
    /dna/intent/api/v1/event/subscription,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.event_subscription:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    subscriptions: string
- name: Update all
  cisco.dnac.event_subscription:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - description: string
        filter:
          categories:
            - string
          domainsSubdomains:
            - domain: string
              subDomains:
                - string
          eventIds:
            - string
          severities:
            - string
          siteIds:
            - string
          sources:
            - string
          types:
            - string
        name: string
        subscriptionEndpoints:
          - instanceId: string
            subscriptionDetails:
              connectorType: string
        subscriptionId: string
        version: string
- name: Create
  cisco.dnac.event_subscription:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - description: string
        filter:
          categories:
            - string
          domainsSubdomains:
            - domain: string
              subDomains:
                - string
          eventIds:
            - string
          severities:
            - string
          siteIds:
            - string
          sources:
            - string
          types:
            - string
        name: string
        subscriptionEndpoints:
          - instanceId: string
            subscriptionDetails:
              connectorType: string
        subscriptionId: string
        version: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "statusUri": "string"
    }
"""
