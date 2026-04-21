#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_cellular_gateway_esims_swap
short_description: Resource module for organizations _cellular _gateway _esims _swap
description:
  - Manage operation create of the resource organizations _cellular _gateway _esims _swap.
  - Swap which profile an eSIM uses.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  swaps:
    description: Each object represents a swap for one eSIM.
    elements: dict
    suboptions:
      eid:
        description: ESIM EID.
        type: str
      target:
        description: Target Profile attributes.
        suboptions:
          accountId:
            description: ID of the target account; can be the account currently tied to the eSIM.
            type: str
          communicationPlan:
            description: Name of the target communication plan.
            type: str
          ratePlan:
            description: Name of the target rate plan.
            type: str
        type: dict
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for cellularGateway createOrganizationCellularGatewayEsimsSwap
    description: Complete reference of the createOrganizationCellularGatewayEsimsSwap API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-cellular-gateway-esims-swap
notes:
  - SDK Method used are
    cellular_gateway.CellularGateway.create_organization_cellular_gateway_esims_swap,
  - Paths used are
    post /organizations/{organizationId}/cellularGateway/esims/swap,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_cellular_gateway_esims_swap:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    organizationId: string
    swaps:
      - eid: '1234567890'
        target:
          accountId: '456'
          communicationPlan: A comm plan
          ratePlan: A rate plan
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "eid": "string",
      "iccid": "string",
      "status": "string"
    }
"""
