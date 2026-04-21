#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_cellular_gateway_esims_service_providers_accounts
short_description: Resource module for organizations _cellular _gateway _esims _service _providers _accounts
description:
  - Manage operations create, update and delete of the resource organizations _cellular _gateway _esims _service _providers _accounts.
  - Add a service provider account.
  - Remove a service provider account's integration with the Dashboard.
  - Edit service provider account info stored in Meraki's database.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  accountId:
    description: Service provider account ID.
    type: str
  apiKey:
    description: Service provider account API key.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  serviceProvider:
    description: Service Provider information.
    suboptions:
      name:
        description: Service provider name.
        type: str
    type: dict
  title:
    description: Service provider account name.
    type: str
  username:
    description: Service provider account username.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for cellularGateway createOrganizationCellularGatewayEsimsServiceProvidersAccount
    description: Complete reference of the createOrganizationCellularGatewayEsimsServiceProvidersAccount API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-cellular-gateway-esims-service-providers-account
  - name: Cisco Meraki documentation for cellularGateway deleteOrganizationCellularGatewayEsimsServiceProvidersAccount
    description: Complete reference of the deleteOrganizationCellularGatewayEsimsServiceProvidersAccount API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-cellular-gateway-esims-service-providers-account
  - name: Cisco Meraki documentation for cellularGateway updateOrganizationCellularGatewayEsimsServiceProvidersAccount
    description: Complete reference of the updateOrganizationCellularGatewayEsimsServiceProvidersAccount API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-cellular-gateway-esims-service-providers-account
notes:
  - SDK Method used are
    cellular_gateway.CellularGateway.create_organization_cellular_gateway_esims_service_providers_account,
    cellular_gateway.CellularGateway.delete_organization_cellular_gateway_esims_service_providers_account,
    cellular_gateway.CellularGateway.update_organization_cellular_gateway_esims_service_providers_account,
  - Paths used are
    post /organizations/{organizationId}/cellularGateway/esims/serviceProviders/accounts,
    delete /organizations/{organizationId}/cellularGateway/esims/serviceProviders/accounts/{accountId},
    put /organizations/{organizationId}/cellularGateway/esims/serviceProviders/accounts/{accountId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_cellular_gateway_esims_service_providers_accounts:
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
    state: present
    accountId: 987654321
    apiKey: foobarfoobarfoobarfoobarfoobarfoobar
    organizationId: string
    serviceProvider:
      name: ATT
    title: My AT&T account
    username: MerakiUser
- name: Delete by id
  cisco.meraki.organizations_cellular_gateway_esims_service_providers_accounts:
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
    state: absent
    accountId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_cellular_gateway_esims_service_providers_accounts:
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
    state: present
    accountId: string
    apiKey: foobarfoobarfoobarfoobarfoobarfoobar
    organizationId: string
    title: My AT&T account
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "accountId": "string",
      "lastUpdatedAt": "string",
      "serviceProvider": {
        "logo": {
          "url": "string"
        },
        "name": "string"
      },
      "title": "string",
      "username": "string"
    }
"""
