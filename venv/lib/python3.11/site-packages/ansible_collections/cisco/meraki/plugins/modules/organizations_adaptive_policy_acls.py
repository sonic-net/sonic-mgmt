#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_adaptive_policy_acls
short_description: Resource module for organizations _adaptive _policy _acls
description:
  - Manage operations create, update and delete of the resource organizations _adaptive _policy _acls.
  - Creates new adaptive policy ACL.
  - Deletes the specified adaptive policy ACL. Note this adaptive policy ACL will also be removed from policies using it.
  - Updates an adaptive policy ACL.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  aclId:
    description: AclId path parameter. Acl ID.
    type: str
  description:
    description: Description of the adaptive policy ACL.
    type: str
  ipVersion:
    description: IP version of adpative policy ACL. One of 'any', 'ipv4' or 'ipv6'.
    type: str
  name:
    description: Name of the adaptive policy ACL.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  rules:
    description: An ordered array of the adaptive policy ACL rules.
    elements: dict
    suboptions:
      dstPort:
        description: Destination port. Must be in the format of single port '1', port list '1,2' or port range '1-10', and in the range of 1-65535,
          or 'any'. Default is 'any'.
        type: str
      log:
        description: If enabled, when this rule is hit an entry will be logged to the event log.
        type: bool
      policy:
        description: '''allow'' or ''deny'' traffic specified by this rule.'
        type: str
      protocol:
        description: The type of protocol (must be 'tcp', 'udp', 'icmp' or 'any').
        type: str
      srcPort:
        description: Source port. Must be in the format of single port '1', port list '1,2' or port range '1-10', and in the range of 1-65535,
          or 'any'. Default is 'any'.
        type: str
      tcpEstablished:
        description: If enabled, means TCP connection with this node must be established.
        type: bool
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationAdaptivePolicyAcl
    description: Complete reference of the createOrganizationAdaptivePolicyAcl API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-adaptive-policy-acl
  - name: Cisco Meraki documentation for organizations deleteOrganizationAdaptivePolicyAcl
    description: Complete reference of the deleteOrganizationAdaptivePolicyAcl API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-adaptive-policy-acl
  - name: Cisco Meraki documentation for organizations updateOrganizationAdaptivePolicyAcl
    description: Complete reference of the updateOrganizationAdaptivePolicyAcl API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-adaptive-policy-acl
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_adaptive_policy_acl,
    organizations.Organizations.delete_organization_adaptive_policy_acl,
    organizations.Organizations.update_organization_adaptive_policy_acl,
  - Paths used are
    post /organizations/{organizationId}/adaptivePolicy/acls,
    delete /organizations/{organizationId}/adaptivePolicy/acls/{aclId},
    put /organizations/{organizationId}/adaptivePolicy/acls/{aclId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_adaptive_policy_acls:
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
    description: Blocks sensitive web traffic
    ipVersion: ipv6
    name: Block sensitive web traffic
    organizationId: string
    rules:
      - dstPort: 22-30
        log: true
        policy: deny
        protocol: tcp
        srcPort: 1,33
        tcpEstablished: true
- name: Delete by id
  cisco.meraki.organizations_adaptive_policy_acls:
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
    aclId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_adaptive_policy_acls:
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
    aclId: string
    description: Blocks sensitive web traffic
    ipVersion: ipv6
    name: Block sensitive web traffic
    organizationId: string
    rules:
      - dstPort: 22-30
        log: true
        policy: deny
        protocol: tcp
        srcPort: 1,33
        tcpEstablished: true
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "aclId": "string",
      "createdAt": "string",
      "description": "string",
      "ipVersion": "string",
      "name": "string",
      "rules": [
        {
          "dstPort": "string",
          "log": true,
          "policy": "string",
          "protocol": "string",
          "srcPort": "string",
          "tcpEstablished": true
        }
      ],
      "updatedAt": "string"
    }
"""
