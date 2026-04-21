#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_appliance_security_intrusion
short_description: Resource module for organizations _appliance _security _intrusion
description:
  - Manage operation update of the resource organizations _appliance _security _intrusion.
  - Sets supported intrusion settings for an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  allowedRules:
    description: Sets a list of specific SNORT signatures to allow.
    elements: dict
    suboptions:
      message:
        description: Message is optional and is ignored on a PUT call. It is allowed in order for PUT to be compatible with GET.
        type: str
      ruleId:
        description: A rule identifier of the format meraki intrusion/snort/GID/<gid>/SID/<sid>. Gid and sid can be obtained from either https
          //www.snort.org/rule-docs or as ruleIds from the security events in /organization/orgId/securityEvents.
        type: str
    type: list
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateOrganizationApplianceSecurityIntrusion
    description: Complete reference of the updateOrganizationApplianceSecurityIntrusion API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-appliance-security-intrusion
notes:
  - SDK Method used are
    appliance.Appliance.update_organization_appliance_security_intrusion,
  - Paths used are
    put /organizations/{organizationId}/appliance/security/intrusion,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.organizations_appliance_security_intrusion:
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
    allowedRules:
      - message: SQL sa login failed
        ruleId: meraki:intrusion/snort/GID/01/SID/688
      - message: MALWARE-OTHER Trackware myway speedbar runtime detection - switch engines
        ruleId: meraki:intrusion/snort/GID/01/SID/5805
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
