#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_branding_policies
short_description: Resource module for organizations _branding _policies
description:
  - Manage operations create, update and delete of the resource organizations _branding _policies.
  - Add a new branding policy to an organization.
  - Delete a branding policy.
  - Update a branding policy.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  adminSettings:
    description: Settings for describing which kinds of admins this policy applies to.
    suboptions:
      appliesTo:
        description: Which kinds of admins this policy applies to. Can be one of 'All organization admins', 'All enterprise admins', 'All network
          admins', 'All admins of networks...', 'All admins of networks tagged...', 'Specific admins...', 'All admins' or 'All SAML admins'.
        type: str
      values:
        description: If 'appliesTo' is set to one of 'Specific admins...', 'All admins of networks...' or 'All admins of networks tagged...',
          then you must specify this 'values' property to provide the set of entities to apply the branding policy to. For 'Specific admins...',
          specify an array of admin IDs. For 'All admins of networks...', specify an array of network IDs and/or configuration template IDs. For
          'All admins of networks tagged...', specify an array of tag names.
        elements: str
        type: list
    type: dict
  brandingPolicyId:
    description: BrandingPolicyId path parameter. Branding policy ID.
    type: str
  customLogo:
    description: Properties describing the custom logo attached to the branding policy.
    suboptions:
      enabled:
        description: Whether or not there is a custom logo enabled.
        type: bool
      image:
        description: Properties for setting the image.
        suboptions:
          contents:
            description: The file contents (a base 64 encoded string) of your new logo.
            type: str
          format:
            description: The format of the encoded contents. Supported formats are 'png', 'gif', and jpg'.
            type: str
        type: dict
    type: dict
  enabled:
    description: Boolean indicating whether this policy is enabled.
    type: bool
  helpSettings:
    description: Settings for describing the modifications to various Help page features. Each property in this object accepts one of 'default
      or inherit' (do not modify functionality), 'hide' (remove the section from Dashboard), or 'show' (always show the section on Dashboard).
      Some properties in this object also accept custom HTML used to replace the section on Dashboard; see the documentation for each property
      to see the allowed values. Each property defaults to 'default or inherit' when not provided.
    suboptions:
      apiDocsSubtab:
        description: The 'Help -> API docs' subtab where a detailed description of the Dashboard API is listed. Can be one of 'default or inherit',
          'hide' or 'show'.
        type: str
      casesSubtab:
        description: The 'Help -> Cases' Dashboard subtab on which Cisco Meraki support cases for this organization can be managed. Can be one
          of 'default or inherit', 'hide' or 'show'.
        type: str
      ciscoMerakiProductDocumentation:
        description: The 'Product Manuals' section of the 'Help -> Get Help' subtab. Can be one of 'default or inherit', 'hide', 'show', or a
          replacement custom HTML string.
        type: str
      communitySubtab:
        description: The 'Help -> Community' subtab which provides a link to Meraki Community. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      dataProtectionRequestsSubtab:
        description: The 'Help -> Data protection requests' Dashboard subtab on which requests to delete, restrict, or export end-user data can
          be audited. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      firewallInfoSubtab:
        description: The 'Help -> Firewall info' subtab where necessary upstream firewall rules for communication to the Cisco Meraki cloud are
          listed. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      getHelpSubtab:
        description: The 'Help -> Get Help' subtab on which Cisco Meraki KB, Product Manuals, and Support/Case Information are displayed. Note
          that if this subtab is hidden, branding customizations for the KB on 'Get help', Cisco Meraki product documentation, and support contact
          info will not be visible. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      getHelpSubtabKnowledgeBaseSearch:
        description: The KB search box which appears on the Help page. Can be one of 'default or inherit', 'hide', 'show', or a replacement custom
          HTML string.
        type: str
      hardwareReplacementsSubtab:
        description: The 'Help -> Replacement info' subtab where important information regarding device replacements is detailed. Can be one of
          'default or inherit', 'hide' or 'show'.
        type: str
      helpTab:
        description: The Help tab, under which all support information resides. If this tab is hidden, no other 'Help' branding customizations
          will be visible. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      helpWidget:
        description: The 'Help Widget' is a support widget which provides access to live chat, documentation links, Sales contact info, and other
          contact avenues to reach Meraki Support. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      newFeaturesSubtab:
        description: The 'Help -> New features' subtab where new Dashboard features are detailed. Can be one of 'default or inherit', 'hide' or
          'show'.
        type: str
      smForums:
        description: The 'SM Forums' subtab which links to community-based support for Cisco Meraki Systems Manager. Only configurable for organizations
          that contain Systems Manager networks. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
      supportContactInfo:
        description: The 'Contact Meraki Support' section of the 'Help -> Get Help' subtab. Can be one of 'default or inherit', 'hide', 'show',
          or a replacement custom HTML string.
        type: str
      universalSearchKnowledgeBaseSearch:
        description: The universal search box always visible on Dashboard will, by default, present results from the Meraki KB. This configures
          whether these Meraki KB results should be returned. Can be one of 'default or inherit', 'hide' or 'show'.
        type: str
    type: dict
  name:
    description: Name of the Dashboard branding policy.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationBrandingPolicy
    description: Complete reference of the createOrganizationBrandingPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-branding-policy
  - name: Cisco Meraki documentation for organizations deleteOrganizationBrandingPolicy
    description: Complete reference of the deleteOrganizationBrandingPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-branding-policy
  - name: Cisco Meraki documentation for organizations updateOrganizationBrandingPolicy
    description: Complete reference of the updateOrganizationBrandingPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-branding-policy
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_branding_policy,
    organizations.Organizations.delete_organization_branding_policy,
    organizations.Organizations.update_organization_branding_policy,
  - Paths used are
    post /organizations/{organizationId}/brandingPolicies,
    delete /organizations/{organizationId}/brandingPolicies/{brandingPolicyId},
    put /organizations/{organizationId}/brandingPolicies/{brandingPolicyId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_branding_policies:
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
    adminSettings:
      appliesTo: All admins of networks...
      values:
        - N_1234
        - L_5678
    customLogo:
      enabled: true
      image:
        contents: Hyperg26C8F4h8CvcoUqpA==
        format: jpg
    enabled: true
    helpSettings:
      apiDocsSubtab: default or inherit
      casesSubtab: hide
      ciscoMerakiProductDocumentation: show
      communitySubtab: show
      dataProtectionRequestsSubtab: default or inherit
      firewallInfoSubtab: hide
      getHelpSubtab: default or inherit
      getHelpSubtabKnowledgeBaseSearch: <h1>Some custom HTML content</h1>
      hardwareReplacementsSubtab: hide
      helpTab: show
      helpWidget: hide
      newFeaturesSubtab: show
      smForums: hide
      supportContactInfo: show
      universalSearchKnowledgeBaseSearch: hide
    name: My Branding Policy
    organizationId: string
- name: Delete by id
  cisco.meraki.organizations_branding_policies:
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
    brandingPolicyId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_branding_policies:
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
    adminSettings:
      appliesTo: All admins of networks...
      values:
        - N_1234
        - L_5678
    brandingPolicyId: string
    customLogo:
      enabled: true
      image:
        contents: Hyperg26C8F4h8CvcoUqpA==
        format: jpg
    enabled: true
    helpSettings:
      apiDocsSubtab: default or inherit
      casesSubtab: hide
      ciscoMerakiProductDocumentation: show
      communitySubtab: show
      dataProtectionRequestsSubtab: default or inherit
      firewallInfoSubtab: hide
      getHelpSubtab: default or inherit
      getHelpSubtabKnowledgeBaseSearch: <h1>Some custom HTML content</h1>
      hardwareReplacementsSubtab: hide
      helpTab: show
      helpWidget: hide
      newFeaturesSubtab: show
      smForums: hide
      supportContactInfo: show
      universalSearchKnowledgeBaseSearch: hide
    name: My Branding Policy
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "adminSettings": {
        "appliesTo": "string",
        "values": [
          "string"
        ]
      },
      "customLogo": {
        "enabled": true,
        "image": {
          "preview": {
            "expiresAt": "string",
            "url": "string"
          }
        }
      },
      "enabled": true,
      "helpSettings": {
        "apiDocsSubtab": "string",
        "casesSubtab": "string",
        "ciscoMerakiProductDocumentation": "string",
        "communitySubtab": "string",
        "dataProtectionRequestsSubtab": "string",
        "firewallInfoSubtab": "string",
        "getHelpSubtab": "string",
        "getHelpSubtabKnowledgeBaseSearch": "string",
        "hardwareReplacementsSubtab": "string",
        "helpTab": "string",
        "helpWidget": "string",
        "newFeaturesSubtab": "string",
        "smForums": "string",
        "supportContactInfo": "string",
        "universalSearchKnowledgeBaseSearch": "string"
      },
      "name": "string"
    }
"""
