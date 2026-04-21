#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_meraki_auth_users
short_description: Resource module for networks _meraki _auth _users
description:
  - Manage operations create, update and delete of the resource networks _meraki _auth _users. - > Authorize a user configured with Meraki Authentication
    for a network currently supports 802.1X, splash guest, and client VPN users, and currently, organizations have a 50,000 user cap .
  - Delete an 802.1X RADIUS user, or deauthorize and optionally delete a splash guest or client VPN user. - > Update a user configured with Meraki
    Authentication currently, 802.1X RADIUS, splash guest, and client VPN users can be updated .
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  accountType:
    description: Authorization type for user. Can be 'Guest' or '802.1X' for wireless networks, or 'Client VPN' for MX networks. Defaults to '802.1X'.
    type: str
  authorizations:
    description: Authorization zones and expiration dates for the user.
    elements: dict
    suboptions:
      expiresAt:
        description: Date for authorization to expire. Set to 'Never' for the authorization to not expire, which is the default.
        type: str
      ssidNumber:
        description: Required for wireless networks. The SSID for which the user is being authorized, which must be configured for the user's
          given accountType.
        type: int
    type: list
  delete:
    description: Delete query parameter. If the ID supplied is for a splash guest or client VPN user, and that user is not authorized for any
      other networks in the organization, then also delete the user. 802.1X RADIUS users are always deleted regardless of this optional attribute.
    type: bool
  email:
    description: Email address of the user.
    type: str
  emailPasswordToUser:
    description: Whether or not Meraki should email the password to user. Default is false.
    type: bool
  isAdmin:
    description: Whether or not the user is a Dashboard administrator.
    type: bool
  merakiAuthUserId:
    description: MerakiAuthUserId path parameter. Meraki auth user ID.
    type: str
  name:
    description: Name of the user. Only required If the user is not a Dashboard administrator.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  password:
    description: The password for this user account. Only required If the user is not a Dashboard administrator.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkMerakiAuthUser
    description: Complete reference of the createNetworkMerakiAuthUser API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-meraki-auth-user
  - name: Cisco Meraki documentation for networks deleteNetworkMerakiAuthUser
    description: Complete reference of the deleteNetworkMerakiAuthUser API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-meraki-auth-user
  - name: Cisco Meraki documentation for networks updateNetworkMerakiAuthUser
    description: Complete reference of the updateNetworkMerakiAuthUser API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-meraki-auth-user
notes:
  - SDK Method used are
    networks.Networks.create_network_meraki_auth_user,
    networks.Networks.delete_network_meraki_auth_user,
    networks.Networks.update_network_meraki_auth_user,
  - Paths used are
    post /networks/{networkId}/merakiAuthUsers,
    delete /networks/{networkId}/merakiAuthUsers/{merakiAuthUserId},
    put /networks/{networkId}/merakiAuthUsers/{merakiAuthUserId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_meraki_auth_users:
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
    accountType: 802.1X
    authorizations:
      - expiresAt: '2018-03-13T00:00:00.090210Z'
        ssidNumber: 1
    email: miles@meraki.com
    emailPasswordToUser: false
    isAdmin: false
    name: Miles Meraki
    networkId: string
    password: secret
- name: Delete by id
  cisco.meraki.networks_meraki_auth_users:
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
    delete: true
    merakiAuthUserId: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_meraki_auth_users:
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
    authorizations:
      - expiresAt: '2018-03-13T00:00:00.090210Z'
        ssidNumber: 1
    emailPasswordToUser: false
    merakiAuthUserId: string
    name: Miles Meraki
    networkId: string
    password: secret
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "accountType": "string",
      "authorizations": [
        {
          "authorizedByEmail": "string",
          "authorizedByName": "string",
          "authorizedZone": "string",
          "expiresAt": "string",
          "ssidNumber": 0
        }
      ],
      "createdAt": "string",
      "email": "string",
      "id": "string",
      "isAdmin": true,
      "name": "string"
    }
"""
