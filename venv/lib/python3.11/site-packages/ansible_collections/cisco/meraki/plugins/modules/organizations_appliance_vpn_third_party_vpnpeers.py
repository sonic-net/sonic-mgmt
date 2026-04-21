#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_appliance_vpn_third_party_vpnpeers
short_description: Resource module for organizations _appliance _vpn _third _party _vpnpeers
description:
  - Manage operation update of the resource organizations _appliance _vpn _third _party _vpnpeers.
  - Update the third party VPN peers for an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  peers:
    description: The list of VPN peers.
    elements: dict
    suboptions:
      ikeVersion:
        description: Optional The IKE version to be used for the IPsec VPN peer configuration. Defaults to '1' when omitted.
        type: str
      ipsecPolicies:
        description: Custom IPSec policies for the VPN peer. If not included and a preset has not been chosen, the default preset for IPSec policies
          will be used.
        suboptions:
          childAuthAlgo:
            description: This is the authentication algorithms to be used in Phase 2. The value should be an array with one of the following algorithms
              'sha256', 'sha1', 'md5'.
            elements: str
            type: list
          childCipherAlgo:
            description: This is the cipher algorithms to be used in Phase 2. The value should be an array with one or more of the following algorithms
              'aes256', 'aes192', 'aes128', 'tripledes', 'des', 'null'.
            elements: str
            type: list
          childLifetime:
            description: The lifetime of the Phase 2 SA in seconds.
            type: int
          childPfsGroup:
            description: This is the Diffie-Hellman group to be used for Perfect Forward Secrecy in Phase 2. The value should be an array with
              one of the following values 'disabled','group14', 'group5', 'group2', 'group1'.
            elements: str
            type: list
          ikeAuthAlgo:
            description: This is the authentication algorithm to be used in Phase 1. The value should be an array with one of the following algorithms
              'sha256', 'sha1', 'md5'.
            elements: str
            type: list
          ikeCipherAlgo:
            description: This is the cipher algorithm to be used in Phase 1. The value should be an array with one of the following algorithms
              'aes256', 'aes192', 'aes128', 'tripledes', 'des'.
            elements: str
            type: list
          ikeDiffieHellmanGroup:
            description: This is the Diffie-Hellman group to be used in Phase 1. The value should be an array with one of the following algorithms
              'group14', 'group5', 'group2', 'group1'.
            elements: str
            type: list
          ikeLifetime:
            description: The lifetime of the Phase 1 SA in seconds.
            type: int
          ikePrfAlgo:
            description: Optional This is the pseudo-random function to be used in IKE_SA. The value should be an array with one of the following
              algorithms 'prfsha256', 'prfsha1', 'prfmd5', 'default'. The 'default' option can be used to default to the Authentication algorithm.
            elements: str
            type: list
        type: dict
      ipsecPoliciesPreset:
        description: One of the following available presets 'default', 'aws', 'azure', 'umbrella', 'zscaler'. If this is provided, the 'ipsecPolicies'
          parameter is ignored.
        type: str
      localId:
        description: Optional The local ID is used to identify the MX to the peer. This will apply to all MXs this peer applies to.
        type: str
      name:
        description: The name of the VPN peer.
        type: str
      networkTags:
        description: A list of network tags that will connect with this peer. Use 'all' for all networks. Use 'none' for no networks. If not included,
          the default is 'all'.
        elements: str
        type: list
      privateSubnets:
        description: The list of the private subnets of the VPN peer.
        elements: str
        type: list
      publicHostname:
        description: Optional The public hostname of the VPN peer.
        type: str
      publicIp:
        description: Optional The public IP of the VPN peer.
        type: str
      remoteId:
        description: Optional The remote ID is used to identify the connecting VPN peer. This can either be a valid IPv4 Address, FQDN or User
          FQDN.
        type: str
      secret:
        description: The shared secret with the VPN peer.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateOrganizationApplianceVpnThirdPartyVPNPeers
    description: Complete reference of the updateOrganizationApplianceVpnThirdPartyVPNPeers API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-appliance-vpn-third-party-vpn-peers
notes:
  - SDK Method used are
    appliance.Appliance.update_organization_appliance_vpn_third_party_vpnpeers,
  - Paths used are
    put /organizations/{organizationId}/appliance/vpn/thirdPartyVPNPeers,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.organizations_appliance_vpn_third_party_vpnpeers:
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
    organizationId: string
    peers:
      - ikeVersion: '2'
        ipsecPolicies:
          childAuthAlgo:
            - sha1
          childCipherAlgo:
            - aes128
          childLifetime: 28800
          childPfsGroup:
            - disabled
          ikeAuthAlgo:
            - sha1
          ikeCipherAlgo:
            - tripledes
          ikeDiffieHellmanGroup:
            - group2
          ikeLifetime: 28800
          ikePrfAlgo:
            - prfsha1
        ipsecPoliciesPreset: default
        localId: myMXId@meraki.com
        name: Peer Name
        networkTags:
          - none
        privateSubnets:
          - 192.168.1.0/24
          - 192.168.128.0/24
        publicHostname: example.com
        publicIp: 123.123.123.1
        remoteId: miles@meraki.com
        secret: Sample Password
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    [
      {
        "ikeVersion": "string",
        "ipsecPolicies": {
          "childAuthAlgo": [
            "string"
          ],
          "childCipherAlgo": [
            "string"
          ],
          "childLifetime": 0,
          "childPfsGroup": [
            "string"
          ],
          "ikeAuthAlgo": [
            "string"
          ],
          "ikeCipherAlgo": [
            "string"
          ],
          "ikeDiffieHellmanGroup": [
            "string"
          ],
          "ikeLifetime": 0,
          "ikePrfAlgo": [
            "string"
          ]
        },
        "ipsecPoliciesPreset": "string",
        "localId": "string",
        "name": "string",
        "networkTags": [
          "string"
        ],
        "privateSubnets": [
          "string"
        ],
        "publicIp": "string",
        "remoteId": "string",
        "secret": "string"
      }
    ]
"""
