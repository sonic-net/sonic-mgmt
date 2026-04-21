#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
author:
  - Kevin Breit (@kbreit)
deprecated:
  alternative: cisco.meraki.organizations_appliance_vpn_third_party_vpnpeers
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Create, edit, query, or delete third party VPN peers in a Meraki environment.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_mx_third_party_vpn_peers
options:
  peers:
    description:
      - The list of VPN peers.
    elements: dict
    suboptions:
      ike_version:
        choices:
          - '1'
          - '2'
        default: '1'
        description:
          - The IKE version to be used for the IPsec VPN peer configuration.
        type: str
      ipsec_policies:
        description:
          - Custom IPSec policies for the VPN peer. If not included and a preset has
            not been chosen, the default preset for IPSec policies will be used.
        suboptions:
          child_auth_algo:
            choices:
              - sha256
              - sha1
              - md5
            description:
              - This is the authentication algorithms to be used in Phase 2.
            elements: str
            type: list
          child_cipher_algo:
            choices:
              - aes256
              - aes192
              - aes128
              - tripledes
              - des
              - 'null'
            description:
              - This is the cipher algorithms to be used in Phase 2.
            elements: str
            type: list
          child_lifetime:
            description:
              - The lifetime of the Phase 2 SA in seconds.
            type: int
          child_pfs_group:
            choices:
              - disabled
              - group14
              - group5
              - group2
              - group1
            description:
              - This is the Diffie-Hellman group to be used for Perfect Forward Secrecy
                in Phase 2.
            elements: str
            type: list
          ike_auth_algo:
            choices:
              - sha256
              - sha1
              - md5
            description:
              - This is the authentication algorithm to be used in Phase 1.
            elements: str
            type: list
          ike_cipher_algo:
            choices:
              - aes256
              - aes192
              - aes128
              - tripledes
              - des
            description:
              - This is the cipher algorithm to be used in Phase 1.
            elements: str
            type: list
          ike_diffie_hellman_group:
            choices:
              - group14
              - group5
              - group2
              - group1
            description:
              - This is the Diffie-Hellman group to be used in Phase 1.
            elements: str
            type: list
          ike_lifetime:
            description:
              - The lifetime of the Phase 1 SA in seconds.
            type: int
          ike_prf_algo:
            choices:
              - prfsha256
              - prfsha1
              - prfmd5
              - default
            description:
              - This is the pseudo-random function to be used in IKE_SA.
            elements: str
            type: list
        type: dict
      ipsec_policies_preset:
        choices:
          - default
          - aws
          - azure
        description:
          - Specifies IPsec preset values. If this is provided, the 'ipsecPolicies'
            parameter is ignored.
        type: str
      name:
        description:
          - The name of the VPN peer.
          - Required when state is present.
        type: str
      network_tags:
        description:
          - A list of network tags that will connect with this peer. If not included,
            the default is ['all'].
        elements: str
        type: list
      private_subnets:
        description:
          - The list of the private subnets of the VPN peer.
          - Required when state is present.
        elements: str
        type: list
      public_ip:
        description:
          - The public IP of the VPN peer.
          - Required when state is present.
        type: str
      remote_id:
        description:
          - The remote ID is used to identify the connecting VPN peer. This can either
            be a valid IPv4 Address, FQDN or User FQDN.
        type: str
      secret:
        description:
          - The shared secret with the VPN peer.
          - Required when state is present.
        type: str
    type: list
  state:
    choices:
      - absent
      - present
      - query
    default: query
    description:
      - Specifies whether object should be queried, created/modified, or removed.
    type: str
short_description: Manage third party (IPSec) VPN peers for MX devices
"""

EXAMPLES = r"""
- name: Query all VPN peers
  meraki_mx_third_party_vpn_peers:
    auth_key: abc123
    state: query
    org_name: orgName
- name: Create VPN peer with an IPsec policy
  meraki_mx_third_party_vpn_peers:
    auth_key: abc123
    state: present
    org_name: orgName
    peers:
      - name: Test peer
        public_ip: 198.51.100.1
        secret: s3cret
        private_subnets:
          - 192.0.2.0/24
        ike_version: '2'
        network_tags:
          - none
        remote_id: 192.0.2.0
        ipsec_policies:
          child_lifetime: 600
          ike_lifetime: 600
          child_auth_algo:
            - md5
          child_cipher_algo:
            - tripledes
            - aes192
          child_pfs_group:
            - disabled
          ike_auth_algo:
            - sha256
          ike_cipher_algo:
            - tripledes
          ike_diffie_hellman_group:
            - group2
          ike_prf_algo:
            - prfmd5
"""

RETURN = r"""

response:
  description: Information about the organization which was created or modified
  returned: success
  type: complex
  contains:
    appliance_ip:
      description: IP address of Meraki appliance in the VLAN
      returned: success
      type: str
      sample: 192.0.1.1
    dnsnamservers:
      description: IP address or Meraki defined DNS servers which VLAN should use by default
      returned: success
      type: str
      sample: upstream_dns
    peers:
      description: The list of VPN peers.
      returned: success
      type: complex
      contains:
        ike_version:
          description: The IKE version to be used for the IPsec VPN peer configuration.
          returned: success
          type: str
          sample: "1"
        ipsec_policies_preset:
          description: Preconfigured IPsec settings.
          returned: success
          type: str
          sample: "aws"
        name:
          description: The name of the VPN peer.
          returned: success
          type: str
          sample: "MyVPNPeer"
        public_ip:
          description: The public IP of the VPN peer.
          returned: success
          type: str
          sample: "198.51.100.1"
        remote_id:
          description: "The remote ID is used to identify the connecting VPN peer."
          returned: success
          type: str
          sample: "s3cret"
        network_tags:
          description: A list of network tags that will connect with this peer.
          returned: success
          type: list
          sample: ["all"]
        private_subnets:
          description: The list of the private subnets of the VPN peer.
          returned: success
          type: list
          sample: ["192.0.2.0/24"]
        ipsec_policies:
          description: Custom IPSec policies for the VPN peer.
          returned: success
          type: complex
          contains:
            child_lifetime:
              description: The lifetime of the Phase 2 SA in seconds.
              returned: success
              type: str
              sample: "60"
            ike_lifetime:
              description: The lifetime of the Phase 1 SA in seconds.
              returned: success
              type: str
              sample: "60"
            child_auth_algo:
              description: This is the authentication algorithms to be used in Phase 2.
              returned: success
              type: list
              sample: ["sha1"]
            child_cipher_algo:
              description: This is the cipher algorithms to be used in Phase 2.
              returned: success
              type: list
              sample: ["aes192"]
            child_pfs_group:
              description: This is the Diffie-Hellman group to be used for Perfect Forward Secrecy in Phase 2.
              returned: success
              type: list
              sample: ["group14"]
            ike_auth_algo:
              description: This is the authentication algorithm to be used in Phase 1.
              returned: success
              type: list
              sample: ["sha1"]
            ike_cipher_algo:
              description: This is the cipher algorithm to be used in Phase 1.
              returned: success
              type: list
              sample: ["aes128"]
            ike_diffie_hellman_group:
              description: This is the Diffie-Hellman group to be used in Phase 1.
              returned: success
              type: list
              sample: ["group14"]
            ike_prf_algo:
              description: This is the pseudo-random function to be used in IKE_SA.
              returned: success
              type: list
              sample: ["prfmd5"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)
import json


def validate_payload(meraki):
    for peer in meraki.params["peers"]:
        if peer["name"] is None:
            meraki.fail_json(msg="Peer name must be specified")
        elif peer["public_ip"] is None:
            meraki.fail_json(msg="Peer public IP must be specified")
        elif peer["secret"] is None:
            meraki.fail_json(msg="Peer secret must be specified")
        elif peer["private_subnets"] is None:
            meraki.fail_json(msg="Peer private subnets must be specified")


def construct_payload(meraki):
    validate_payload(meraki)
    peer_list = []
    for peer in meraki.params["peers"]:
        current_peer = dict()
        current_peer["name"] = peer["name"]
        current_peer["publicIp"] = peer["public_ip"]
        current_peer["secret"] = peer["secret"]
        current_peer["privateSubnets"] = peer["private_subnets"]
        if peer["ike_version"] is not None:
            current_peer["ikeVersion"] = peer["ike_version"]
        if peer["ipsec_policies_preset"] is not None:
            current_peer["ipsecPoliciesPreset"] = peer["ipsec_policies_preset"]
        if peer["remote_id"] is not None:
            current_peer["remoteId"] = peer["remote_id"]
        if peer["network_tags"] is not None:
            current_peer["networkTags"] = peer["network_tags"]
        if peer["ipsec_policies"] is not None:
            current_peer["ipsecPolicies"] = dict()
            if peer["ipsec_policies"]["child_lifetime"] is not None:
                current_peer["ipsecPolicies"]["childLifetime"] = peer["ipsec_policies"][
                    "child_lifetime"
                ]
            if peer["ipsec_policies"]["ike_lifetime"] is not None:
                current_peer["ipsecPolicies"]["ikeLifetime"] = peer["ipsec_policies"][
                    "ike_lifetime"
                ]
            if peer["ipsec_policies"]["child_auth_algo"] is not None:
                current_peer["ipsecPolicies"]["childAuthAlgo"] = peer["ipsec_policies"][
                    "child_auth_algo"
                ]
            if peer["ipsec_policies"]["child_cipher_algo"] is not None:
                current_peer["ipsecPolicies"]["childCipherAlgo"] = peer[
                    "ipsec_policies"
                ]["child_cipher_algo"]
            if peer["ipsec_policies"]["child_pfs_group"] is not None:
                current_peer["ipsecPolicies"]["childPfsGroup"] = peer["ipsec_policies"][
                    "child_pfs_group"
                ]
            if peer["ipsec_policies"]["ike_auth_algo"] is not None:
                current_peer["ipsecPolicies"]["ikeAuthAlgo"] = peer["ipsec_policies"][
                    "ike_auth_algo"
                ]
            if peer["ipsec_policies"]["ike_cipher_algo"] is not None:
                current_peer["ipsecPolicies"]["ikeCipherAlgo"] = peer["ipsec_policies"][
                    "ike_cipher_algo"
                ]
            if peer["ipsec_policies"]["ike_diffie_hellman_group"] is not None:
                current_peer["ipsecPolicies"]["ikeDiffieHellmanGroup"] = peer[
                    "ipsec_policies"
                ]["ike_diffie_hellman_group"]
            if peer["ipsec_policies"]["ike_prf_algo"] is not None:
                current_peer["ipsecPolicies"]["ikePrfAlgo"] = peer["ipsec_policies"][
                    "ike_prf_algo"
                ]

        peer_list.append(current_peer)
    payload = {"peers": peer_list}
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    ipsec_policies_arg_spec = dict(
        child_lifetime=dict(type="int", default=None),
        ike_lifetime=dict(type="int", default=None),
        child_auth_algo=dict(
            type="list", elements="str", default=None, choices=["sha256", "sha1", "md5"]
        ),
        child_cipher_algo=dict(
            type="list",
            elements="str",
            default=None,
            choices=["aes256", "aes192", "aes128", "tripledes", "des", "null"],
        ),
        child_pfs_group=dict(
            type="list",
            elements="str",
            default=None,
            choices=["disabled", "group14", "group5", "group2", "group1"],
        ),
        ike_auth_algo=dict(
            type="list", elements="str", default=None, choices=["sha256", "sha1", "md5"]
        ),
        ike_cipher_algo=dict(
            type="list",
            elements="str",
            default=None,
            choices=["aes256", "aes192", "aes128", "tripledes", "des"],
        ),
        ike_diffie_hellman_group=dict(
            type="list",
            elements="str",
            default=None,
            choices=["group14", "group5", "group2", "group1"],
        ),
        ike_prf_algo=dict(
            type="list",
            elements="str",
            default=None,
            choices=["prfsha256", "prfsha1", "prfmd5", "default"],
        ),
    )

    peers_arg_spec = dict(
        name=dict(type="str"),
        public_ip=dict(type="str"),
        secret=dict(type="str", no_log=True),
        private_subnets=dict(type="list", elements="str"),
        ike_version=dict(type="str", choices=["1", "2"], default="1"),
        ipsec_policies_preset=dict(
            type="str", choices=["default", "aws", "azure"], default=None
        ),
        remote_id=dict(type="str", default=None),
        network_tags=dict(type="list", elements="str", default=None),
        ipsec_policies=dict(type="dict", options=ipsec_policies_arg_spec, default=None),
    )

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        state=dict(type="str", choices=["absent", "present", "query"], default="query"),
        peers=dict(type="list", elements="dict", options=peers_arg_spec),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    meraki = MerakiModule(module, function="third_party_vpn_peer")

    meraki.params["follow_redirects"] = "all"

    query_urls = {
        "third_party_vpn_peer": "/organizations/{org_id}/appliance/vpn/thirdPartyVPNPeers"
    }
    update_url = {
        "third_party_vpn_peer": "/organizations/{org_id}/appliance/vpn/thirdPartyVPNPeers"
    }

    meraki.url_catalog["get_all"].update(query_urls)
    meraki.url_catalog["update"] = update_url

    payload = None
    if meraki.params["org_id"] is None and meraki.params["org_name"] is None:
        meraki.fail_json(msg="Organization must be specified via org_name or org_id")

    org_id = meraki.params["org_id"]
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params["org_name"])

    if meraki.params["state"] == "query":
        path = meraki.construct_path("get_all", org_id=org_id)
        response = meraki.request(path, "GET")
        meraki.result["data"] = response
    elif meraki.params["state"] == "present":
        payload = construct_payload(meraki)
        have = meraki.request(meraki.construct_path("get_all", org_id=org_id), "GET")
        # meraki.fail_json(msg="Compare", have=have, payload=payload)
        if meraki.is_update_required(have, payload):
            meraki.generate_diff(have, payload)
            path = meraki.construct_path("update", org_id=org_id)
            if meraki.module.check_mode is False:
                response = meraki.request(path, "PUT", payload=json.dumps(payload))
                meraki.result["data"] = response
            else:
                meraki.result["data"] = payload
            meraki.result["changed"] = True
            meraki.exit_json(**meraki.result)
        meraki.result["data"] = have
    elif meraki.params["state"] == "absent":
        return

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
