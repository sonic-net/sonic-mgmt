#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_vpn_ipsec_phase1
short_description: Configure VPN remote gateway in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ipsec feature and phase1 category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    vpn_ipsec_phase1:
        description:
            - Configure VPN remote gateway.
        default: null
        type: dict
        suboptions:
            acct_verify:
                description:
                    - Enable/disable verification of RADIUS accounting record.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            add_gw_route:
                description:
                    - Enable/disable automatically add a route to the remote gateway.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            add_route:
                description:
                    - Enable/disable control addition of a route to peer destination selector.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            addke1:
                description:
                    - ADDKE1 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke2:
                description:
                    - ADDKE2 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke3:
                description:
                    - ADDKE3 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke4:
                description:
                    - ADDKE4 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke5:
                description:
                    - ADDKE5 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke6:
                description:
                    - ADDKE6 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke7:
                description:
                    - ADDKE7 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            assign_ip:
                description:
                    - Enable/disable assignment of IP to IPsec interface via configuration method.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            assign_ip_from:
                description:
                    - Method by which the IP address will be assigned.
                type: str
                choices:
                    - 'range'
                    - 'usrgrp'
                    - 'dhcp'
                    - 'name'
            authmethod:
                description:
                    - Authentication method.
                type: str
                choices:
                    - 'psk'
                    - 'signature'
            authmethod_remote:
                description:
                    - Authentication method (remote side).
                type: str
                choices:
                    - 'psk'
                    - 'signature'
            authpasswd:
                description:
                    - XAuth password (max 35 characters).
                type: str
            authusr:
                description:
                    - XAuth user name.
                type: str
            authusrgrp:
                description:
                    - Authentication user group. Source user.group.name.
                type: str
            auto_negotiate:
                description:
                    - Enable/disable automatic initiation of IKE SA negotiation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_transport_threshold:
                description:
                    - Timeout in seconds before falling back to next transport protocol.
                type: int
            azure_ad_autoconnect:
                description:
                    - Enable/disable Azure AD Auto-Connect for FortiClient.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            backup_gateway:
                description:
                    - Instruct unity clients about the backup gateway address(es).
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - Address of backup gateway.
                        required: true
                        type: str
            banner:
                description:
                    - Message that unity client should display after connecting.
                type: str
            cert_id_validation:
                description:
                    - Enable/disable cross validation of peer ID and the identity in the peer"s certificate as specified in RFC 4945.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cert_peer_username_strip:
                description:
                    - Enable/disable domain stripping on certificate identity.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            cert_peer_username_validation:
                description:
                    - Enable/disable cross validation of peer username and the identity in the peer"s certificate.
                type: str
                choices:
                    - 'none'
                    - 'othername'
                    - 'rfc822name'
                    - 'cn'
            cert_trust_store:
                description:
                    - CA certificate trust store.
                type: str
                choices:
                    - 'local'
                    - 'ems'
            certificate:
                description:
                    - Names of up to 4 signed personal certificates.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate name. Source vpn.certificate.local.name.
                        required: true
                        type: str
            childless_ike:
                description:
                    - Enable/disable childless IKEv2 initiation (RFC 6023).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            client_auto_negotiate:
                description:
                    - Enable/disable allowing the VPN client to bring up the tunnel when there is no traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            client_keep_alive:
                description:
                    - Enable/disable allowing the VPN client to keep the tunnel up when there is no traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            client_resume:
                description:
                    - Enable/disable resumption of offline FortiClient sessions.  When a FortiClient enabled laptop is closed or enters sleep/hibernate mode,
                       enabling this feature allows FortiClient to keep the tunnel during this period, and allows users to immediately resume using the IPsec
                          tunnel when the device wakes up.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            client_resume_interval:
                description:
                    - Maximum time in seconds during which a VPN client may resume using a tunnel after a client PC has entered sleep mode or temporarily lost
                       its network connection (120 - 172800).
                type: int
            comments:
                description:
                    - Comment.
                type: str
            dev_id:
                description:
                    - Device ID carried by the device ID notification.
                type: str
            dev_id_notification:
                description:
                    - Enable/disable device ID notification.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_ra_giaddr:
                description:
                    - Relay agent gateway IP address to use in the giaddr field of DHCP requests.
                type: str
            dhcp6_ra_linkaddr:
                description:
                    - Relay agent IPv6 link address to use in DHCP6 requests.
                type: str
            dhgrp:
                description:
                    - DH group.
                type: list
                elements: str
                choices:
                    - '1'
                    - '2'
                    - '5'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
            digital_signature_auth:
                description:
                    - Enable/disable IKEv2 Digital Signature Authentication (RFC 7427).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            distance:
                description:
                    - Distance for routes added by IKE (1 - 255).
                type: int
            dns_mode:
                description:
                    - DNS server mode.
                type: str
                choices:
                    - 'manual'
                    - 'auto'
            dns_suffix_search:
                description:
                    - One or more DNS domain name suffixes in quotes separated by spaces.
                type: list
                elements: dict
                suboptions:
                    dns_suffix:
                        description:
                            - DNS suffix.
                        required: true
                        type: str
            domain:
                description:
                    - Instruct unity clients about the single default DNS domain.
                type: str
            dpd:
                description:
                    - Dead Peer Detection mode.
                type: str
                choices:
                    - 'disable'
                    - 'on-idle'
                    - 'on-demand'
            dpd_retrycount:
                description:
                    - Number of DPD retry attempts.
                type: int
            dpd_retryinterval:
                description:
                    - DPD retry interval.
                type: str
            eap:
                description:
                    - Enable/disable IKEv2 EAP authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_cert_auth:
                description:
                    - Enable/disable peer certificate authentication in addition to EAP if peer is a FortiClient endpoint.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_exclude_peergrp:
                description:
                    - Peer group excluded from EAP authentication. Source user.peergrp.name.
                type: str
            eap_identity:
                description:
                    - IKEv2 EAP peer identity type.
                type: str
                choices:
                    - 'use-id-payload'
                    - 'send-request'
            ems_sn_check:
                description:
                    - Enable/disable verification of EMS serial number.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            enforce_unique_id:
                description:
                    - Enable/disable peer ID uniqueness check.
                type: str
                choices:
                    - 'disable'
                    - 'keep-new'
                    - 'keep-old'
            esn:
                description:
                    - Extended sequence number (ESN) negotiation.
                type: str
                choices:
                    - 'require'
                    - 'allow'
                    - 'disable'
            exchange_fgt_device_id:
                description:
                    - Enable/disable device identifier exchange with peer FortiGate units for use of VPN monitor data by FortiManager.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fallback_tcp_threshold:
                description:
                    - Timeout in seconds before falling back IKE/IPsec traffic to tcp.
                type: int
            fec_base:
                description:
                    - Number of base Forward Error Correction packets (1 - 20).
                type: int
            fec_codec:
                description:
                    - Forward Error Correction encoding/decoding algorithm.
                type: str
                choices:
                    - 'rs'
                    - 'xor'
            fec_egress:
                description:
                    - Enable/disable Forward Error Correction for egress IPsec traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fec_health_check:
                description:
                    - SD-WAN health check. Source system.sdwan.health-check.name.
                type: str
            fec_ingress:
                description:
                    - Enable/disable Forward Error Correction for ingress IPsec traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fec_mapping_profile:
                description:
                    - Forward Error Correction (FEC) mapping profile. Source vpn.ipsec.fec.name.
                type: str
            fec_receive_timeout:
                description:
                    - Timeout in milliseconds before dropping Forward Error Correction packets (1 - 1000).
                type: int
            fec_redundant:
                description:
                    - Number of redundant Forward Error Correction packets (1 - 5 for reed-solomon, 1 for xor).
                type: int
            fec_send_timeout:
                description:
                    - Timeout in milliseconds before sending Forward Error Correction packets (1 - 1000).
                type: int
            fgsp_sync:
                description:
                    - Enable/disable IPsec syncing of tunnels for FGSP IPsec.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_enforcement:
                description:
                    - Enable/disable FortiClient enforcement.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortinet_esp:
                description:
                    - Enable/disable Fortinet ESP encapsulaton.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fragmentation:
                description:
                    - Enable/disable fragment IKE message on re-transmission.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fragmentation_mtu:
                description:
                    - IKE fragmentation MTU (500 - 16000).
                type: int
            group_authentication:
                description:
                    - Enable/disable IKEv2 IDi group authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            group_authentication_secret:
                description:
                    - Password for IKEv2 ID group authentication. ASCII string or hexadecimal indicated by a leading 0x.
                type: str
            ha_sync_esp_seqno:
                description:
                    - Enable/disable sequence number jump ahead for IPsec HA.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            idle_timeout:
                description:
                    - Enable/disable IPsec tunnel idle timeout.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            idle_timeoutinterval:
                description:
                    - IPsec tunnel idle timeout in minutes (5 - 43200).
                type: int
            ike_version:
                description:
                    - IKE protocol version.
                type: str
                choices:
                    - '1'
                    - '2'
            inbound_dscp_copy:
                description:
                    - Enable/disable copy the dscp in the ESP header to the inner IP Header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            include_local_lan:
                description:
                    - Enable/disable allow local LAN access on unity clients.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                description:
                    - Local physical, aggregate, or VLAN outgoing interface. Source system.interface.name.
                type: str
            internal_domain_list:
                description:
                    - One or more internal domain names in quotes separated by spaces.
                type: list
                elements: dict
                suboptions:
                    domain_name:
                        description:
                            - Domain name.
                        required: true
                        type: str
            ip_delay_interval:
                description:
                    - IP address reuse delay interval in seconds (0 - 28800).
                type: int
            ipv4_dns_server1:
                description:
                    - IPv4 DNS server 1.
                type: str
            ipv4_dns_server2:
                description:
                    - IPv4 DNS server 2.
                type: str
            ipv4_dns_server3:
                description:
                    - IPv4 DNS server 3.
                type: str
            ipv4_end_ip:
                description:
                    - End of IPv4 range.
                type: str
            ipv4_exclude_range:
                description:
                    - Configuration Method IPv4 exclude ranges.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IPv4 exclusive range.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    start_ip:
                        description:
                            - Start of IPv4 exclusive range.
                        type: str
            ipv4_name:
                description:
                    - IPv4 address name. Source firewall.address.name firewall.addrgrp.name.
                type: str
            ipv4_netmask:
                description:
                    - IPv4 Netmask.
                type: str
            ipv4_split_exclude:
                description:
                    - IPv4 subnets that should not be sent over the IPsec tunnel. Source firewall.address.name firewall.addrgrp.name.
                type: str
            ipv4_split_include:
                description:
                    - IPv4 split-include subnets. Source firewall.address.name firewall.addrgrp.name.
                type: str
            ipv4_start_ip:
                description:
                    - Start of IPv4 range.
                type: str
            ipv4_wins_server1:
                description:
                    - WINS server 1.
                type: str
            ipv4_wins_server2:
                description:
                    - WINS server 2.
                type: str
            ipv6_auto_linklocal:
                description:
                    - Enable/disable auto generation of IPv6 link-local address using last 8 bytes of mode-cfg assigned IPv6 address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_dns_server1:
                description:
                    - IPv6 DNS server 1.
                type: str
            ipv6_dns_server2:
                description:
                    - IPv6 DNS server 2.
                type: str
            ipv6_dns_server3:
                description:
                    - IPv6 DNS server 3.
                type: str
            ipv6_end_ip:
                description:
                    - End of IPv6 range.
                type: str
            ipv6_exclude_range:
                description:
                    - Configuration method IPv6 exclude ranges.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IPv6 exclusive range.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    start_ip:
                        description:
                            - Start of IPv6 exclusive range.
                        type: str
            ipv6_name:
                description:
                    - IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            ipv6_prefix:
                description:
                    - IPv6 prefix.
                type: int
            ipv6_split_exclude:
                description:
                    - IPv6 subnets that should not be sent over the IPsec tunnel. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            ipv6_split_include:
                description:
                    - IPv6 split-include subnets. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            ipv6_start_ip:
                description:
                    - Start of IPv6 range.
                type: str
            keepalive:
                description:
                    - NAT-T keep alive interval.
                type: int
            keylife:
                description:
                    - Time to wait in seconds before phase 1 encryption key expires.
                type: int
            kms:
                description:
                    - Key Management Services server. Source vpn.kmip-server.name.
                type: str
            link_cost:
                description:
                    - VPN tunnel underlay link cost.
                type: int
            local_gw:
                description:
                    - Local VPN gateway.
                type: str
            localid:
                description:
                    - Local ID.
                type: str
            localid_type:
                description:
                    - Local ID type.
                type: str
                choices:
                    - 'auto'
                    - 'fqdn'
                    - 'user-fqdn'
                    - 'keyid'
                    - 'address'
                    - 'asn1dn'
            loopback_asymroute:
                description:
                    - Enable/disable asymmetric routing for IKE traffic on loopback interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mesh_selector_type:
                description:
                    - Add selectors containing subsets of the configuration depending on traffic.
                type: str
                choices:
                    - 'disable'
                    - 'subnet'
                    - 'host'
            mode:
                description:
                    - ID protection mode used to establish a secure channel.
                type: str
                choices:
                    - 'aggressive'
                    - 'main'
            mode_cfg:
                description:
                    - Enable/disable configuration method.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            mode_cfg_allow_client_selector:
                description:
                    - Enable/disable mode-cfg client to use custom phase2 selectors.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - IPsec remote gateway name.
                required: true
                type: str
            nattraversal:
                description:
                    - Enable/disable NAT traversal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'forced'
            negotiate_timeout:
                description:
                    - IKE SA negotiation timeout in seconds (1 - 300).
                type: int
            network_id:
                description:
                    - VPN gateway network ID.
                type: int
            network_overlay:
                description:
                    - Enable/disable network overlays.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            npu_offload:
                description:
                    - Enable/disable offloading NPU.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            peer:
                description:
                    - Accept this peer certificate. Source user.peer.name.
                type: str
            peergrp:
                description:
                    - Accept this peer certificate group. Source user.peergrp.name.
                type: str
            peerid:
                description:
                    - Accept this peer identity.
                type: str
            peertype:
                description:
                    - Accept this peer type.
                type: str
                choices:
                    - 'any'
                    - 'one'
                    - 'dialup'
                    - 'peer'
                    - 'peergrp'
            ppk:
                description:
                    - Enable/disable IKEv2 Postquantum Preshared Key (PPK).
                type: str
                choices:
                    - 'disable'
                    - 'allow'
                    - 'require'
            ppk_identity:
                description:
                    - IKEv2 Postquantum Preshared Key Identity.
                type: str
            ppk_secret:
                description:
                    - IKEv2 Postquantum Preshared Key (ASCII string or hexadecimal encoded with a leading 0x).
                type: str
            priority:
                description:
                    - Priority for routes added by IKE (1 - 65535).
                type: int
            proposal:
                description:
                    - Phase1 proposal.
                type: list
                elements: str
                choices:
                    - 'des-md5'
                    - 'des-sha1'
                    - 'des-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-md5'
                    - '3des-sha1'
                    - '3des-sha256'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes128-sha256'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes128gcm-prfsha1'
                    - 'aes128gcm-prfsha256'
                    - 'aes128gcm-prfsha384'
                    - 'aes128gcm-prfsha512'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes192-sha256'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'aes256-sha256'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'aes256gcm-prfsha1'
                    - 'aes256gcm-prfsha256'
                    - 'aes256gcm-prfsha384'
                    - 'aes256gcm-prfsha512'
                    - 'chacha20poly1305-prfsha1'
                    - 'chacha20poly1305-prfsha256'
                    - 'chacha20poly1305-prfsha384'
                    - 'chacha20poly1305-prfsha512'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
            psksecret:
                description:
                    - Pre-shared secret for PSK authentication (ASCII string or hexadecimal encoded with a leading 0x).
                type: str
            psksecret_remote:
                description:
                    - Pre-shared secret for remote side PSK authentication (ASCII string or hexadecimal encoded with a leading 0x).
                type: str
            qkd:
                description:
                    - Enable/disable use of Quantum Key Distribution (QKD) server.
                type: str
                choices:
                    - 'disable'
                    - 'allow'
                    - 'require'
            qkd_hybrid:
                description:
                    - Enable/disable use of Quantum Key Distribution (QKD) hybrid keys.
                type: str
                choices:
                    - 'disable'
                    - 'allow'
                    - 'require'
            qkd_profile:
                description:
                    - Quantum Key Distribution (QKD) server profile. Source vpn.qkd.name.
                type: str
            reauth:
                description:
                    - Enable/disable re-authentication upon IKE SA lifetime expiration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            rekey:
                description:
                    - Enable/disable phase1 rekey.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            remote_gw:
                description:
                    - Remote VPN gateway.
                type: str
            remote_gw_country:
                description:
                    - IPv4 addresses associated to a specific country.
                type: str
            remote_gw_end_ip:
                description:
                    - Last IPv4 address in the range.
                type: str
            remote_gw_match:
                description:
                    - Set type of IPv4 remote gateway address matching.
                type: str
                choices:
                    - 'any'
                    - 'ipmask'
                    - 'iprange'
                    - 'geography'
                    - 'ztna'
            remote_gw_start_ip:
                description:
                    - First IPv4 address in the range.
                type: str
            remote_gw_subnet:
                description:
                    - IPv4 address and subnet mask.
                type: str
            remote_gw_ztna_tags:
                description:
                    - IPv4 ZTNA posture tags.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            remote_gw6_country:
                description:
                    - IPv6 addresses associated to a specific country.
                type: str
            remote_gw6_end_ip:
                description:
                    - Last IPv6 address in the range.
                type: str
            remote_gw6_match:
                description:
                    - Set type of IPv6 remote gateway address matching.
                type: str
                choices:
                    - 'any'
                    - 'ipprefix'
                    - 'iprange'
                    - 'geography'
            remote_gw6_start_ip:
                description:
                    - First IPv6 address in the range.
                type: str
            remote_gw6_subnet:
                description:
                    - IPv6 address and prefix.
                type: str
            remotegw_ddns:
                description:
                    - Domain name of remote gateway. For example, name.ddns.com.
                type: str
            rsa_signature_format:
                description:
                    - Digital Signature Authentication RSA signature format.
                type: str
                choices:
                    - 'pkcs1'
                    - 'pss'
            rsa_signature_hash_override:
                description:
                    - Enable/disable IKEv2 RSA signature hash algorithm override.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            save_password:
                description:
                    - Enable/disable saving XAuth username and password on VPN clients.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            send_cert_chain:
                description:
                    - Enable/disable sending certificate chain.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            shared_idle_timeout:
                description:
                    - Enable/disable IPsec tunnel shared idle timeout.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            signature_hash_alg:
                description:
                    - Digital Signature Authentication hash algorithms.
                type: list
                elements: str
                choices:
                    - 'sha1'
                    - 'sha2-256'
                    - 'sha2-384'
                    - 'sha2-512'
            split_include_service:
                description:
                    - Split-include services. Source firewall.service.group.name firewall.service.custom.name.
                type: str
            suite_b:
                description:
                    - Use Suite-B.
                type: str
                choices:
                    - 'disable'
                    - 'suite-b-gcm-128'
                    - 'suite-b-gcm-256'
            transport:
                description:
                    - Set IKE transport protocol.
                type: str
                choices:
                    - 'udp'
                    - 'auto'
                    - 'tcp'
                    - 'udp-fallback-tcp'
            type:
                description:
                    - Remote gateway type.
                type: str
                choices:
                    - 'static'
                    - 'dynamic'
                    - 'ddns'
            unity_support:
                description:
                    - Enable/disable support for Cisco UNITY Configuration Method extensions.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            usrgrp:
                description:
                    - User group name for dialup peers. Source user.group.name.
                type: str
            wizard_type:
                description:
                    - GUI VPN Wizard Type.
                type: str
                choices:
                    - 'custom'
                    - 'dialup-forticlient'
                    - 'dialup-ios'
                    - 'dialup-android'
                    - 'dialup-windows'
                    - 'dialup-cisco'
                    - 'static-fortigate'
                    - 'dialup-fortigate'
                    - 'static-cisco'
                    - 'dialup-cisco-fw'
                    - 'simplified-static-fortigate'
                    - 'hub-fortigate-auto-discovery'
                    - 'spoke-fortigate-auto-discovery'
                    - 'fabric-overlay-orchestrator'
            xauthtype:
                description:
                    - XAuth type.
                type: str
                choices:
                    - 'disable'
                    - 'client'
                    - 'pap'
                    - 'chap'
                    - 'auto'
"""

EXAMPLES = """
- name: Configure VPN remote gateway.
  fortinet.fortios.fortios_vpn_ipsec_phase1:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ipsec_phase1:
          acct_verify: "enable"
          add_gw_route: "enable"
          add_route: "disable"
          addke1: "0"
          addke2: "0"
          addke3: "0"
          addke4: "0"
          addke5: "0"
          addke6: "0"
          addke7: "0"
          assign_ip: "disable"
          assign_ip_from: "range"
          authmethod: "psk"
          authmethod_remote: "psk"
          authpasswd: "<your_own_value>"
          authusr: "<your_own_value>"
          authusrgrp: "<your_own_value> (source user.group.name)"
          auto_negotiate: "enable"
          auto_transport_threshold: "15"
          azure_ad_autoconnect: "enable"
          backup_gateway:
              -
                  address: "<your_own_value>"
          banner: "<your_own_value>"
          cert_id_validation: "enable"
          cert_peer_username_strip: "disable"
          cert_peer_username_validation: "none"
          cert_trust_store: "local"
          certificate:
              -
                  name: "default_name_31 (source vpn.certificate.local.name)"
          childless_ike: "enable"
          client_auto_negotiate: "disable"
          client_keep_alive: "disable"
          client_resume: "enable"
          client_resume_interval: "7200"
          comments: "<your_own_value>"
          dev_id: "<your_own_value>"
          dev_id_notification: "disable"
          dhcp_ra_giaddr: "<your_own_value>"
          dhcp6_ra_linkaddr: "<your_own_value>"
          dhgrp: "1"
          digital_signature_auth: "enable"
          distance: "15"
          dns_mode: "manual"
          dns_suffix_search:
              -
                  dns_suffix: "<your_own_value>"
          domain: "<your_own_value>"
          dpd: "disable"
          dpd_retrycount: "3"
          dpd_retryinterval: "<your_own_value>"
          eap: "enable"
          eap_cert_auth: "enable"
          eap_exclude_peergrp: "<your_own_value> (source user.peergrp.name)"
          eap_identity: "use-id-payload"
          ems_sn_check: "enable"
          enforce_unique_id: "disable"
          esn: "require"
          exchange_fgt_device_id: "enable"
          fallback_tcp_threshold: "15"
          fec_base: "10"
          fec_codec: "rs"
          fec_egress: "enable"
          fec_health_check: "<your_own_value> (source system.sdwan.health-check.name)"
          fec_ingress: "enable"
          fec_mapping_profile: "<your_own_value> (source vpn.ipsec.fec.name)"
          fec_receive_timeout: "50"
          fec_redundant: "1"
          fec_send_timeout: "5"
          fgsp_sync: "enable"
          forticlient_enforcement: "enable"
          fortinet_esp: "enable"
          fragmentation: "enable"
          fragmentation_mtu: "1200"
          group_authentication: "enable"
          group_authentication_secret: "<your_own_value>"
          ha_sync_esp_seqno: "enable"
          idle_timeout: "enable"
          idle_timeoutinterval: "15"
          ike_version: "1"
          inbound_dscp_copy: "enable"
          include_local_lan: "disable"
          interface: "<your_own_value> (source system.interface.name)"
          internal_domain_list:
              -
                  domain_name: "<your_own_value>"
          ip_delay_interval: "0"
          ipv4_dns_server1: "<your_own_value>"
          ipv4_dns_server2: "<your_own_value>"
          ipv4_dns_server3: "<your_own_value>"
          ipv4_end_ip: "<your_own_value>"
          ipv4_exclude_range:
              -
                  end_ip: "<your_own_value>"
                  id: "93"
                  start_ip: "<your_own_value>"
          ipv4_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          ipv4_netmask: "<your_own_value>"
          ipv4_split_exclude: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          ipv4_split_include: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          ipv4_start_ip: "<your_own_value>"
          ipv4_wins_server1: "<your_own_value>"
          ipv4_wins_server2: "<your_own_value>"
          ipv6_auto_linklocal: "enable"
          ipv6_dns_server1: "<your_own_value>"
          ipv6_dns_server2: "<your_own_value>"
          ipv6_dns_server3: "<your_own_value>"
          ipv6_end_ip: "<your_own_value>"
          ipv6_exclude_range:
              -
                  end_ip: "<your_own_value>"
                  id: "109"
                  start_ip: "<your_own_value>"
          ipv6_name: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          ipv6_prefix: "128"
          ipv6_split_exclude: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          ipv6_split_include: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          ipv6_start_ip: "<your_own_value>"
          keepalive: "10"
          keylife: "86400"
          kms: "<your_own_value> (source vpn.kmip-server.name)"
          link_cost: "0"
          local_gw: "<your_own_value>"
          localid: "<your_own_value>"
          localid_type: "auto"
          loopback_asymroute: "enable"
          mesh_selector_type: "disable"
          mode: "aggressive"
          mode_cfg: "disable"
          mode_cfg_allow_client_selector: "disable"
          name: "default_name_128"
          nattraversal: "enable"
          negotiate_timeout: "30"
          network_id: "0"
          network_overlay: "disable"
          npu_offload: "enable"
          peer: "<your_own_value> (source user.peer.name)"
          peergrp: "<your_own_value> (source user.peergrp.name)"
          peerid: "<your_own_value>"
          peertype: "any"
          ppk: "disable"
          ppk_identity: "<your_own_value>"
          ppk_secret: "<your_own_value>"
          priority: "1"
          proposal: "des-md5"
          psksecret: "<your_own_value>"
          psksecret_remote: "<your_own_value>"
          qkd: "disable"
          qkd_hybrid: "disable"
          qkd_profile: "<your_own_value> (source vpn.qkd.name)"
          reauth: "disable"
          rekey: "enable"
          remote_gw: "<your_own_value>"
          remote_gw_country: "<your_own_value>"
          remote_gw_end_ip: "<your_own_value>"
          remote_gw_match: "any"
          remote_gw_start_ip: "<your_own_value>"
          remote_gw_subnet: "<your_own_value>"
          remote_gw_ztna_tags:
              -
                  name: "default_name_157 (source firewall.address.name firewall.addrgrp.name)"
          remote_gw6_country: "<your_own_value>"
          remote_gw6_end_ip: "<your_own_value>"
          remote_gw6_match: "any"
          remote_gw6_start_ip: "<your_own_value>"
          remote_gw6_subnet: "<your_own_value>"
          remotegw_ddns: "<your_own_value>"
          rsa_signature_format: "pkcs1"
          rsa_signature_hash_override: "enable"
          save_password: "disable"
          send_cert_chain: "enable"
          shared_idle_timeout: "enable"
          signature_hash_alg: "sha1"
          split_include_service: "<your_own_value> (source firewall.service.group.name firewall.service.custom.name)"
          suite_b: "disable"
          transport: "udp"
          type: "static"
          unity_support: "disable"
          usrgrp: "<your_own_value> (source user.group.name)"
          wizard_type: "custom"
          xauthtype: "disable"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_vpn_ipsec_phase1_data(json):
    option_list = [
        "acct_verify",
        "add_gw_route",
        "add_route",
        "addke1",
        "addke2",
        "addke3",
        "addke4",
        "addke5",
        "addke6",
        "addke7",
        "assign_ip",
        "assign_ip_from",
        "authmethod",
        "authmethod_remote",
        "authpasswd",
        "authusr",
        "authusrgrp",
        "auto_negotiate",
        "auto_transport_threshold",
        "azure_ad_autoconnect",
        "backup_gateway",
        "banner",
        "cert_id_validation",
        "cert_peer_username_strip",
        "cert_peer_username_validation",
        "cert_trust_store",
        "certificate",
        "childless_ike",
        "client_auto_negotiate",
        "client_keep_alive",
        "client_resume",
        "client_resume_interval",
        "comments",
        "dev_id",
        "dev_id_notification",
        "dhcp_ra_giaddr",
        "dhcp6_ra_linkaddr",
        "dhgrp",
        "digital_signature_auth",
        "distance",
        "dns_mode",
        "dns_suffix_search",
        "domain",
        "dpd",
        "dpd_retrycount",
        "dpd_retryinterval",
        "eap",
        "eap_cert_auth",
        "eap_exclude_peergrp",
        "eap_identity",
        "ems_sn_check",
        "enforce_unique_id",
        "esn",
        "exchange_fgt_device_id",
        "fallback_tcp_threshold",
        "fec_base",
        "fec_codec",
        "fec_egress",
        "fec_health_check",
        "fec_ingress",
        "fec_mapping_profile",
        "fec_receive_timeout",
        "fec_redundant",
        "fec_send_timeout",
        "fgsp_sync",
        "forticlient_enforcement",
        "fortinet_esp",
        "fragmentation",
        "fragmentation_mtu",
        "group_authentication",
        "group_authentication_secret",
        "ha_sync_esp_seqno",
        "idle_timeout",
        "idle_timeoutinterval",
        "ike_version",
        "inbound_dscp_copy",
        "include_local_lan",
        "interface",
        "internal_domain_list",
        "ip_delay_interval",
        "ipv4_dns_server1",
        "ipv4_dns_server2",
        "ipv4_dns_server3",
        "ipv4_end_ip",
        "ipv4_exclude_range",
        "ipv4_name",
        "ipv4_netmask",
        "ipv4_split_exclude",
        "ipv4_split_include",
        "ipv4_start_ip",
        "ipv4_wins_server1",
        "ipv4_wins_server2",
        "ipv6_auto_linklocal",
        "ipv6_dns_server1",
        "ipv6_dns_server2",
        "ipv6_dns_server3",
        "ipv6_end_ip",
        "ipv6_exclude_range",
        "ipv6_name",
        "ipv6_prefix",
        "ipv6_split_exclude",
        "ipv6_split_include",
        "ipv6_start_ip",
        "keepalive",
        "keylife",
        "kms",
        "link_cost",
        "local_gw",
        "localid",
        "localid_type",
        "loopback_asymroute",
        "mesh_selector_type",
        "mode",
        "mode_cfg",
        "mode_cfg_allow_client_selector",
        "name",
        "nattraversal",
        "negotiate_timeout",
        "network_id",
        "network_overlay",
        "npu_offload",
        "peer",
        "peergrp",
        "peerid",
        "peertype",
        "ppk",
        "ppk_identity",
        "ppk_secret",
        "priority",
        "proposal",
        "psksecret",
        "psksecret_remote",
        "qkd",
        "qkd_hybrid",
        "qkd_profile",
        "reauth",
        "rekey",
        "remote_gw",
        "remote_gw_country",
        "remote_gw_end_ip",
        "remote_gw_match",
        "remote_gw_start_ip",
        "remote_gw_subnet",
        "remote_gw_ztna_tags",
        "remote_gw6_country",
        "remote_gw6_end_ip",
        "remote_gw6_match",
        "remote_gw6_start_ip",
        "remote_gw6_subnet",
        "remotegw_ddns",
        "rsa_signature_format",
        "rsa_signature_hash_override",
        "save_password",
        "send_cert_chain",
        "shared_idle_timeout",
        "signature_hash_alg",
        "split_include_service",
        "suite_b",
        "transport",
        "type",
        "unity_support",
        "usrgrp",
        "wizard_type",
        "xauthtype",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["proposal"],
        ["dhgrp"],
        ["addke1"],
        ["addke2"],
        ["addke3"],
        ["addke4"],
        ["addke5"],
        ["addke6"],
        ["addke7"],
        ["signature_hash_alg"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def vpn_ipsec_phase1(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_ipsec_phase1_data = data["vpn_ipsec_phase1"]

    filtered_data = filter_vpn_ipsec_phase1_data(vpn_ipsec_phase1_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.ipsec", "phase1", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.ipsec", "phase1", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["vpn_ipsec_phase1"] = filtered_data
    fos.do_member_operation(
        "vpn.ipsec",
        "phase1",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("vpn.ipsec", "phase1", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("vpn.ipsec", "phase1", mkey=converted_data["name"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_vpn_ipsec(data, fos, check_mode):

    if data["vpn_ipsec_phase1"]:
        resp = vpn_ipsec_phase1(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_ipsec_phase1"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "static"}, {"value": "dynamic"}, {"value": "ddns"}],
        },
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ike_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "1"}, {"value": "2"}],
        },
        "remote_gw": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "local_gw": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "remotegw_ddns": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "keylife": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "certificate": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "authmethod": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "psk"}, {"value": "signature"}],
        },
        "authmethod_remote": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "psk"}, {"value": "signature"}],
        },
        "mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "aggressive"}, {"value": "main"}],
        },
        "peertype": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "any"},
                {"value": "one"},
                {"value": "dialup"},
                {"value": "peer"},
                {"value": "peergrp"},
            ],
        },
        "peerid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "usrgrp": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "peer": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "peergrp": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mode_cfg": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mode_cfg_allow_client_selector": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "assign_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "assign_ip_from": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "range"},
                {"value": "usrgrp"},
                {"value": "dhcp"},
                {"value": "name"},
            ],
        },
        "ipv4_start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_netmask": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dhcp_ra_giaddr": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
        },
        "dhcp6_ra_linkaddr": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
        },
        "dns_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "manual"}, {"value": "auto"}],
        },
        "ipv4_dns_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_dns_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_dns_server3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "internal_domain_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "domain_name": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.1", ""]],
        },
        "dns_suffix_search": {
            "type": "list",
            "elements": "dict",
            "children": {
                "dns_suffix": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "ipv4_wins_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_wins_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_exclude_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ipv4_split_include": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "split_include_service": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv4_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_prefix": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipv6_dns_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_dns_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_dns_server3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_exclude_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ipv6_split_include": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip_delay_interval": {"v_range": [["v7.0.1", ""]], "type": "integer"},
        "unity_support": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "domain": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "banner": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "include_local_lan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ipv4_split_exclude": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ipv6_split_exclude": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "save_password": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "client_auto_negotiate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "client_keep_alive": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "backup_gateway": {
            "type": "list",
            "elements": "dict",
            "children": {
                "address": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "proposal": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "des-md5"},
                {"value": "des-sha1"},
                {"value": "des-sha256"},
                {"value": "des-sha384"},
                {"value": "des-sha512"},
                {"value": "3des-md5"},
                {"value": "3des-sha1"},
                {"value": "3des-sha256"},
                {"value": "3des-sha384"},
                {"value": "3des-sha512"},
                {"value": "aes128-md5"},
                {"value": "aes128-sha1"},
                {"value": "aes128-sha256"},
                {"value": "aes128-sha384"},
                {"value": "aes128-sha512"},
                {"value": "aes128gcm-prfsha1"},
                {"value": "aes128gcm-prfsha256"},
                {"value": "aes128gcm-prfsha384"},
                {"value": "aes128gcm-prfsha512"},
                {"value": "aes192-md5"},
                {"value": "aes192-sha1"},
                {"value": "aes192-sha256"},
                {"value": "aes192-sha384"},
                {"value": "aes192-sha512"},
                {"value": "aes256-md5"},
                {"value": "aes256-sha1"},
                {"value": "aes256-sha256"},
                {"value": "aes256-sha384"},
                {"value": "aes256-sha512"},
                {"value": "aes256gcm-prfsha1"},
                {"value": "aes256gcm-prfsha256"},
                {"value": "aes256gcm-prfsha384"},
                {"value": "aes256gcm-prfsha512"},
                {"value": "chacha20poly1305-prfsha1"},
                {"value": "chacha20poly1305-prfsha256"},
                {"value": "chacha20poly1305-prfsha384"},
                {"value": "chacha20poly1305-prfsha512"},
                {"value": "aria128-md5"},
                {"value": "aria128-sha1"},
                {"value": "aria128-sha256"},
                {"value": "aria128-sha384"},
                {"value": "aria128-sha512"},
                {"value": "aria192-md5"},
                {"value": "aria192-sha1"},
                {"value": "aria192-sha256"},
                {"value": "aria192-sha384"},
                {"value": "aria192-sha512"},
                {"value": "aria256-md5"},
                {"value": "aria256-sha1"},
                {"value": "aria256-sha256"},
                {"value": "aria256-sha384"},
                {"value": "aria256-sha512"},
                {"value": "seed-md5"},
                {"value": "seed-sha1"},
                {"value": "seed-sha256"},
                {"value": "seed-sha384"},
                {"value": "seed-sha512"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "add_route": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "add_gw_route": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "psksecret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "psksecret_remote": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "keepalive": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "localid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "localid_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "fqdn"},
                {"value": "user-fqdn"},
                {"value": "keyid"},
                {"value": "address"},
                {"value": "asn1dn"},
            ],
        },
        "auto_negotiate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "negotiate_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fragmentation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dpd": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "on-idle"},
                {"value": "on-demand"},
            ],
        },
        "dpd_retrycount": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dpd_retryinterval": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "npu_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "send_cert_chain": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "1"},
                {"value": "2"},
                {"value": "5"},
                {"value": "14"},
                {"value": "15"},
                {"value": "16"},
                {"value": "17"},
                {"value": "18"},
                {"value": "19"},
                {"value": "20"},
                {"value": "21"},
                {"value": "27"},
                {"value": "28"},
                {"value": "29"},
                {"value": "30"},
                {"value": "31"},
                {"value": "32", "v_range": [["v6.2.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke1": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke2": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke3": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke4": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke5": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke6": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke7": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "suite_b": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "suite-b-gcm-128"},
                {"value": "suite-b-gcm-256"},
            ],
        },
        "eap": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eap_identity": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "use-id-payload"}, {"value": "send-request"}],
        },
        "eap_exclude_peergrp": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "eap_cert_auth": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "acct_verify": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ppk": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "allow"}, {"value": "require"}],
        },
        "ppk_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ppk_identity": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wizard_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "custom"},
                {"value": "dialup-forticlient"},
                {"value": "dialup-ios"},
                {"value": "dialup-android"},
                {"value": "dialup-windows"},
                {"value": "dialup-cisco"},
                {"value": "static-fortigate"},
                {"value": "dialup-fortigate"},
                {"value": "static-cisco"},
                {"value": "dialup-cisco-fw"},
                {"value": "simplified-static-fortigate", "v_range": [["v6.2.0", ""]]},
                {"value": "hub-fortigate-auto-discovery", "v_range": [["v6.2.0", ""]]},
                {
                    "value": "spoke-fortigate-auto-discovery",
                    "v_range": [["v6.2.0", ""]],
                },
                {"value": "fabric-overlay-orchestrator", "v_range": [["v7.6.1", ""]]},
            ],
        },
        "xauthtype": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "client"},
                {"value": "pap"},
                {"value": "chap"},
                {"value": "auto"},
            ],
        },
        "reauth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "authusr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "authpasswd": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "group_authentication": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "group_authentication_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "authusrgrp": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mesh_selector_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "subnet"}, {"value": "host"}],
        },
        "idle_timeout": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "shared_idle_timeout": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "idle_timeoutinterval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ha_sync_esp_seqno": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fgsp_sync": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "inbound_dscp_copy": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nattraversal": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}, {"value": "forced"}],
        },
        "esn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "require"}, {"value": "allow"}, {"value": "disable"}],
        },
        "fragmentation_mtu": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "childless_ike": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "azure_ad_autoconnect": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_resume": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_resume_interval": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "rekey": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "digital_signature_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "signature_hash_alg": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "sha1"},
                {"value": "sha2-256"},
                {"value": "sha2-384"},
                {"value": "sha2-512"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rsa_signature_format": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pkcs1"}, {"value": "pss"}],
        },
        "rsa_signature_hash_override": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "enforce_unique_id": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "keep-new"},
                {"value": "keep-old"},
            ],
        },
        "cert_id_validation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fec_egress": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fec_send_timeout": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "fec_base": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "fec_codec": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "rs", "v_range": [["v7.0.2", ""]]},
                {"value": "xor", "v_range": [["v7.0.2", ""]]},
            ],
        },
        "fec_redundant": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "fec_ingress": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fec_receive_timeout": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "fec_health_check": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "fec_mapping_profile": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "network_overlay": {
            "v_range": [["v6.2.0", "v7.0.1"], ["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "network_id": {
            "v_range": [["v6.2.0", "v7.0.1"], ["v7.4.2", ""]],
            "type": "integer",
        },
        "dev_id_notification": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dev_id": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "loopback_asymroute": {
            "v_range": [["v7.0.0", "v7.0.1"], ["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "link_cost": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "kms": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "exchange_fgt_device_id": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_auto_linklocal": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ems_sn_check": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cert_trust_store": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "local"}, {"value": "ems"}],
        },
        "qkd": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "allow"}, {"value": "require"}],
        },
        "qkd_hybrid": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "allow"}, {"value": "require"}],
        },
        "qkd_profile": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "transport": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [
                {"value": "udp"},
                {"value": "auto", "v_range": [["v7.6.0", ""]]},
                {"value": "tcp"},
                {"value": "udp-fallback-tcp", "v_range": [["v7.4.2", "v7.4.4"]]},
            ],
        },
        "fortinet_esp": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_transport_threshold": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "remote_gw_match": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "any"},
                {"value": "ipmask"},
                {"value": "iprange"},
                {"value": "geography"},
                {"value": "ztna", "v_range": [["v7.6.0", ""]]},
            ],
        },
        "remote_gw_subnet": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw_start_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw_end_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw_country": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw_ztna_tags": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", ""]],
        },
        "remote_gw6_match": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "any"},
                {"value": "ipprefix"},
                {"value": "iprange"},
                {"value": "geography"},
            ],
        },
        "remote_gw6_subnet": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw6_start_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw6_end_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "remote_gw6_country": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "cert_peer_username_validation": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "othername"},
                {"value": "rfc822name"},
                {"value": "cn"},
            ],
        },
        "cert_peer_username_strip": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "fallback_tcp_threshold": {
            "v_range": [["v7.4.2", "v7.4.4"]],
            "type": "integer",
        },
        "forticlient_enforcement": {
            "v_range": [["v6.0.0", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "vpn_ipsec_phase1": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_ipsec_phase1"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ipsec_phase1"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "vpn_ipsec_phase1"
        )

        is_error, has_changed, result, diff = fortios_vpn_ipsec(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
