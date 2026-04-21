#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_set_global_properties
short_description: Edit Global Properties.
description:
  - Edit Global Properties.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  firewall:
    description:
      - Add implied rules to or remove them from the Firewall Rule Base. Determine the position of the implied rules in the Rule Base, and whether or
        not to log them.
    type: dict
    suboptions:
      accept_control_connections:
        description:
          - Used for,<br>&nbsp;&nbsp;&nbsp;&nbsp; <ul><li> Installing the security policy from the Security Management server to the
            gateways.</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Sending logs from the gateways to the Security Management server.</li><br>&nbsp;&nbsp;&nbsp;&nbsp;
            <li> Communication between SmartConsole clients and the Security Management Server</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Communication between
            Firewall daemons on different machines (Security Management Server, Security Gateway).</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Connecting to OPSEC
            applications such as RADIUS and TACACS authentication servers.</li></ul>If you disable Accept Control Connections and you want Check Point
            components to communicate with each other and with OPSEC components, you must explicitly allow these connections in the Rule Base.
        type: bool
      accept_ips1_management_connections:
        description:
          - Accepts IPS-1 connections.<br>Available only if accept-control-connections is true.
        type: bool
      accept_remote_access_control_connections:
        description:
          - Accepts Remote Access connections.<br>Available only if accept-control-connections is true.
        type: bool
      accept_smart_update_connections:
        description:
          - Accepts SmartUpdate connections.
        type: bool
      accept_outgoing_packets_originating_from_gw:
        description:
          - Accepts all packets from connections that originate at the Check Point Security Gateway.
        type: bool
      accept_outgoing_packets_originating_from_gw_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-outgoing-packets-originating-from-gw is false.
        type: str
        choices: ['first', 'last', 'before last']
      accept_outgoing_packets_originating_from_connectra_gw:
        description:
          - Accepts outgoing packets originating from Connectra gateway.<br>Available only if accept-outgoing-packets-originating-from-gw is false.
        type: bool
      accept_outgoing_packets_to_cp_online_services:
        description:
          - Allow Security Gateways to access Check Point online services. Supported for R80.10 Gateway and higher.<br>Available only if
            accept-outgoing-packets-originating-from-gw is false.
        type: bool
      accept_outgoing_packets_to_cp_online_services_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-outgoing-packets-to-cp-online-services is true.
        type: str
        choices: ['first', 'last', 'before last']
      accept_domain_name_over_tcp:
        description:
          - Accepts Domain Name (DNS) queries and replies over TCP, to allow downloading of the domain name-resolving tables used for zone
            transfers between servers. For clients, DNS over TCP is only used if the tables to be transferred are very large.
        type: bool
      accept_domain_name_over_tcp_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-domain-name-over-tcp is true.
        type: str
        choices: ['first', 'last', 'before last']
      accept_domain_name_over_udp:
        description:
          - Accepts Domain Name (DNS) queries and replies over UDP.
        type: bool
      accept_domain_name_over_udp_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-domain-name-over-udp is true.
        type: str
        choices: ['first', 'last', 'before last']
      accept_dynamic_addr_modules_outgoing_internet_connections:
        description:
          - Accept Dynamic Address modules' outgoing internet connections.Accepts DHCP traffic for DAIP (Dynamically Assigned IP Address)
            gateways. In Small Office Appliance gateways, this rule allows outgoing DHCP, PPP, PPTP and L2TP Internet connections (regardless of whether it is
            or is not a DAIP gateway).
        type: bool
      accept_icmp_requests:
        description:
          - Accepts Internet Control Message Protocol messages.
        type: bool
      accept_icmp_requests_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-icmp-requests is true.
        type: str
        choices: ['first', 'last', 'before last']
      accept_identity_awareness_control_connections:
        description:
          - Accepts traffic between Security Gateways in distributed environment configurations of Identity Awareness.
        type: bool
      accept_identity_awareness_control_connections_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-identity-awareness-control-connections is true.
        type: str
        choices: ['first', 'last', 'before last']
      accept_incoming_traffic_to_dhcp_and_dns_services_of_gws:
        description:
          - Allows the Small Office Appliance gateway to provide DHCP relay, DHCP server and DNS proxy services regardless of the rule base.
        type: bool
      accept_rip:
        description:
          - Accepts Routing Information Protocol (RIP), using UDP on port 520.
        type: bool
      accept_rip_position:
        description:
          - The position of the implied rules in the Rule Base.<br>Available only if accept-rip is true.
        type: str
        choices: ['first', 'last', 'before last']
      accept_vrrp_packets_originating_from_cluster_members:
        description:
          - Selecting this option creates an implied rule in the security policy Rule Base that accepts VRRP inbound and outbound traffic to and
            from the members of the cluster.
        type: bool
      accept_web_and_ssh_connections_for_gw_administration:
        description:
          - Accepts Web and SSH connections for Small Office Appliance gateways.
        type: bool
      log_implied_rules:
        description:
          - Produces log records for communications that match the implied rules that are generated in the Rule Base from the properties defined
            in this window.
        type: bool
      security_server:
        description:
          - Control the welcome messages that users will see when logging in to servers behind Check Point Security Gateways.
        type: dict
        suboptions:
          client_auth_welcome_file:
            description:
              - Client authentication welcome file is the name of a file whose contents are to be displayed when a user begins a Client
                Authenticated session (optional) using the Manual Sign On Method. Client Authenticated Sessions initiated by Manual Sign On are not mediated
                by a security server.
            type: str
          ftp_welcome_msg_file:
            description:
              - FTP welcome message file is the name of a file whose contents are to be displayed when a user begins an Authenticated FTP session.
            type: str
          rlogin_welcome_msg_file:
            description:
              - Rlogin welcome message file is the name of a file whose contents are to be displayed when a user begins an Authenticated RLOGIN session.
            type: str
          telnet_welcome_msg_file:
            description:
              - Telnet welcome message file is the name of a file whose contents are to be displayed when a user begins an Authenticated Telnet session.
            type: str
          mdq_welcome_msg:
            description:
              - MDQ Welcome Message is the message to be displayed when a user begins an MDQ session. The MDQ Welcome Message should contain
                characters according to RFC 1035 and it must follow the ARPANET host name rules,<br>   - This message must begin with a number or letter.
                After the first letter or number character the remaining characters can be a letter, number, space, tab or hyphen.<br>   - This message must
                not end with a space or a tab and is limited to 63 characters.
            type: str
          smtp_welcome_msg:
            description:
              - SMTP Welcome Message is the message to be displayed when a user begins an SMTP session.
            type: str
          http_next_proxy_host:
            description:
              - HTTP next proxy host is the host name of the HTTP proxy behind the Check Point Security Gateway HTTP security server (if there
                is one). Changing the HTTP Next Proxy fields takes effect after the Security Gateway database is downloaded to the authenticating gateway, or
                after the security policy is re-installed. <br>These settings apply only to firewalled gateways prior to NG. For later versions, these
                settings should be defined in the Node Properties window.
               - Available from R82 management version.
            type: str
          http_next_proxy_port:
            description:
              - HTTP next proxy port is the port of the HTTP proxy behind the Check Point Security Gateway HTTP security server (if there is
                one). Changing the HTTP Next Proxy fields takes effect after the Security Gateway database is downloaded to the authenticating gateway, or
                after the security policy is re-installed. <br>These settings apply only to firewalled gateways prior to NG. For later versions, these
                settings should be defined in the Node Properties window.
              - Available from R82 management version.
            type: int
          http_servers:
            description:
              - This list specifies the HTTP servers. Defining HTTP servers allows you to restrict incoming HTTP.
            type: list
            elements: dict
            suboptions:
              logical_name:
                description:
                  - Unique Logical Name of the HTTP Server.
                type: str
              host:
                description:
                  - Host name of the HTTP Server.
                type: str
              port:
                description:
                  - Port number of the HTTP Server.
                type: int
              reauthentication:
                description:
                  - Specify whether users must reauthenticate when accessing a specific server.
                type: str
                choices: ['standard', 'post request', 'every request']
          server_for_null_requests:
            description:
              - The Logical Name of a Null Requests Server from http-servers.
            type: str
  nat:
    description:
      - Configure settings that apply to all NAT connections.
    type: dict
    suboptions:
      allow_bi_directional_nat:
        description:
          - Applies to automatic NAT rules in the NAT Rule Base, and allows two automatic NAT rules to match a connection. Without Bidirectional
            NAT, only one automatic NAT rule can match a connection.
        type: bool
      auto_arp_conf:
        description:
          - Ensures that ARP requests for a translated (NATed) machine, network or address range are answered by the Check Point Security Gateway.
        type: bool
      merge_manual_proxy_arp_conf:
        description:
          - Merges the automatic and manual ARP configurations. Manual proxy ARP configuration is required for manual Static NAT
            rules.<br>Available only if auto-arp-conf is true.
        type: bool
      auto_translate_dest_on_client_side:
        description:
          - Applies to packets originating at the client, with the server as its destination. Static NAT for the server is performed on the client side.
        type: bool
      manually_translate_dest_on_client_side:
        description:
          - Applies to packets originating at the client, with the server as its destination. Static NAT for the server is performed on the client side.
        type: bool
      enable_ip_pool_nat:
        description:
          - Applies to packets originating at the client, with the server as its destination. Static NAT for the server is performed on the client side.
        type: bool
      addr_alloc_and_release_track:
        description:
          - Specifies whether to log each allocation and release of an IP address from the IP Pool.<br>Available only if enable-ip-pool-nat is true.
        type: str
        choices: ['ip allocation log', 'none']
      addr_exhaustion_track:
        description:
          - Specifies the action to take if the IP Pool is exhausted.<br>Available only if enable-ip-pool-nat is true.
        type: str
        choices: ['ip exhaustion alert', 'none', 'ip exhaustion log']
  authentication:
    description:
      - Define Authentication properties that are common to all users and to the various ways that the Check Point Security Gateway asks for passwords
        (User, Client and Session Authentication).
    type: dict
    suboptions:
      auth_internal_users_with_specific_suffix:
        description:
          - Enforce suffix for internal users authentication.
        type: bool
      allowed_suffix_for_internal_users:
        description:
          - Suffix for internal users authentication.
        type: str
      max_days_before_expiration_of_non_pulled_user_certificates:
        description:
          - Users certificates which were initiated but not pulled will expire after the specified number of days. Any value from 1 to 60 days can
            be entered in this field.
        type: int
      max_client_auth_attempts_before_connection_termination:
        description:
          - Allowed Number of Failed Client Authentication Attempts Before Session Termination. Any value from 1 to 800 attempts can be entered in this field.
        type: int
      max_rlogin_attempts_before_connection_termination:
        description:
          - Allowed Number of Failed rlogin Attempts Before Session Termination. Any value from 1 to 800 attempts can be entered in this field.
        type: int
      max_session_auth_attempts_before_connection_termination:
        description:
          - Allowed Number of Failed Session Authentication Attempts Before Session Termination. Any value from 1 to 800 attempts can be entered in this field.
        type: int
      max_telnet_attempts_before_connection_termination:
        description:
          - Allowed Number of Failed telnet Attempts Before Session Termination. Any value from 1 to 800 attempts can be entered in this field.
        type: int
      enable_delayed_auth:
        description:
          - all authentications other than certificate-based authentications will be delayed by the specified time. Applying this delay will stall
            brute force authentication attacks. The delay is applied for both failed and successful authentication attempts.
        type: bool
      delay_each_auth_attempt_by:
        description:
          - Delay each authentication attempt by the specified number of milliseconds. Any value from 1 to 25000 can be entered in this field.
        type: int
  vpn:
    description:
      - Configure settings relevant to VPN.
    type: dict
    suboptions:
      vpn_conf_method:
        description:
          - Decide on Simplified or Traditional mode for all new security policies or decide which mode to use on a policy by policy basis.
        type: str
        choices: ['simplified', 'traditional', 'per policy']
      domain_name_for_dns_resolving:
        description:
          - Enter the domain name that will be used for gateways DNS lookup. The DNS host name that is used is "gateway_name.domain_name".
        type: str
      enable_backup_gw:
        description:
          - Enable Backup Gateway.
        type: bool
      enable_decrypt_on_accept_for_gw_to_gw_traffic:
        description:
          - Enable decrypt on accept for gateway to gateway traffic. This is only relevant for policies in traditional mode. In Traditional Mode,
            the 'Accept' action determines that a connection is allowed, while the 'Encrypt' action determines that a connection is allowed and encrypted.
            Select whether VPN accepts an encrypted packet that matches a rule with an 'Accept' action or drops it.
        type: bool
      enable_load_distribution_for_mep_conf:
        description:
          - Enable load distribution for Multiple Entry Points configurations (Site To Site connections). The VPN Multiple Entry Point (MEP)
            feature supplies high availability and load distribution for Check Point Security Gateways. MEP works in four modes,<br>&nbsp;&nbsp;&nbsp;&nbsp;
            <ul><li> First to Respond, in which the first gateway to reply to the peer gateway is chosen. An organization would choose this option if, for
            example, the organization has two gateways in a MEPed configuration - one in London, the other in New York. It makes sense for Check Point
            Security Gateway peers located in England to try the London gateway first and the NY gateway second. Being geographically closer to Check Point
            Security Gateway peers in England, the London gateway will be the first to respond, and becomes the entry point to the internal
            network.</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> VPN Domain, is when the destination IP belongs to a particular VPN domain, the gateway of that
            domain becomes the chosen entry point. This gateway becomes the primary gateway while other gateways in the MEP configuration become its backup
            gateways.</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Random Selection, in which the remote Check Point Security Gateway peer randomly selects a gateway
            with which to open a VPN connection. For each IP source/destination address pair, a new gateway is randomly selected. An organization might have a
            number of machines with equal performance abilities. In this case, it makes sense to enable load distribution. The machines are used in a random
            and equal way.</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Manually set priority list, gateway priorities can be set manually for the entire community
            or for individual satellite gateways.</li></ul>.
        type: bool
      enable_vpn_directional_match_in_vpn_column:
        description:
          - Enable VPN Directional Match in VPN Column.<br>Note, VPN Directional Match is supported only on Gaia, SecurePlatform, Linux and IPSO.
        type: bool
      grace_period_after_the_crl_is_not_valid:
        description:
          - When establishing VPN tunnels, the peer presents its certificate for authentication. The clock on the gateway machine must be
            synchronized with the clock on the Certificate Authority machine. Otherwise, the Certificate Revocation List (CRL) used for validating the peer's
            certificate may be considered invalid and thus the authentication fails. To resolve the issue of differing clock times, a Grace Period permits a
            wider window for CRL validity.
        type: int
      grace_period_before_the_crl_is_valid:
        description:
          - When establishing VPN tunnels, the peer presents its certificate for authentication. The clock on the gateway machine must be
            synchronized with the clock on the Certificate Authority machine. Otherwise, the Certificate Revocation List (CRL) used for validating the peer's
            certificate may be considered invalid and thus the authentication fails. To resolve the issue of differing clock times, a Grace Period permits a
            wider window for CRL validity.
        type: int
      grace_period_extension_for_secure_remote_secure_client:
        description:
          - When dealing with remote clients the Grace Period needs to be extended. The remote client sometimes relies on the peer gateway to
            supply the CRL. If the client's clock is not synchronized with the gateway's clock, a CRL that is considered valid by the gateway may be
            considered invalid by the client.
        type: int
      support_ike_dos_protection_from_identified_src:
        description:
          - When the number of IKE negotiations handled simultaneously exceeds a threshold above VPN's capacity, a gateway concludes that it is
            either under a high load or experiencing a Denial of Service attack. VPN can filter out peers that are the probable source of the potential Denial
            of Service attack. There are two kinds of protection,<br>&nbsp;&nbsp;&nbsp;&nbsp; <ul><li> Stateless - the peer has to respond to an IKE
            notification in a way that proves the peer's IP address is not spoofed. If the peer cannot prove this, VPN does not allocate resources for the IKE
            negotiation</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Puzzles - this is the same as Stateless, but in addition, the peer has to solve a mathematical
            puzzle. Solving this puzzle consumes peer CPU resources in a way that makes it difficult to initiate multiple IKE negotiations
            simultaneously.</li></ul>Puzzles is more secure then Stateless, but affects performance.<br>Since these kinds of attacks involve a new proprietary
            addition to the IKE protocol, enabling these protection mechanisms may cause difficulties with non Check Point VPN products or older versions of
            VPN.
        type: str
        choices: ['puzzles', 'stateless', 'none']
      support_ike_dos_protection_from_unidentified_src:
        description:
          - When the number of IKE negotiations handled simultaneously exceeds a threshold above VPN's capacity, a gateway concludes that it is
            either under a high load or experiencing a Denial of Service attack. VPN can filter out peers that are the probable source of the potential Denial
            of Service attack. There are two kinds of protection,<br>&nbsp;&nbsp;&nbsp;&nbsp; <ul><li> Stateless - the peer has to respond to an IKE
            notification in a way that proves the peer's IP address is not spoofed. If the peer cannot prove this, VPN does not allocate resources for the IKE
            negotiation</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li> Puzzles - this is the same as Stateless, but in addition, the peer has to solve a mathematical
            puzzle. Solving this puzzle consumes peer CPU resources in a way that makes it difficult to initiate multiple IKE negotiations
            simultaneously.</li></ul>Puzzles is more secure then Stateless, but affects performance.<br>Since these kinds of attacks involve a new proprietary
            addition to the IKE protocol, enabling these protection mechanisms may cause difficulties with non Check Point VPN products or older versions of
            VPN.
        type: str
        choices: ['puzzles', 'stateless', 'none']
  remote_access:
    description:
      - Configure Remote Access properties.
    type: dict
    suboptions:
      enable_back_connections:
        description:
          - Usually communication with remote clients must be initialized by the clients. However, once a client has opened a connection, the
            hosts behind VPN can open a return or back connection to the client. For a back connection, the client's details must be maintained on all the
            devices between the client and the gateway, and on the gateway itself. Determine whether the back connection is enabled.
        type: bool
      keep_alive_packet_to_gw_interval:
        description:
          - Usually communication with remote clients must be initialized by the clients. However, once a client has opened a connection, the
            hosts behind VPN can open a return or back connection to the client. For a back connection, the client's details must be maintained on all the
            devices between the client and the gateway, and on the gateway itself. Determine frequency (in seconds) of the Keep Alive packets sent by the
            client in order to maintain the connection with the gateway.<br>Available only if enable-back-connections is true.
        type: int
      encrypt_dns_traffic:
        description:
          - You can decide whether DNS queries sent by the remote client to a DNS server located on the corporate LAN are passed through the VPN
            tunnel or not. Disable this option if the client has to make DNS queries to the DNS server on the corporate LAN while connecting to the
            organization but without using the SecuRemote client.
        type: bool
      simultaneous_login_mode:
        description:
          - Select the simultaneous login mode.
        type: str
        choices: ['allowonlysinglelogintouser', 'allowseverallogintouser']
      vpn_authentication_and_encryption:
        description:
          - configure supported Encryption and Authentication methods for Remote Access clients.
        type: dict
        suboptions:
          encryption_algorithms:
            description:
              - Select the methods negotiated in IKE phase 2 and used in IPSec connections.
            type: dict
            suboptions:
              ike:
                description:
                  - Configure the IKE Phase 1 settings.
                type: dict
                suboptions:
                  support_encryption_algorithms:
                    description:
                      - Select the encryption algorithms that will be supported with remote hosts.
                    type: dict
                    suboptions:
                      tdes:
                        description:
                          - Select whether the Triple DES encryption algorithm will be supported with remote hosts.
                        type: bool
                      aes_128:
                        description:
                          - Select whether the AES-128 encryption algorithm will be supported with remote hosts.
                        type: bool
                      aes_256:
                        description:
                          - Select whether the AES-256 encryption algorithm will be supported with remote hosts.
                        type: bool
                      des:
                        description:
                          - Select whether the DES encryption algorithm will be supported with remote hosts.
                        type: bool
                  use_encryption_algorithm:
                    description:
                      - Choose the encryption algorithm that will have the highest priority of the selected algorithms. If given a
                        choice of more that one encryption algorithm to use, the algorithm selected in this field will be used.
                    type: str
                    choices: ['AES-256', 'DES', 'AES-128', 'TDES']
                  support_data_integrity:
                    description:
                      - Select the hash algorithms that will be supported with remote hosts to ensure data integrity.
                    type: dict
                    suboptions:
                      aes_xcbc:
                        description:
                          - Select whether the AES-XCBC hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      md5:
                        description:
                          - Select whether the MD5 hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      sha1:
                        description:
                          - Select whether the SHA1 hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      sha256:
                        description:
                          - Select whether the SHA256 hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      sha384:
                        description:
                          - Select whether the SHA384 hash algorithm will be supported with remote hosts to ensure data integrity.
                          - Available from R82 management version.
                        type: bool
                      sha512:
                        description:
                          - Select whether the SHA512 hash algorithm will be supported with remote hosts to ensure data integrity.
                          - Available from R82 management version.
                        type: bool
                  use_data_integrity:
                    description:
                      - The hash algorithm chosen here will be given the highest priority if more than one choice is offered.
                    type: str
                    choices: ['aes-xcbc', 'sha256', 'sha1', 'md5', 'sha384', 'sha512']
                  support_diffie_hellman_groups:
                    description:
                      - Select the Diffie-Hellman groups that will be supported with remote hosts.
                    type: dict
                    suboptions:
                      group1:
                        description:
                          - Select whether Diffie-Hellman Group 1 (768 bit) will be supported with remote hosts.
                        type: bool
                      group14:
                        description:
                          - Select whether Diffie-Hellman Group 14 (2048 bit) will be supported with remote hosts.
                        type: bool
                      group2:
                        description:
                          - Select whether Diffie-Hellman Group 2 (1024 bit) will be supported with remote hosts.
                        type: bool
                      group5:
                        description:
                          - Select whether Diffie-Hellman Group 5 (1536 bit) will be supported with remote hosts.
                        type: bool
                  use_diffie_hellman_group:
                    description:
                      - SecureClient users utilize the Diffie-Hellman group selected in this field.
                    type: str
                    choices: ['group 1', 'group 2', 'group 5', 'group 14']
              ipsec:
                description:
                  - Configure the IPSEC Phase 2 settings.
                type: dict
                suboptions:
                  support_encryption_algorithms:
                    description:
                      - Select the encryption algorithms that will be supported with remote hosts.
                    type: dict
                    suboptions:
                      tdes:
                        description:
                          - Select whether the Triple DES encryption algorithm will be supported with remote hosts.
                        type: bool
                      aes_128:
                        description:
                          - Select whether the AES-128 encryption algorithm will be supported with remote hosts.
                        type: bool
                      aes_256:
                        description:
                          - Select whether the AES-256 encryption algorithm will be supported with remote hosts.
                        type: bool
                      des:
                        description:
                          - Select whether the DES encryption algorithm will be supported with remote hosts.
                        type: bool
                  use_encryption_algorithm:
                    description:
                      - Choose the encryption algorithm that will have the highest priority of the selected algorithms. If given a
                        choice of more that one encryption algorithm to use, the algorithm selected in this field will be used.
                    type: str
                    choices: ['AES-256', 'DES', 'AES-128', 'TDES']
                  support_data_integrity:
                    description:
                      - Select the hash algorithms that will be supported with remote hosts to ensure data integrity.
                    type: dict
                    suboptions:
                      aes_xcbc:
                        description:
                          - Select whether the AES-XCBC hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      md5:
                        description:
                          - Select whether the MD5 hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      sha1:
                        description:
                          - Select whether the SHA1 hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      sha256:
                        description:
                          - Select whether the SHA256 hash algorithm will be supported with remote hosts to ensure data integrity.
                        type: bool
                      sha384:
                        description:
                          - Select whether the SHA384 hash algorithm will be supported with remote hosts to ensure data integrity.
                          - Available from R82 management version.
                        type: bool
                      sha512:
                        description:
                          - Select whether the SHA512 hash algorithm will be supported with remote hosts to ensure data integrity.
                          - Available from R82 management version.
                        type: bool
                  use_data_integrity:
                    description:
                      - The hash algorithm chosen here will be given the highest priority if more than one choice is offered.
                    type: str
                    choices: ['aes-xcbc', 'sha1', 'sha256', 'sha384', 'sha512', 'md5']
                  enforce_encryption_alg_and_data_integrity_on_all_users:
                    description:
                      - Enforce Encryption Algorithm and Data Integrity on all users.
                    type: bool
          encryption_method:
            description:
              - Select the encryption method.
            type: str
            choices: ['prefer_ikev2_support_ikev1', 'ike_v2_only', 'ike_v1_only']
          pre_shared_secret:
            description:
              - the user password is specified in the Authentication tab in the user's IKE properties (in the user properties window, Encryption tab > Edit).
            type: bool
          support_legacy_auth_for_sc_l2tp_nokia_clients:
            description:
              - Support Legacy Authentication for SC (hybrid mode), L2TP (PAP) and Nokia clients (CRACK).
            type: bool
          support_legacy_eap:
            description:
              - Support Legacy EAP (Extensible Authentication Protocol).
            type: bool
          support_l2tp_with_pre_shared_key:
            description:
              - Use a centrally managed pre-shared key for IKE.
            type: bool
          l2tp_pre_shared_key:
            description:
              - Type in the pre-shared key.<br>Available only if support-l2tp-with-pre-shared-key is set to true.
            type: str
      vpn_advanced:
        description:
          - Configure encryption methods and interface resolution for remote access clients.
        type: dict
        suboptions:
          allow_clear_traffic_to_encryption_domain_when_disconnected:
            description:
              - SecuRemote/SecureClient behavior while disconnected - How traffic to the VPN domain is handled when the Remote Access VPN
                client is not connected to the site. Traffic can either be dropped or sent in clear without encryption.
            type: bool
          enable_load_distribution_for_mep_conf:
            description:
              - Load distribution for Multiple Entry Points configurations - Remote access clients will randomly select a gateway from the
                list of entry points. Make sure to define the same VPN domain for all the Security Gateways you want to be entry points.
            type: bool
          use_first_allocated_om_ip_addr_for_all_conn_to_the_gws_of_the_site:
            description:
              - Use first allocated Office Mode IP Address for all connections to the Gateways of the site.After a remote user connects and
                receives an Office Mode IP address from a gateway, every connection to that gateways encryption domain will go out with the Office Mode IP as
                the internal source IP. The Office Mode IP is what hosts in the encryption domain will recognize as the remote user's IP address. The Office
                Mode IP address assigned by a specific gateway can be used in its own encryption domain and in neighboring encryption domains as well. The
                neighboring encryption domains should reside behind gateways that are members of the same VPN community as the assigning gateway. Since the
                remote hosts connections are dependant on the Office Mode IP address it received, should the gateway that issued the IP become unavailable,
                all the connections to the site will terminate.
            type: bool
      scv:
        description:
          - Define properties of the Secure Configuration Verification process.
        type: dict
        suboptions:
          apply_scv_on_simplified_mode_fw_policies:
            description:
              - Determine whether the gateway verifies that remote access clients are securely configured. This is set here only if the
                security policy is defined in the Simplified Mode. If the security policy is defined in the Traditional Mode, verification takes place per
                rule.
            type: bool
          exceptions:
            description:
              - Specify the hosts that can be accessed using the selected services even if the client is not verified.<br>Available only if
                apply-scv-on-simplified-mode-fw-policies is true.
            type: list
            elements: dict
            suboptions:
              hosts:
                description:
                  - Specify the Hosts to be excluded from SCV.
                type: list
                elements: str
              services:
                description:
                  - Specify the services to be accessed.
                type: list
                elements: str
          no_scv_for_unsupported_cp_clients:
            description:
              - Do not apply Secure Configuration Verification for connections from Check Point VPN clients that don't support it, such as SSL
                Network Extender, GO, Capsule VPN / Connect, Endpoint Connects lower than R75, or L2TP clients.<br>Available only if
                apply-scv-on-simplified-mode-fw-policies is true.
            type: bool
          upon_verification_accept_and_log_client_connection:
            description:
              - If the gateway verifies the client's configuration, decide how the gateway should handle connections with clients that fail
                the Security Configuration Verification. It is possible to either drop the connection or Accept the connection and log it.
            type: bool
          only_tcp_ip_protocols_are_used:
            description:
              - Most SCV checks are configured via the SCV policy. Specify whether to verify that  only TCP/IP protocols are used.
            type: bool
          policy_installed_on_all_interfaces:
            description:
              - Most SCV checks are configured via the SCV policy. Specify whether to verify that  the Desktop Security Policy is installed on
                all the interfaces of the client.
            type: bool
          generate_log:
            description:
              - If the client identifies that the secure configuration has been violated, select whether a log is generated by the remote
                access client and sent to the Security Management server.
            type: bool
          notify_user:
            description:
              - If the client identifies that the secure configuration has been violated, select whether to user should be notified.
            type: bool
      ssl_network_extender:
        description:
          - Define properties for SSL Network Extender users.
        type: dict
        suboptions:
          user_auth_method:
            description:
              - Wide Impact, Also applies for SecureClient Mobile devices and Check Point GO clients!<br>User authentication method indicates
                how the user will be authenticated by the gateway. Changes made here will also apply for SSL clients.<br>Legacy - Username and password
                only.<br>Certificate - Certificate only with an existing certificate.<br>Certificate with Enrollment - Allows you to obtain a new certificate
                and then use certificate authentication only.<br>Mixed - Can use either username and password or certificate.
            type: str
            choices: ['certificate_with_enrollment', 'certificate', 'mixed', 'legacy']
          supported_encryption_methods:
            description:
              - Wide Impact, Also applies to SecureClient Mobile devices!<br>Select the encryption algorithms that will be supported for
                remote users. Changes made here will also apply for all SSL clients.
            type: str
            choices: ['3des_or_rc4', '3des_only']
          client_upgrade_upon_connection:
            description:
              - When a client connects to the gateway with SSL Network Extender, the client automatically checks for upgrade. Select whether
                the client should automatically upgrade.
            type: str
            choices: ['force_upgrade', 'ask_user', 'no_upgrade']
          client_uninstall_upon_disconnection:
            description:
              - Select whether the client should automatically uninstall SSL Network Extender when it disconnects from the gateway.
            type: str
            choices: ['force_uninstall', 'ask_user', 'dont_uninstall']
          re_auth_user_interval:
            description:
              - Wide Impact, Applies for the SecureClient Mobile!<br>Select the interval that users will need to reauthenticate.
            type: int
          scan_ep_machine_for_compliance_with_ep_compliance_policy:
            description:
              - Set to true if you want endpoint machines to be scanned for compliance with the Endpoint Compliance Policy.
            type: bool
          client_outgoing_keep_alive_packets_frequency:
            description:
              - Select the interval which the keep-alive packets are sent.
            type: int
      secure_client_mobile:
        description:
          - Define properties for SecureClient Mobile.
        type: dict
        suboptions:
          user_auth_method:
            description:
              - Wide Impact, Also applies for SSL Network Extender clients and Check Point GO clients.<br>How the user will be authenticated by the gateway.
            type: str
            choices: ['certificate_with_enrollment', 'certificate', 'mixed', 'legacy']
          enable_password_caching:
            description:
              - If the password entered to authenticate is saved locally on the user's machine.
            type: str
            choices: ['client_decide', 'true', 'false']
          cache_password_timeout:
            description:
              - Cached password timeout (in minutes).
            type: int
          re_auth_user_interval:
            description:
              - Wide Impact, Also applies for SSL Network Extender clients!<br>The length of time (in minutes) until the user's credentials
                are resent to the gateway to verify authorization.
            type: int
          connect_mode:
            description:
              - Methods by which a connection to the gateway will be initiated,<br>Configured On Endpoint Client - the method used for
                initiating a connection to a gateway is determined by the endpoint client<br>Manual - VPN connections will not be initiated
                automatically.<br>Always connected - SecureClient Mobile will automatically establish a connection to the last connected gateway under the
                following circumstances, (a) the device has a valid IP address, (b) when the device "wakes up" from a low-power state or a soft-reset, or (c)
                after a condition that caused the device to automatically disconnect ceases to exist (for example, Device is out of PC Sync, Disconnect is not
                idle.).<br>On application request - Applications requiring access to resources through the VPN will be able to initiate a VPN connection.
            type: str
            choices: ['manual', 'always connected', 'on application request', 'configured on endpoint client']
          automatically_initiate_dialup:
            description:
              - When selected, the client will initiate a GPRS dialup connection before attempting to establish the VPN connection. Note that
                if a local IP address is already available through another network interface, then the GPRS dialup is not initiated.
            type: str
            choices: ['client_decide', 'true', 'false']
          disconnect_when_device_is_idle:
            description:
              - Enabling this feature will disconnect users from the gateway if there is no traffic sent during the defined time period.
            type: str
            choices: ['client_decide', 'true', 'false']
          supported_encryption_methods:
            description:
              - Wide Impact, Also applies for SSL Network Extender clients!<br>Select the encryption algorithms that will be supported with remote users.
            type: str
            choices: ['3des_or_rc4', '3des_only']
          route_all_traffic_to_gw:
            description:
              - Operates the client in Hub Mode, sending all traffic to the VPN server for routing, filtering, and processing.
            type: str
            choices: ['client_decide', 'true', 'false']
      endpoint_connect:
        description:
          - Configure global settings for Endpoint Connect. These settings apply to all gateways.
        type: dict
        suboptions:
          enable_password_caching:
            description:
              - If the password entered to authenticate is saved locally on the user's machine.
            type: str
            choices: ['client_decide', 'true', 'false']
          cache_password_timeout:
            description:
              - Cached password timeout (in minutes).
            type: int
          re_auth_user_interval:
            description:
              - The length of time (in minutes) until the user's credentials are resent to the gateway to verify authorization.
            type: int
          connect_mode:
            description:
              - Methods by which a connection to the gateway will be initiated,<br>Manual - VPN connections will not be initiated
                automatically.<br>Always connected - Endpoint Connect will automatically establish a connection to the last connected gateway under the
                following circumstances, (a) the device has a valid IP address, (b) when the device "wakes up" from a low-power state or a soft-reset, or (c)
                after a condition that caused the device to automatically disconnect ceases to exist (for example, Device is out of PC Sync, Disconnect is not
                idle.).<br>Configured on endpoint client - the method used for initiating a connection to a gateway is determined by the endpoint client.
            type: str
            choices: ['Manual', 'Always Connected', 'Configured On Endpoint Client']
          network_location_awareness:
            description:
              - Wide Impact, Also applies for Check Point GO clients!<br>Endpoint Connect intelligently detects whether it is inside or
                outside of the VPN domain (Enterprise LAN), and automatically connects or disconnects as required. Select true and edit
                network-location-awareness-conf to configure this capability.
            type: str
            choices: ['client_decide', 'true', 'false']
          network_location_awareness_conf:
            description:
              - Configure how the client determines its location in relation to the internal network.
            type: dict
            suboptions:
              vpn_clients_are_considered_inside_the_internal_network_when_the_client:
                description:
                  - When a VPN client is within the internal network, the internal resources are available and the VPN tunnel should be
                    disconnected. Determine when VPN clients are considered inside the internal network,<br>Connects to GW through internal interface - The
                    client connects to the gateway through one of its internal interfaces (recommended).<br>Connects from network or group - The client
                    connects from a network or group specified in network-or-group-of-conn-vpn-client.<br>Runs on computer with access to Active Directory
                    domain - The client runs on a computer that can access its Active Directory domain.<br>Note, The VPN tunnel will resume automatically when
                    the VPN client is no longer in the internal network and the client is set to "Always connected" mode.
                type: str
                choices: ['connects to gw through internal interface', 'connects from network or group',
                         'runs on computer with access to active directory domain']
              network_or_group_of_conn_vpn_client:
                description:
                  - Name or UID of Network or Group the VPN client is connected from.<br>Available only if
                    vpn-clients-are-considered-inside-the-internal-network-when-the-client is set to "Connects from network or group".
                type: str
              consider_wireless_networks_as_external:
                description:
                  - The speed at which locations are classified as internal or external can be increased by creating a list of wireless
                    networks that are known to be external. A wireless network is identified by its Service Set Identifier (SSID) a name used to identify a
                    particular 802.11 wireless LAN.
                type: bool
              excluded_internal_wireless_networks:
                description:
                  - Excludes the specified internal networks names (SSIDs).<br>Available only if consider-wireless-networks-as-external is set to true.
                type: list
                elements: str
              consider_undefined_dns_suffixes_as_external:
                description:
                  - The speed at which locations are classified as internal or external can be increased by creating a list of DNS
                    suffixes that are known to be external. Enable this to be able to define DNS suffixes which won't be considered external.
                type: bool
              dns_suffixes:
                description:
                  - DNS suffixes not defined here will be considered as external. If this list is empty
                    consider-undefined-dns-suffixes-as-external will automatically be set to false.<br>Available only if
                    consider-undefined-dns-suffixes-as-external is set to true.
                type: list
                elements: str
              remember_previously_detected_external_networks:
                description:
                  - The speed at which locations are classified as internal or external can be increased by caching (on the client side)
                    names of networks that were previously determined to be external.
                type: bool
          disconnect_when_conn_to_network_is_lost:
            description:
              - Enabling this feature disconnects users from the gateway when connectivity to the network is lost.
            type: str
            choices: ['client_decide', 'true', 'false']
          disconnect_when_device_is_idle:
            description:
              - Enabling this feature will disconnect users from the gateway if there is no traffic sent during the defined time period.
            type: str
            choices: ['client_decide', 'true', 'false']
          route_all_traffic_to_gw:
            description:
              - Operates the client in Hub Mode, sending all traffic to the VPN server for routing, filtering, and processing.
            type: str
            choices: ['client_decide', 'true', 'false']
          client_upgrade_mode:
            description:
              - Select an option to determine how the client is upgraded.
            type: str
            choices: ['force_upgrade', 'ask_user', 'no_upgrade']
      hot_spot_and_hotel_registration:
        description:
          - Configure the settings for Wireless Hot Spot and Hotel Internet access registration.
        type: dict
        suboptions:
          enable_registration:
            description:
              - Set Enable registration to true in order to configure settings. Set Enable registration to false in order to cancel
                registration (the configurations below won't be available). When the feature is enabled, you have several minutes to complete registration.
            type: bool
          local_subnets_access_only:
            description:
              - Local subnets access only.
            type: bool
          registration_timeout:
            description:
              - Maximum time (in seconds) to complete registration.
            type: int
          track_log:
            description:
              - Track log.
            type: bool
          max_ip_access_during_registration:
            description:
              - Maximum number of addresses to allow access to during registration.
            type: int
          ports:
            description:
              - Ports to be opened during registration (up to 10 ports).
            type: list
            elements: str
  user_directory:
    description:
      - User can enable LDAP User Directory as well as specify global parameters for LDAP. If LDAP User Directory is enabled, this means that users
        are managed on an external LDAP server and not on the internal Check Point Security Gateway users databases.
    type: dict
    suboptions:
      enable_password_change_when_user_active_directory_expires:
        description:
          - For organizations using MS Active Directory, this setting enables users whose passwords have expired to automatically create new passwords.
        type: bool
      cache_size:
        description:
          - The maximum number of cached users allowed. The cache is FIFO (first-in, first-out). When a new user is added to a full cache, the
            first user is deleted to make room for the new user. The Check Point Security Gateway does not query the LDAP server for users already in the
            cache, unless the cache has timed out.
        type: int
      enable_password_expiration_configuration:
        description:
          - Enable configuring of the number of days during which the password is valid.<br>If
            enable-password-change-when-user-active-directory-expires is true, the password expiration time is determined by the Active Directory. In this
            case it is recommended not to set this to true.
        type: bool
      password_expires_after:
        description:
          - Specifies the number of days during which the password is valid. Users are authenticated using a special LDAP password. Should this
            password expire, a new password must be defined.<br>Available only if enable-password-expiration-configuration is true.
        type: int
      timeout_on_cached_users:
        description:
          - The period of time in which a cached user is timed out and will need to be fetched again from the LDAP server.
        type: int
      display_user_dn_at_login:
        description:
          - Decide whether or not you would like to display the user's DN when logging in. If you choose to display the user DN, you can select
            whether to display it, when the user is prompted for the password at login, or on the request of the authentication scheme. This property is a
            useful diagnostic tool when there is more than one user with the same name in an Account Unit. In this case, the first one is chosen and the
            others are ignored.
        type: str
        choices: ['no display', 'display upon request', 'display']
      enforce_rules_for_user_mgmt_admins:
        description:
          - Enforces password strength rules on LDAP users when you create or modify a Check Point Password.
        type: bool
      min_password_length:
        description:
          - Specifies the minimum length (in characters) of the password.
        type: int
      password_must_include_a_digit:
        description:
          - Password must include a digit.
        type: bool
      password_must_include_a_symbol:
        description:
          - Password must include a symbol.
        type: bool
      password_must_include_lowercase_char:
        description:
          - Password must include a lowercase character.
        type: bool
      password_must_include_uppercase_char:
        description:
          - Password must include an uppercase character.
        type: bool
  qos:
    description:
      - Define the general parameters of Quality of Service (QoS) and apply them to QoS rules.
    type: dict
    suboptions:
      default_weight_of_rule:
        description:
          - Define a Weight at which bandwidth will be guaranteed. Set a default weight for a rule.<br>Note, Value will be applied to new rules only.
        type: int
      max_weight_of_rule:
        description:
          - Define a Weight at which bandwidth will be guaranteed. Set a maximum weight for a rule.
        type: int
      unit_of_measure:
        description:
          - Define the Rate at which packets are transmitted, for which bandwidth will be guaranteed. Set a Unit of measure.
        type: str
        choices: ['bits-per-sec', 'bytes-per-sec', 'kbits-per-sec', 'kbytes-per-sec', 'mbits-per-sec', 'mbytes-per-sec']
      authenticated_ip_expiration:
        description:
          - Define the Authentication time-out for QoS. This timeout is set in minutes. In an Authenticated IP all connections which are open in a
            specified time limit will be guaranteed bandwidth, but will not be guaranteed bandwidth after the time limit.
        type: int
      non_authenticated_ip_expiration:
        description:
          - Define the Authentication time-out for QoS. This timeout is set in minutes.
        type: int
      unanswered_queried_ip_expiration:
        description:
          - Define the Authentication time-out for QoS. This timeout is set in minutes.
        type: int
  carrier_security:
    description:
      - Specify system-wide properties. Select GTP intra tunnel inspection options, including anti-spoofing; tracking and logging options, and integrity tests.
    type: dict
    suboptions:
      block_gtp_in_gtp:
        description:
          - Prevents GTP packets from being encapsulated inside GTP tunnels. When this option is checked, such packets are dropped and logged.
        type: bool
      enforce_gtp_anti_spoofing:
        description:
          - verifies that G-PDUs are using the end user IP address that has been agreed upon in the PDP context activation process. When this
            option is checked, packets that do not use this IP address are dropped and logged.
        type: bool
      produce_extended_logs_on_unmatched_pdus:
        description:
          - logs GTP packets not matched by previous rules with Carrier Security's extended GTP-related log fields. These logs are brown and their
            Action attribute is empty. The default setting is checked.
        type: bool
      produce_extended_logs_on_unmatched_pdus_position:
        description:
          - Choose to place this implicit rule Before Last or as the Last rule.<br>Available only if produce-extended-logs-on-unmatched-pdus is true.
        type: str
        choices: ['before last', 'last']
      protocol_violation_track_option:
        description:
          - Set the appropriate track or alert option to be used when a protocol violation (malformed packet) is detected.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      enable_g_pdu_seq_number_check_with_max_deviation:
        description:
          - If set to false, sequence checking is not enforced and all out-of-sequence G-PDUs will be accepted.<br>To enhance performance, disable
            this extended integrity test.
        type: bool
      g_pdu_seq_number_check_max_deviation:
        description:
          - specifies that a G-PDU is accepted only if the difference between its sequence number and the expected sequence number is less than or
            equal to the allowed deviation.<br>Available only ifenable-g-pdu-seq-number-check-with-max-deviation is true.
        type: int
      verify_flow_labels:
        description:
          - See that each packet's flow label matches the flow labels defined by GTP signaling. This option is relevant for GTP version 0
            only.<br>To enhance performance, disable this extended integrity test.
        type: bool
      allow_ggsn_replies_from_multiple_interfaces:
        description:
          - Allows GTP signaling replies from an IP address different from the IP address to which the requests are sent (Relevant only for
            gateways below R80).
        type: bool
      enable_reverse_connections:
        description:
          - Allows Carrier Security gateways to accept PDUs sent from the GGSN to the SGSN, on a previously established PDP context, even if these
            PDUs are sent over ports that do not match the ports of the established PDP context.
        type: bool
      gtp_signaling_rate_limit_sampling_interval:
        description:
          - Works in correlation with the property Enforce GTP Signal packet rate limit found in the Carrier Security window of the GSN network
            object. For example, with the rate limit sampling interval default of 1 second, and the network object enforced a GTP signal packet rate limit of
            the default 2048 PDU per second, sampling will occur one time per second, or 2048 signaling PDUs between two consecutive samplings.
        type: int
      one_gtp_echo_on_each_path_frequency:
        description:
          - sets the number of GTP Echo exchanges per path allowed per configured time period. Echo requests exceeding this rate are dropped and
            logged. Setting the value to 0 disables the feature and allows an unlimited number of echo requests per path at any interval.
        type: int
      aggressive_aging:
        description:
          - If true, enables configuring aggressive aging thresholds and time out value.
        type: bool
      aggressive_timeout:
        description:
          - Aggressive timeout. Available only if aggressive-aging is true.
        type: int
      memory_activation_threshold:
        description:
          - Memory activation threshold. Available only if aggressive-aging is true.
        type: int
      memory_deactivation_threshold:
        description:
          - Memory deactivation threshold. Available only if aggressive-aging is true.
        type: int
      tunnel_activation_threshold:
        description:
          - Tunnel activation threshold. Available only if aggressive-aging is true.
        type: int
      tunnel_deactivation_threshold:
        description:
          - Tunnel deactivation threshold. Available only if aggressive-aging is true.
        type: int
  user_accounts:
    description:
      - Set the expiration for a user account and configure "about to expire" warnings.
    type: dict
    suboptions:
      expiration_date_method:
        description:
          - Select an Expiration Date Method.<br>Expire at - Account expires on the date that you select.<br>Expire after - Account expires after
            the number of days that you select.
        type: str
        choices: ['expire after', 'expire at']
      expiration_date:
        description:
          - Specify an Expiration Date in the following format, YYYY-MM-DD.<br>Available only if expiration-date-method is set to "expire at".
        type: str
      days_until_expiration:
        description:
          - Account expires after the number of days that you select.<br>Available only if expiration-date-method is set to "expire after".
        type: int
      show_accounts_expiration_indication_days_in_advance:
        description:
          - Activates the Expired Accounts link, to open the Expired Accounts window.
        type: bool
  user_authority:
    description:
      - Decide whether to display and access the WebAccess rule base. This policy defines which users (that is, which Windows Domains) have access to
        the internal sites of the organization.
    type: dict
    suboptions:
      display_web_access_view:
        description:
          - Specify whether or not to display the WebAccess rule base. This rule base is used for UserAuthority.
        type: bool
      windows_domains_to_trust:
        description:
          - When matching Firewall usernames to Windows Domains usernames for Single Sign on, selectwhether to trust all or specify which Windows
            Domain should be trusted.<br>ALL - Enables you to allow all Windows domains to access the internal sites of the organization.<br>SELECTIVELY -
            Enables you to specify which Windows domains will have access to the internal sites of the organization.
        type: str
        choices: ['selectively', 'all']
      trust_only_following_windows_domains:
        description:
          - Specify which Windows domains will have access to the internal sites of the organization.<br>Available only if
            windows-domains-to-trust is set to SELECTIVELY.
        type: list
        elements: str
  connect_control:
    description:
      - Configure settings that relate to ConnectControl server load balancing.
    type: dict
    suboptions:
      load_agents_port:
        description:
          - Sets the port number on which load measuring agents communicate with ConnectControl.
        type: int
      load_measurement_interval:
        description:
          - sets how often (in seconds) the load measuring agents report their load status to ConnectControl.
        type: int
      persistence_server_timeout:
        description:
          - Sets the amount of time (in seconds) that a client, once directed to a particular server, will continue to be directed to that same server.
        type: int
      server_availability_check_interval:
        description:
          - Sets how often (in seconds) ConnectControl checks to make sure the load balanced servers are running and responding to service requests.
        type: int
      server_check_retries:
        description:
          - Sets how many times ConnectControl attempts to contact a server before ceasing to direct traffic to it.
        type: int
  stateful_inspection:
    description:
      - Adjust Stateful Inspection parameters.
    type: dict
    suboptions:
      tcp_start_timeout:
        description:
          - A TCP connection will be timed out if the interval between the arrival of the first packet and establishment of the connection (TCP
            three-way handshake) exceeds TCP start timeout seconds.
        type: int
      tcp_session_timeout:
        description:
          - The length of time (in seconds) an idle connection will remain in the Security Gateway connections table.
        type: int
      tcp_end_timeout:
        description:
          - A TCP connection will only terminate TCP end timeout seconds after two FIN packets (one in each direction, client-to-server, and
            server-to-client) or an RST packet. When a TCP connection ends (FIN packets sent or connection reset) the Check Point Security Gateway will keep
            the connection in the connections table for another TCP end timeout seconds, to allow for stray ACKs of the connection that arrive late.
        type: int
      tcp_end_timeout_r8020_gw_and_above:
        description:
          - A TCP connection will only terminate TCP end timeout seconds after two FIN packets (one in each direction, client-to-server, and
            server-to-client) or an RST packet. When a TCP connection ends (FIN packets sent or connection reset) the Check Point Security Gateway will keep
            the connection in the connections table for another TCP end timeout seconds, to allow for stray ACKs of the connection that arrive late.
        type: int
      udp_virtual_session_timeout:
        description:
          - Specifies the amount of time (in seconds) a UDP reply channel may remain open without any packets being returned.
        type: int
      icmp_virtual_session_timeout:
        description:
          - An ICMP virtual session will be considered to have timed out after this time period (in seconds).
        type: int
      other_ip_protocols_virtual_session_timeout:
        description:
          - A virtual session of services which are not explicitly configured here will be considered to have timed out after this time period (in seconds).
        type: int
      sctp_start_timeout:
        description:
          - SCTP connections will be timed out if the interval between the arrival of the first packet and establishment of the connection exceeds
            this value (in seconds).
        type: int
      sctp_session_timeout:
        description:
          - Time (in seconds) an idle connection will remain in the Security Gateway connections table.
        type: int
      sctp_end_timeout:
        description:
          - SCTP connections end after this number of seconds, after the connection ends or is reset, to allow for stray ACKs of the connection
            that arrive late.
        type: int
      accept_stateful_udp_replies_for_unknown_services:
        description:
          - Specifies if UDP replies are to be accepted for unknown services.
        type: bool
      accept_stateful_icmp_errors:
        description:
          - Accept ICMP error packets which refer to another non-ICMP connection (for example, to an ongoing TCP or UDP connection) that was
            accepted by the Rule Base.
        type: bool
      accept_stateful_icmp_replies:
        description:
          - Accept ICMP reply packets for ICMP requests that were accepted by the Rule Base.
        type: bool
      accept_stateful_other_ip_protocols_replies_for_unknown_services:
        description:
          - Accept reply packets for other undefined services (that is, services which are not one of the following, TCP, UDP, ICMP).
        type: bool
      drop_out_of_state_tcp_packets:
        description:
          - Drop TCP packets which are not consistent with the current state of the connection.
        type: bool
      log_on_drop_out_of_state_tcp_packets:
        description:
          - Generates a log entry when these out of state TCP packets are dropped.<br>Available only if drop-out-of-state-tcp-packets is true.
        type: bool
      tcp_out_of_state_drop_exceptions:
        description:
          - Name or uid of the gateways and clusters for which Out of State packets are allowed.
        type: list
        elements: str
      drop_out_of_state_icmp_packets:
        description:
          - Drop ICMP packets which are not consistent with the current state of the connection.
        type: bool
      log_on_drop_out_of_state_icmp_packets:
        description:
          - Generates a log entry when these out of state ICMP packets are dropped.<br>Available only if drop-out-of-state-icmp-packets is true.
        type: bool
      drop_out_of_state_sctp_packets:
        description:
          - Drop SCTP packets which are not consistent with the current state of the connection.
        type: bool
      log_on_drop_out_of_state_sctp_packets:
        description:
          - Generates a log entry when these out of state SCTP packets are dropped.<br>Available only if drop-out-of-state-sctp-packets is true.
        type: bool
  log_and_alert:
    description:
      - Define system-wide logging and alerting parameters.
    type: dict
    suboptions:
      administrative_notifications:
        description:
          - Administrative notifications specifies the action to be taken when an administrative event (for example, when a certificate is about
            to expire) occurs.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      connection_matched_by_sam:
        description:
          - Connection matched by SAM specifies the action to be taken when a connection is blocked by SAM (Suspicious Activities Monitoring).
        type: str
        choices: ['Popup Alert', 'Mail Alert', 'SNMP Trap Alert', 'User Defined Alert no.1', 'User Defined Alert no.2', 'User Defined Alert no.3']
      dynamic_object_resolution_failure:
        description:
          - Dynamic object resolution failure specifies the action to be taken when a dynamic object cannot be resolved.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      ip_options_drop:
        description:
          - IP Options drop specifies the action to take when a packet with IP Options is encountered. The Check Point Security Gateway always
            drops these packets, but you can log them or issue an alert.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      packet_is_incorrectly_tagged:
        description:
          - Packet is incorrectly tagged.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      packet_tagging_brute_force_attack:
        description:
          - Packet tagging brute force attack.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      sla_violation:
        description:
          - SLA violation specifies the action to be taken when an SLA violation occurs, as defined in the Virtual Links window.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      vpn_conf_and_key_exchange_errors:
        description:
          - VPN configuration & key exchange errors specifies the action to be taken when logging configuration or key exchange errors occur, for
            example, when attempting to establish encrypted communication with a network object inside the same encryption domain.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      vpn_packet_handling_error:
        description:
          - VPN packet handling errors specifies the action to be taken when encryption or decryption errors occurs. A log entry contains the
            action performed (Drop or Reject) and a short description of the error cause, for example, scheme or method mismatch.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      vpn_successful_key_exchange:
        description:
          - VPN successful key exchange specifies the action to be taken when VPN keys are successfully exchanged.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      log_every_authenticated_http_connection:
        description:
          - Log every authenticated HTTP connection specifies that a log entry should be generated for every authenticated HTTP connection.
        type: bool
      log_traffic:
        description:
          - Log Traffic specifies whether or not to log traffic.
        type: str
        choices: ['none', 'log']
      alerts:
        description:
          - Define the behavior of alert logs and the type of alert used for System Alert logs.
        type: dict
        suboptions:
          send_popup_alert_to_smartview_monitor:
            description:
              - Send popup alert to SmartView Monitor when an alert is issued, it is also sent to SmartView Monitor.
            type: bool
          popup_alert_script:
            description:
              - Run popup alert script the operating system script to be executed when an alert is issued. For example, set another form of
                notification, such as an email or a user-defined command.
            type: str
          send_mail_alert_to_smartview_monitor:
            description:
              - Send mail alert to SmartView Monitor when a mail alert is issued, it is also sent to SmartView Monitor.
            type: bool
          mail_alert_script:
            description:
              - Run mail alert script the operating system script to be executed when Mail is specified as the Track in a rule. The default is
                internal_sendmail, which is not a script but an internal Security Gateway command.
            type: str
          send_snmp_trap_alert_to_smartview_monitor:
            description:
              - Send SNMP trap alert to SmartView Monitor when an SNMP trap alert is issued, it is also sent to SmartView Monitor.
            type: bool
          snmp_trap_alert_script:
            description:
              - Run SNMP trap alert script command to be executed when SNMP Trap is specified as the Track in a rule. By default the
                internal_snmp_trap is used. This command is executed by the fwd process.
            type: str
          send_user_defined_alert_num1_to_smartview_monitor:
            description:
              - Send user defined alert no. 1 to SmartView Monitor when an alert is issued, it is also sent to SmartView Monitor.
            type: bool
          user_defined_script_num1:
            description:
              - Run user defined script the operating system script to be run when User-Defined is specified as the Track in a rule, or when
                User Defined Alert no. 1 is selected as a Track Option.
            type: str
          send_user_defined_alert_num2_to_smartview_monitor:
            description:
              - Send user defined alert no. 2 to SmartView Monitor when an alert is issued, it is also sent to SmartView Monitor.
            type: bool
          user_defined_script_num2:
            description:
              - Run user defined 2 script the operating system script to be run when User-Defined is specified as the Track in a rule, or when
                User Defined Alert no. 2 is selected as a Track Option.
            type: str
          send_user_defined_alert_num3_to_smartview_monitor:
            description:
              - Send user defined alert no. 3 to SmartView Monitor when an alert is issued, it is also sent to SmartView Monitor.
            type: bool
          user_defined_script_num3:
            description:
              - Run user defined 3 script the operating system script to be run when User-Defined is specified as the Track in a rule, or when
                User Defined Alert no. 3 is selected as a Track Option.
            type: str
          default_track_option_for_system_alerts:
            description:
              - Set the default track option for System Alerts.
            type: str
            choices: ['Popup Alert', 'Mail Alert', 'SNMP Trap Alert', 'User Defined Alert no.1', 'User Defined Alert no.2', 'User Defined Alert no.3']
      time_settings:
        description:
          - Configure the time settings associated with system-wide logging and alerting parameters.
        type: dict
        suboptions:
          excessive_log_grace_period:
            description:
              - Specifies the minimum amount of time (in seconds) between consecutive logs of similar packets. Two packets are considered
                similar if they have the same source address, source port, destination address, and destination port; and the same protocol was used. After
                the first packet, similar packets encountered in the grace period will be acted upon according to the security policy, but only the first
                packet generates a log entry or an alert. Any value from 0 to 90 seconds can be entered in this field.<br>Note, This option only applies for
                DROP rules with logging.
            type: int
          logs_resolving_timeout:
            description:
              - Specifies the amount of time (in seconds), after which the log page is displayed without resolving names and while showing
                only IP addresses. Any value from 0 to 90 seconds can be entered in this field.
            type: int
          status_fetching_interval:
            description:
              - Specifies the frequency at which the Security Management server queries the Check Point Security gateway, Check Point QoS and
                other gateways it manages for status information. Any value from 30 to 900 seconds can be entered in this field.
            type: int
          virtual_link_statistics_logging_interval:
            description:
              - Specifies the frequency (in seconds) with which Virtual Link statistics will be logged. This parameter is relevant only for
                Virtual Links defined with SmartView Monitor statistics enabled in the SLA Parameters tab of the Virtual Link window. Any value from 60 to
                3600 seconds can be entered in this field.
            type: int
  data_access_control:
    description:
      - Configure automatic downloads from Check Point and anonymously share product data. Options selected here apply to all Security Gateways,
        Clusters and VSX devices managed by this management server.
    type: dict
    suboptions:
      auto_download_important_data:
        description:
          - Automatically download and install Software Blade Contracts, security updates and other important data (highly recommended).
        type: bool
      auto_download_sw_updates_and_new_features:
        description:
          - Automatically download software updates and new features (highly recommended).<br>Available only if auto-download-important-data is set to true.
        type: bool
      send_anonymous_info:
        description:
          - Help Check Point improve the product by sending anonymous information.
        type: bool
      share_sensitive_info:
        description:
          - Approve sharing core dump files and other relevant crash data which might contain personal information. All shared data will be
            processed in accordance with Check Point's Privacy Policy.<br>Available only if send-anonymous-info is set to true.
        type: bool
  non_unique_ip_address_ranges:
    description:
      - Specify Non Unique IP Address Ranges.
    type: list
    elements: dict
    suboptions:
      address_type:
        description:
          - The type of the IP Address.
        type: str
        choices: ['IPv4', 'IPv6']
      first_ipv4_address:
        description:
          - The first IPV4 Address in the range.
        type: str
      first_ipv6_address:
        description:
          - The first IPV6 Address in the range.
        type: str
      last_ipv4_address:
        description:
          - The last IPV4 Address in the range.
        type: str
      last_ipv6_address:
        description:
          - The last IPV6 Address in the range.
        type: str
  proxy:
    description:
      - Select whether a proxy server is used when servers, gateways, or clients need to access the internet for certain Check Point features and set
        the default proxy server that will be used.
    type: dict
    suboptions:
      use_proxy_server:
        description:
          - If set to true, a proxy server is used when features need to access the internet.
        type: bool
      proxy_address:
        description:
          - Specify the URL or IP address of the proxy server.<br>Available only if use-proxy-server is set to true.
        type: str
      proxy_port:
        description:
          - Specify the Port on which the server will be accessed.<br>Available only if use-proxy-server is set to true.
        type: int
  user_check:
    description:
      - Set a language for the UserCheck message if the language setting in the user's browser cannot be determined.
    type: dict
    suboptions:
      preferred_language:
        description:
          - The preferred language for new UserCheck message.
        type: str
        choices: ['Afrikaans', 'Albanian', 'Amharic', 'Arabic', 'Armenian', 'Basque', 'Belarusian', 'Bosnian', 'Bulgarian', 'Catalan',
                 'Chinese', 'Croatian', 'Czech', 'Danish', 'Dutch', 'English', 'Estonian', 'Finnish', 'French', 'Gaelic', 'Georgian', 'German', 'Greek',
                 'Hebrew', 'Hindi', 'Hungarian', 'Icelandic', 'Indonesian', 'Irish', 'Italian', 'Japanese', 'Korean', 'Latvian', 'Lithuanian', 'Macedonia',
                 'Maltese', 'Nepali', 'Norwegian', 'Polish', 'Portuguese', 'Romanian', 'Russian', 'Serbian', 'Slovak', 'Slovenian', 'Sorbian', 'Spanish',
                 'Swahili', 'Swedish', 'Thai', 'Turkish', 'Ukrainian', 'Vietnamese', 'Welsh']
      send_emails_using_mail_server:
        description:
          - Name or UID of mail server to send emails to.
        type: str
  hit_count:
    description:
      - Enable the Hit Count feature that tracks the number of connections that each rule matches.
    type: dict
    suboptions:
      enable_hit_count:
        description:
          - Select to enable or clear to disable all Security Gateways to monitor the number of connections each rule matches.
        type: bool
      keep_hit_count_data_up_to:
        description:
          - Select one of the time range options. Data is kept in the Security Management Server database for this period and is shown in the Hits column.
        type: str
        choices: ['3 months', '6 months', '1 year', '2 years']
  advanced_conf:
    description:
      - Configure advanced global attributes. It's highly recommended to consult with Check Point's Technical Support before modifying these values.
    type: dict
    suboptions:
      certs_and_pki:
        description:
          - Configure Certificates and PKI properties.
        type: dict
        suboptions:
          cert_validation_enforce_key_size:
            description:
              - Enforce key length in certificate validation (R80+ gateways only).
            type: str
            choices: ['off', 'alert', 'fail']
          host_certs_ecdsa_key_size:
            description:
              - Select the key size for ECDSA of the host certificate.
            type: str
            choices: ['p-256', 'p-384', 'p-521']
          host_certs_key_size:
            description:
              - Select the key size of the host certificate.
            type: str
            choices: ['4096', '1024', '2048']
  allow_remote_registration_of_opsec_products:
    description:
      - After installing an OPSEC application, the remote administration (RA) utility enables an OPSEC product to finish registering itself without
        having to access the SmartConsole. If set to true, any host including the application host can run the utility. Otherwise,  the RA utility can only be
        run from the Security Management host.
    type: bool
  num_spoofing_errs_that_trigger_brute_force:
    description:
      - Indicates how many incorrectly signed packets will be tolerated before assuming that there is an attack on the packet tagging and revoking the
        client's key.
    type: int
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
  auto_publish_session:
    description:
    - Publish the current session if changes have been performed after task completes.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-global-properties
  cp_mgmt_set_global_properties:
    firewall:
      security_server:
        http_servers:
          - host: host name of server
            logical_name: unique logical name
            port: 8080
            reauthentication: post request
"""

RETURN = """
cp_mgmt_set_global_properties:
  description: The checkpoint set-global-properties output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(
        firewall=dict(
            type="dict",
            options=dict(
                accept_control_connections=dict(type="bool"),
                accept_ips1_management_connections=dict(type="bool"),
                accept_remote_access_control_connections=dict(type="bool"),
                accept_smart_update_connections=dict(type="bool"),
                accept_outgoing_packets_originating_from_gw=dict(type="bool"),
                accept_outgoing_packets_originating_from_gw_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_outgoing_packets_originating_from_connectra_gw=dict(
                    type="bool"
                ),
                accept_outgoing_packets_to_cp_online_services=dict(
                    type="bool"
                ),
                accept_outgoing_packets_to_cp_online_services_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_domain_name_over_tcp=dict(type="bool"),
                accept_domain_name_over_tcp_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_domain_name_over_udp=dict(type="bool"),
                accept_domain_name_over_udp_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_dynamic_addr_modules_outgoing_internet_connections=dict(
                    type="bool"
                ),
                accept_icmp_requests=dict(type="bool"),
                accept_icmp_requests_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_identity_awareness_control_connections=dict(
                    type="bool"
                ),
                accept_identity_awareness_control_connections_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_incoming_traffic_to_dhcp_and_dns_services_of_gws=dict(
                    type="bool"
                ),
                accept_rip=dict(type="bool"),
                accept_rip_position=dict(
                    type="str", choices=["first", "last", "before last"]
                ),
                accept_vrrp_packets_originating_from_cluster_members=dict(
                    type="bool"
                ),
                accept_web_and_ssh_connections_for_gw_administration=dict(
                    type="bool"
                ),
                log_implied_rules=dict(type="bool"),
                security_server=dict(
                    type="dict",
                    options=dict(
                        client_auth_welcome_file=dict(type="str"),
                        ftp_welcome_msg_file=dict(type="str"),
                        rlogin_welcome_msg_file=dict(type="str"),
                        telnet_welcome_msg_file=dict(type="str"),
                        mdq_welcome_msg=dict(type="str"),
                        smtp_welcome_msg=dict(type="str"),
                        http_next_proxy_host=dict(type="str"),
                        http_next_proxy_port=dict(type="int"),
                        http_servers=dict(
                            type="list",
                            elements="dict",
                            options=dict(
                                logical_name=dict(type="str"),
                                host=dict(type="str"),
                                port=dict(type="int"),
                                reauthentication=dict(
                                    type="str",
                                    choices=[
                                        "standard",
                                        "post request",
                                        "every request",
                                    ],
                                ),
                            ),
                        ),
                        server_for_null_requests=dict(type="str"),
                    ),
                ),
            ),
        ),
        nat=dict(
            type="dict",
            options=dict(
                allow_bi_directional_nat=dict(type="bool"),
                auto_arp_conf=dict(type="bool"),
                merge_manual_proxy_arp_conf=dict(type="bool"),
                auto_translate_dest_on_client_side=dict(type="bool"),
                manually_translate_dest_on_client_side=dict(type="bool"),
                enable_ip_pool_nat=dict(type="bool"),
                addr_alloc_and_release_track=dict(
                    type="str", choices=["ip allocation log", "none"]
                ),
                addr_exhaustion_track=dict(
                    type="str",
                    choices=[
                        "ip exhaustion alert",
                        "none",
                        "ip exhaustion log",
                    ],
                ),
            ),
        ),
        authentication=dict(
            type="dict",
            options=dict(
                auth_internal_users_with_specific_suffix=dict(type="bool"),
                allowed_suffix_for_internal_users=dict(type="str"),
                max_days_before_expiration_of_non_pulled_user_certificates=dict(
                    type="int"
                ),
                max_client_auth_attempts_before_connection_termination=dict(
                    type="int"
                ),
                max_rlogin_attempts_before_connection_termination=dict(
                    type="int"
                ),
                max_session_auth_attempts_before_connection_termination=dict(
                    type="int"
                ),
                max_telnet_attempts_before_connection_termination=dict(
                    type="int"
                ),
                enable_delayed_auth=dict(type="bool"),
                delay_each_auth_attempt_by=dict(type="int"),
            ),
        ),
        vpn=dict(
            type="dict",
            options=dict(
                vpn_conf_method=dict(
                    type="str",
                    choices=["simplified", "traditional", "per policy"],
                ),
                domain_name_for_dns_resolving=dict(type="str"),
                enable_backup_gw=dict(type="bool"),
                enable_decrypt_on_accept_for_gw_to_gw_traffic=dict(
                    type="bool"
                ),
                enable_load_distribution_for_mep_conf=dict(type="bool"),
                enable_vpn_directional_match_in_vpn_column=dict(type="bool"),
                grace_period_after_the_crl_is_not_valid=dict(type="int"),
                grace_period_before_the_crl_is_valid=dict(type="int"),
                grace_period_extension_for_secure_remote_secure_client=dict(
                    type="int"
                ),
                support_ike_dos_protection_from_identified_src=dict(
                    type="str", choices=["puzzles", "stateless", "none"]
                ),
                support_ike_dos_protection_from_unidentified_src=dict(
                    type="str", choices=["puzzles", "stateless", "none"]
                ),
            ),
        ),
        remote_access=dict(
            type="dict",
            options=dict(
                enable_back_connections=dict(type="bool"),
                keep_alive_packet_to_gw_interval=dict(type="int"),
                encrypt_dns_traffic=dict(type="bool"),
                simultaneous_login_mode=dict(
                    type="str",
                    choices=[
                        "allowonlysinglelogintouser",
                        "allowseverallogintouser",
                    ],
                ),
                vpn_authentication_and_encryption=dict(
                    type="dict",
                    options=dict(
                        encryption_algorithms=dict(
                            type="dict",
                            options=dict(
                                ike=dict(
                                    type="dict",
                                    options=dict(
                                        support_encryption_algorithms=dict(
                                            type="dict",
                                            options=dict(
                                                tdes=dict(type="bool"),
                                                aes_128=dict(type="bool"),
                                                aes_256=dict(type="bool"),
                                                des=dict(type="bool"),
                                            ),
                                        ),
                                        use_encryption_algorithm=dict(
                                            type="str",
                                            choices=[
                                                "AES-256",
                                                "DES",
                                                "AES-128",
                                                "TDES",
                                            ],
                                        ),
                                        support_data_integrity=dict(
                                            type="dict",
                                            options=dict(
                                                aes_xcbc=dict(type="bool"),
                                                md5=dict(type="bool"),
                                                sha1=dict(type="bool"),
                                                sha256=dict(type="bool"),
                                                sha384=dict(type="bool"),
                                                sha512=dict(type="bool"),
                                            ),
                                        ),
                                        use_data_integrity=dict(
                                            type="str",
                                            choices=[
                                                "aes-xcbc",
                                                "sha256",
                                                "sha1",
                                                "md5",
                                                "sha384",
                                                "sha512",
                                            ],
                                        ),
                                        support_diffie_hellman_groups=dict(
                                            type="dict",
                                            options=dict(
                                                group1=dict(type="bool"),
                                                group14=dict(type="bool"),
                                                group2=dict(type="bool"),
                                                group5=dict(type="bool"),
                                            ),
                                        ),
                                        use_diffie_hellman_group=dict(
                                            type="str",
                                            choices=[
                                                "group 1",
                                                "group 2",
                                                "group 5",
                                                "group 14",
                                            ],
                                        ),
                                    ),
                                ),
                                ipsec=dict(
                                    type="dict",
                                    options=dict(
                                        support_encryption_algorithms=dict(
                                            type="dict",
                                            options=dict(
                                                tdes=dict(type="bool"),
                                                aes_128=dict(type="bool"),
                                                aes_256=dict(type="bool"),
                                                des=dict(type="bool"),
                                            ),
                                        ),
                                        use_encryption_algorithm=dict(
                                            type="str",
                                            choices=[
                                                "AES-256",
                                                "DES",
                                                "AES-128",
                                                "TDES",
                                            ],
                                        ),
                                        support_data_integrity=dict(
                                            type="dict",
                                            options=dict(
                                                aes_xcbc=dict(type="bool"),
                                                md5=dict(type="bool"),
                                                sha1=dict(type="bool"),
                                                sha256=dict(type="bool"),
                                                sha384=dict(type="bool"),
                                                sha512=dict(type="bool"),
                                            ),
                                        ),
                                        use_data_integrity=dict(
                                            type="str",
                                            choices=[
                                                "aes-xcbc",
                                                "sha1",
                                                "sha256",
                                                "sha384",
                                                "sha512",
                                                "md5",
                                            ],
                                        ),
                                        enforce_encryption_alg_and_data_integrity_on_all_users=dict(
                                            type="bool"
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        encryption_method=dict(
                            type="str",
                            choices=[
                                "prefer_ikev2_support_ikev1",
                                "ike_v2_only",
                                "ike_v1_only",
                            ],
                        ),
                        pre_shared_secret=dict(type="bool"),
                        support_legacy_auth_for_sc_l2tp_nokia_clients=dict(
                            type="bool"
                        ),
                        support_legacy_eap=dict(type="bool"),
                        support_l2tp_with_pre_shared_key=dict(type="bool"),
                        l2tp_pre_shared_key=dict(type="str", no_log=True),
                    ),
                ),
                vpn_advanced=dict(
                    type="dict",
                    options=dict(
                        allow_clear_traffic_to_encryption_domain_when_disconnected=dict(
                            type="bool"
                        ),
                        enable_load_distribution_for_mep_conf=dict(
                            type="bool"
                        ),
                        use_first_allocated_om_ip_addr_for_all_conn_to_the_gws_of_the_site=dict(
                            type="bool"
                        ),
                    ),
                ),
                scv=dict(
                    type="dict",
                    options=dict(
                        apply_scv_on_simplified_mode_fw_policies=dict(
                            type="bool"
                        ),
                        exceptions=dict(
                            type="list",
                            elements="dict",
                            options=dict(
                                hosts=dict(type="list", elements="str"),
                                services=dict(type="list", elements="str"),
                            ),
                        ),
                        no_scv_for_unsupported_cp_clients=dict(type="bool"),
                        upon_verification_accept_and_log_client_connection=dict(
                            type="bool"
                        ),
                        only_tcp_ip_protocols_are_used=dict(type="bool"),
                        policy_installed_on_all_interfaces=dict(type="bool"),
                        generate_log=dict(type="bool"),
                        notify_user=dict(type="bool"),
                    ),
                ),
                ssl_network_extender=dict(
                    type="dict",
                    options=dict(
                        user_auth_method=dict(
                            type="str",
                            choices=[
                                "certificate_with_enrollment",
                                "certificate",
                                "mixed",
                                "legacy",
                            ],
                        ),
                        supported_encryption_methods=dict(
                            type="str", choices=["3des_or_rc4", "3des_only"]
                        ),
                        client_upgrade_upon_connection=dict(
                            type="str",
                            choices=[
                                "force_upgrade",
                                "ask_user",
                                "no_upgrade",
                            ],
                        ),
                        client_uninstall_upon_disconnection=dict(
                            type="str",
                            choices=[
                                "force_uninstall",
                                "ask_user",
                                "dont_uninstall",
                            ],
                        ),
                        re_auth_user_interval=dict(type="int"),
                        scan_ep_machine_for_compliance_with_ep_compliance_policy=dict(
                            type="bool"
                        ),
                        client_outgoing_keep_alive_packets_frequency=dict(
                            type="int"
                        ),
                    ),
                ),
                secure_client_mobile=dict(
                    type="dict",
                    options=dict(
                        user_auth_method=dict(
                            type="str",
                            choices=[
                                "certificate_with_enrollment",
                                "certificate",
                                "mixed",
                                "legacy",
                            ],
                        ),
                        enable_password_caching=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        cache_password_timeout=dict(type="int"),
                        re_auth_user_interval=dict(type="int"),
                        connect_mode=dict(
                            type="str",
                            choices=[
                                "manual",
                                "always connected",
                                "on application request",
                                "configured on endpoint client",
                            ],
                        ),
                        automatically_initiate_dialup=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        disconnect_when_device_is_idle=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        supported_encryption_methods=dict(
                            type="str", choices=["3des_or_rc4", "3des_only"]
                        ),
                        route_all_traffic_to_gw=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                    ),
                ),
                endpoint_connect=dict(
                    type="dict",
                    options=dict(
                        enable_password_caching=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        cache_password_timeout=dict(type="int"),
                        re_auth_user_interval=dict(type="int"),
                        connect_mode=dict(
                            type="str",
                            choices=[
                                "Manual",
                                "Always Connected",
                                "Configured On Endpoint Client",
                            ],
                        ),
                        network_location_awareness=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        network_location_awareness_conf=dict(
                            type="dict",
                            options=dict(
                                vpn_clients_are_considered_inside_the_internal_network_when_the_client=dict(
                                    type="str",
                                    choices=[
                                        "connects to gw through internal interface",
                                        "connects from network or group",
                                        "runs on computer with access to active directory domain",
                                    ],
                                ),
                                network_or_group_of_conn_vpn_client=dict(
                                    type="str"
                                ),
                                consider_wireless_networks_as_external=dict(
                                    type="bool"
                                ),
                                excluded_internal_wireless_networks=dict(
                                    type="list", elements="str"
                                ),
                                consider_undefined_dns_suffixes_as_external=dict(
                                    type="bool"
                                ),
                                dns_suffixes=dict(type="list", elements="str"),
                                remember_previously_detected_external_networks=dict(
                                    type="bool"
                                ),
                            ),
                        ),
                        disconnect_when_conn_to_network_is_lost=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        disconnect_when_device_is_idle=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        route_all_traffic_to_gw=dict(
                            type="str",
                            choices=["client_decide", "true", "false"],
                        ),
                        client_upgrade_mode=dict(
                            type="str",
                            choices=[
                                "force_upgrade",
                                "ask_user",
                                "no_upgrade",
                            ],
                        ),
                    ),
                ),
                hot_spot_and_hotel_registration=dict(
                    type="dict",
                    options=dict(
                        enable_registration=dict(type="bool"),
                        local_subnets_access_only=dict(type="bool"),
                        registration_timeout=dict(type="int"),
                        track_log=dict(type="bool"),
                        max_ip_access_during_registration=dict(type="int"),
                        ports=dict(type="list", elements="str"),
                    ),
                ),
            ),
        ),
        user_directory=dict(
            type="dict",
            options=dict(
                enable_password_change_when_user_active_directory_expires=dict(
                    type="bool"
                ),
                cache_size=dict(type="int"),
                enable_password_expiration_configuration=dict(type="bool"),
                password_expires_after=dict(type="int", no_log=False),
                timeout_on_cached_users=dict(type="int"),
                display_user_dn_at_login=dict(
                    type="str",
                    choices=["no display", "display upon request", "display"],
                ),
                enforce_rules_for_user_mgmt_admins=dict(type="bool"),
                min_password_length=dict(type="int", no_log=False),
                password_must_include_a_digit=dict(type="bool"),
                password_must_include_a_symbol=dict(type="bool"),
                password_must_include_lowercase_char=dict(type="bool"),
                password_must_include_uppercase_char=dict(type="bool"),
            ),
        ),
        qos=dict(
            type="dict",
            options=dict(
                default_weight_of_rule=dict(type="int"),
                max_weight_of_rule=dict(type="int"),
                unit_of_measure=dict(
                    type="str",
                    choices=[
                        "bits-per-sec",
                        "bytes-per-sec",
                        "kbits-per-sec",
                        "kbytes-per-sec",
                        "mbits-per-sec",
                        "mbytes-per-sec",
                    ],
                ),
                authenticated_ip_expiration=dict(type="int"),
                non_authenticated_ip_expiration=dict(type="int"),
                unanswered_queried_ip_expiration=dict(type="int"),
            ),
        ),
        carrier_security=dict(
            type="dict",
            options=dict(
                block_gtp_in_gtp=dict(type="bool"),
                enforce_gtp_anti_spoofing=dict(type="bool"),
                produce_extended_logs_on_unmatched_pdus=dict(type="bool"),
                produce_extended_logs_on_unmatched_pdus_position=dict(
                    type="str", choices=["before last", "last"]
                ),
                protocol_violation_track_option=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                enable_g_pdu_seq_number_check_with_max_deviation=dict(
                    type="bool"
                ),
                g_pdu_seq_number_check_max_deviation=dict(type="int"),
                verify_flow_labels=dict(type="bool"),
                allow_ggsn_replies_from_multiple_interfaces=dict(type="bool"),
                enable_reverse_connections=dict(type="bool"),
                gtp_signaling_rate_limit_sampling_interval=dict(type="int"),
                one_gtp_echo_on_each_path_frequency=dict(type="int"),
                aggressive_aging=dict(type="bool"),
                aggressive_timeout=dict(type="int"),
                memory_activation_threshold=dict(type="int"),
                memory_deactivation_threshold=dict(type="int"),
                tunnel_activation_threshold=dict(type="int"),
                tunnel_deactivation_threshold=dict(type="int"),
            ),
        ),
        user_accounts=dict(
            type="dict",
            options=dict(
                expiration_date_method=dict(
                    type="str", choices=["expire after", "expire at"]
                ),
                expiration_date=dict(type="str"),
                days_until_expiration=dict(type="int"),
                show_accounts_expiration_indication_days_in_advance=dict(
                    type="bool"
                ),
            ),
        ),
        user_authority=dict(
            type="dict",
            options=dict(
                display_web_access_view=dict(type="bool"),
                windows_domains_to_trust=dict(
                    type="str", choices=["selectively", "all"]
                ),
                trust_only_following_windows_domains=dict(
                    type="list", elements="str"
                ),
            ),
        ),
        connect_control=dict(
            type="dict",
            options=dict(
                load_agents_port=dict(type="int"),
                load_measurement_interval=dict(type="int"),
                persistence_server_timeout=dict(type="int"),
                server_availability_check_interval=dict(type="int"),
                server_check_retries=dict(type="int"),
            ),
        ),
        stateful_inspection=dict(
            type="dict",
            options=dict(
                tcp_start_timeout=dict(type="int"),
                tcp_session_timeout=dict(type="int"),
                tcp_end_timeout=dict(type="int"),
                tcp_end_timeout_r8020_gw_and_above=dict(type="int"),
                udp_virtual_session_timeout=dict(type="int"),
                icmp_virtual_session_timeout=dict(type="int"),
                other_ip_protocols_virtual_session_timeout=dict(type="int"),
                sctp_start_timeout=dict(type="int"),
                sctp_session_timeout=dict(type="int"),
                sctp_end_timeout=dict(type="int"),
                accept_stateful_udp_replies_for_unknown_services=dict(
                    type="bool"
                ),
                accept_stateful_icmp_errors=dict(type="bool"),
                accept_stateful_icmp_replies=dict(type="bool"),
                accept_stateful_other_ip_protocols_replies_for_unknown_services=dict(
                    type="bool"
                ),
                drop_out_of_state_tcp_packets=dict(type="bool"),
                log_on_drop_out_of_state_tcp_packets=dict(type="bool"),
                tcp_out_of_state_drop_exceptions=dict(
                    type="list", elements="str"
                ),
                drop_out_of_state_icmp_packets=dict(type="bool"),
                log_on_drop_out_of_state_icmp_packets=dict(type="bool"),
                drop_out_of_state_sctp_packets=dict(type="bool"),
                log_on_drop_out_of_state_sctp_packets=dict(type="bool"),
            ),
        ),
        log_and_alert=dict(
            type="dict",
            options=dict(
                administrative_notifications=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                connection_matched_by_sam=dict(
                    type="str",
                    choices=[
                        "Popup Alert",
                        "Mail Alert",
                        "SNMP Trap Alert",
                        "User Defined Alert no.1",
                        "User Defined Alert no.2",
                        "User Defined Alert no.3",
                    ],
                ),
                dynamic_object_resolution_failure=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                ip_options_drop=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                packet_is_incorrectly_tagged=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                packet_tagging_brute_force_attack=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                sla_violation=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                vpn_conf_and_key_exchange_errors=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                vpn_packet_handling_error=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                vpn_successful_key_exchange=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                log_every_authenticated_http_connection=dict(type="bool"),
                log_traffic=dict(type="str", choices=["none", "log"]),
                alerts=dict(
                    type="dict",
                    options=dict(
                        send_popup_alert_to_smartview_monitor=dict(
                            type="bool"
                        ),
                        popup_alert_script=dict(type="str"),
                        send_mail_alert_to_smartview_monitor=dict(type="bool"),
                        mail_alert_script=dict(type="str"),
                        send_snmp_trap_alert_to_smartview_monitor=dict(
                            type="bool"
                        ),
                        snmp_trap_alert_script=dict(type="str"),
                        send_user_defined_alert_num1_to_smartview_monitor=dict(
                            type="bool"
                        ),
                        user_defined_script_num1=dict(type="str"),
                        send_user_defined_alert_num2_to_smartview_monitor=dict(
                            type="bool"
                        ),
                        user_defined_script_num2=dict(type="str"),
                        send_user_defined_alert_num3_to_smartview_monitor=dict(
                            type="bool"
                        ),
                        user_defined_script_num3=dict(type="str"),
                        default_track_option_for_system_alerts=dict(
                            type="str",
                            choices=[
                                "Popup Alert",
                                "Mail Alert",
                                "SNMP Trap Alert",
                                "User Defined Alert no.1",
                                "User Defined Alert no.2",
                                "User Defined Alert no.3",
                            ],
                        ),
                    ),
                ),
                time_settings=dict(
                    type="dict",
                    options=dict(
                        excessive_log_grace_period=dict(type="int"),
                        logs_resolving_timeout=dict(type="int"),
                        status_fetching_interval=dict(type="int"),
                        virtual_link_statistics_logging_interval=dict(
                            type="int"
                        ),
                    ),
                ),
            ),
        ),
        data_access_control=dict(
            type="dict",
            options=dict(
                auto_download_important_data=dict(type="bool"),
                auto_download_sw_updates_and_new_features=dict(type="bool"),
                send_anonymous_info=dict(type="bool"),
                share_sensitive_info=dict(type="bool"),
            ),
        ),
        non_unique_ip_address_ranges=dict(
            type="list",
            elements="dict",
            options=dict(
                address_type=dict(type="str", choices=["IPv4", "IPv6"]),
                first_ipv4_address=dict(type="str"),
                first_ipv6_address=dict(type="str"),
                last_ipv4_address=dict(type="str"),
                last_ipv6_address=dict(type="str"),
            ),
        ),
        proxy=dict(
            type="dict",
            options=dict(
                use_proxy_server=dict(type="bool"),
                proxy_address=dict(type="str"),
                proxy_port=dict(type="int"),
            ),
        ),
        user_check=dict(
            type="dict",
            options=dict(
                preferred_language=dict(
                    type="str",
                    choices=[
                        "Afrikaans",
                        "Albanian",
                        "Amharic",
                        "Arabic",
                        "Armenian",
                        "Basque",
                        "Belarusian",
                        "Bosnian",
                        "Bulgarian",
                        "Catalan",
                        "Chinese",
                        "Croatian",
                        "Czech",
                        "Danish",
                        "Dutch",
                        "English",
                        "Estonian",
                        "Finnish",
                        "French",
                        "Gaelic",
                        "Georgian",
                        "German",
                        "Greek",
                        "Hebrew",
                        "Hindi",
                        "Hungarian",
                        "Icelandic",
                        "Indonesian",
                        "Irish",
                        "Italian",
                        "Japanese",
                        "Korean",
                        "Latvian",
                        "Lithuanian",
                        "Macedonia",
                        "Maltese",
                        "Nepali",
                        "Norwegian",
                        "Polish",
                        "Portuguese",
                        "Romanian",
                        "Russian",
                        "Serbian",
                        "Slovak",
                        "Slovenian",
                        "Sorbian",
                        "Spanish",
                        "Swahili",
                        "Swedish",
                        "Thai",
                        "Turkish",
                        "Ukrainian",
                        "Vietnamese",
                        "Welsh",
                    ],
                ),
                send_emails_using_mail_server=dict(type="str"),
            ),
        ),
        hit_count=dict(
            type="dict",
            options=dict(
                enable_hit_count=dict(type="bool"),
                keep_hit_count_data_up_to=dict(
                    type="str",
                    choices=["3 months", "6 months", "1 year", "2 years"],
                ),
            ),
        ),
        advanced_conf=dict(
            type="dict",
            options=dict(
                certs_and_pki=dict(
                    type="dict",
                    options=dict(
                        cert_validation_enforce_key_size=dict(
                            type="str", choices=["off", "alert", "fail"]
                        ),
                        host_certs_ecdsa_key_size=dict(
                            type="str", choices=["p-256", "p-384", "p-521"]
                        ),
                        host_certs_key_size=dict(
                            type="str", choices=["4096", "1024", "2048"]
                        ),
                    ),
                )
            ),
        ),
        allow_remote_registration_of_opsec_products=dict(type="bool"),
        num_spoofing_errs_that_trigger_brute_force=dict(type="int"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        domains_to_process=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
        auto_publish_session=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-global-properties"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
