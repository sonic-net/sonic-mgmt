#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_vap_dynamicmapping
short_description: Configure Virtual Access Points
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    vap:
        description: The parameter (vap) in requested url.
        type: str
        required: true
    vap_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _centmgmt:
                type: str
                description: Centmgmt.
                choices:
                    - 'disable'
                    - 'enable'
            _dhcp_svr_id:
                type: str
                description: Dhcp svr id.
            _intf_allowaccess:
                type: list
                elements: str
                description: Intf allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
                    - 'auto-ipsec'
                    - 'radius-acct'
                    - 'probe-response'
                    - 'capwap'
                    - 'dnp'
                    - 'ftm'
                    - 'fabric'
                    - 'speed-test'
            _intf_device_identification:
                aliases: ['_intf_device-identification']
                type: str
                description: Intf device identification.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_device_netscan:
                aliases: ['_intf_device-netscan']
                type: str
                description: Intf device netscan.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp_relay_ip:
                aliases: ['_intf_dhcp-relay-ip']
                type: raw
                description: (list) Intf dhcp relay ip.
            _intf_dhcp_relay_service:
                aliases: ['_intf_dhcp-relay-service']
                type: str
                description: Intf dhcp relay service.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp_relay_type:
                aliases: ['_intf_dhcp-relay-type']
                type: str
                description: Intf dhcp relay type.
                choices:
                    - 'regular'
                    - 'ipsec'
            _intf_dhcp6_relay_ip:
                aliases: ['_intf_dhcp6-relay-ip']
                type: str
                description: Intf dhcp6 relay ip.
            _intf_dhcp6_relay_service:
                aliases: ['_intf_dhcp6-relay-service']
                type: str
                description: Intf dhcp6 relay service.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp6_relay_type:
                aliases: ['_intf_dhcp6-relay-type']
                type: str
                description: Intf dhcp6 relay type.
                choices:
                    - 'regular'
            _intf_ip:
                type: str
                description: Intf ip.
            _intf_ip6_address:
                aliases: ['_intf_ip6-address']
                type: str
                description: Intf ip6 address.
            _intf_ip6_allowaccess:
                aliases: ['_intf_ip6-allowaccess']
                type: list
                elements: str
                description: Intf ip6 allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'any'
                    - 'fgfm'
                    - 'capwap'
            _intf_listen_forticlient_connection:
                aliases: ['_intf_listen-forticlient-connection']
                type: str
                description: Intf listen forticlient connection.
                choices:
                    - 'disable'
                    - 'enable'
            _scope:
                type: list
                elements: dict
                description: Scope.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            acct_interim_interval:
                aliases: ['acct-interim-interval']
                type: int
                description: Acct interim interval.
            address_group:
                aliases: ['address-group']
                type: str
                description: Address group.
            alias:
                type: str
                description: Alias.
            atf_weight:
                aliases: ['atf-weight']
                type: int
                description: Atf weight.
            auth:
                type: str
                description: Auth.
                choices:
                    - 'PSK'
                    - 'psk'
                    - 'RADIUS'
                    - 'radius'
                    - 'usergroup'
            broadcast_ssid:
                aliases: ['broadcast-ssid']
                type: str
                description: Broadcast ssid.
                choices:
                    - 'disable'
                    - 'enable'
            broadcast_suppression:
                aliases: ['broadcast-suppression']
                type: list
                elements: str
                description: Broadcast suppression.
                choices:
                    - 'dhcp'
                    - 'arp'
                    - 'dhcp2'
                    - 'arp2'
                    - 'netbios-ns'
                    - 'netbios-ds'
                    - 'arp3'
                    - 'dhcp-up'
                    - 'dhcp-down'
                    - 'arp-known'
                    - 'arp-unknown'
                    - 'arp-reply'
                    - 'ipv6'
                    - 'dhcp-starvation'
                    - 'arp-poison'
                    - 'all-other-mc'
                    - 'all-other-bc'
                    - 'arp-proxy'
                    - 'dhcp-ucast'
            captive_portal_ac_name:
                aliases: ['captive-portal-ac-name']
                type: str
                description: Captive portal ac name.
            captive_portal_macauth_radius_secret:
                aliases: ['captive-portal-macauth-radius-secret']
                type: raw
                description: (list) Captive portal macauth radius secret.
            captive_portal_macauth_radius_server:
                aliases: ['captive-portal-macauth-radius-server']
                type: str
                description: Captive portal macauth radius server.
            captive_portal_radius_secret:
                aliases: ['captive-portal-radius-secret']
                type: raw
                description: (list) Captive portal radius secret.
            captive_portal_radius_server:
                aliases: ['captive-portal-radius-server']
                type: str
                description: Captive portal radius server.
            captive_portal_session_timeout_interval:
                aliases: ['captive-portal-session-timeout-interval']
                type: int
                description: Captive portal session timeout interval.
            client_count:
                aliases: ['client-count']
                type: int
                description: Client count.
            dhcp_lease_time:
                aliases: ['dhcp-lease-time']
                type: int
                description: Dhcp lease time.
            dhcp_option82_circuit_id_insertion:
                aliases: ['dhcp-option82-circuit-id-insertion']
                type: str
                description: Dhcp option82 circuit id insertion.
                choices:
                    - 'disable'
                    - 'style-1'
                    - 'style-2'
                    - 'style-3'
            dhcp_option82_insertion:
                aliases: ['dhcp-option82-insertion']
                type: str
                description: Dhcp option82 insertion.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_option82_remote_id_insertion:
                aliases: ['dhcp-option82-remote-id-insertion']
                type: str
                description: Dhcp option82 remote id insertion.
                choices:
                    - 'disable'
                    - 'style-1'
            dynamic_vlan:
                aliases: ['dynamic-vlan']
                type: str
                description: Dynamic vlan.
                choices:
                    - 'disable'
                    - 'enable'
            eap_reauth:
                aliases: ['eap-reauth']
                type: str
                description: Eap reauth.
                choices:
                    - 'disable'
                    - 'enable'
            eap_reauth_intv:
                aliases: ['eap-reauth-intv']
                type: int
                description: Eap reauth intv.
            eapol_key_retries:
                aliases: ['eapol-key-retries']
                type: str
                description: Eapol key retries.
                choices:
                    - 'disable'
                    - 'enable'
            encrypt:
                type: str
                description: Encrypt.
                choices:
                    - 'TKIP'
                    - 'AES'
                    - 'TKIP-AES'
            external_fast_roaming:
                aliases: ['external-fast-roaming']
                type: str
                description: External fast roaming.
                choices:
                    - 'disable'
                    - 'enable'
            external_logout:
                aliases: ['external-logout']
                type: str
                description: External logout.
            external_web:
                aliases: ['external-web']
                type: str
                description: External web.
            fast_bss_transition:
                aliases: ['fast-bss-transition']
                type: str
                description: Fast bss transition.
                choices:
                    - 'disable'
                    - 'enable'
            fast_roaming:
                aliases: ['fast-roaming']
                type: str
                description: Fast roaming.
                choices:
                    - 'disable'
                    - 'enable'
            ft_mobility_domain:
                aliases: ['ft-mobility-domain']
                type: int
                description: Ft mobility domain.
            ft_over_ds:
                aliases: ['ft-over-ds']
                type: str
                description: Ft over ds.
                choices:
                    - 'disable'
                    - 'enable'
            ft_r0_key_lifetime:
                aliases: ['ft-r0-key-lifetime']
                type: int
                description: Ft r0 key lifetime.
            gtk_rekey:
                aliases: ['gtk-rekey']
                type: str
                description: Gtk rekey.
                choices:
                    - 'disable'
                    - 'enable'
            gtk_rekey_intv:
                aliases: ['gtk-rekey-intv']
                type: int
                description: Gtk rekey intv.
            hotspot20_profile:
                aliases: ['hotspot20-profile']
                type: str
                description: Hotspot20 profile.
            intra_vap_privacy:
                aliases: ['intra-vap-privacy']
                type: str
                description: Intra vap privacy.
                choices:
                    - 'disable'
                    - 'enable'
            ip:
                type: str
                description: Ip.
            key:
                type: raw
                description: (list) Key.
            keyindex:
                type: int
                description: Keyindex.
            ldpc:
                type: str
                description: Ldpc.
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'rxtx'
            local_authentication:
                aliases: ['local-authentication']
                type: str
                description: Local authentication.
                choices:
                    - 'disable'
                    - 'enable'
            local_bridging:
                aliases: ['local-bridging']
                type: str
                description: Local bridging.
                choices:
                    - 'disable'
                    - 'enable'
            local_lan:
                aliases: ['local-lan']
                type: str
                description: Local lan.
                choices:
                    - 'deny'
                    - 'allow'
            local_standalone:
                aliases: ['local-standalone']
                type: str
                description: Local standalone.
                choices:
                    - 'disable'
                    - 'enable'
            local_standalone_nat:
                aliases: ['local-standalone-nat']
                type: str
                description: Local standalone nat.
                choices:
                    - 'disable'
                    - 'enable'
            local_switching:
                aliases: ['local-switching']
                type: str
                description: Local switching.
                choices:
                    - 'disable'
                    - 'enable'
            mac_auth_bypass:
                aliases: ['mac-auth-bypass']
                type: str
                description: Mac auth bypass.
                choices:
                    - 'disable'
                    - 'enable'
            mac_filter:
                aliases: ['mac-filter']
                type: str
                description: Mac filter.
                choices:
                    - 'disable'
                    - 'enable'
            mac_filter_policy_other:
                aliases: ['mac-filter-policy-other']
                type: str
                description: Mac filter policy other.
                choices:
                    - 'deny'
                    - 'allow'
            max_clients:
                aliases: ['max-clients']
                type: int
                description: Max clients.
            max_clients_ap:
                aliases: ['max-clients-ap']
                type: int
                description: Max clients ap.
            me_disable_thresh:
                aliases: ['me-disable-thresh']
                type: int
                description: Me disable thresh.
            mesh_backhaul:
                aliases: ['mesh-backhaul']
                type: str
                description: Mesh backhaul.
                choices:
                    - 'disable'
                    - 'enable'
            mpsk:
                type: str
                description: Mpsk.
                choices:
                    - 'disable'
                    - 'enable'
            mpsk_concurrent_clients:
                aliases: ['mpsk-concurrent-clients']
                type: int
                description: Mpsk concurrent clients.
            multicast_enhance:
                aliases: ['multicast-enhance']
                type: str
                description: Multicast enhance.
                choices:
                    - 'disable'
                    - 'enable'
            multicast_rate:
                aliases: ['multicast-rate']
                type: str
                description: Multicast rate.
                choices:
                    - '0'
                    - '6000'
                    - '12000'
                    - '24000'
            okc:
                type: str
                description: Okc.
                choices:
                    - 'disable'
                    - 'enable'
            owe_groups:
                aliases: ['owe-groups']
                type: list
                elements: str
                description: Owe groups.
                choices:
                    - '19'
                    - '20'
                    - '21'
            owe_transition:
                aliases: ['owe-transition']
                type: str
                description: Owe transition.
                choices:
                    - 'disable'
                    - 'enable'
            owe_transition_ssid:
                aliases: ['owe-transition-ssid']
                type: str
                description: Owe transition ssid.
            passphrase:
                type: raw
                description: (list) Passphrase.
            pmf:
                type: str
                description: Pmf.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            pmf_assoc_comeback_timeout:
                aliases: ['pmf-assoc-comeback-timeout']
                type: int
                description: Pmf assoc comeback timeout.
            pmf_sa_query_retry_timeout:
                aliases: ['pmf-sa-query-retry-timeout']
                type: int
                description: Pmf sa query retry timeout.
            portal_message_override_group:
                aliases: ['portal-message-override-group']
                type: str
                description: Portal message override group.
            portal_type:
                aliases: ['portal-type']
                type: str
                description: Portal type.
                choices:
                    - 'auth'
                    - 'auth+disclaimer'
                    - 'disclaimer'
                    - 'email-collect'
                    - 'cmcc'
                    - 'cmcc-macauth'
                    - 'auth-mac'
                    - 'external-auth'
                    - 'external-macauth'
            probe_resp_suppression:
                aliases: ['probe-resp-suppression']
                type: str
                description: Probe resp suppression.
                choices:
                    - 'disable'
                    - 'enable'
            probe_resp_threshold:
                aliases: ['probe-resp-threshold']
                type: str
                description: Probe resp threshold.
            ptk_rekey:
                aliases: ['ptk-rekey']
                type: str
                description: Ptk rekey.
                choices:
                    - 'disable'
                    - 'enable'
            ptk_rekey_intv:
                aliases: ['ptk-rekey-intv']
                type: int
                description: Ptk rekey intv.
            qos_profile:
                aliases: ['qos-profile']
                type: str
                description: Qos profile.
            quarantine:
                type: str
                description: Quarantine.
                choices:
                    - 'disable'
                    - 'enable'
            radio_2g_threshold:
                aliases: ['radio-2g-threshold']
                type: str
                description: Radio 2g threshold.
            radio_5g_threshold:
                aliases: ['radio-5g-threshold']
                type: str
                description: Radio 5g threshold.
            radio_sensitivity:
                aliases: ['radio-sensitivity']
                type: str
                description: Radio sensitivity.
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_auth:
                aliases: ['radius-mac-auth']
                type: str
                description: Radius mac auth.
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_auth_server:
                aliases: ['radius-mac-auth-server']
                type: str
                description: Radius mac auth server.
            radius_mac_auth_usergroups:
                aliases: ['radius-mac-auth-usergroups']
                type: raw
                description: (list) Radius mac auth usergroups.
            radius_server:
                aliases: ['radius-server']
                type: str
                description: Radius server.
            rates_11a:
                aliases: ['rates-11a']
                type: list
                elements: str
                description: Rates 11a.
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '11'
                    - '11-basic'
            rates_11ac_ss12:
                aliases: ['rates-11ac-ss12']
                type: list
                elements: str
                description: Rates 11ac ss12.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates_11ac_ss34:
                aliases: ['rates-11ac-ss34']
                type: list
                elements: str
                description: Rates 11ac ss34.
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs10/4'
                    - 'mcs11/4'
            rates_11bg:
                aliases: ['rates-11bg']
                type: list
                elements: str
                description: Rates 11bg.
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '11'
                    - '11-basic'
            rates_11n_ss12:
                aliases: ['rates-11n-ss12']
                type: list
                elements: str
                description: Rates 11n ss12.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
                    - 'mcs12/2'
                    - 'mcs13/2'
                    - 'mcs14/2'
                    - 'mcs15/2'
            rates_11n_ss34:
                aliases: ['rates-11n-ss34']
                type: list
                elements: str
                description: Rates 11n ss34.
                choices:
                    - 'mcs16/3'
                    - 'mcs17/3'
                    - 'mcs18/3'
                    - 'mcs19/3'
                    - 'mcs20/3'
                    - 'mcs21/3'
                    - 'mcs22/3'
                    - 'mcs23/3'
                    - 'mcs24/4'
                    - 'mcs25/4'
                    - 'mcs26/4'
                    - 'mcs27/4'
                    - 'mcs28/4'
                    - 'mcs29/4'
                    - 'mcs30/4'
                    - 'mcs31/4'
            sae_groups:
                aliases: ['sae-groups']
                type: list
                elements: str
                description: Sae groups.
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
            sae_password:
                aliases: ['sae-password']
                type: raw
                description: (list) Sae password.
            schedule:
                type: raw
                description: (list or str) Schedule.
            security:
                type: str
                description: Security.
                choices:
                    - 'None'
                    - 'WEP64'
                    - 'wep64'
                    - 'WEP128'
                    - 'wep128'
                    - 'WPA_PSK'
                    - 'WPA_RADIUS'
                    - 'WPA'
                    - 'WPA2'
                    - 'WPA2_AUTO'
                    - 'open'
                    - 'wpa-personal'
                    - 'wpa-enterprise'
                    - 'captive-portal'
                    - 'wpa-only-personal'
                    - 'wpa-only-enterprise'
                    - 'wpa2-only-personal'
                    - 'wpa2-only-enterprise'
                    - 'wpa-personal+captive-portal'
                    - 'wpa-only-personal+captive-portal'
                    - 'wpa2-only-personal+captive-portal'
                    - 'osen'
                    - 'wpa3-enterprise'
                    - 'sae'
                    - 'sae-transition'
                    - 'owe'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
                    - 'wpa3-only-enterprise'
                    - 'wpa3-enterprise-transition'
            security_exempt_list:
                aliases: ['security-exempt-list']
                type: str
                description: Security exempt list.
            security_obsolete_option:
                aliases: ['security-obsolete-option']
                type: str
                description: Security obsolete option.
                choices:
                    - 'disable'
                    - 'enable'
            security_redirect_url:
                aliases: ['security-redirect-url']
                type: str
                description: Security redirect url.
            selected_usergroups:
                aliases: ['selected-usergroups']
                type: raw
                description: (list or str) Selected usergroups.
            split_tunneling:
                aliases: ['split-tunneling']
                type: str
                description: Split tunneling.
                choices:
                    - 'disable'
                    - 'enable'
            ssid:
                type: str
                description: Ssid.
            tkip_counter_measure:
                aliases: ['tkip-counter-measure']
                type: str
                description: Tkip counter measure.
                choices:
                    - 'disable'
                    - 'enable'
            usergroup:
                type: raw
                description: (list or str) Usergroup.
            utm_profile:
                aliases: ['utm-profile']
                type: str
                description: Utm profile.
            vdom:
                type: raw
                description: (list or str) Vdom.
            vlan_auto:
                aliases: ['vlan-auto']
                type: str
                description: Vlan auto.
                choices:
                    - 'disable'
                    - 'enable'
            vlan_pooling:
                aliases: ['vlan-pooling']
                type: str
                description: Vlan pooling.
                choices:
                    - 'wtp-group'
                    - 'round-robin'
                    - 'hash'
                    - 'disable'
            vlanid:
                type: int
                description: Vlanid.
            voice_enterprise:
                aliases: ['voice-enterprise']
                type: str
                description: Voice enterprise.
                choices:
                    - 'disable'
                    - 'enable'
            mu_mimo:
                aliases: ['mu-mimo']
                type: str
                description: Mu mimo.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_device_access_list:
                aliases: ['_intf_device-access-list']
                type: str
                description: Intf device access list.
            external_web_format:
                aliases: ['external-web-format']
                type: str
                description: External web format.
                choices:
                    - 'auto-detect'
                    - 'no-query-string'
                    - 'partial-query-string'
            high_efficiency:
                aliases: ['high-efficiency']
                type: str
                description: High efficiency.
                choices:
                    - 'disable'
                    - 'enable'
            primary_wag_profile:
                aliases: ['primary-wag-profile']
                type: str
                description: Primary wag profile.
            secondary_wag_profile:
                aliases: ['secondary-wag-profile']
                type: str
                description: Secondary wag profile.
            target_wake_time:
                aliases: ['target-wake-time']
                type: str
                description: Target wake time.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_echo_interval:
                aliases: ['tunnel-echo-interval']
                type: int
                description: Tunnel echo interval.
            tunnel_fallback_interval:
                aliases: ['tunnel-fallback-interval']
                type: int
                description: Tunnel fallback interval.
            access_control_list:
                aliases: ['access-control-list']
                type: str
                description: Access control list.
            captive_portal_auth_timeout:
                aliases: ['captive-portal-auth-timeout']
                type: int
                description: Captive portal auth timeout.
            ipv6_rules:
                aliases: ['ipv6-rules']
                type: list
                elements: str
                description: Ipv6 rules.
                choices:
                    - 'drop-icmp6ra'
                    - 'drop-icmp6rs'
                    - 'drop-llmnr6'
                    - 'drop-icmp6mld2'
                    - 'drop-dhcp6s'
                    - 'drop-dhcp6c'
                    - 'ndp-proxy'
                    - 'drop-ns-dad'
                    - 'drop-ns-nondad'
            sticky_client_remove:
                aliases: ['sticky-client-remove']
                type: str
                description: Sticky client remove.
                choices:
                    - 'disable'
                    - 'enable'
            sticky_client_threshold_2g:
                aliases: ['sticky-client-threshold-2g']
                type: str
                description: Sticky client threshold 2g.
            sticky_client_threshold_5g:
                aliases: ['sticky-client-threshold-5g']
                type: str
                description: Sticky client threshold 5g.
            bss_color_partial:
                aliases: ['bss-color-partial']
                type: str
                description: Bss color partial.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_option43_insertion:
                aliases: ['dhcp-option43-insertion']
                type: str
                description: Dhcp option43 insertion.
                choices:
                    - 'disable'
                    - 'enable'
            mpsk_profile:
                aliases: ['mpsk-profile']
                type: str
                description: Mpsk profile.
            igmp_snooping:
                aliases: ['igmp-snooping']
                type: str
                description: Enable/disable IGMP snooping.
                choices:
                    - 'disable'
                    - 'enable'
            port_macauth:
                aliases: ['port-macauth']
                type: str
                description: Enable/disable LAN port MAC authentication
                choices:
                    - 'disable'
                    - 'radius'
                    - 'address-group'
            port_macauth_reauth_timeout:
                aliases: ['port-macauth-reauth-timeout']
                type: int
                description: LAN port MAC authentication re-authentication timeout value
            port_macauth_timeout:
                aliases: ['port-macauth-timeout']
                type: int
                description: LAN port MAC authentication idle timeout value
            additional_akms:
                aliases: ['additional-akms']
                type: list
                elements: str
                description: Additional AKMs.
                choices:
                    - 'akm6'
                    - 'akm24'
            bstm_disassociation_imminent:
                aliases: ['bstm-disassociation-imminent']
                type: str
                description: Enable/disable forcing of disassociation after the BSTM request timer has been reached
                choices:
                    - 'disable'
                    - 'enable'
            bstm_load_balancing_disassoc_timer:
                aliases: ['bstm-load-balancing-disassoc-timer']
                type: int
                description: Time interval for client to voluntarily leave AP before forcing a disassociation due to AP load-balancing
            bstm_rssi_disassoc_timer:
                aliases: ['bstm-rssi-disassoc-timer']
                type: int
                description: Time interval for client to voluntarily leave AP before forcing a disassociation due to low RSSI
            dhcp_address_enforcement:
                aliases: ['dhcp-address-enforcement']
                type: str
                description: Enable/disable DHCP address enforcement
                choices:
                    - 'disable'
                    - 'enable'
            gas_comeback_delay:
                aliases: ['gas-comeback-delay']
                type: int
                description: GAS comeback delay
            gas_fragmentation_limit:
                aliases: ['gas-fragmentation-limit']
                type: int
                description: GAS fragmentation limit
            mac_called_station_delimiter:
                aliases: ['mac-called-station-delimiter']
                type: str
                description: MAC called station delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_calling_station_delimiter:
                aliases: ['mac-calling-station-delimiter']
                type: str
                description: MAC calling station delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_case:
                aliases: ['mac-case']
                type: str
                description: MAC case
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac_password_delimiter:
                aliases: ['mac-password-delimiter']
                type: str
                description: MAC authentication password delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_username_delimiter:
                aliases: ['mac-username-delimiter']
                type: str
                description: MAC authentication username delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mbo:
                type: str
                description: Enable/disable Multiband Operation
                choices:
                    - 'disable'
                    - 'enable'
            mbo_cell_data_conn_pref:
                aliases: ['mbo-cell-data-conn-pref']
                type: str
                description: MBO cell data connection preference
                choices:
                    - 'excluded'
                    - 'prefer-not'
                    - 'prefer-use'
            nac:
                type: str
                description: Enable/disable network access control.
                choices:
                    - 'disable'
                    - 'enable'
            nac_profile:
                aliases: ['nac-profile']
                type: str
                description: NAC profile name.
            neighbor_report_dual_band:
                aliases: ['neighbor-report-dual-band']
                type: str
                description: Enable/disable dual-band neighbor report
                choices:
                    - 'disable'
                    - 'enable'
            address_group_policy:
                aliases: ['address-group-policy']
                type: str
                description: Configure MAC address filtering policy for MAC addresses that are in the address-group.
                choices:
                    - 'disable'
                    - 'allow'
                    - 'deny'
            antivirus_profile:
                aliases: ['antivirus-profile']
                type: str
                description: AntiVirus profile name.
            application_detection_engine:
                aliases: ['application-detection-engine']
                type: str
                description: Enable/disable application detection engine
                choices:
                    - 'disable'
                    - 'enable'
            application_list:
                aliases: ['application-list']
                type: str
                description: Application control list name.
            application_report_intv:
                aliases: ['application-report-intv']
                type: int
                description: Application report interval
            auth_cert:
                aliases: ['auth-cert']
                type: str
                description: HTTPS server certificate.
            auth_portal_addr:
                aliases: ['auth-portal-addr']
                type: str
                description: Address of captive portal.
            beacon_advertising:
                aliases: ['beacon-advertising']
                type: list
                elements: str
                description: Fortinet beacon advertising IE data
                choices:
                    - 'name'
                    - 'model'
                    - 'serial-number'
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: IPS sensor name.
            l3_roaming:
                aliases: ['l3-roaming']
                type: str
                description: Enable/disable layer 3 roaming
                choices:
                    - 'disable'
                    - 'enable'
            local_standalone_dns:
                aliases: ['local-standalone-dns']
                type: str
                description: Enable/disable AP local standalone DNS.
                choices:
                    - 'disable'
                    - 'enable'
            local_standalone_dns_ip:
                aliases: ['local-standalone-dns-ip']
                type: raw
                description: (list) IPv4 addresses for the local standalone DNS.
            osen:
                type: str
                description: Enable/disable OSEN as part of key management
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_mpsk_auth:
                aliases: ['radius-mac-mpsk-auth']
                type: str
                description: Enable/disable RADIUS-based MAC authentication of clients for MPSK authentication
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_mpsk_timeout:
                aliases: ['radius-mac-mpsk-timeout']
                type: int
                description: RADIUS MAC MPSK cache timeout interval
            rates_11ax_ss12:
                aliases: ['rates-11ax-ss12']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates_11ax_ss34:
                aliases: ['rates-11ax-ss34']
                type: list
                elements: str
                description: Allowed data rates for 802.
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/4'
                    - 'mcs11/4'
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Block or monitor connections to Botnet servers or disable Botnet scanning.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            utm_log:
                aliases: ['utm-log']
                type: str
                description: Enable/disable UTM logging.
                choices:
                    - 'disable'
                    - 'enable'
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable to add one or more security profiles
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: WebFilter profile name.
            sae_h2e_only:
                aliases: ['sae-h2e-only']
                type: str
                description: Use hash-to-element-only mechanism for PWE derivation
                choices:
                    - 'disable'
                    - 'enable'
            sae_pk:
                aliases: ['sae-pk']
                type: str
                description: Enable/disable WPA3 SAE-PK
                choices:
                    - 'disable'
                    - 'enable'
            sae_private_key:
                aliases: ['sae-private-key']
                type: str
                description: Private key used for WPA3 SAE-PK authentication.
            sticky_client_threshold_6g:
                aliases: ['sticky-client-threshold-6g']
                type: str
                description: Minimum signal level/threshold in dBm required for the 6G client to be serviced by the AP
            application_dscp_marking:
                aliases: ['application-dscp-marking']
                type: str
                description: Enable/disable application attribute based DSCP marking
                choices:
                    - 'disable'
                    - 'enable'
            l3_roaming_mode:
                aliases: ['l3-roaming-mode']
                type: str
                description: Select the way that layer 3 roaming traffic is passed
                choices:
                    - 'direct'
                    - 'indirect'
            rates_11ac_mcs_map:
                aliases: ['rates-11ac-mcs-map']
                type: str
                description: Comma separated list of max supported VHT MCS for spatial streams 1 through 8.
            rates_11ax_mcs_map:
                aliases: ['rates-11ax-mcs-map']
                type: str
                description: Comma separated list of max supported HE MCS for spatial streams 1 through 8.
            captive_portal_fw_accounting:
                aliases: ['captive-portal-fw-accounting']
                type: str
                description: Enable/disable RADIUS accounting for captive portal firewall authentication session.
                choices:
                    - 'disable'
                    - 'enable'
            radius_mac_auth_block_interval:
                aliases: ['radius-mac-auth-block-interval']
                type: int
                description: Dont send RADIUS MAC auth request again if the client has been rejected within specific interval
            _is_factory_setting:
                type: str
                description: Is factory setting.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'ext'
            d80211k:
                aliases: ['80211k']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            d80211v:
                aliases: ['80211v']
                type: str
                description: Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            roaming_acct_interim_update:
                aliases: ['roaming-acct-interim-update']
                type: str
                description: Enable/disable using accounting interim update instead of accounting start/stop on roaming for WPA-Enterprise security.
                choices:
                    - 'disable'
                    - 'enable'
            sae_hnp_only:
                aliases: ['sae-hnp-only']
                type: str
                description: Use hunting-and-pecking-only mechanism for PWE derivation
                choices:
                    - 'disable'
                    - 'enable'
            akm24_only:
                aliases: ['akm24-only']
                type: str
                description: WPA3 SAE using group-dependent hash only
                choices:
                    - 'disable'
                    - 'enable'
            beacon_protection:
                aliases: ['beacon-protection']
                type: str
                description: Enable/disable beacon protection support
                choices:
                    - 'disable'
                    - 'enable'
            captive_portal:
                aliases: ['captive-portal']
                type: str
                description: Enable/disable captive portal.
                choices:
                    - 'disable'
                    - 'enable'
            nas_filter_rule:
                aliases: ['nas-filter-rule']
                type: str
                description: Enable/disable NAS filter rule support
                choices:
                    - 'disable'
                    - 'enable'
            rates_11be_mcs_map:
                aliases: ['rates-11be-mcs-map']
                type: str
                description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 20MHz/40MHz/80MHz bandwidth.
            rates_11be_mcs_map_160:
                aliases: ['rates-11be-mcs-map-160']
                type: str
                description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 160MHz bandwidth.
            rates_11be_mcs_map_320:
                aliases: ['rates-11be-mcs-map-320']
                type: str
                description: Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 320MHz bandwidth.
            _intf_ip_managed_by_fortiipam:
                aliases: ['_intf_ip-managed-by-fortiipam']
                type: str
                description: Intf ip managed by fortiipam.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'inherit-global'
            _intf_managed_subnetwork_size:
                aliases: ['_intf_managed-subnetwork-size']
                type: str
                description: Intf managed subnetwork size.
                choices:
                    - '32'
                    - '64'
                    - '128'
                    - '256'
                    - '512'
                    - '1024'
                    - '2048'
                    - '4096'
                    - '8192'
                    - '16384'
                    - '32768'
                    - '65536'
            domain_name_stripping:
                aliases: ['domain-name-stripping']
                type: str
                description: Enable/disable stripping domain name from identity
                choices:
                    - 'disable'
                    - 'enable'
            local_lan_partition:
                aliases: ['local-lan-partition']
                type: str
                description: Enable/disable segregating client traffic to local LAN side
                choices:
                    - 'disable'
                    - 'enable'
            _intf_role:
                type: str
                description: Intf role.
                choices:
                    - 'lan'
                    - 'wan'
                    - 'dmz'
                    - 'undefined'
            called_station_id_type:
                aliases: ['called-station-id-type']
                type: str
                description: The format type of RADIUS attribute Called-Station-Id
                choices:
                    - 'mac'
                    - 'ip'
                    - 'apname'
            external_pre_auth:
                aliases: ['external-pre-auth']
                type: str
                description: Enable/disable pre-authentication with external APs not managed by the FortiGate
                choices:
                    - 'disable'
                    - 'enable'
            pre_auth:
                aliases: ['pre-auth']
                type: str
                description: Enable/disable pre-authentication, where supported by clients
                choices:
                    - 'disable'
                    - 'enable'
            _intf_ip6_send_adv:
                aliases: ['_intf_ip6-send-adv']
                type: str
                description: Intf ip6 send adv.
                choices:
                    - 'disable'
                    - 'enable'
            ip6_prefix_list:
                aliases: ['ip6-prefix-list']
                type: list
                elements: dict
                description: Ip6 prefix list.
                suboptions:
                    autonomous_flag:
                        aliases: ['autonomous-flag']
                        type: str
                        description: Autonomous flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    dnssl:
                        type: raw
                        description: (list) Dnssl.
                    onlink_flag:
                        aliases: ['onlink-flag']
                        type: str
                        description: Onlink flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    preferred_life_time:
                        aliases: ['preferred-life-time']
                        type: int
                        description: Preferred life time.
                    prefix:
                        type: str
                        description: Prefix.
                    rdnss:
                        type: raw
                        description: (list) Rdnss.
                    valid_life_time:
                        aliases: ['valid-life-time']
                        type: int
                        description: Valid life time.
            _intf_vrf:
                type: int
                description: Intf vrf.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure Virtual Access Points
      fortinet.fortimanager.fmgr_vap_dynamicmapping:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        vap: <your own value>
        state: present # <value in [present, absent]>
        vap_dynamicmapping:
          _scope: # Required variable, list of device
            - name: <string>
              vdom: <string>
          # _centmgmt: <value in [disable, enable]>
          # _dhcp_svr_id: <string>
          # _intf_allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "fgfm"
          #   - "auto-ipsec"
          #   - "radius-acct"
          #   - "probe-response"
          #   - "capwap"
          #   - "dnp"
          #   - "ftm"
          #   - "fabric"
          #   - "speed-test"
          # _intf_device_identification: <value in [disable, enable]>
          # _intf_device_netscan: <value in [disable, enable]>
          # _intf_dhcp_relay_ip: <list or string>
          # _intf_dhcp_relay_service: <value in [disable, enable]>
          # _intf_dhcp_relay_type: <value in [regular, ipsec]>
          # _intf_dhcp6_relay_ip: <string>
          # _intf_dhcp6_relay_service: <value in [disable, enable]>
          # _intf_dhcp6_relay_type: <value in [regular]>
          # _intf_ip: <string>
          # _intf_ip6_address: <string>
          # _intf_ip6_allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "any"
          #   - "fgfm"
          #   - "capwap"
          # _intf_listen_forticlient_connection: <value in [disable, enable]>
          # acct_interim_interval: <integer>
          # address_group: <string>
          # alias: <string>
          # atf_weight: <integer>
          # auth: <value in [PSK, psk, RADIUS, ...]>
          # broadcast_ssid: <value in [disable, enable]>
          # broadcast_suppression:
          #   - "dhcp"
          #   - "arp"
          #   - "dhcp2"
          #   - "arp2"
          #   - "netbios-ns"
          #   - "netbios-ds"
          #   - "arp3"
          #   - "dhcp-up"
          #   - "dhcp-down"
          #   - "arp-known"
          #   - "arp-unknown"
          #   - "arp-reply"
          #   - "ipv6"
          #   - "dhcp-starvation"
          #   - "arp-poison"
          #   - "all-other-mc"
          #   - "all-other-bc"
          #   - "arp-proxy"
          #   - "dhcp-ucast"
          # captive_portal_ac_name: <string>
          # captive_portal_macauth_radius_secret: <list or string>
          # captive_portal_macauth_radius_server: <string>
          # captive_portal_radius_secret: <list or string>
          # captive_portal_radius_server: <string>
          # captive_portal_session_timeout_interval: <integer>
          # client_count: <integer>
          # dhcp_lease_time: <integer>
          # dhcp_option82_circuit_id_insertion: <value in [disable, style-1, style-2, ...]>
          # dhcp_option82_insertion: <value in [disable, enable]>
          # dhcp_option82_remote_id_insertion: <value in [disable, style-1]>
          # dynamic_vlan: <value in [disable, enable]>
          # eap_reauth: <value in [disable, enable]>
          # eap_reauth_intv: <integer>
          # eapol_key_retries: <value in [disable, enable]>
          # encrypt: <value in [TKIP, AES, TKIP-AES]>
          # external_fast_roaming: <value in [disable, enable]>
          # external_logout: <string>
          # external_web: <string>
          # fast_bss_transition: <value in [disable, enable]>
          # fast_roaming: <value in [disable, enable]>
          # ft_mobility_domain: <integer>
          # ft_over_ds: <value in [disable, enable]>
          # ft_r0_key_lifetime: <integer>
          # gtk_rekey: <value in [disable, enable]>
          # gtk_rekey_intv: <integer>
          # hotspot20_profile: <string>
          # intra_vap_privacy: <value in [disable, enable]>
          # ip: <string>
          # key: <list or string>
          # keyindex: <integer>
          # ldpc: <value in [disable, tx, rx, ...]>
          # local_authentication: <value in [disable, enable]>
          # local_bridging: <value in [disable, enable]>
          # local_lan: <value in [deny, allow]>
          # local_standalone: <value in [disable, enable]>
          # local_standalone_nat: <value in [disable, enable]>
          # local_switching: <value in [disable, enable]>
          # mac_auth_bypass: <value in [disable, enable]>
          # mac_filter: <value in [disable, enable]>
          # mac_filter_policy_other: <value in [deny, allow]>
          # max_clients: <integer>
          # max_clients_ap: <integer>
          # me_disable_thresh: <integer>
          # mesh_backhaul: <value in [disable, enable]>
          # mpsk: <value in [disable, enable]>
          # mpsk_concurrent_clients: <integer>
          # multicast_enhance: <value in [disable, enable]>
          # multicast_rate: <value in [0, 6000, 12000, ...]>
          # okc: <value in [disable, enable]>
          # owe_groups:
          #   - "19"
          #   - "20"
          #   - "21"
          # owe_transition: <value in [disable, enable]>
          # owe_transition_ssid: <string>
          # passphrase: <list or string>
          # pmf: <value in [disable, enable, optional]>
          # pmf_assoc_comeback_timeout: <integer>
          # pmf_sa_query_retry_timeout: <integer>
          # portal_message_override_group: <string>
          # portal_type: <value in [auth, auth+disclaimer, disclaimer, ...]>
          # probe_resp_suppression: <value in [disable, enable]>
          # probe_resp_threshold: <string>
          # ptk_rekey: <value in [disable, enable]>
          # ptk_rekey_intv: <integer>
          # qos_profile: <string>
          # quarantine: <value in [disable, enable]>
          # radio_2g_threshold: <string>
          # radio_5g_threshold: <string>
          # radio_sensitivity: <value in [disable, enable]>
          # radius_mac_auth: <value in [disable, enable]>
          # radius_mac_auth_server: <string>
          # radius_mac_auth_usergroups: <list or string>
          # radius_server: <string>
          # rates_11a:
          #   - "1"
          #   - "1-basic"
          #   - "2"
          #   - "2-basic"
          #   - "5.5"
          #   - "5.5-basic"
          #   - "6"
          #   - "6-basic"
          #   - "9"
          #   - "9-basic"
          #   - "12"
          #   - "12-basic"
          #   - "18"
          #   - "18-basic"
          #   - "24"
          #   - "24-basic"
          #   - "36"
          #   - "36-basic"
          #   - "48"
          #   - "48-basic"
          #   - "54"
          #   - "54-basic"
          #   - "11"
          #   - "11-basic"
          # rates_11ac_ss12:
          #   - "mcs0/1"
          #   - "mcs1/1"
          #   - "mcs2/1"
          #   - "mcs3/1"
          #   - "mcs4/1"
          #   - "mcs5/1"
          #   - "mcs6/1"
          #   - "mcs7/1"
          #   - "mcs8/1"
          #   - "mcs9/1"
          #   - "mcs0/2"
          #   - "mcs1/2"
          #   - "mcs2/2"
          #   - "mcs3/2"
          #   - "mcs4/2"
          #   - "mcs5/2"
          #   - "mcs6/2"
          #   - "mcs7/2"
          #   - "mcs8/2"
          #   - "mcs9/2"
          #   - "mcs10/1"
          #   - "mcs11/1"
          #   - "mcs10/2"
          #   - "mcs11/2"
          # rates_11ac_ss34:
          #   - "mcs0/3"
          #   - "mcs1/3"
          #   - "mcs2/3"
          #   - "mcs3/3"
          #   - "mcs4/3"
          #   - "mcs5/3"
          #   - "mcs6/3"
          #   - "mcs7/3"
          #   - "mcs8/3"
          #   - "mcs9/3"
          #   - "mcs0/4"
          #   - "mcs1/4"
          #   - "mcs2/4"
          #   - "mcs3/4"
          #   - "mcs4/4"
          #   - "mcs5/4"
          #   - "mcs6/4"
          #   - "mcs7/4"
          #   - "mcs8/4"
          #   - "mcs9/4"
          #   - "mcs10/3"
          #   - "mcs11/3"
          #   - "mcs10/4"
          #   - "mcs11/4"
          # rates_11bg:
          #   - "1"
          #   - "1-basic"
          #   - "2"
          #   - "2-basic"
          #   - "5.5"
          #   - "5.5-basic"
          #   - "6"
          #   - "6-basic"
          #   - "9"
          #   - "9-basic"
          #   - "12"
          #   - "12-basic"
          #   - "18"
          #   - "18-basic"
          #   - "24"
          #   - "24-basic"
          #   - "36"
          #   - "36-basic"
          #   - "48"
          #   - "48-basic"
          #   - "54"
          #   - "54-basic"
          #   - "11"
          #   - "11-basic"
          # rates_11n_ss12:
          #   - "mcs0/1"
          #   - "mcs1/1"
          #   - "mcs2/1"
          #   - "mcs3/1"
          #   - "mcs4/1"
          #   - "mcs5/1"
          #   - "mcs6/1"
          #   - "mcs7/1"
          #   - "mcs8/2"
          #   - "mcs9/2"
          #   - "mcs10/2"
          #   - "mcs11/2"
          #   - "mcs12/2"
          #   - "mcs13/2"
          #   - "mcs14/2"
          #   - "mcs15/2"
          # rates_11n_ss34:
          #   - "mcs16/3"
          #   - "mcs17/3"
          #   - "mcs18/3"
          #   - "mcs19/3"
          #   - "mcs20/3"
          #   - "mcs21/3"
          #   - "mcs22/3"
          #   - "mcs23/3"
          #   - "mcs24/4"
          #   - "mcs25/4"
          #   - "mcs26/4"
          #   - "mcs27/4"
          #   - "mcs28/4"
          #   - "mcs29/4"
          #   - "mcs30/4"
          #   - "mcs31/4"
          # sae_groups:
          #   - "1"
          #   - "2"
          #   - "5"
          #   - "14"
          #   - "15"
          #   - "16"
          #   - "17"
          #   - "18"
          #   - "19"
          #   - "20"
          #   - "21"
          #   - "27"
          #   - "28"
          #   - "29"
          #   - "30"
          #   - "31"
          # sae_password: <list or string>
          # schedule: <list or string>
          # security: <value in [None, WEP64, wep64, ...]>
          # security_exempt_list: <string>
          # security_obsolete_option: <value in [disable, enable]>
          # security_redirect_url: <string>
          # selected_usergroups: <list or string>
          # split_tunneling: <value in [disable, enable]>
          # ssid: <string>
          # tkip_counter_measure: <value in [disable, enable]>
          # usergroup: <list or string>
          # utm_profile: <string>
          # vdom: <list or string>
          # vlan_auto: <value in [disable, enable]>
          # vlan_pooling: <value in [wtp-group, round-robin, hash, ...]>
          # vlanid: <integer>
          # voice_enterprise: <value in [disable, enable]>
          # mu_mimo: <value in [disable, enable]>
          # _intf_device_access_list: <string>
          # external_web_format: <value in [auto-detect, no-query-string, partial-query-string]>
          # high_efficiency: <value in [disable, enable]>
          # primary_wag_profile: <string>
          # secondary_wag_profile: <string>
          # target_wake_time: <value in [disable, enable]>
          # tunnel_echo_interval: <integer>
          # tunnel_fallback_interval: <integer>
          # access_control_list: <string>
          # captive_portal_auth_timeout: <integer>
          # ipv6_rules:
          #   - "drop-icmp6ra"
          #   - "drop-icmp6rs"
          #   - "drop-llmnr6"
          #   - "drop-icmp6mld2"
          #   - "drop-dhcp6s"
          #   - "drop-dhcp6c"
          #   - "ndp-proxy"
          #   - "drop-ns-dad"
          #   - "drop-ns-nondad"
          # sticky_client_remove: <value in [disable, enable]>
          # sticky_client_threshold_2g: <string>
          # sticky_client_threshold_5g: <string>
          # bss_color_partial: <value in [disable, enable]>
          # dhcp_option43_insertion: <value in [disable, enable]>
          # mpsk_profile: <string>
          # igmp_snooping: <value in [disable, enable]>
          # port_macauth: <value in [disable, radius, address-group]>
          # port_macauth_reauth_timeout: <integer>
          # port_macauth_timeout: <integer>
          # additional_akms:
          #   - "akm6"
          #   - "akm24"
          # bstm_disassociation_imminent: <value in [disable, enable]>
          # bstm_load_balancing_disassoc_timer: <integer>
          # bstm_rssi_disassoc_timer: <integer>
          # dhcp_address_enforcement: <value in [disable, enable]>
          # gas_comeback_delay: <integer>
          # gas_fragmentation_limit: <integer>
          # mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_case: <value in [uppercase, lowercase]>
          # mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mbo: <value in [disable, enable]>
          # mbo_cell_data_conn_pref: <value in [excluded, prefer-not, prefer-use]>
          # nac: <value in [disable, enable]>
          # nac_profile: <string>
          # neighbor_report_dual_band: <value in [disable, enable]>
          # address_group_policy: <value in [disable, allow, deny]>
          # antivirus_profile: <string>
          # application_detection_engine: <value in [disable, enable]>
          # application_list: <string>
          # application_report_intv: <integer>
          # auth_cert: <string>
          # auth_portal_addr: <string>
          # beacon_advertising:
          #   - "name"
          #   - "model"
          #   - "serial-number"
          # ips_sensor: <string>
          # l3_roaming: <value in [disable, enable]>
          # local_standalone_dns: <value in [disable, enable]>
          # local_standalone_dns_ip: <list or string>
          # osen: <value in [disable, enable]>
          # radius_mac_mpsk_auth: <value in [disable, enable]>
          # radius_mac_mpsk_timeout: <integer>
          # rates_11ax_ss12:
          #   - "mcs0/1"
          #   - "mcs1/1"
          #   - "mcs2/1"
          #   - "mcs3/1"
          #   - "mcs4/1"
          #   - "mcs5/1"
          #   - "mcs6/1"
          #   - "mcs7/1"
          #   - "mcs8/1"
          #   - "mcs9/1"
          #   - "mcs10/1"
          #   - "mcs11/1"
          #   - "mcs0/2"
          #   - "mcs1/2"
          #   - "mcs2/2"
          #   - "mcs3/2"
          #   - "mcs4/2"
          #   - "mcs5/2"
          #   - "mcs6/2"
          #   - "mcs7/2"
          #   - "mcs8/2"
          #   - "mcs9/2"
          #   - "mcs10/2"
          #   - "mcs11/2"
          # rates_11ax_ss34:
          #   - "mcs0/3"
          #   - "mcs1/3"
          #   - "mcs2/3"
          #   - "mcs3/3"
          #   - "mcs4/3"
          #   - "mcs5/3"
          #   - "mcs6/3"
          #   - "mcs7/3"
          #   - "mcs8/3"
          #   - "mcs9/3"
          #   - "mcs10/3"
          #   - "mcs11/3"
          #   - "mcs0/4"
          #   - "mcs1/4"
          #   - "mcs2/4"
          #   - "mcs3/4"
          #   - "mcs4/4"
          #   - "mcs5/4"
          #   - "mcs6/4"
          #   - "mcs7/4"
          #   - "mcs8/4"
          #   - "mcs9/4"
          #   - "mcs10/4"
          #   - "mcs11/4"
          # scan_botnet_connections: <value in [disable, block, monitor]>
          # utm_log: <value in [disable, enable]>
          # utm_status: <value in [disable, enable]>
          # webfilter_profile: <string>
          # sae_h2e_only: <value in [disable, enable]>
          # sae_pk: <value in [disable, enable]>
          # sae_private_key: <string>
          # sticky_client_threshold_6g: <string>
          # application_dscp_marking: <value in [disable, enable]>
          # l3_roaming_mode: <value in [direct, indirect]>
          # rates_11ac_mcs_map: <string>
          # rates_11ax_mcs_map: <string>
          # captive_portal_fw_accounting: <value in [disable, enable]>
          # radius_mac_auth_block_interval: <integer>
          # _is_factory_setting: <value in [disable, enable, ext]>
          # d80211k: <value in [disable, enable]>
          # d80211v: <value in [disable, enable]>
          # roaming_acct_interim_update: <value in [disable, enable]>
          # sae_hnp_only: <value in [disable, enable]>
          # akm24_only: <value in [disable, enable]>
          # beacon_protection: <value in [disable, enable]>
          # captive_portal: <value in [disable, enable]>
          # nas_filter_rule: <value in [disable, enable]>
          # rates_11be_mcs_map: <string>
          # rates_11be_mcs_map_160: <string>
          # rates_11be_mcs_map_320: <string>
          # _intf_ip_managed_by_fortiipam: <value in [disable, enable, inherit-global]>
          # _intf_managed_subnetwork_size: <value in [32, 64, 128, ...]>
          # domain_name_stripping: <value in [disable, enable]>
          # local_lan_partition: <value in [disable, enable]>
          # _intf_role: <value in [lan, wan, dmz, ...]>
          # called_station_id_type: <value in [mac, ip, apname]>
          # external_pre_auth: <value in [disable, enable]>
          # pre_auth: <value in [disable, enable]>
          # _intf_ip6_send_adv: <value in [disable, enable]>
          # ip6_prefix_list:
          #   - autonomous_flag: <value in [disable, enable]>
          #     dnssl: <list or string>
          #     onlink_flag: <value in [disable, enable]>
          #     preferred_life_time: <integer>
          #     prefix: <string>
          #     rdnss: <list or string>
          #     valid_life_time: <integer>
          # _intf_vrf: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping',
        '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping'
    ]
    url_params = ['adom', 'vap']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vap': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vap_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_centmgmt': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_dhcp_svr_id': {'type': 'str'},
                '_intf_allowaccess': {
                    'type': 'list',
                    'choices': [
                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response', 'capwap', 'dnp', 'ftm',
                        'fabric', 'speed-test'
                    ],
                    'elements': 'str'
                },
                '_intf_device-identification': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_device-netscan': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp-relay-ip': {'type': 'raw'},
                '_intf_dhcp-relay-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp-relay-type': {'choices': ['regular', 'ipsec'], 'type': 'str'},
                '_intf_dhcp6-relay-ip': {'type': 'str'},
                '_intf_dhcp6-relay-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp6-relay-type': {'choices': ['regular'], 'type': 'str'},
                '_intf_ip': {'type': 'str'},
                '_intf_ip6-address': {'type': 'str'},
                '_intf_ip6-allowaccess': {
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'any', 'fgfm', 'capwap'],
                    'elements': 'str'
                },
                '_intf_listen-forticlient-connection': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'acct-interim-interval': {'type': 'int'},
                'address-group': {'type': 'str'},
                'alias': {'type': 'str'},
                'atf-weight': {'type': 'int'},
                'auth': {'choices': ['PSK', 'psk', 'RADIUS', 'radius', 'usergroup'], 'type': 'str'},
                'broadcast-ssid': {'choices': ['disable', 'enable'], 'type': 'str'},
                'broadcast-suppression': {
                    'type': 'list',
                    'choices': [
                        'dhcp', 'arp', 'dhcp2', 'arp2', 'netbios-ns', 'netbios-ds', 'arp3', 'dhcp-up', 'dhcp-down', 'arp-known', 'arp-unknown',
                        'arp-reply', 'ipv6', 'dhcp-starvation', 'arp-poison', 'all-other-mc', 'all-other-bc', 'arp-proxy', 'dhcp-ucast'
                    ],
                    'elements': 'str'
                },
                'captive-portal-ac-name': {'type': 'str'},
                'captive-portal-macauth-radius-secret': {'no_log': True, 'type': 'raw'},
                'captive-portal-macauth-radius-server': {'type': 'str'},
                'captive-portal-radius-secret': {'no_log': True, 'type': 'raw'},
                'captive-portal-radius-server': {'type': 'str'},
                'captive-portal-session-timeout-interval': {'type': 'int'},
                'client-count': {'type': 'int'},
                'dhcp-lease-time': {'type': 'int'},
                'dhcp-option82-circuit-id-insertion': {'choices': ['disable', 'style-1', 'style-2', 'style-3'], 'type': 'str'},
                'dhcp-option82-insertion': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-option82-remote-id-insertion': {'choices': ['disable', 'style-1'], 'type': 'str'},
                'dynamic-vlan': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-reauth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-reauth-intv': {'type': 'int'},
                'eapol-key-retries': {'choices': ['disable', 'enable'], 'type': 'str'},
                'encrypt': {'choices': ['TKIP', 'AES', 'TKIP-AES'], 'type': 'str'},
                'external-fast-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                'external-logout': {'type': 'str'},
                'external-web': {'type': 'str'},
                'fast-bss-transition': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fast-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ft-mobility-domain': {'type': 'int'},
                'ft-over-ds': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ft-r0-key-lifetime': {'no_log': True, 'type': 'int'},
                'gtk-rekey': {'choices': ['disable', 'enable'], 'type': 'str'},
                'gtk-rekey-intv': {'no_log': True, 'type': 'int'},
                'hotspot20-profile': {'type': 'str'},
                'intra-vap-privacy': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ip': {'type': 'str'},
                'key': {'no_log': True, 'type': 'raw'},
                'keyindex': {'no_log': True, 'type': 'int'},
                'ldpc': {'choices': ['disable', 'tx', 'rx', 'rxtx'], 'type': 'str'},
                'local-authentication': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-bridging': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-lan': {'choices': ['deny', 'allow'], 'type': 'str'},
                'local-standalone': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-switching': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-auth-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-filter-policy-other': {'choices': ['deny', 'allow'], 'type': 'str'},
                'max-clients': {'type': 'int'},
                'max-clients-ap': {'type': 'int'},
                'me-disable-thresh': {'type': 'int'},
                'mesh-backhaul': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-concurrent-clients': {'type': 'int'},
                'multicast-enhance': {'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-rate': {'choices': ['0', '6000', '12000', '24000'], 'type': 'str'},
                'okc': {'choices': ['disable', 'enable'], 'type': 'str'},
                'owe-groups': {'type': 'list', 'choices': ['19', '20', '21'], 'elements': 'str'},
                'owe-transition': {'choices': ['disable', 'enable'], 'type': 'str'},
                'owe-transition-ssid': {'type': 'str'},
                'passphrase': {'no_log': True, 'type': 'raw'},
                'pmf': {'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                'pmf-assoc-comeback-timeout': {'type': 'int'},
                'pmf-sa-query-retry-timeout': {'type': 'int'},
                'portal-message-override-group': {'type': 'str'},
                'portal-type': {
                    'choices': [
                        'auth', 'auth+disclaimer', 'disclaimer', 'email-collect', 'cmcc', 'cmcc-macauth', 'auth-mac', 'external-auth',
                        'external-macauth'
                    ],
                    'type': 'str'
                },
                'probe-resp-suppression': {'choices': ['disable', 'enable'], 'type': 'str'},
                'probe-resp-threshold': {'type': 'str'},
                'ptk-rekey': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ptk-rekey-intv': {'no_log': True, 'type': 'int'},
                'qos-profile': {'type': 'str'},
                'quarantine': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radio-2g-threshold': {'type': 'str'},
                'radio-5g-threshold': {'type': 'str'},
                'radio-sensitivity': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth-server': {'type': 'str'},
                'radius-mac-auth-usergroups': {'type': 'raw'},
                'radius-server': {'type': 'str'},
                'rates-11a': {
                    'type': 'list',
                    'choices': [
                        '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic', '24',
                        '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-ss12': {
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs0/2', 'mcs1/2', 'mcs2/2',
                        'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/1', 'mcs11/1', 'mcs10/2', 'mcs11/2'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-ss34': {
                    'type': 'list',
                    'choices': [
                        'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs0/4', 'mcs1/4', 'mcs2/4',
                        'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/3', 'mcs11/3', 'mcs10/4', 'mcs11/4'
                    ],
                    'elements': 'str'
                },
                'rates-11bg': {
                    'type': 'list',
                    'choices': [
                        '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic', '24',
                        '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                    ],
                    'elements': 'str'
                },
                'rates-11n-ss12': {
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2',
                        'mcs12/2', 'mcs13/2', 'mcs14/2', 'mcs15/2'
                    ],
                    'elements': 'str'
                },
                'rates-11n-ss34': {
                    'type': 'list',
                    'choices': [
                        'mcs16/3', 'mcs17/3', 'mcs18/3', 'mcs19/3', 'mcs20/3', 'mcs21/3', 'mcs22/3', 'mcs23/3', 'mcs24/4', 'mcs25/4', 'mcs26/4',
                        'mcs27/4', 'mcs28/4', 'mcs29/4', 'mcs30/4', 'mcs31/4'
                    ],
                    'elements': 'str'
                },
                'sae-groups': {
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31'],
                    'elements': 'str'
                },
                'sae-password': {'no_log': True, 'type': 'raw'},
                'schedule': {'type': 'raw'},
                'security': {
                    'choices': [
                        'None', 'WEP64', 'wep64', 'WEP128', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open', 'wpa-personal',
                        'wpa-enterprise', 'captive-portal', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal', 'wpa2-only-enterprise',
                        'wpa-personal+captive-portal', 'wpa-only-personal+captive-portal', 'wpa2-only-personal+captive-portal', 'osen',
                        'wpa3-enterprise', 'sae', 'sae-transition', 'owe', 'wpa3-sae', 'wpa3-sae-transition', 'wpa3-only-enterprise',
                        'wpa3-enterprise-transition'
                    ],
                    'type': 'str'
                },
                'security-exempt-list': {'type': 'str'},
                'security-obsolete-option': {'choices': ['disable', 'enable'], 'type': 'str'},
                'security-redirect-url': {'type': 'str'},
                'selected-usergroups': {'type': 'raw'},
                'split-tunneling': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssid': {'type': 'str'},
                'tkip-counter-measure': {'choices': ['disable', 'enable'], 'type': 'str'},
                'usergroup': {'type': 'raw'},
                'utm-profile': {'type': 'str'},
                'vdom': {'type': 'raw'},
                'vlan-auto': {'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-pooling': {'choices': ['wtp-group', 'round-robin', 'hash', 'disable'], 'type': 'str'},
                'vlanid': {'type': 'int'},
                'voice-enterprise': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mu-mimo': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_device-access-list': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'external-web-format': {'v_range': [['6.2.2', '']], 'choices': ['auto-detect', 'no-query-string', 'partial-query-string'], 'type': 'str'},
                'high-efficiency': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'primary-wag-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'secondary-wag-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'target-wake-time': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-echo-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'tunnel-fallback-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'access-control-list': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'captive-portal-auth-timeout': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'ipv6-rules': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'choices': [
                        'drop-icmp6ra', 'drop-icmp6rs', 'drop-llmnr6', 'drop-icmp6mld2', 'drop-dhcp6s', 'drop-dhcp6c', 'ndp-proxy', 'drop-ns-dad',
                        'drop-ns-nondad'
                    ],
                    'elements': 'str'
                },
                'sticky-client-remove': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sticky-client-threshold-2g': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'sticky-client-threshold-5g': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'bss-color-partial': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-option43-insertion': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-profile': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'igmp-snooping': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port-macauth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'radius', 'address-group'], 'type': 'str'},
                'port-macauth-reauth-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'port-macauth-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'additional-akms': {'v_range': [['7.0.0', '']], 'type': 'list', 'choices': ['akm6', 'akm24'], 'elements': 'str'},
                'bstm-disassociation-imminent': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bstm-load-balancing-disassoc-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'bstm-rssi-disassoc-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'dhcp-address-enforcement': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gas-comeback-delay': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'gas-fragmentation-limit': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'mac-called-station-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-calling-station-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-case': {'v_range': [['7.0.0', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                'mac-password-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-username-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mbo': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mbo-cell-data-conn-pref': {'v_range': [['7.0.0', '']], 'choices': ['excluded', 'prefer-not', 'prefer-use'], 'type': 'str'},
                'nac': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nac-profile': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'neighbor-report-dual-band': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'address-group-policy': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'allow', 'deny'], 'type': 'str'},
                'antivirus-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'application-detection-engine': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'application-list': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'application-report-intv': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'auth-cert': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'auth-portal-addr': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'beacon-advertising': {'v_range': [['7.0.2', '']], 'type': 'list', 'choices': ['name', 'model', 'serial-number'], 'elements': 'str'},
                'ips-sensor': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'l3-roaming': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-dns': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-dns-ip': {'v_range': [['7.0.1', '']], 'type': 'raw'},
                'osen': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-mpsk-auth': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-mpsk-timeout': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'rates-11ax-ss12': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs10/1', 'mcs11/1',
                        'mcs0/2', 'mcs1/2', 'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2'
                    ],
                    'elements': 'str'
                },
                'rates-11ax-ss34': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs10/3', 'mcs11/3',
                        'mcs0/4', 'mcs1/4', 'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/4', 'mcs11/4'
                    ],
                    'elements': 'str'
                },
                'scan-botnet-connections': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'utm-log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utm-status': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'sae-h2e-only': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-pk': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-private-key': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'no_log': True, 'type': 'str'},
                'sticky-client-threshold-6g': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                'application-dscp-marking': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'l3-roaming-mode': {'v_range': [['7.2.1', '']], 'choices': ['direct', 'indirect'], 'type': 'str'},
                'rates-11ac-mcs-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'rates-11ax-mcs-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'captive-portal-fw-accounting': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth-block-interval': {'v_range': [['7.2.2', '']], 'type': 'int'},
                '_is_factory_setting': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                '80211k': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '80211v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'roaming-acct-interim-update': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-hnp-only': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'akm24-only': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'beacon-protection': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'captive-portal': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nas-filter-rule': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rates-11be-mcs-map': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rates-11be-mcs-map-160': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rates-11be-mcs-map-320': {'v_range': [['7.4.3', '']], 'type': 'str'},
                '_intf_ip-managed-by-fortiipam': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable', 'inherit-global'], 'type': 'str'},
                '_intf_managed-subnetwork-size': {
                    'v_range': [['7.6.0', '']],
                    'choices': ['32', '64', '128', '256', '512', '1024', '2048', '4096', '8192', '16384', '32768', '65536'],
                    'type': 'str'
                },
                'domain-name-stripping': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-lan-partition': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_role': {
                    'v_range': [['7.2.10', '7.2.11'], ['7.4.6', '7.4.7'], ['7.6.2', '']],
                    'choices': ['lan', 'wan', 'dmz', 'undefined'],
                    'type': 'str'
                },
                'called-station-id-type': {'v_range': [['7.6.2', '']], 'choices': ['mac', 'ip', 'apname'], 'type': 'str'},
                'external-pre-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_ip6-send-adv': {
                    'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'ip6-prefix-list': {
                    'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']],
                    'type': 'list',
                    'options': {
                        'autonomous-flag': {
                            'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'dnssl': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'raw'},
                        'onlink-flag': {
                            'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'preferred-life-time': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                        'rdnss': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'raw'},
                        'valid-life-time': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                '_intf_vrf': {'v_range': [['7.6.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vap_dynamicmapping'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
