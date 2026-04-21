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
module: fortios_vpn_ssl_web_portal
short_description: Portal in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ssl_web feature and portal category.
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
    vpn_ssl_web_portal:
        description:
            - Portal.
        default: null
        type: dict
        suboptions:
            allow_user_access:
                description:
                    - Allow user access to Agentless VPN applications.
                type: list
                elements: str
                choices:
                    - 'web'
                    - 'ftp'
                    - 'smb'
                    - 'sftp'
                    - 'telnet'
                    - 'ssh'
                    - 'vnc'
                    - 'rdp'
                    - 'ping'
                    - 'citrix'
                    - 'portforward'
            auto_connect:
                description:
                    - Enable/disable automatic connect by client when system is up.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bookmark_group:
                description:
                    - Portal bookmark group.
                type: list
                elements: dict
                suboptions:
                    bookmarks:
                        description:
                            - Bookmark table.
                        type: list
                        elements: dict
                        suboptions:
                            additional_params:
                                description:
                                    - Additional parameters.
                                type: str
                            apptype:
                                description:
                                    - Application type.
                                type: str
                                choices:
                                    - 'ftp'
                                    - 'rdp'
                                    - 'sftp'
                                    - 'smb'
                                    - 'ssh'
                                    - 'telnet'
                                    - 'vnc'
                                    - 'web'
                                    - 'citrix'
                                    - 'portforward'
                            color_depth:
                                description:
                                    - Color depth per pixel.
                                type: str
                                choices:
                                    - '32'
                                    - '16'
                                    - '8'
                            description:
                                description:
                                    - Description.
                                type: str
                            domain:
                                description:
                                    - Login domain.
                                type: str
                            folder:
                                description:
                                    - Network shared file folder parameter.
                                type: str
                            form_data:
                                description:
                                    - Form data.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - Name.
                                        required: true
                                        type: str
                                    value:
                                        description:
                                            - Value.
                                        type: str
                            height:
                                description:
                                    - Screen height (range from 0 - 65535).
                                type: int
                            host:
                                description:
                                    - Host name/IP parameter.
                                type: str
                            keyboard_layout:
                                description:
                                    - Keyboard layout.
                                type: str
                                choices:
                                    - 'ar-101'
                                    - 'ar-102'
                                    - 'ar-102-azerty'
                                    - 'can-mul'
                                    - 'cz'
                                    - 'cz-qwerty'
                                    - 'cz-pr'
                                    - 'da'
                                    - 'nl'
                                    - 'de'
                                    - 'de-ch'
                                    - 'de-ibm'
                                    - 'en-uk'
                                    - 'en-uk-ext'
                                    - 'en-us'
                                    - 'en-us-dvorak'
                                    - 'es'
                                    - 'es-var'
                                    - 'fi'
                                    - 'fi-sami'
                                    - 'fr'
                                    - 'fr-apple'
                                    - 'fr-ca'
                                    - 'fr-ch'
                                    - 'fr-be'
                                    - 'hr'
                                    - 'hu'
                                    - 'hu-101'
                                    - 'it'
                                    - 'it-142'
                                    - 'ja'
                                    - 'ja-106'
                                    - 'ko'
                                    - 'la-am'
                                    - 'lt'
                                    - 'lt-ibm'
                                    - 'lt-std'
                                    - 'lav-std'
                                    - 'lav-leg'
                                    - 'mk'
                                    - 'mk-std'
                                    - 'no'
                                    - 'no-sami'
                                    - 'pol-214'
                                    - 'pol-pr'
                                    - 'pt'
                                    - 'pt-br'
                                    - 'pt-br-abnt2'
                                    - 'ru'
                                    - 'ru-mne'
                                    - 'ru-t'
                                    - 'sl'
                                    - 'sv'
                                    - 'sv-sami'
                                    - 'tuk'
                                    - 'tur-f'
                                    - 'tur-q'
                                    - 'zh-sym-sg-us'
                                    - 'zh-sym-us'
                                    - 'zh-tr-hk'
                                    - 'zh-tr-mo'
                                    - 'zh-tr-us'
                            listening_port:
                                description:
                                    - Listening port (0 - 65535).
                                type: int
                            load_balancing_info:
                                description:
                                    - The load balancing information or cookie which should be provided to the connection broker.
                                type: str
                            logon_password:
                                description:
                                    - Logon password.
                                type: str
                            logon_user:
                                description:
                                    - Logon user.
                                type: str
                            name:
                                description:
                                    - Bookmark name.
                                required: true
                                type: str
                            port:
                                description:
                                    - Remote port.
                                type: int
                            preconnection_blob:
                                description:
                                    - An arbitrary string which identifies the RDP source.
                                type: str
                            preconnection_id:
                                description:
                                    - The numeric ID of the RDP source (0-4294967295).
                                type: int
                            remote_port:
                                description:
                                    - Remote port (0 - 65535).
                                type: int
                            restricted_admin:
                                description:
                                    - Enable/disable restricted admin mode for RDP.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            security:
                                description:
                                    - Security mode for RDP connection .
                                type: str
                                choices:
                                    - 'any'
                                    - 'rdp'
                                    - 'nla'
                                    - 'tls'
                            send_preconnection_id:
                                description:
                                    - Enable/disable sending of preconnection ID.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            server_layout:
                                description:
                                    - Server side keyboard layout.
                                type: str
                                choices:
                                    - 'de-de-qwertz'
                                    - 'en-gb-qwerty'
                                    - 'en-us-qwerty'
                                    - 'es-es-qwerty'
                                    - 'fr-ca-qwerty'
                                    - 'fr-fr-azerty'
                                    - 'fr-ch-qwertz'
                                    - 'it-it-qwerty'
                                    - 'ja-jp-qwerty'
                                    - 'pt-br-qwerty'
                                    - 'sv-se-qwerty'
                                    - 'tr-tr-qwerty'
                                    - 'failsafe'
                            show_status_window:
                                description:
                                    - Enable/disable showing of status window.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            sso:
                                description:
                                    - Single sign-on.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'static'
                                    - 'auto'
                            sso_credential:
                                description:
                                    - Single sign-on credentials.
                                type: str
                                choices:
                                    - 'sslvpn-login'
                                    - 'alternative'
                            sso_credential_sent_once:
                                description:
                                    - Single sign-on credentials are only sent once to remote server.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            sso_password:
                                description:
                                    - SSO password.
                                type: str
                            sso_username:
                                description:
                                    - SSO user name.
                                type: str
                            url:
                                description:
                                    - URL parameter.
                                type: str
                            vnc_keyboard_layout:
                                description:
                                    - Keyboard layout.
                                type: str
                                choices:
                                    - 'default'
                                    - 'da'
                                    - 'nl'
                                    - 'en-uk'
                                    - 'en-uk-ext'
                                    - 'fi'
                                    - 'fr'
                                    - 'fr-be'
                                    - 'fr-ca-mul'
                                    - 'de'
                                    - 'de-ch'
                                    - 'it'
                                    - 'it-142'
                                    - 'pt'
                                    - 'pt-br-abnt2'
                                    - 'no'
                                    - 'gd'
                                    - 'es'
                                    - 'sv'
                                    - 'us-intl'
                            width:
                                description:
                                    - Screen width (range from 0 - 65535).
                                type: int
                    name:
                        description:
                            - Bookmark group name.
                        required: true
                        type: str
            client_src_range:
                description:
                    - Allow client to add source range for the tunnel traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            clipboard:
                description:
                    - Enable to support RDP/VPC clipboard functionality.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            custom_lang:
                description:
                    - Change the web portal display language. Overrides config system global set language. You can use config system custom-language and
                       execute system custom-language to add custom language files. Source system.custom-language.name.
                type: str
            customize_forticlient_download_url:
                description:
                    - Enable support of customized download URL for FortiClient.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_protocol:
                description:
                    - Application type that is set by default.
                type: str
                choices:
                    - 'web'
                    - 'ftp'
                    - 'telnet'
                    - 'smb'
                    - 'vnc'
                    - 'rdp'
                    - 'ssh'
                    - 'sftp'
            default_window_height:
                description:
                    - Screen height (range from 0 - 65535).
                type: int
            default_window_width:
                description:
                    - Screen width (range from 0 - 65535).
                type: int
            dhcp_ip_overlap:
                description:
                    - Configure overlapping DHCP IP allocation assignment.
                type: str
                choices:
                    - 'use-new'
                    - 'use-old'
            dhcp_ra_giaddr:
                description:
                    - Relay agent gateway IP address to use in the giaddr field of DHCP requests.
                type: str
            dhcp_reservation:
                description:
                    - Enable/disable dhcp reservation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp6_ra_linkaddr:
                description:
                    - Relay agent IPv6 link address to use in DHCP6 requests.
                type: str
            display_bookmark:
                description:
                    - Enable to display the web portal bookmark widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            display_connection_tools:
                description:
                    - Enable to display the web portal connection tools widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            display_history:
                description:
                    - Enable to display the web portal user login history widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            display_status:
                description:
                    - Enable to display the web portal status widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dns_server1:
                description:
                    - IPv4 DNS server 1.
                type: str
            dns_server2:
                description:
                    - IPv4 DNS server 2.
                type: str
            dns_suffix:
                description:
                    - DNS suffix.
                type: str
            exclusive_routing:
                description:
                    - Enable/disable all traffic go through tunnel only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            focus_bookmark:
                description:
                    - Enable to prioritize the placement of the bookmark section over the quick-connection section in the Agentless VPN application.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_download:
                description:
                    - Enable/disable download option for FortiClient.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_download_method:
                description:
                    - FortiClient download method.
                type: str
                choices:
                    - 'direct'
                    - 'ssl-vpn'
            heading:
                description:
                    - Web portal heading message.
                type: str
            hide_sso_credential:
                description:
                    - Enable to prevent SSO credential being sent to client.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            host_check:
                description:
                    - Type of host checking performed on endpoints.
                type: str
                choices:
                    - 'none'
                    - 'av'
                    - 'fw'
                    - 'av-fw'
                    - 'custom'
            host_check_interval:
                description:
                    - Periodic host check interval. Value of 0 means disabled and host checking only happens when the endpoint connects.
                type: int
            host_check_policy:
                description:
                    - One or more policies to require the endpoint to have specific security software.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Host check software list name. Source vpn.ssl.web.host-check-software.name.
                        required: true
                        type: str
            ip_mode:
                description:
                    - Method by which users of this SSL-VPN tunnel obtain IP addresses.
                type: str
                choices:
                    - 'range'
                    - 'user-group'
                    - 'dhcp'
                    - 'no-ip'
            ip_pools:
                description:
                    - IPv4 firewall source address objects reserved for SSL-VPN tunnel mode clients.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ipv6_dns_server1:
                description:
                    - IPv6 DNS server 1.
                type: str
            ipv6_dns_server2:
                description:
                    - IPv6 DNS server 2.
                type: str
            ipv6_exclusive_routing:
                description:
                    - Enable/disable all IPv6 traffic go through tunnel only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_pools:
                description:
                    - IPv6 firewall source address objects reserved for SSL-VPN tunnel mode clients.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            ipv6_service_restriction:
                description:
                    - Enable/disable IPv6 tunnel service restriction.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_split_tunneling:
                description:
                    - Enable/disable IPv6 split tunneling.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_split_tunneling_routing_address:
                description:
                    - IPv6 SSL-VPN tunnel mode firewall address objects that override firewall policy destination addresses to control split-tunneling access.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            ipv6_split_tunneling_routing_negate:
                description:
                    - Enable to negate IPv6 split tunneling routing address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_tunnel_mode:
                description:
                    - Enable/disable IPv6 SSL-VPN tunnel mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_wins_server1:
                description:
                    - IPv6 WINS server 1.
                type: str
            ipv6_wins_server2:
                description:
                    - IPv6 WINS server 2.
                type: str
            keep_alive:
                description:
                    - Enable/disable automatic reconnect for FortiClient connections.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            landing_page:
                description:
                    - Landing page options.
                type: dict
                suboptions:
                    form_data:
                        description:
                            - Form data.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value.
                                type: str
                    logout_url:
                        description:
                            - Landing page log out URL.
                        type: str
                    sso:
                        description:
                            - Single sign-on.
                        type: str
                        choices:
                            - 'disable'
                            - 'static'
                            - 'auto'
                    sso_credential:
                        description:
                            - Single sign-on credentials.
                        type: str
                        choices:
                            - 'sslvpn-login'
                            - 'alternative'
                    sso_password:
                        description:
                            - SSO password.
                        type: str
                    sso_username:
                        description:
                            - SSO user name.
                        type: str
                    url:
                        description:
                            - Landing page URL.
                        type: str
            landing_page_mode:
                description:
                    - Enable/disable Agentless VPN landing page mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            limit_user_logins:
                description:
                    - Enable to limit each user to one Agentless VPN session at a time.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_addr_action:
                description:
                    - Client MAC address action.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mac_addr_check:
                description:
                    - Enable/disable MAC address host checking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_addr_check_rule:
                description:
                    - Client MAC address check rule.
                type: list
                elements: dict
                suboptions:
                    mac_addr_list:
                        description:
                            - Client MAC address list.
                        type: list
                        elements: dict
                        suboptions:
                            addr:
                                description:
                                    - Client MAC address.
                                required: true
                                type: str
                    mac_addr_mask:
                        description:
                            - Client MAC address mask.
                        type: int
                    name:
                        description:
                            - Client MAC address check rule name.
                        required: true
                        type: str
            macos_forticlient_download_url:
                description:
                    - Download URL for Mac FortiClient.
                type: str
            name:
                description:
                    - Portal name.
                required: true
                type: str
            os_check:
                description:
                    - Enable to let the FortiGate decide action based on client OS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            os_check_list:
                description:
                    - SSL-VPN OS checks.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - OS check options.
                        type: str
                        choices:
                            - 'deny'
                            - 'allow'
                            - 'check-up-to-date'
                    latest_patch_level:
                        description:
                            - Latest OS patch level.
                        type: str
                    name:
                        description:
                            - Name.
                        required: true
                        type: str
                    tolerance:
                        description:
                            - OS patch level tolerance.
                        type: int
            prefer_ipv6_dns:
                description:
                    - Prefer to query IPv6 DNS server first if enabled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redir_url:
                description:
                    - Client login redirect URL.
                type: str
            rewrite_ip_uri_ui:
                description:
                    - Rewrite contents for URI contains IP and /ui/ .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            save_password:
                description:
                    - Enable/disable FortiClient saving the user"s password.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            service_restriction:
                description:
                    - Enable/disable tunnel service restriction.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            skip_check_for_browser:
                description:
                    - Enable to skip host check for browser support.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            skip_check_for_unsupported_browser:
                description:
                    - Enable to skip host check if browser does not support it.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            skip_check_for_unsupported_os:
                description:
                    - Enable to skip host check if client OS does not support it.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            smb_max_version:
                description:
                    - SMB maximum client protocol version.
                type: str
                choices:
                    - 'smbv1'
                    - 'smbv2'
                    - 'smbv3'
            smb_min_version:
                description:
                    - SMB minimum client protocol version.
                type: str
                choices:
                    - 'smbv1'
                    - 'smbv2'
                    - 'smbv3'
            smb_ntlmv1_auth:
                description:
                    - Enable support of NTLMv1 for Samba authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            smbv1:
                description:
                    - SMB version 1.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            split_dns:
                description:
                    - Split DNS for SSL-VPN.
                type: list
                elements: dict
                suboptions:
                    dns_server1:
                        description:
                            - DNS server 1.
                        type: str
                    dns_server2:
                        description:
                            - DNS server 2.
                        type: str
                    domains:
                        description:
                            - Split DNS domains used for SSL-VPN clients separated by comma.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ipv6_dns_server1:
                        description:
                            - IPv6 DNS server 1.
                        type: str
                    ipv6_dns_server2:
                        description:
                            - IPv6 DNS server 2.
                        type: str
            split_tunneling:
                description:
                    - Enable/disable IPv4 split tunneling.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            split_tunneling_routing_address:
                description:
                    - IPv4 SSL-VPN tunnel mode firewall address objects that override firewall policy destination addresses to control split-tunneling access.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            split_tunneling_routing_negate:
                description:
                    - Enable to negate split tunneling routing address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            theme:
                description:
                    - Web portal color scheme.
                type: str
                choices:
                    - 'jade'
                    - 'neutrino'
                    - 'mariner'
                    - 'graphite'
                    - 'melongene'
                    - 'jet-stream'
                    - 'security-fabric'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
                    - 'blue'
                    - 'green'
                    - 'red'
            transform_backward_slashes:
                description:
                    - Transform backward slashes to forward slashes in URLs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_mode:
                description:
                    - Enable/disable IPv4 SSL-VPN tunnel mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            use_sdwan:
                description:
                    - Use SD-WAN rules to get output interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            user_bookmark:
                description:
                    - Enable to allow web portal users to create their own bookmarks.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            user_group_bookmark:
                description:
                    - Enable to allow web portal users to create bookmarks for all users in the same user group.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_mode:
                description:
                    - Enable/disable Agentless VPN web mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            windows_forticlient_download_url:
                description:
                    - Download URL for Windows FortiClient.
                type: str
            wins_server1:
                description:
                    - IPv4 WINS server 1.
                type: str
            wins_server2:
                description:
                    - IPv4 WINS server 1.
                type: str
"""

EXAMPLES = """
- name: Portal.
  fortinet.fortios.fortios_vpn_ssl_web_portal:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ssl_web_portal:
          allow_user_access: "web"
          auto_connect: "enable"
          bookmark_group:
              -
                  bookmarks:
                      -
                          additional_params: "<your_own_value>"
                          apptype: "ftp"
                          color_depth: "32"
                          description: "<your_own_value>"
                          domain: "<your_own_value>"
                          folder: "<your_own_value>"
                          form_data:
                              -
                                  name: "default_name_14"
                                  value: "<your_own_value>"
                          height: "768"
                          host: "myhostname"
                          keyboard_layout: "ar-101"
                          listening_port: "0"
                          load_balancing_info: "<your_own_value>"
                          logon_password: "<your_own_value>"
                          logon_user: "<your_own_value>"
                          name: "default_name_23"
                          port: "0"
                          preconnection_blob: "<your_own_value>"
                          preconnection_id: "2147483648"
                          remote_port: "0"
                          restricted_admin: "enable"
                          security: "any"
                          send_preconnection_id: "enable"
                          server_layout: "de-de-qwertz"
                          show_status_window: "enable"
                          sso: "disable"
                          sso_credential: "sslvpn-login"
                          sso_credential_sent_once: "enable"
                          sso_password: "<your_own_value>"
                          sso_username: "<your_own_value>"
                          url: "myurl.com"
                          vnc_keyboard_layout: "default"
                          width: "1024"
                  name: "default_name_41"
          client_src_range: "enable"
          clipboard: "enable"
          custom_lang: "<your_own_value> (source system.custom-language.name)"
          customize_forticlient_download_url: "enable"
          default_protocol: "web"
          default_window_height: "768"
          default_window_width: "1024"
          dhcp_ip_overlap: "use-new"
          dhcp_ra_giaddr: "<your_own_value>"
          dhcp_reservation: "enable"
          dhcp6_ra_linkaddr: "<your_own_value>"
          display_bookmark: "enable"
          display_connection_tools: "enable"
          display_history: "enable"
          display_status: "enable"
          dns_server1: "<your_own_value>"
          dns_server2: "<your_own_value>"
          dns_suffix: "<your_own_value>"
          exclusive_routing: "enable"
          focus_bookmark: "enable"
          forticlient_download: "enable"
          forticlient_download_method: "direct"
          heading: "<your_own_value>"
          hide_sso_credential: "enable"
          host_check: "none"
          host_check_interval: "0"
          host_check_policy:
              -
                  name: "default_name_69 (source vpn.ssl.web.host-check-software.name)"
          ip_mode: "range"
          ip_pools:
              -
                  name: "default_name_72 (source firewall.address.name firewall.addrgrp.name)"
          ipv6_dns_server1: "<your_own_value>"
          ipv6_dns_server2: "<your_own_value>"
          ipv6_exclusive_routing: "enable"
          ipv6_pools:
              -
                  name: "default_name_77 (source firewall.address6.name firewall.addrgrp6.name)"
          ipv6_service_restriction: "enable"
          ipv6_split_tunneling: "enable"
          ipv6_split_tunneling_routing_address:
              -
                  name: "default_name_81 (source firewall.address6.name firewall.addrgrp6.name)"
          ipv6_split_tunneling_routing_negate: "enable"
          ipv6_tunnel_mode: "enable"
          ipv6_wins_server1: "<your_own_value>"
          ipv6_wins_server2: "<your_own_value>"
          keep_alive: "enable"
          landing_page:
              form_data:
                  -
                      name: "default_name_89"
                      value: "<your_own_value>"
              logout_url: "<your_own_value>"
              sso: "disable"
              sso_credential: "sslvpn-login"
              sso_password: "<your_own_value>"
              sso_username: "<your_own_value>"
              url: "myurl.com"
          landing_page_mode: "enable"
          limit_user_logins: "enable"
          mac_addr_action: "allow"
          mac_addr_check: "enable"
          mac_addr_check_rule:
              -
                  mac_addr_list:
                      -
                          addr: "<your_own_value>"
                  mac_addr_mask: "48"
                  name: "default_name_105"
          macos_forticlient_download_url: "<your_own_value>"
          name: "default_name_107"
          os_check: "enable"
          os_check_list:
              -
                  action: "deny"
                  latest_patch_level: "<your_own_value>"
                  name: "default_name_112"
                  tolerance: "0"
          prefer_ipv6_dns: "enable"
          redir_url: "<your_own_value>"
          rewrite_ip_uri_ui: "enable"
          save_password: "enable"
          service_restriction: "enable"
          skip_check_for_browser: "enable"
          skip_check_for_unsupported_browser: "enable"
          skip_check_for_unsupported_os: "enable"
          smb_max_version: "smbv1"
          smb_min_version: "smbv1"
          smb_ntlmv1_auth: "enable"
          smbv1: "enable"
          split_dns:
              -
                  dns_server1: "<your_own_value>"
                  dns_server2: "<your_own_value>"
                  domains: "<your_own_value>"
                  id: "130"
                  ipv6_dns_server1: "<your_own_value>"
                  ipv6_dns_server2: "<your_own_value>"
          split_tunneling: "enable"
          split_tunneling_routing_address:
              -
                  name: "default_name_135 (source firewall.address.name firewall.addrgrp.name)"
          split_tunneling_routing_negate: "enable"
          theme: "jade"
          transform_backward_slashes: "enable"
          tunnel_mode: "enable"
          use_sdwan: "enable"
          user_bookmark: "enable"
          user_group_bookmark: "enable"
          web_mode: "enable"
          windows_forticlient_download_url: "<your_own_value>"
          wins_server1: "<your_own_value>"
          wins_server2: "<your_own_value>"
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


def filter_vpn_ssl_web_portal_data(json):
    option_list = [
        "allow_user_access",
        "auto_connect",
        "bookmark_group",
        "client_src_range",
        "clipboard",
        "custom_lang",
        "customize_forticlient_download_url",
        "default_protocol",
        "default_window_height",
        "default_window_width",
        "dhcp_ip_overlap",
        "dhcp_ra_giaddr",
        "dhcp_reservation",
        "dhcp6_ra_linkaddr",
        "display_bookmark",
        "display_connection_tools",
        "display_history",
        "display_status",
        "dns_server1",
        "dns_server2",
        "dns_suffix",
        "exclusive_routing",
        "focus_bookmark",
        "forticlient_download",
        "forticlient_download_method",
        "heading",
        "hide_sso_credential",
        "host_check",
        "host_check_interval",
        "host_check_policy",
        "ip_mode",
        "ip_pools",
        "ipv6_dns_server1",
        "ipv6_dns_server2",
        "ipv6_exclusive_routing",
        "ipv6_pools",
        "ipv6_service_restriction",
        "ipv6_split_tunneling",
        "ipv6_split_tunneling_routing_address",
        "ipv6_split_tunneling_routing_negate",
        "ipv6_tunnel_mode",
        "ipv6_wins_server1",
        "ipv6_wins_server2",
        "keep_alive",
        "landing_page",
        "landing_page_mode",
        "limit_user_logins",
        "mac_addr_action",
        "mac_addr_check",
        "mac_addr_check_rule",
        "macos_forticlient_download_url",
        "name",
        "os_check",
        "os_check_list",
        "prefer_ipv6_dns",
        "redir_url",
        "rewrite_ip_uri_ui",
        "save_password",
        "service_restriction",
        "skip_check_for_browser",
        "skip_check_for_unsupported_browser",
        "skip_check_for_unsupported_os",
        "smb_max_version",
        "smb_min_version",
        "smb_ntlmv1_auth",
        "smbv1",
        "split_dns",
        "split_tunneling",
        "split_tunneling_routing_address",
        "split_tunneling_routing_negate",
        "theme",
        "transform_backward_slashes",
        "tunnel_mode",
        "use_sdwan",
        "user_bookmark",
        "user_group_bookmark",
        "web_mode",
        "windows_forticlient_download_url",
        "wins_server1",
        "wins_server2",
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
        ["allow_user_access"],
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


def vpn_ssl_web_portal(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_ssl_web_portal_data = data["vpn_ssl_web_portal"]

    filtered_data = filter_vpn_ssl_web_portal_data(vpn_ssl_web_portal_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.ssl.web", "portal", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.ssl.web", "portal", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_ssl_web_portal"] = filtered_data
    fos.do_member_operation(
        "vpn.ssl.web",
        "portal",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("vpn.ssl.web", "portal", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "vpn.ssl.web", "portal", mkey=converted_data["name"], vdom=vdom
        )
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


def fortios_vpn_ssl_web(data, fos, check_mode):

    if data["vpn_ssl_web_portal"]:
        resp = vpn_ssl_web_portal(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_ssl_web_portal"))
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
        "dns_suffix": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "web_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "landing_page_mode": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "display_bookmark": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_bookmark": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_user_access": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "web"},
                {"value": "ftp"},
                {"value": "smb"},
                {"value": "sftp", "v_range": [["v6.2.0", ""]]},
                {"value": "telnet"},
                {"value": "ssh"},
                {"value": "vnc"},
                {"value": "rdp"},
                {"value": "ping"},
                {"value": "citrix", "v_range": [["v6.0.0", "v7.0.0"]]},
                {"value": "portforward", "v_range": [["v6.0.0", "v7.0.0"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "default_protocol": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [
                {"value": "web"},
                {"value": "ftp"},
                {"value": "telnet"},
                {"value": "smb"},
                {"value": "vnc"},
                {"value": "rdp"},
                {"value": "ssh"},
                {"value": "sftp"},
            ],
        },
        "user_group_bookmark": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bookmark_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "bookmarks": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "apptype": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "ftp"},
                                {"value": "rdp"},
                                {"value": "sftp", "v_range": [["v6.2.0", ""]]},
                                {"value": "smb"},
                                {"value": "ssh"},
                                {"value": "telnet"},
                                {"value": "vnc"},
                                {"value": "web"},
                                {"value": "citrix", "v_range": [["v6.0.0", "v6.0.11"]]},
                                {
                                    "value": "portforward",
                                    "v_range": [["v6.0.0", "v6.0.11"]],
                                },
                            ],
                        },
                        "url": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "host": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "folder": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "domain": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                        },
                        "additional_params": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "keyboard_layout": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "ar-101"},
                                {"value": "ar-102"},
                                {"value": "ar-102-azerty"},
                                {"value": "can-mul"},
                                {"value": "cz"},
                                {"value": "cz-qwerty"},
                                {"value": "cz-pr"},
                                {"value": "da"},
                                {"value": "nl"},
                                {"value": "de"},
                                {"value": "de-ch"},
                                {"value": "de-ibm"},
                                {"value": "en-uk"},
                                {"value": "en-uk-ext"},
                                {"value": "en-us"},
                                {"value": "en-us-dvorak"},
                                {"value": "es"},
                                {"value": "es-var"},
                                {"value": "fi"},
                                {"value": "fi-sami"},
                                {"value": "fr"},
                                {"value": "fr-apple", "v_range": [["v7.0.6", ""]]},
                                {"value": "fr-ca"},
                                {"value": "fr-ch"},
                                {"value": "fr-be"},
                                {"value": "hr"},
                                {"value": "hu"},
                                {"value": "hu-101"},
                                {"value": "it"},
                                {"value": "it-142"},
                                {"value": "ja"},
                                {"value": "ja-106", "v_range": [["v7.4.2", ""]]},
                                {"value": "ko"},
                                {"value": "la-am", "v_range": [["v7.4.1", ""]]},
                                {"value": "lt"},
                                {"value": "lt-ibm"},
                                {"value": "lt-std"},
                                {"value": "lav-std"},
                                {"value": "lav-leg"},
                                {"value": "mk"},
                                {"value": "mk-std"},
                                {"value": "no"},
                                {"value": "no-sami"},
                                {"value": "pol-214"},
                                {"value": "pol-pr"},
                                {"value": "pt"},
                                {"value": "pt-br"},
                                {"value": "pt-br-abnt2"},
                                {"value": "ru"},
                                {"value": "ru-mne"},
                                {"value": "ru-t"},
                                {"value": "sl"},
                                {"value": "sv"},
                                {"value": "sv-sami"},
                                {"value": "tuk"},
                                {"value": "tur-f"},
                                {"value": "tur-q"},
                                {"value": "zh-sym-sg-us"},
                                {"value": "zh-sym-us"},
                                {"value": "zh-tr-hk"},
                                {"value": "zh-tr-mo"},
                                {"value": "zh-tr-us"},
                            ],
                        },
                        "security": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "any"},
                                {"value": "rdp"},
                                {"value": "nla"},
                                {"value": "tls"},
                            ],
                        },
                        "send_preconnection_id": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "preconnection_id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "preconnection_blob": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "load_balancing_info": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "restricted_admin": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "logon_user": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "logon_password": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "color_depth": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "32"},
                                {"value": "16"},
                                {"value": "8"},
                            ],
                        },
                        "sso": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "disable"},
                                {"value": "static"},
                                {"value": "auto"},
                            ],
                        },
                        "form_data": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                    "required": True,
                                },
                                "value": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                            },
                            "v_range": [["v6.0.0", ""]],
                        },
                        "sso_credential": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "sslvpn-login"},
                                {"value": "alternative"},
                            ],
                        },
                        "sso_username": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "sso_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "sso_credential_sent_once": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "width": {"v_range": [["v7.0.4", ""]], "type": "integer"},
                        "height": {"v_range": [["v7.0.4", ""]], "type": "integer"},
                        "vnc_keyboard_layout": {
                            "v_range": [["v7.2.4", ""]],
                            "type": "string",
                            "options": [
                                {"value": "default"},
                                {"value": "da"},
                                {"value": "nl"},
                                {"value": "en-uk"},
                                {"value": "en-uk-ext"},
                                {"value": "fi"},
                                {"value": "fr"},
                                {"value": "fr-be"},
                                {"value": "fr-ca-mul"},
                                {"value": "de"},
                                {"value": "de-ch"},
                                {"value": "it"},
                                {"value": "it-142"},
                                {"value": "pt"},
                                {"value": "pt-br-abnt2"},
                                {"value": "no"},
                                {"value": "gd"},
                                {"value": "es"},
                                {"value": "sv"},
                                {"value": "us-intl"},
                            ],
                        },
                        "listening_port": {
                            "v_range": [["v6.0.0", "v7.0.0"]],
                            "type": "integer",
                        },
                        "remote_port": {
                            "v_range": [["v6.0.0", "v7.0.0"]],
                            "type": "integer",
                        },
                        "show_status_window": {
                            "v_range": [["v6.0.0", "v7.0.0"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "server_layout": {
                            "v_range": [["v6.0.0", "v7.0.0"]],
                            "type": "string",
                            "options": [
                                {"value": "de-de-qwertz"},
                                {"value": "en-gb-qwerty"},
                                {"value": "en-us-qwerty"},
                                {"value": "es-es-qwerty"},
                                {
                                    "value": "fr-ca-qwerty",
                                    "v_range": [["v6.2.0", "v7.0.0"]],
                                },
                                {"value": "fr-fr-azerty"},
                                {"value": "fr-ch-qwertz"},
                                {"value": "it-it-qwerty"},
                                {"value": "ja-jp-qwerty"},
                                {"value": "pt-br-qwerty"},
                                {"value": "sv-se-qwerty"},
                                {"value": "tr-tr-qwerty"},
                                {"value": "failsafe"},
                            ],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "display_connection_tools": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "display_history": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "focus_bookmark": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "display_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rewrite_ip_uri_ui": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "heading": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "redir_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "theme": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "jade", "v_range": [["v7.0.0", ""]]},
                {"value": "neutrino", "v_range": [["v6.2.0", ""]]},
                {"value": "mariner"},
                {"value": "graphite", "v_range": [["v7.0.0", ""]]},
                {"value": "melongene"},
                {"value": "jet-stream", "v_range": [["v7.4.0", ""]]},
                {"value": "security-fabric", "v_range": [["v7.4.0", ""]]},
                {"value": "dark-matter", "v_range": [["v7.0.0", ""]]},
                {"value": "onyx", "v_range": [["v7.0.0", ""]]},
                {"value": "eclipse", "v_range": [["v7.0.0", ""]]},
                {"value": "blue", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "green", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "red", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
        },
        "custom_lang": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "smb_ntlmv1_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "smbv1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "smb_min_version": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "smbv1"}, {"value": "smbv2"}, {"value": "smbv3"}],
        },
        "smb_max_version": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "smbv1"}, {"value": "smbv2"}, {"value": "smbv3"}],
        },
        "use_sdwan": {
            "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "prefer_ipv6_dns": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "clipboard": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_window_width": {"v_range": [["v7.0.6", ""]], "type": "integer"},
        "default_window_height": {"v_range": [["v7.0.6", ""]], "type": "integer"},
        "limit_user_logins": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "hide_sso_credential": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "landing_page": {
            "v_range": [["v7.4.0", ""]],
            "type": "dict",
            "children": {
                "url": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "sso": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "static"},
                        {"value": "auto"},
                    ],
                },
                "form_data": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "value": {"v_range": [["v7.4.0", ""]], "type": "string"},
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "sso_credential": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "sslvpn-login"}, {"value": "alternative"}],
                },
                "sso_username": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "sso_password": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "logout_url": {"v_range": [["v7.4.0", "v7.4.0"]], "type": "string"},
            },
        },
        "forticlient_download": {
            "v_range": [["v6.0.0", "v7.6.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_download_method": {
            "v_range": [["v6.0.0", "v7.6.3"]],
            "type": "string",
            "options": [{"value": "direct"}, {"value": "ssl-vpn"}],
        },
        "customize_forticlient_download_url": {
            "v_range": [["v6.0.0", "v7.6.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "windows_forticlient_download_url": {
            "v_range": [["v6.0.0", "v7.6.3"]],
            "type": "string",
        },
        "macos_forticlient_download_url": {
            "v_range": [["v6.0.0", "v7.6.3"]],
            "type": "string",
        },
        "tunnel_mode": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_mode": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [
                {"value": "range"},
                {"value": "user-group"},
                {
                    "value": "dhcp",
                    "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", "v7.6.2"]],
                },
                {"value": "no-ip", "v_range": [["v7.2.4", "v7.6.2"]]},
            ],
        },
        "dhcp_ip_overlap": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "use-new"}, {"value": "use-old"}],
        },
        "auto_connect": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "keep_alive": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_reservation": {
            "v_range": [["v7.6.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "save_password": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_pools": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "exclusive_routing": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "service_restriction": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_tunneling": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_tunneling_routing_negate": {
            "v_range": [["v6.4.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_tunneling_routing_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "dns_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "dns_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "wins_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "wins_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "dhcp_ra_giaddr": {"v_range": [["v7.2.4", "v7.6.2"]], "type": "string"},
        "ipv6_tunnel_mode": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_pools": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "ipv6_exclusive_routing": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_service_restriction": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_split_tunneling": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_split_tunneling_routing_negate": {
            "v_range": [["v6.4.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_split_tunneling_routing_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "ipv6_dns_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_dns_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_wins_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_wins_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "dhcp6_ra_linkaddr": {"v_range": [["v7.2.4", "v7.6.2"]], "type": "string"},
        "client_src_range": {
            "v_range": [["v7.2.4", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "host_check": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "av"},
                {"value": "fw"},
                {"value": "av-fw"},
                {"value": "custom"},
            ],
        },
        "host_check_interval": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "integer"},
        "host_check_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "mac_addr_check": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mac_addr_action": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mac_addr_check_rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                },
                "mac_addr_mask": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "integer"},
                "mac_addr_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "addr": {
                            "v_range": [["v6.0.0", "v7.6.2"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v7.6.2"]],
                },
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "os_check": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "skip_check_for_unsupported_os": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "skip_check_for_browser": {
            "v_range": [["v6.2.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_dns": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "integer",
                    "required": True,
                },
                "domains": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
                "dns_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
                "dns_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
                "ipv6_dns_server1": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                },
                "ipv6_dns_server2": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "os_check_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "action": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [
                        {"value": "deny"},
                        {"value": "allow"},
                        {"value": "check-up-to-date"},
                    ],
                },
                "tolerance": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "latest_patch_level": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "transform_backward_slashes": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "skip_check_for_unsupported_browser": {
            "v_range": [["v6.0.0", "v6.0.11"]],
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
        "vpn_ssl_web_portal": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_ssl_web_portal"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ssl_web_portal"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "vpn_ssl_web_portal"
        )

        is_error, has_changed, result, diff = fortios_vpn_ssl_web(
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
