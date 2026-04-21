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
module: fortios_firewall_profile_protocol_options
short_description: Configure protocol options in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and profile_protocol_options category.
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
    firewall_profile_protocol_options:
        description:
            - Configure protocol options.
        default: null
        type: dict
        suboptions:
            cifs:
                description:
                    - Configure CIFS protocol options.
                type: dict
                suboptions:
                    domain_controller:
                        description:
                            - Domain for which to decrypt CIFS traffic. Source user.domain-controller.name credential-store.domain-controller.server-name.
                        type: str
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'oversize'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    server_credential_type:
                        description:
                            - CIFS server credential type.
                        type: str
                        choices:
                            - 'none'
                            - 'credential-replication'
                            - 'credential-keytab'
                    server_keytab:
                        description:
                            - Server keytab.
                        type: list
                        elements: dict
                        suboptions:
                            keytab:
                                description:
                                    - Base64 encoded keytab file containing credential of the server.
                                type: str
                            principal:
                                description:
                                    - Service principal. For example, host/cifsserver.example.com@example.com.
                                required: true
                                type: str
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tcp_window_maximum:
                        description:
                            - Maximum dynamic TCP window size.
                        type: int
                    tcp_window_minimum:
                        description:
                            - Minimum dynamic TCP window size.
                        type: int
                    tcp_window_size:
                        description:
                            - Set TCP static window size.
                        type: int
                    tcp_window_type:
                        description:
                            - TCP window type to use for this protocol.
                        type: str
                        choices:
                            - 'auto-tuning'
                            - 'system'
                            - 'static'
                            - 'dynamic'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            comment:
                description:
                    - Optional comments.
                type: str
            dns:
                description:
                    - Configure DNS protocol options.
                type: dict
                suboptions:
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            ftp:
                description:
                    - Configure FTP protocol options.
                type: dict
                suboptions:
                    comfort_amount:
                        description:
                            - Number of bytes to send in each transmission for client comforting (bytes).
                        type: int
                    comfort_interval:
                        description:
                            - Interval between successive transmissions of data for client comforting (seconds).
                        type: int
                    explicit_ftp_tls:
                        description:
                            - Enable/disable FTP redirection for explicit FTPS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'clientcomfort'
                            - 'oversize'
                            - 'splice'
                            - 'bypass-rest-command'
                            - 'bypass-mode-command'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    stream_based_uncompressed_limit:
                        description:
                            - Maximum stream-based uncompressed data size that will be scanned in megabytes. Stream-based uncompression used only under
                               certain conditions (unlimited = 0).
                        type: int
                    tcp_window_maximum:
                        description:
                            - Maximum dynamic TCP window size.
                        type: int
                    tcp_window_minimum:
                        description:
                            - Minimum dynamic TCP window size.
                        type: int
                    tcp_window_size:
                        description:
                            - Set TCP static window size.
                        type: int
                    tcp_window_type:
                        description:
                            - TCP window type to use for this protocol.
                        type: str
                        choices:
                            - 'auto-tuning'
                            - 'system'
                            - 'static'
                            - 'dynamic'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            http:
                description:
                    - Configure HTTP protocol options.
                type: dict
                suboptions:
                    address_ip_rating:
                        description:
                            - Enable/disable IP based URL rating.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    block_page_status_code:
                        description:
                            - Code number returned for blocked HTTP pages (non-FortiGuard only) (100 - 599).
                        type: int
                    comfort_amount:
                        description:
                            - Number of bytes to send in each transmission for client comforting (bytes).
                        type: int
                    comfort_interval:
                        description:
                            - Interval between successive transmissions of data for client comforting (seconds).
                        type: int
                    domain_fronting:
                        description:
                            - Configure HTTP domain fronting .
                        type: str
                        choices:
                            - 'allow'
                            - 'monitor'
                            - 'block'
                            - 'strict'
                    fortinet_bar:
                        description:
                            - Enable/disable Fortinet bar on HTML content.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    fortinet_bar_port:
                        description:
                            - Port for use by Fortinet Bar (1 - 65535).
                        type: int
                    h2c:
                        description:
                            - Enable/disable h2c HTTP connection upgrade.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_http_0dot9:
                        description:
                            - Configure action to take upon receipt of HTTP 0.9 request.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    http_policy:
                        description:
                            - Enable/disable HTTP policy check.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'clientcomfort'
                            - 'servercomfort'
                            - 'oversize'
                            - 'chunkedbypass'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    post_lang:
                        description:
                            - ID codes for character sets to be used to convert to UTF-8 for banned words and DLP on HTTP posts (maximum of 5 character sets).
                        type: list
                        elements: str
                        choices:
                            - 'jisx0201'
                            - 'jisx0208'
                            - 'jisx0212'
                            - 'gb2312'
                            - 'ksc5601-ex'
                            - 'euc-jp'
                            - 'sjis'
                            - 'iso2022-jp'
                            - 'iso2022-jp-1'
                            - 'iso2022-jp-2'
                            - 'euc-cn'
                            - 'ces-gbk'
                            - 'hz'
                            - 'ces-big5'
                            - 'euc-kr'
                            - 'iso2022-jp-3'
                            - 'iso8859-1'
                            - 'tis620'
                            - 'cp874'
                            - 'cp1252'
                            - 'cp1251'
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    range_block:
                        description:
                            - Enable/disable blocking of partial downloads.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    retry_count:
                        description:
                            - Number of attempts to retry HTTP connection (0 - 100).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    stream_based_uncompressed_limit:
                        description:
                            - Maximum stream-based uncompressed data size that will be scanned in megabytes. Stream-based uncompression used only under
                               certain conditions (unlimited = 0).
                        type: int
                    streaming_content_bypass:
                        description:
                            - Enable/disable bypassing of streaming content from buffering.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    strip_x_forwarded_for:
                        description:
                            - Enable/disable stripping of HTTP X-Forwarded-For header.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    switching_protocols:
                        description:
                            - Bypass from scanning, or block a connection that attempts to switch protocol.
                        type: str
                        choices:
                            - 'bypass'
                            - 'block'
                    tcp_window_maximum:
                        description:
                            - Maximum dynamic TCP window size.
                        type: int
                    tcp_window_minimum:
                        description:
                            - Minimum dynamic TCP window size.
                        type: int
                    tcp_window_size:
                        description:
                            - Set TCP static window size.
                        type: int
                    tcp_window_type:
                        description:
                            - TCP window type to use for this protocol.
                        type: str
                        choices:
                            - 'auto-tuning'
                            - 'system'
                            - 'static'
                            - 'dynamic'
                    tunnel_non_http:
                        description:
                            - Configure how to process non-HTTP traffic when a profile configured for HTTP traffic accepts a non-HTTP session. Can occur if an
                               application sends non-HTTP traffic using an HTTP destination port.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
                    unknown_content_encoding:
                        description:
                            - Configure the action the FortiGate unit will take on unknown content-encoding.
                        type: str
                        choices:
                            - 'block'
                            - 'inspect'
                            - 'bypass'
                    unknown_http_version:
                        description:
                            - How to handle HTTP sessions that do not comply with HTTP 0.9, 1.0, or 1.1.
                        type: str
                        choices:
                            - 'reject'
                            - 'tunnel'
                            - 'best-effort'
                    verify_dns_for_policy_matching:
                        description:
                            - Enable/disable verification of DNS for policy matching.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            imap:
                description:
                    - Configure IMAP protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'fragmail'
                            - 'oversize'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            mail_signature:
                description:
                    - Configure Mail signature.
                type: dict
                suboptions:
                    signature:
                        description:
                            - Email signature to be added to outgoing email (if the signature contains spaces, enclose with quotation marks).
                        type: str
                    status:
                        description:
                            - Enable/disable adding an email signature to SMTP email messages as they pass through the FortiGate.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            mapi:
                description:
                    - Configure MAPI protocol options.
                type: dict
                suboptions:
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'fragmail'
                            - 'oversize'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            nntp:
                description:
                    - Configure NNTP protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'oversize'
                            - 'splice'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            oversize_log:
                description:
                    - Enable/disable logging for antivirus oversize file blocking.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            pop3:
                description:
                    - Configure POP3 protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'fragmail'
                            - 'oversize'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            replacemsg_group:
                description:
                    - Name of the replacement message group to be used. Source system.replacemsg-group.name.
                type: str
            rpc_over_http:
                description:
                    - Enable/disable inspection of RPC over HTTP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            smtp:
                description:
                    - Configure SMTP protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'fragmail'
                            - 'oversize'
                            - 'splice'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    server_busy:
                        description:
                            - Enable/disable SMTP server busy when server not available.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            ssh:
                description:
                    - Configure SFTP and SCP protocol options.
                type: dict
                suboptions:
                    comfort_amount:
                        description:
                            - Number of bytes to send in each transmission for client comforting (bytes).
                        type: int
                    comfort_interval:
                        description:
                            - Interval between successive transmissions of data for client comforting (seconds).
                        type: int
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: list
                        elements: str
                        choices:
                            - 'oversize'
                            - 'clientcomfort'
                            - 'servercomfort'
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (MB).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - 'no'
                            - 'yes'
                    stream_based_uncompressed_limit:
                        description:
                            - Maximum stream-based uncompressed data size that will be scanned in megabytes. Stream-based uncompression used only under
                               certain conditions (unlimited = 0).
                        type: int
                    tcp_window_maximum:
                        description:
                            - Maximum dynamic TCP window size.
                        type: int
                    tcp_window_minimum:
                        description:
                            - Minimum dynamic TCP window size.
                        type: int
                    tcp_window_size:
                        description:
                            - Set TCP static window size.
                        type: int
                    tcp_window_type:
                        description:
                            - TCP window type to use for this protocol.
                        type: str
                        choices:
                            - 'auto-tuning'
                            - 'system'
                            - 'static'
                            - 'dynamic'
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (MB).
                        type: int
            switching_protocols_log:
                description:
                    - Enable/disable logging for HTTP/HTTPS switching protocols.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
"""

EXAMPLES = """
- name: Configure protocol options.
  fortinet.fortios.fortios_firewall_profile_protocol_options:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_profile_protocol_options:
          cifs:
              domain_controller: "<your_own_value> (source user.domain-controller.name credential-store.domain-controller.server-name)"
              options: "oversize"
              oversize_limit: "10"
              ports: "<your_own_value>"
              scan_bzip2: "enable"
              server_credential_type: "none"
              server_keytab:
                  -
                      keytab: "<your_own_value>"
                      principal: "<your_own_value>"
              status: "enable"
              tcp_window_maximum: "8388608"
              tcp_window_minimum: "131072"
              tcp_window_size: "262144"
              tcp_window_type: "auto-tuning"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          comment: "Optional comments."
          dns:
              ports: "<your_own_value>"
              status: "enable"
          ftp:
              comfort_amount: "1"
              comfort_interval: "10"
              explicit_ftp_tls: "enable"
              inspect_all: "enable"
              options: "clientcomfort"
              oversize_limit: "10"
              ports: "<your_own_value>"
              scan_bzip2: "enable"
              ssl_offloaded: "no"
              status: "enable"
              stream_based_uncompressed_limit: "0"
              tcp_window_maximum: "8388608"
              tcp_window_minimum: "131072"
              tcp_window_size: "262144"
              tcp_window_type: "auto-tuning"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          http:
              address_ip_rating: "enable"
              block_page_status_code: "403"
              comfort_amount: "1"
              comfort_interval: "10"
              domain_fronting: "allow"
              fortinet_bar: "enable"
              fortinet_bar_port: "32767"
              h2c: "enable"
              set_http_0dot9: "allow"
              http_policy: "disable"
              inspect_all: "enable"
              options: "clientcomfort"
              oversize_limit: "10"
              ports: "<your_own_value>"
              post_lang: "jisx0201"
              proxy_after_tcp_handshake: "enable"
              range_block: "disable"
              retry_count: "0"
              scan_bzip2: "enable"
              ssl_offloaded: "no"
              status: "enable"
              stream_based_uncompressed_limit: "0"
              streaming_content_bypass: "enable"
              strip_x_forwarded_for: "disable"
              switching_protocols: "bypass"
              tcp_window_maximum: "8388608"
              tcp_window_minimum: "131072"
              tcp_window_size: "262144"
              tcp_window_type: "auto-tuning"
              tunnel_non_http: "enable"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
              unknown_content_encoding: "block"
              unknown_http_version: "reject"
              verify_dns_for_policy_matching: "enable"
          imap:
              inspect_all: "enable"
              options: "fragmail"
              oversize_limit: "10"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              scan_bzip2: "enable"
              ssl_offloaded: "no"
              status: "enable"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          mail_signature:
              signature: "<your_own_value>"
              status: "disable"
          mapi:
              options: "fragmail"
              oversize_limit: "10"
              ports: "<your_own_value>"
              scan_bzip2: "enable"
              status: "enable"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          name: "default_name_100"
          nntp:
              inspect_all: "enable"
              options: "oversize"
              oversize_limit: "10"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              scan_bzip2: "enable"
              status: "enable"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          oversize_log: "disable"
          pop3:
              inspect_all: "enable"
              options: "fragmail"
              oversize_limit: "10"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              scan_bzip2: "enable"
              ssl_offloaded: "no"
              status: "enable"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          rpc_over_http: "enable"
          smtp:
              inspect_all: "enable"
              options: "fragmail"
              oversize_limit: "10"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              scan_bzip2: "enable"
              server_busy: "enable"
              ssl_offloaded: "no"
              status: "enable"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          ssh:
              comfort_amount: "1"
              comfort_interval: "10"
              options: "oversize"
              oversize_limit: "10"
              scan_bzip2: "enable"
              ssl_offloaded: "no"
              stream_based_uncompressed_limit: "0"
              tcp_window_maximum: "8388608"
              tcp_window_minimum: "131072"
              tcp_window_size: "262144"
              tcp_window_type: "auto-tuning"
              uncompressed_nest_limit: "12"
              uncompressed_oversize_limit: "10"
          switching_protocols_log: "disable"
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


def filter_firewall_profile_protocol_options_data(json):
    option_list = [
        "cifs",
        "comment",
        "dns",
        "ftp",
        "http",
        "imap",
        "mail_signature",
        "mapi",
        "name",
        "nntp",
        "oversize_log",
        "pop3",
        "replacemsg_group",
        "rpc_over_http",
        "smtp",
        "ssh",
        "switching_protocols_log",
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
        ["http", "ports"],
        ["http", "options"],
        ["http", "post_lang"],
        ["ftp", "ports"],
        ["ftp", "options"],
        ["imap", "ports"],
        ["imap", "options"],
        ["mapi", "ports"],
        ["mapi", "options"],
        ["pop3", "ports"],
        ["pop3", "options"],
        ["smtp", "ports"],
        ["smtp", "options"],
        ["nntp", "ports"],
        ["nntp", "options"],
        ["ssh", "options"],
        ["dns", "ports"],
        ["cifs", "ports"],
        ["cifs", "options"],
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"http_0.9": "set_http_0dot9"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def firewall_profile_protocol_options(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_profile_protocol_options_data = data["firewall_profile_protocol_options"]

    filtered_data = filter_firewall_profile_protocol_options_data(
        firewall_profile_protocol_options_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "firewall", "profile-protocol-options", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "firewall", "profile-protocol-options", vdom=vdom, mkey=mkey
        )
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
    data_copy["firewall_profile_protocol_options"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "profile-protocol-options",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "firewall", "profile-protocol-options", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "firewall",
            "profile-protocol-options",
            mkey=converted_data["name"],
            vdom=vdom,
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


def fortios_firewall(data, fos, check_mode):

    if data["firewall_profile_protocol_options"]:
        resp = firewall_profile_protocol_options(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_profile_protocol_options")
        )
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
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "replacemsg_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "oversize_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "switching_protocols_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "http": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "clientcomfort"},
                        {"value": "servercomfort"},
                        {"value": "oversize"},
                        {"value": "chunkedbypass"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "comfort_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "comfort_amount": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "range_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "strip_x_forwarded_for": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "post_lang": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "jisx0201"},
                        {"value": "jisx0208"},
                        {"value": "jisx0212"},
                        {"value": "gb2312"},
                        {"value": "ksc5601-ex"},
                        {"value": "euc-jp"},
                        {"value": "sjis"},
                        {"value": "iso2022-jp"},
                        {"value": "iso2022-jp-1"},
                        {"value": "iso2022-jp-2"},
                        {"value": "euc-cn"},
                        {"value": "ces-gbk"},
                        {"value": "hz"},
                        {"value": "ces-big5"},
                        {"value": "euc-kr"},
                        {"value": "iso2022-jp-3"},
                        {"value": "iso8859-1"},
                        {"value": "tis620"},
                        {"value": "cp874"},
                        {"value": "cp1252"},
                        {"value": "cp1251"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "streaming_content_bypass": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "switching_protocols": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "bypass"}, {"value": "block"}],
                },
                "unknown_http_version": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "reject"},
                        {"value": "tunnel"},
                        {"value": "best-effort"},
                    ],
                },
                "tunnel_non_http": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "h2c": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "unknown_content_encoding": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "block"},
                        {"value": "inspect"},
                        {"value": "bypass"},
                    ],
                },
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "stream_based_uncompressed_limit": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "verify_dns_for_policy_matching": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "block_page_status_code": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "retry_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "domain_fronting": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "monitor"},
                        {"value": "block"},
                        {"value": "strict", "v_range": [["v7.6.4", ""]]},
                    ],
                },
                "tcp_window_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto-tuning", "v_range": [["v7.0.4", ""]]},
                        {"value": "system"},
                        {"value": "static"},
                        {"value": "dynamic"},
                    ],
                },
                "tcp_window_minimum": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "tcp_window_maximum": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "tcp_window_size": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "ssl_offloaded": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "no"}, {"value": "yes"}],
                },
                "address_ip_rating": {
                    "v_range": [["v7.0.6", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortinet_bar": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortinet_bar_port": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "integer",
                },
                "http_policy": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "set_http_0dot9": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
            },
        },
        "ftp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "clientcomfort"},
                        {"value": "oversize"},
                        {"value": "splice"},
                        {"value": "bypass-rest-command"},
                        {"value": "bypass-mode-command"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "comfort_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "comfort_amount": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "stream_based_uncompressed_limit": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tcp_window_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto-tuning", "v_range": [["v7.0.4", ""]]},
                        {"value": "system"},
                        {"value": "static"},
                        {"value": "dynamic"},
                    ],
                },
                "tcp_window_minimum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "tcp_window_maximum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "tcp_window_size": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "ssl_offloaded": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "no"}, {"value": "yes"}],
                },
                "explicit_ftp_tls": {
                    "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "imap": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [{"value": "fragmail"}, {"value": "oversize"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_offloaded": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "no"}, {"value": "yes"}],
                },
            },
        },
        "mapi": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [{"value": "fragmail"}, {"value": "oversize"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "pop3": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [{"value": "fragmail"}, {"value": "oversize"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_offloaded": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "no"}, {"value": "yes"}],
                },
            },
        },
        "smtp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "fragmail"},
                        {"value": "oversize"},
                        {"value": "splice"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "server_busy": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_offloaded": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "no"}, {"value": "yes"}],
                },
            },
        },
        "nntp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [{"value": "oversize"}, {"value": "splice"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "oversize_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "ssh": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "options": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "oversize"},
                        {"value": "clientcomfort"},
                        {"value": "servercomfort"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "comfort_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "comfort_amount": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "oversize_limit": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "stream_based_uncompressed_limit": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tcp_window_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto-tuning", "v_range": [["v7.0.4", ""]]},
                        {"value": "system"},
                        {"value": "static"},
                        {"value": "dynamic"},
                    ],
                },
                "tcp_window_minimum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "tcp_window_maximum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "tcp_window_size": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "ssl_offloaded": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "no"}, {"value": "yes"}],
                },
            },
        },
        "dns": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "cifs": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "options": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "list",
                    "options": [{"value": "oversize"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "oversize_limit": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "uncompressed_oversize_limit": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "uncompressed_nest_limit": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "scan_bzip2": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tcp_window_type": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto-tuning", "v_range": [["v7.0.4", ""]]},
                        {"value": "system"},
                        {"value": "static"},
                        {"value": "dynamic"},
                    ],
                },
                "tcp_window_minimum": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "tcp_window_maximum": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "tcp_window_size": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "server_credential_type": {
                    "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "credential-replication"},
                        {"value": "credential-keytab"},
                    ],
                },
                "domain_controller": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "server_keytab": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "principal": {
                            "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "keytab": {
                            "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
                },
            },
        },
        "mail_signature": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "signature": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
        },
        "rpc_over_http": {
            "v_range": [["v6.0.0", ""]],
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
        "firewall_profile_protocol_options": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_profile_protocol_options"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_profile_protocol_options"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "firewall_profile_protocol_options"
        )

        is_error, has_changed, result, diff = fortios_firewall(
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
