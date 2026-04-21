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
module: fortios_webfilter_profile
short_description: Configure Web filter profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify webfilter feature and profile category.
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
    webfilter_profile:
        description:
            - Configure Web filter profiles.
        default: null
        type: dict
        suboptions:
            antiphish:
                description:
                    - AntiPhishing profile.
                type: dict
                suboptions:
                    authentication:
                        description:
                            - Authentication methods.
                        type: str
                        choices:
                            - 'domain-controller'
                            - 'ldap'
                    check_basic_auth:
                        description:
                            - Enable/disable checking of HTTP Basic Auth field for known credentials.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    check_uri:
                        description:
                            - Enable/disable checking of GET URI parameters for known credentials.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    check_username_only:
                        description:
                            - Enable/disable username only matching of credentials. Action will be taken for valid usernames regardless of password validity.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    custom_patterns:
                        description:
                            - Custom username and password regex patterns.
                        type: list
                        elements: dict
                        suboptions:
                            category:
                                description:
                                    - Category that the pattern matches.
                                type: str
                                choices:
                                    - 'username'
                                    - 'password'
                            pattern:
                                description:
                                    - Target pattern.
                                required: true
                                type: str
                            type:
                                description:
                                    - Pattern will be treated either as a regex pattern or literal string.
                                type: str
                                choices:
                                    - 'regex'
                                    - 'literal'
                    default_action:
                        description:
                            - Action to be taken when there is no matching rule.
                        type: str
                        choices:
                            - 'exempt'
                            - 'log'
                            - 'block'
                    domain_controller:
                        description:
                            - Domain for which to verify received credentials against. Source user.domain-controller.name credential-store.domain-controller
                              .server-name.
                        type: str
                    inspection_entries:
                        description:
                            - AntiPhishing entries.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action to be taken upon an AntiPhishing match.
                                type: str
                                choices:
                                    - 'exempt'
                                    - 'log'
                                    - 'block'
                            fortiguard_category:
                                description:
                                    - FortiGuard category to match.
                                type: list
                                elements: str
                            name:
                                description:
                                    - Inspection target name.
                                required: true
                                type: str
                    ldap:
                        description:
                            - LDAP server for which to verify received credentials against. Source user.ldap.name.
                        type: str
                    max_body_len:
                        description:
                            - Maximum size of a POST body to check for credentials.
                        type: int
                    status:
                        description:
                            - Toggle AntiPhishing functionality.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            comment:
                description:
                    - Optional comments.
                type: str
            extended_log:
                description:
                    - Enable/disable extended logging for web filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            file_filter:
                description:
                    - File filter.
                type: dict
                suboptions:
                    entries:
                        description:
                            - File filter entries.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action taken for matched file.
                                type: str
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                description:
                                    - Comment.
                                type: str
                            direction:
                                description:
                                    - Match files transmitted in the session"s originating or reply direction.
                                type: str
                                choices:
                                    - 'incoming'
                                    - 'outgoing'
                                    - 'any'
                            file_type:
                                description:
                                    - Select file type.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - File type name. Source antivirus.filetype.name.
                                        required: true
                                        type: str
                            filter:
                                description:
                                    - Add a file filter.
                                required: true
                                type: str
                            password_protected:
                                description:
                                    - Match password-protected files.
                                type: str
                                choices:
                                    - 'yes'
                                    - 'any'
                            protocol:
                                description:
                                    - Protocols to apply with.
                                type: list
                                elements: str
                                choices:
                                    - 'http'
                                    - 'ftp'
                    log:
                        description:
                            - Enable/disable file filter logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_archive_contents:
                        description:
                            - Enable/disable file filter archive contents scan.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable file filter.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            ftgd_wf:
                description:
                    - FortiGuard Web Filter settings.
                type: dict
                suboptions:
                    exempt_quota:
                        description:
                            - Do not stop quota for these categories.
                        type: list
                        elements: str
                    filters:
                        description:
                            - FortiGuard filters.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action to take for matches.
                                type: str
                                choices:
                                    - 'block'
                                    - 'authenticate'
                                    - 'monitor'
                                    - 'warning'
                            auth_usr_grp:
                                description:
                                    - Groups with permission to authenticate.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - User group name. Source user.group.name.
                                        required: true
                                        type: str
                            category:
                                description:
                                    - Categories and groups the filter examines.
                                type: int
                            id:
                                description:
                                    - ID number. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            override_replacemsg:
                                description:
                                    - Override replacement message.
                                type: str
                            warn_duration:
                                description:
                                    - Duration of warnings.
                                type: str
                            warning_duration_type:
                                description:
                                    - Re-display warning after closing browser or after a timeout.
                                type: str
                                choices:
                                    - 'session'
                                    - 'timeout'
                            warning_prompt:
                                description:
                                    - Warning prompts in each category or each domain.
                                type: str
                                choices:
                                    - 'per-domain'
                                    - 'per-category'
                    max_quota_timeout:
                        description:
                            - Maximum FortiGuard quota used by single page view in seconds (excludes streams).
                        type: int
                    options:
                        description:
                            - Options for FortiGuard Web Filter.
                        type: list
                        elements: str
                        choices:
                            - 'error-allow'
                            - 'rate-server-ip'
                            - 'connect-request-bypass'
                            - 'ftgd-disable'
                    ovrd:
                        description:
                            - Allow web filter profile overrides.
                        type: list
                        elements: str
                    quota:
                        description:
                            - FortiGuard traffic quota settings.
                        type: list
                        elements: dict
                        suboptions:
                            category:
                                description:
                                    - FortiGuard categories to apply quota to (category action must be set to monitor).
                                type: list
                                elements: str
                            duration:
                                description:
                                    - Duration of quota.
                                type: str
                            id:
                                description:
                                    - ID number. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            override_replacemsg:
                                description:
                                    - Override replacement message.
                                type: str
                            type:
                                description:
                                    - Quota type.
                                type: str
                                choices:
                                    - 'time'
                                    - 'traffic'
                            unit:
                                description:
                                    - Traffic quota unit of measurement.
                                type: str
                                choices:
                                    - 'B'
                                    - 'KB'
                                    - 'MB'
                                    - 'GB'
                            value:
                                description:
                                    - Traffic quota value.
                                type: int
                    rate_crl_urls:
                        description:
                            - Enable/disable rating CRL by URL.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_css_urls:
                        description:
                            - Enable/disable rating CSS by URL.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_image_urls:
                        description:
                            - Enable/disable rating images by URL.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_javascript_urls:
                        description:
                            - Enable/disable rating JavaScript by URL.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    risk:
                        description:
                            - FortiGuard risk level settings.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action to take for matches.
                                type: str
                                choices:
                                    - 'block'
                                    - 'monitor'
                            id:
                                description:
                                    - ID number. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            risk_level:
                                description:
                                    - Risk level to be examined. Source webfilter.ftgd-risk-level.name.
                                type: str
            https_replacemsg:
                description:
                    - Enable replacement messages for HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            inspection_mode:
                description:
                    - Web filtering inspection mode.
                type: str
                choices:
                    - 'proxy'
                    - 'flow-based'
            log_all_url:
                description:
                    - Enable/disable logging all URLs visited.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            options:
                description:
                    - Options.
                type: list
                elements: str
                choices:
                    - 'activexfilter'
                    - 'cookiefilter'
                    - 'javafilter'
                    - 'block-invalid-url'
                    - 'jscript'
                    - 'js'
                    - 'vbs'
                    - 'unknown'
                    - 'intrinsic'
                    - 'wf-referer'
                    - 'wf-cookie'
                    - 'per-user-bal'
                    - 'per-user-bwl'
            override:
                description:
                    - Web Filter override settings.
                type: dict
                suboptions:
                    ovrd_cookie:
                        description:
                            - Allow/deny browser-based (cookie) overrides.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    ovrd_dur:
                        description:
                            - Override duration.
                        type: str
                    ovrd_dur_mode:
                        description:
                            - Override duration mode.
                        type: str
                        choices:
                            - 'constant'
                            - 'ask'
                    ovrd_scope:
                        description:
                            - Override scope.
                        type: str
                        choices:
                            - 'user'
                            - 'user-group'
                            - 'ip'
                            - 'browser'
                            - 'ask'
                    ovrd_user_group:
                        description:
                            - User groups with permission to use the override.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - User group name. Source user.group.name.
                                required: true
                                type: str
                    profile:
                        description:
                            - Web filter profile with permission to create overrides.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Web profile. Source webfilter.profile.name.
                                required: true
                                type: str
                    profile_attribute:
                        description:
                            - Profile attribute to retrieve from the RADIUS server.
                        type: str
                        choices:
                            - 'User-Name'
                            - 'NAS-IP-Address'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Filter-Id'
                            - 'Login-IP-Host'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'Class'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Session-Id'
                            - 'Acct-Multi-Session-Id'
                    profile_type:
                        description:
                            - Override profile type.
                        type: str
                        choices:
                            - 'list'
                            - 'radius'
            ovrd_perm:
                description:
                    - Permitted override types.
                type: list
                elements: str
                choices:
                    - 'bannedword-override'
                    - 'urlfilter-override'
                    - 'fortiguard-wf-override'
                    - 'contenttype-check-override'
            post_action:
                description:
                    - Action taken for HTTP POST traffic.
                type: str
                choices:
                    - 'normal'
                    - 'block'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            url_extraction:
                description:
                    - Configure URL Extraction
                type: dict
                suboptions:
                    redirect_header:
                        description:
                            - HTTP header name to use for client redirect on blocked requests
                        type: str
                    redirect_no_content:
                        description:
                            - Enable / Disable empty message-body entity in HTTP response
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    redirect_url:
                        description:
                            - HTTP header value to use for client redirect on blocked requests
                        type: str
                    server_fqdn:
                        description:
                            - URL extraction server FQDN (fully qualified domain name)
                        type: str
                    status:
                        description:
                            - Enable URL Extraction
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            web:
                description:
                    - Web content filtering settings.
                type: dict
                suboptions:
                    allowlist:
                        description:
                            - FortiGuard allowlist settings.
                        type: list
                        elements: str
                        choices:
                            - 'exempt-av'
                            - 'exempt-webcontent'
                            - 'exempt-activex-java-cookie'
                            - 'exempt-dlp'
                            - 'exempt-rangeblock'
                            - 'extended-log-others'
                    blacklist:
                        description:
                            - Enable/disable automatic addition of URLs detected by FortiSandbox to blacklist.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    blocklist:
                        description:
                            - Enable/disable automatic addition of URLs detected by FortiSandbox to blocklist.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bword_table:
                        description:
                            - Banned word table ID. Source webfilter.content.id.
                        type: int
                    bword_threshold:
                        description:
                            - Banned word score threshold.
                        type: int
                    content_header_list:
                        description:
                            - Content header list. Source webfilter.content-header.id.
                        type: int
                    keyword_match:
                        description:
                            - Search keywords to log when match is found.
                        type: list
                        elements: dict
                        suboptions:
                            pattern:
                                description:
                                    - Pattern/keyword to search for.
                                required: true
                                type: str
                    log_search:
                        description:
                            - Enable/disable logging all search phrases.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    safe_search:
                        description:
                            - Safe search type.
                        type: list
                        elements: str
                        choices:
                            - 'url'
                            - 'header'
                    urlfilter_table:
                        description:
                            - URL filter table ID. Source webfilter.urlfilter.id.
                        type: int
                    vimeo_restrict:
                        description:
                            - Set Vimeo-restrict ("7" = don"t show mature content, "134" = don"t show unrated and mature content). A value of cookie
                               "content_rating".
                        type: str
                    whitelist:
                        description:
                            - FortiGuard whitelist settings.
                        type: list
                        elements: str
                        choices:
                            - 'exempt-av'
                            - 'exempt-webcontent'
                            - 'exempt-activex-java-cookie'
                            - 'exempt-dlp'
                            - 'exempt-rangeblock'
                            - 'extended-log-others'
                    youtube_restrict:
                        description:
                            - YouTube EDU filter level.
                        type: str
                        choices:
                            - 'none'
                            - 'strict'
                            - 'moderate'
            web_antiphishing_log:
                description:
                    - Enable/disable logging of AntiPhishing checks.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_content_log:
                description:
                    - Enable/disable logging logging blocked web content.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_extended_all_action_log:
                description:
                    - Enable/disable extended any filter action logging for web filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_activex_log:
                description:
                    - Enable/disable logging ActiveX.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_applet_log:
                description:
                    - Enable/disable logging Java applets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_command_block_log:
                description:
                    - Enable/disable logging blocked commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_cookie_log:
                description:
                    - Enable/disable logging cookie filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_cookie_removal_log:
                description:
                    - Enable/disable logging blocked cookies.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_js_log:
                description:
                    - Enable/disable logging Java scripts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_jscript_log:
                description:
                    - Enable/disable logging JScripts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_referer_log:
                description:
                    - Enable/disable logging referrers.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_unknown_log:
                description:
                    - Enable/disable logging unknown scripts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_filter_vbs_log:
                description:
                    - Enable/disable logging VBS scripts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_flow_log_encoding:
                description:
                    - Log encoding in flow mode.
                type: str
                choices:
                    - 'utf-8'
                    - 'punycode'
            web_ftgd_err_log:
                description:
                    - Enable/disable logging rating errors.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_ftgd_quota_usage:
                description:
                    - Enable/disable logging daily quota usage.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_invalid_domain_log:
                description:
                    - Enable/disable logging invalid domain names.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            web_url_log:
                description:
                    - Enable/disable logging URL filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wisp:
                description:
                    - Enable/disable web proxy WISP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wisp_algorithm:
                description:
                    - WISP server selection algorithm.
                type: str
                choices:
                    - 'primary-secondary'
                    - 'round-robin'
                    - 'auto-learning'
            wisp_servers:
                description:
                    - WISP servers.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Server name. Source web-proxy.wisp.name.
                        required: true
                        type: str
            youtube_channel_filter:
                description:
                    - YouTube channel filter.
                type: list
                elements: dict
                suboptions:
                    channel_id:
                        description:
                            - YouTube channel ID to be filtered.
                        type: str
                    comment:
                        description:
                            - Comment.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            youtube_channel_status:
                description:
                    - YouTube channel filter status.
                type: str
                choices:
                    - 'disable'
                    - 'blacklist'
                    - 'whitelist'
"""

EXAMPLES = """
- name: Configure Web filter profiles.
  fortinet.fortios.fortios_webfilter_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      webfilter_profile:
          antiphish:
              authentication: "domain-controller"
              check_basic_auth: "enable"
              check_uri: "enable"
              check_username_only: "enable"
              custom_patterns:
                  -
                      category: "username"
                      pattern: "<your_own_value>"
                      type: "regex"
              default_action: "exempt"
              domain_controller: "<your_own_value> (source user.domain-controller.name credential-store.domain-controller.server-name)"
              inspection_entries:
                  -
                      action: "exempt"
                      fortiguard_category: "<your_own_value>"
                      name: "default_name_17"
              ldap: "<your_own_value> (source user.ldap.name)"
              max_body_len: "1024"
              status: "enable"
          comment: "Optional comments."
          extended_log: "enable"
          feature_set: "flow"
          file_filter:
              entries:
                  -
                      action: "log"
                      comment: "Comment."
                      direction: "incoming"
                      file_type:
                          -
                              name: "default_name_30 (source antivirus.filetype.name)"
                      filter: "<your_own_value>"
                      password_protected: "yes"
                      protocol: "http"
              log: "enable"
              scan_archive_contents: "enable"
              status: "enable"
          ftgd_wf:
              exempt_quota: "<your_own_value>"
              filters:
                  -
                      action: "block"
                      auth_usr_grp:
                          -
                              name: "default_name_42 (source user.group.name)"
                      category: "0"
                      id: "44"
                      log: "enable"
                      override_replacemsg: "<your_own_value>"
                      warn_duration: "<your_own_value>"
                      warning_duration_type: "session"
                      warning_prompt: "per-domain"
              max_quota_timeout: "300"
              options: "error-allow"
              ovrd: "<your_own_value>"
              quota:
                  -
                      category: "<your_own_value>"
                      duration: "<your_own_value>"
                      id: "56"
                      override_replacemsg: "<your_own_value>"
                      type: "time"
                      unit: "B"
                      value: "1024"
              rate_crl_urls: "disable"
              rate_css_urls: "disable"
              rate_image_urls: "disable"
              rate_javascript_urls: "disable"
              risk:
                  -
                      action: "block"
                      id: "67"
                      log: "enable"
                      risk_level: "<your_own_value> (source webfilter.ftgd-risk-level.name)"
          https_replacemsg: "enable"
          inspection_mode: "proxy"
          log_all_url: "enable"
          name: "default_name_73"
          options: "activexfilter"
          override:
              ovrd_cookie: "allow"
              ovrd_dur: "<your_own_value>"
              ovrd_dur_mode: "constant"
              ovrd_scope: "user"
              ovrd_user_group:
                  -
                      name: "default_name_81 (source user.group.name)"
              profile:
                  -
                      name: "default_name_83 (source webfilter.profile.name)"
              profile_attribute: "User-Name"
              profile_type: "list"
          ovrd_perm: "bannedword-override"
          post_action: "normal"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          url_extraction:
              redirect_header: "<your_own_value>"
              redirect_no_content: "enable"
              redirect_url: "<your_own_value>"
              server_fqdn: "<your_own_value>"
              status: "enable"
          web:
              allowlist: "exempt-av"
              blacklist: "enable"
              blocklist: "enable"
              bword_table: "0"
              bword_threshold: "10"
              content_header_list: "0"
              keyword_match:
                  -
                      pattern: "<your_own_value>"
              log_search: "enable"
              safe_search: "url"
              urlfilter_table: "0"
              vimeo_restrict: "<your_own_value>"
              whitelist: "exempt-av"
              youtube_restrict: "none"
          web_antiphishing_log: "enable"
          web_content_log: "enable"
          web_extended_all_action_log: "enable"
          web_filter_activex_log: "enable"
          web_filter_applet_log: "enable"
          web_filter_command_block_log: "enable"
          web_filter_cookie_log: "enable"
          web_filter_cookie_removal_log: "enable"
          web_filter_js_log: "enable"
          web_filter_jscript_log: "enable"
          web_filter_referer_log: "enable"
          web_filter_unknown_log: "enable"
          web_filter_vbs_log: "enable"
          web_flow_log_encoding: "utf-8"
          web_ftgd_err_log: "enable"
          web_ftgd_quota_usage: "enable"
          web_invalid_domain_log: "enable"
          web_url_log: "enable"
          wisp: "enable"
          wisp_algorithm: "primary-secondary"
          wisp_servers:
              -
                  name: "default_name_131 (source web-proxy.wisp.name)"
          youtube_channel_filter:
              -
                  channel_id: "<your_own_value>"
                  comment: "Comment."
                  id: "135"
          youtube_channel_status: "disable"
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


def filter_webfilter_profile_data(json):
    option_list = [
        "antiphish",
        "comment",
        "extended_log",
        "feature_set",
        "file_filter",
        "ftgd_wf",
        "https_replacemsg",
        "inspection_mode",
        "log_all_url",
        "name",
        "options",
        "override",
        "ovrd_perm",
        "post_action",
        "replacemsg_group",
        "url_extraction",
        "web",
        "web_antiphishing_log",
        "web_content_log",
        "web_extended_all_action_log",
        "web_filter_activex_log",
        "web_filter_applet_log",
        "web_filter_command_block_log",
        "web_filter_cookie_log",
        "web_filter_cookie_removal_log",
        "web_filter_js_log",
        "web_filter_jscript_log",
        "web_filter_referer_log",
        "web_filter_unknown_log",
        "web_filter_vbs_log",
        "web_flow_log_encoding",
        "web_ftgd_err_log",
        "web_ftgd_quota_usage",
        "web_invalid_domain_log",
        "web_url_log",
        "wisp",
        "wisp_algorithm",
        "wisp_servers",
        "youtube_channel_filter",
        "youtube_channel_status",
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
        ["options"],
        ["ovrd_perm"],
        ["web", "allowlist"],
        ["web", "safe_search"],
        ["web", "whitelist"],
        ["ftgd_wf", "options"],
        ["ftgd_wf", "exempt_quota"],
        ["ftgd_wf", "ovrd"],
        ["ftgd_wf", "quota", "category"],
        ["antiphish", "inspection_entries", "fortiguard_category"],
        ["file_filter", "entries", "protocol"],
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


def webfilter_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    webfilter_profile_data = data["webfilter_profile"]

    filtered_data = filter_webfilter_profile_data(webfilter_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("webfilter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("webfilter", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["webfilter_profile"] = filtered_data
    fos.do_member_operation(
        "webfilter",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("webfilter", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "webfilter", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_webfilter(data, fos, check_mode):

    if data["webfilter_profile"]:
        resp = webfilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("webfilter_profile"))
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
        "feature_set": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "flow"}, {"value": "proxy"}],
        },
        "replacemsg_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "options": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "activexfilter"},
                {"value": "cookiefilter"},
                {"value": "javafilter"},
                {"value": "block-invalid-url"},
                {"value": "jscript"},
                {"value": "js"},
                {"value": "vbs"},
                {"value": "unknown"},
                {"value": "intrinsic"},
                {"value": "wf-referer"},
                {"value": "wf-cookie"},
                {"value": "per-user-bal", "v_range": [["v7.0.0", ""]]},
                {"value": "per-user-bwl", "v_range": [["v6.0.0", "v6.4.4"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "https_replacemsg": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_flow_log_encoding": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "utf-8"}, {"value": "punycode"}],
        },
        "ovrd_perm": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "bannedword-override"},
                {"value": "urlfilter-override"},
                {"value": "fortiguard-wf-override"},
                {"value": "contenttype-check-override"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "post_action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "normal"}, {"value": "block"}],
        },
        "override": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ovrd_cookie": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
                "ovrd_scope": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "user"},
                        {"value": "user-group"},
                        {"value": "ip"},
                        {"value": "browser"},
                        {"value": "ask"},
                    ],
                },
                "profile_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "list"}, {"value": "radius"}],
                },
                "ovrd_dur_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "constant"}, {"value": "ask"}],
                },
                "ovrd_dur": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "profile_attribute": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "User-Name"},
                        {"value": "NAS-IP-Address"},
                        {"value": "Framed-IP-Address"},
                        {"value": "Framed-IP-Netmask"},
                        {"value": "Filter-Id"},
                        {"value": "Login-IP-Host"},
                        {"value": "Reply-Message"},
                        {"value": "Callback-Number"},
                        {"value": "Callback-Id"},
                        {"value": "Framed-Route"},
                        {"value": "Framed-IPX-Network"},
                        {"value": "Class"},
                        {"value": "Called-Station-Id"},
                        {"value": "Calling-Station-Id"},
                        {"value": "NAS-Identifier"},
                        {"value": "Proxy-State"},
                        {"value": "Login-LAT-Service"},
                        {"value": "Login-LAT-Node"},
                        {"value": "Login-LAT-Group"},
                        {"value": "Framed-AppleTalk-Zone"},
                        {"value": "Acct-Session-Id"},
                        {"value": "Acct-Multi-Session-Id"},
                    ],
                },
                "ovrd_user_group": {
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
                "profile": {
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
            },
        },
        "web": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "bword_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "bword_table": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "urlfilter_table": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "content_header_list": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowlist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "exempt-av"},
                        {"value": "exempt-webcontent"},
                        {"value": "exempt-activex-java-cookie"},
                        {"value": "exempt-dlp"},
                        {"value": "exempt-rangeblock"},
                        {"value": "extended-log-others"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "safe_search": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [{"value": "url"}, {"value": "header"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "youtube_restrict": {
                    "v_range": [["v6.0.0", "v6.4.4"], ["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "strict"},
                        {"value": "moderate"},
                    ],
                },
                "vimeo_restrict": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "log_search": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "keyword_match": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "pattern": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "blacklist": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "whitelist": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "exempt-av"},
                        {"value": "exempt-webcontent"},
                        {"value": "exempt-activex-java-cookie"},
                        {"value": "exempt-dlp"},
                        {"value": "exempt-rangeblock"},
                        {"value": "extended-log-others"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "ftgd_wf": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "error-allow"},
                        {"value": "rate-server-ip"},
                        {"value": "connect-request-bypass"},
                        {"value": "ftgd-disable"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "exempt_quota": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "ovrd": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "filters": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "category": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "block"},
                                {"value": "authenticate"},
                                {"value": "monitor"},
                                {"value": "warning"},
                            ],
                        },
                        "warn_duration": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "auth_usr_grp": {
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
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "override_replacemsg": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "warning_prompt": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "per-domain"},
                                {"value": "per-category"},
                            ],
                        },
                        "warning_duration_type": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "session"}, {"value": "timeout"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "risk": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "risk_level": {"v_range": [["v7.6.1", ""]], "type": "string"},
                        "action": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "options": [{"value": "block"}, {"value": "monitor"}],
                        },
                        "log": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v7.6.1", ""]],
                },
                "quota": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "category": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "type": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "time"}, {"value": "traffic"}],
                        },
                        "unit": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "B"},
                                {"value": "KB"},
                                {"value": "MB"},
                                {"value": "GB"},
                            ],
                        },
                        "value": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "duration": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "override_replacemsg": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "max_quota_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "rate_javascript_urls": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "rate_css_urls": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "rate_crl_urls": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "rate_image_urls": {
                    "v_range": [["v6.0.0", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "antiphish": {
            "v_range": [["v6.4.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "default_action": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "exempt"},
                        {"value": "log"},
                        {"value": "block"},
                    ],
                },
                "check_uri": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "check_basic_auth": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "check_username_only": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "max_body_len": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "inspection_entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "fortiguard_category": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "action": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "exempt"},
                                {"value": "log"},
                                {"value": "block"},
                            ],
                        },
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "custom_patterns": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "pattern": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "category": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "options": [{"value": "username"}, {"value": "password"}],
                        },
                        "type": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "regex"}, {"value": "literal"}],
                        },
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "authentication": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "domain-controller"}, {"value": "ldap"}],
                },
                "domain_controller": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "ldap": {"v_range": [["v7.0.0", ""]], "type": "string"},
            },
        },
        "url_extraction": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "server_fqdn": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "redirect_header": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "redirect_url": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "redirect_no_content": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "wisp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wisp_servers": {
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
        "wisp_algorithm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "primary-secondary"},
                {"value": "round-robin"},
                {"value": "auto-learning"},
            ],
        },
        "log_all_url": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_content_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_activex_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_command_block_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_cookie_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_applet_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_jscript_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_js_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_vbs_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_unknown_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_referer_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_filter_cookie_removal_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_url_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_invalid_domain_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_ftgd_err_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_ftgd_quota_usage": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extended_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_extended_all_action_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_antiphishing_log": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "youtube_channel_status": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "blacklist"},
                {"value": "whitelist"},
            ],
        },
        "youtube_channel_filter": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "integer",
                    "required": True,
                },
                "channel_id": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "comment": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
            },
            "v_range": [["v6.0.0", "v6.4.4"]],
        },
        "file_filter": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "scan_archive_contents": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "filter": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        },
                        "comment": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                        },
                        "protocol": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "list",
                            "options": [{"value": "http"}, {"value": "ftp"}],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "action": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [{"value": "log"}, {"value": "block"}],
                        },
                        "direction": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [
                                {"value": "incoming"},
                                {"value": "outgoing"},
                                {"value": "any"},
                            ],
                        },
                        "password_protected": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [{"value": "yes"}, {"value": "any"}],
                        },
                        "file_type": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v6.2.0", "v6.2.7"]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.2.0", "v6.2.7"]],
                        },
                    },
                    "v_range": [["v6.2.0", "v6.2.7"]],
                },
            },
        },
        "inspection_mode": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "proxy"}, {"value": "flow-based"}],
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
        "webfilter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["webfilter_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["webfilter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "webfilter_profile"
        )

        is_error, has_changed, result, diff = fortios_webfilter(
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
