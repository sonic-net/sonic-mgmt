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
module: fmgr_webfilter_profile
short_description: Configure Web filter profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    webfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable extended logging for web filtering.
                choices:
                    - 'disable'
                    - 'enable'
            https_replacemsg:
                aliases: ['https-replacemsg']
                type: str
                description: Enable replacement messages for HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            inspection_mode:
                aliases: ['inspection-mode']
                type: str
                description: Web filtering inspection mode.
                choices:
                    - 'proxy'
                    - 'flow-based'
                    - 'dns'
            log_all_url:
                aliases: ['log-all-url']
                type: str
                description: Enable/disable logging all URLs visited.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Profile name.
                required: true
            options:
                type: list
                elements: str
                description: Options.
                choices:
                    - 'block-invalid-url'
                    - 'jscript'
                    - 'js'
                    - 'vbs'
                    - 'unknown'
                    - 'wf-referer'
                    - 'https-scan'
                    - 'intrinsic'
                    - 'wf-cookie'
                    - 'per-user-bwl'
                    - 'activexfilter'
                    - 'cookiefilter'
                    - 'https-url-scan'
                    - 'javafilter'
                    - 'rangeblock'
                    - 'contenttype-check'
                    - 'per-user-bal'
            ovrd_perm:
                aliases: ['ovrd-perm']
                type: list
                elements: str
                description: Permitted override types.
                choices:
                    - 'bannedword-override'
                    - 'urlfilter-override'
                    - 'fortiguard-wf-override'
                    - 'contenttype-check-override'
            post_action:
                aliases: ['post-action']
                type: str
                description: Action taken for HTTP POST traffic.
                choices:
                    - 'normal'
                    - 'comfort'
                    - 'block'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group.
            web_content_log:
                aliases: ['web-content-log']
                type: str
                description: Enable/disable logging logging blocked web content.
                choices:
                    - 'disable'
                    - 'enable'
            web_extended_all_action_log:
                aliases: ['web-extended-all-action-log']
                type: str
                description: Enable/disable extended any filter action logging for web filtering.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_activex_log:
                aliases: ['web-filter-activex-log']
                type: str
                description: Enable/disable logging ActiveX.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_applet_log:
                aliases: ['web-filter-applet-log']
                type: str
                description: Enable/disable logging Java applets.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_command_block_log:
                aliases: ['web-filter-command-block-log']
                type: str
                description: Enable/disable logging blocked commands.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_cookie_log:
                aliases: ['web-filter-cookie-log']
                type: str
                description: Enable/disable logging cookie filtering.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_cookie_removal_log:
                aliases: ['web-filter-cookie-removal-log']
                type: str
                description: Enable/disable logging blocked cookies.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_js_log:
                aliases: ['web-filter-js-log']
                type: str
                description: Enable/disable logging Java scripts.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_jscript_log:
                aliases: ['web-filter-jscript-log']
                type: str
                description: Enable/disable logging JScripts.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_referer_log:
                aliases: ['web-filter-referer-log']
                type: str
                description: Enable/disable logging referrers.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_unknown_log:
                aliases: ['web-filter-unknown-log']
                type: str
                description: Enable/disable logging unknown scripts.
                choices:
                    - 'disable'
                    - 'enable'
            web_filter_vbs_log:
                aliases: ['web-filter-vbs-log']
                type: str
                description: Enable/disable logging VBS scripts.
                choices:
                    - 'disable'
                    - 'enable'
            web_ftgd_err_log:
                aliases: ['web-ftgd-err-log']
                type: str
                description: Enable/disable logging rating errors.
                choices:
                    - 'disable'
                    - 'enable'
            web_ftgd_quota_usage:
                aliases: ['web-ftgd-quota-usage']
                type: str
                description: Enable/disable logging daily quota usage.
                choices:
                    - 'disable'
                    - 'enable'
            web_invalid_domain_log:
                aliases: ['web-invalid-domain-log']
                type: str
                description: Enable/disable logging invalid domain names.
                choices:
                    - 'disable'
                    - 'enable'
            web_url_log:
                aliases: ['web-url-log']
                type: str
                description: Enable/disable logging URL filtering.
                choices:
                    - 'disable'
                    - 'enable'
            wisp:
                type: str
                description: Enable/disable web proxy WISP.
                choices:
                    - 'disable'
                    - 'enable'
            wisp_algorithm:
                aliases: ['wisp-algorithm']
                type: str
                description: WISP server selection algorithm.
                choices:
                    - 'auto-learning'
                    - 'primary-secondary'
                    - 'round-robin'
            wisp_servers:
                aliases: ['wisp-servers']
                type: raw
                description: (list or str) WISP servers.
            youtube_channel_filter:
                aliases: ['youtube-channel-filter']
                type: list
                elements: dict
                description: Youtube channel filter.
                suboptions:
                    channel_id:
                        aliases: ['channel-id']
                        type: str
                        description: YouTube channel ID to be filtered.
                    comment:
                        type: str
                        description: Comment.
                    id:
                        type: int
                        description: ID.
            youtube_channel_status:
                aliases: ['youtube-channel-status']
                type: str
                description: YouTube channel filter status.
                choices:
                    - 'disable'
                    - 'blacklist'
                    - 'whitelist'
            feature_set:
                aliases: ['feature-set']
                type: str
                description: Flow/proxy feature set.
                choices:
                    - 'proxy'
                    - 'flow'
            web_antiphishing_log:
                aliases: ['web-antiphishing-log']
                type: str
                description: Enable/disable logging of AntiPhishing checks.
                choices:
                    - 'disable'
                    - 'enable'
            antiphish:
                type: dict
                description: Antiphish.
                suboptions:
                    check_basic_auth:
                        aliases: ['check-basic-auth']
                        type: str
                        description: Enable/disable checking of HTTP Basic Auth field for known credentials.
                        choices:
                            - 'disable'
                            - 'enable'
                    check_uri:
                        aliases: ['check-uri']
                        type: str
                        description: Enable/disable checking of GET URI parameters for known credentials.
                        choices:
                            - 'disable'
                            - 'enable'
                    check_username_only:
                        aliases: ['check-username-only']
                        type: str
                        description: Enable/disable acting only on valid username credentials.
                        choices:
                            - 'disable'
                            - 'enable'
                    custom_patterns:
                        aliases: ['custom-patterns']
                        type: list
                        elements: dict
                        description: Custom patterns.
                        suboptions:
                            category:
                                type: str
                                description: Category that the pattern matches.
                                choices:
                                    - 'username'
                                    - 'password'
                            pattern:
                                type: str
                                description: Target pattern.
                            type:
                                type: str
                                description: Pattern will be treated either as a regex pattern or literal string.
                                choices:
                                    - 'regex'
                                    - 'literal'
                    default_action:
                        aliases: ['default-action']
                        type: str
                        description: Action to be taken when there is no matching rule.
                        choices:
                            - 'log'
                            - 'block'
                            - 'exempt'
                    domain_controller:
                        aliases: ['domain-controller']
                        type: str
                        description: Domain for which to verify received credentials against.
                    inspection_entries:
                        aliases: ['inspection-entries']
                        type: list
                        elements: dict
                        description: Inspection entries.
                        suboptions:
                            action:
                                type: str
                                description: Action to be taken upon an AntiPhishing match.
                                choices:
                                    - 'log'
                                    - 'block'
                                    - 'exempt'
                            fortiguard_category:
                                aliases: ['fortiguard-category']
                                type: raw
                                description: (list) FortiGuard category to match.
                            name:
                                type: str
                                description: Inspection target name.
                    max_body_len:
                        aliases: ['max-body-len']
                        type: int
                        description: Maximum size of a POST body to check for credentials.
                    status:
                        type: str
                        description: Toggle AntiPhishing functionality.
                        choices:
                            - 'disable'
                            - 'enable'
                    authentication:
                        type: str
                        description: Authentication methods.
                        choices:
                            - 'domain-controller'
                            - 'ldap'
                    ldap:
                        type: str
                        description: LDAP server for which to verify received credentials against.
            ftgd_wf:
                aliases: ['ftgd-wf']
                type: dict
                description: Ftgd wf.
                suboptions:
                    exempt_quota:
                        aliases: ['exempt-quota']
                        type: raw
                        description: (list or str) Do not stop quota for these categories.
                    filters:
                        type: list
                        elements: dict
                        description: Filters.
                        suboptions:
                            action:
                                type: str
                                description: Action to take for matches.
                                choices:
                                    - 'block'
                                    - 'monitor'
                                    - 'warning'
                                    - 'authenticate'
                            auth_usr_grp:
                                aliases: ['auth-usr-grp']
                                type: raw
                                description: (list or str) Groups with permission to authenticate.
                            category:
                                type: str
                                description: Categories and groups the filter examines.
                            id:
                                type: int
                                description: ID number.
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            override_replacemsg:
                                aliases: ['override-replacemsg']
                                type: str
                                description: Override replacement message.
                            warn_duration:
                                aliases: ['warn-duration']
                                type: str
                                description: Duration of warnings.
                            warning_duration_type:
                                aliases: ['warning-duration-type']
                                type: str
                                description: Re-display warning after closing browser or after a timeout.
                                choices:
                                    - 'session'
                                    - 'timeout'
                            warning_prompt:
                                aliases: ['warning-prompt']
                                type: str
                                description: Warning prompts in each category or each domain.
                                choices:
                                    - 'per-domain'
                                    - 'per-category'
                    max_quota_timeout:
                        aliases: ['max-quota-timeout']
                        type: int
                        description: Maximum FortiGuard quota used by single page view in seconds
                    options:
                        type: list
                        elements: str
                        description: Options for FortiGuard Web Filter.
                        choices:
                            - 'error-allow'
                            - 'http-err-detail'
                            - 'rate-image-urls'
                            - 'strict-blocking'
                            - 'rate-server-ip'
                            - 'redir-block'
                            - 'connect-request-bypass'
                            - 'log-all-url'
                            - 'ftgd-disable'
                    ovrd:
                        type: raw
                        description: (list or str) Allow web filter profile overrides.
                    quota:
                        type: list
                        elements: dict
                        description: Quota.
                        suboptions:
                            category:
                                type: raw
                                description: (list or str) FortiGuard categories to apply quota to
                            duration:
                                type: str
                                description: Duration of quota.
                            id:
                                type: int
                                description: ID number.
                            override_replacemsg:
                                aliases: ['override-replacemsg']
                                type: str
                                description: Override replacement message.
                            type:
                                type: str
                                description: Quota type.
                                choices:
                                    - 'time'
                                    - 'traffic'
                            unit:
                                type: str
                                description: Traffic quota unit of measurement.
                                choices:
                                    - 'B'
                                    - 'KB'
                                    - 'MB'
                                    - 'GB'
                            value:
                                type: int
                                description: Traffic quota value.
                    rate_crl_urls:
                        aliases: ['rate-crl-urls']
                        type: str
                        description: Enable/disable rating CRL by URL.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_css_urls:
                        aliases: ['rate-css-urls']
                        type: str
                        description: Enable/disable rating CSS by URL.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_image_urls:
                        aliases: ['rate-image-urls']
                        type: str
                        description: Enable/disable rating images by URL.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_javascript_urls:
                        aliases: ['rate-javascript-urls']
                        type: str
                        description: Enable/disable rating JavaScript by URL.
                        choices:
                            - 'disable'
                            - 'enable'
                    category_override:
                        aliases: ['category-override']
                        type: str
                        description: Local categories take precedence over FortiGuard categories.
                    risk:
                        type: list
                        elements: dict
                        description: Risk.
                        suboptions:
                            action:
                                type: str
                                description: Action to take for matches.
                                choices:
                                    - 'block'
                                    - 'monitor'
                            id:
                                type: int
                                description: ID number.
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            risk_level:
                                aliases: ['risk-level']
                                type: raw
                                description: (list) Risk level to be examined.
            override:
                type: dict
                description: Override.
                suboptions:
                    ovrd_cookie:
                        aliases: ['ovrd-cookie']
                        type: str
                        description: Allow/deny browser-based
                        choices:
                            - 'deny'
                            - 'allow'
                    ovrd_dur:
                        aliases: ['ovrd-dur']
                        type: str
                        description: Override duration.
                    ovrd_dur_mode:
                        aliases: ['ovrd-dur-mode']
                        type: str
                        description: Override duration mode.
                        choices:
                            - 'constant'
                            - 'ask'
                    ovrd_scope:
                        aliases: ['ovrd-scope']
                        type: str
                        description: Override scope.
                        choices:
                            - 'user'
                            - 'user-group'
                            - 'ip'
                            - 'ask'
                            - 'browser'
                    ovrd_user_group:
                        aliases: ['ovrd-user-group']
                        type: raw
                        description: (list or str) User groups with permission to use the override.
                    profile:
                        type: raw
                        description: (list or str) Web filter profile with permission to create overrides.
                    profile_attribute:
                        aliases: ['profile-attribute']
                        type: str
                        description: Profile attribute to retrieve from the RADIUS server.
                        choices:
                            - 'User-Name'
                            - 'User-Password'
                            - 'CHAP-Password'
                            - 'NAS-IP-Address'
                            - 'NAS-Port'
                            - 'Service-Type'
                            - 'Framed-Protocol'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Framed-Routing'
                            - 'Filter-Id'
                            - 'Framed-MTU'
                            - 'Framed-Compression'
                            - 'Login-IP-Host'
                            - 'Login-Service'
                            - 'Login-TCP-Port'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'State'
                            - 'Class'
                            - 'Vendor-Specific'
                            - 'Session-Timeout'
                            - 'Idle-Timeout'
                            - 'Termination-Action'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Link'
                            - 'Framed-AppleTalk-Network'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Status-Type'
                            - 'Acct-Delay-Time'
                            - 'Acct-Input-Octets'
                            - 'Acct-Output-Octets'
                            - 'Acct-Session-Id'
                            - 'Acct-Authentic'
                            - 'Acct-Session-Time'
                            - 'Acct-Input-Packets'
                            - 'Acct-Output-Packets'
                            - 'Acct-Terminate-Cause'
                            - 'Acct-Multi-Session-Id'
                            - 'Acct-Link-Count'
                            - 'CHAP-Challenge'
                            - 'NAS-Port-Type'
                            - 'Port-Limit'
                            - 'Login-LAT-Port'
                    profile_type:
                        aliases: ['profile-type']
                        type: str
                        description: Override profile type.
                        choices:
                            - 'list'
                            - 'radius'
            url_extraction:
                aliases: ['url-extraction']
                type: dict
                description: Url extraction.
                suboptions:
                    redirect_header:
                        aliases: ['redirect-header']
                        type: str
                        description: HTTP header name to use for client redirect on blocked requests
                    redirect_no_content:
                        aliases: ['redirect-no-content']
                        type: str
                        description: Enable / Disable empty message-body entity in HTTP response
                        choices:
                            - 'disable'
                            - 'enable'
                    redirect_url:
                        aliases: ['redirect-url']
                        type: str
                        description: HTTP header value to use for client redirect on blocked requests
                    server_fqdn:
                        aliases: ['server-fqdn']
                        type: str
                        description: URL extraction server FQDN
                    status:
                        type: str
                        description: Enable URL Extraction
                        choices:
                            - 'disable'
                            - 'enable'
            web:
                type: dict
                description: Web.
                suboptions:
                    blacklist:
                        type: str
                        description: Enable/disable automatic addition of URLs detected by FortiSandbox to blacklist.
                        choices:
                            - 'disable'
                            - 'enable'
                    bword_table:
                        aliases: ['bword-table']
                        type: str
                        description: Banned word table ID.
                    bword_threshold:
                        aliases: ['bword-threshold']
                        type: int
                        description: Banned word score threshold.
                    content_header_list:
                        aliases: ['content-header-list']
                        type: str
                        description: Content header list.
                    keyword_match:
                        aliases: ['keyword-match']
                        type: raw
                        description: (list) Search keywords to log when match is found.
                    log_search:
                        aliases: ['log-search']
                        type: str
                        description: Enable/disable logging all search phrases.
                        choices:
                            - 'disable'
                            - 'enable'
                    safe_search:
                        aliases: ['safe-search']
                        type: list
                        elements: str
                        description: Safe search type.
                        choices:
                            - 'google'
                            - 'yahoo'
                            - 'bing'
                            - 'url'
                            - 'header'
                    urlfilter_table:
                        aliases: ['urlfilter-table']
                        type: str
                        description: URL filter table ID.
                    whitelist:
                        type: list
                        elements: str
                        description: FortiGuard whitelist settings.
                        choices:
                            - 'exempt-av'
                            - 'exempt-webcontent'
                            - 'exempt-activex-java-cookie'
                            - 'exempt-dlp'
                            - 'exempt-rangeblock'
                            - 'extended-log-others'
                    youtube_restrict:
                        aliases: ['youtube-restrict']
                        type: str
                        description: YouTube EDU filter level.
                        choices:
                            - 'strict'
                            - 'none'
                            - 'moderate'
                    allowlist:
                        type: list
                        elements: str
                        description: FortiGuard allowlist settings.
                        choices:
                            - 'exempt-av'
                            - 'exempt-webcontent'
                            - 'exempt-activex-java-cookie'
                            - 'exempt-dlp'
                            - 'exempt-rangeblock'
                            - 'extended-log-others'
                    blocklist:
                        type: str
                        description: Enable/disable automatic addition of URLs detected by FortiSandbox to blocklist.
                        choices:
                            - 'disable'
                            - 'enable'
                    vimeo_restrict:
                        aliases: ['vimeo-restrict']
                        type: str
                        description: Set Vimeo-restrict
            file_filter:
                aliases: ['file-filter']
                type: dict
                description: File filter.
                suboptions:
                    entries:
                        type: list
                        elements: dict
                        description: Entries.
                        suboptions:
                            action:
                                type: str
                                description: Action taken for matched file.
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                type: str
                                description: Comment.
                            direction:
                                type: str
                                description: Match files transmitted in the sessions originating or reply direction.
                                choices:
                                    - 'any'
                                    - 'incoming'
                                    - 'outgoing'
                            encryption:
                                type: str
                                description: Encryption.
                                choices:
                                    - 'any'
                                    - 'yes'
                            file_type:
                                aliases: ['file-type']
                                type: raw
                                description: (list) Select file type.
                            filter:
                                type: str
                                description: Add a file filter.
                            password_protected:
                                aliases: ['password-protected']
                                type: str
                                description: Match password-protected files.
                                choices:
                                    - 'any'
                                    - 'yes'
                            protocol:
                                type: list
                                elements: str
                                description: Protocols to apply with.
                                choices:
                                    - 'http'
                                    - 'ftp'
                    log:
                        type: str
                        description: Enable/disable file filter logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    scan_archive_contents:
                        aliases: ['scan-archive-contents']
                        type: str
                        description: Enable/disable file filter archive contents scan.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable file filter.
                        choices:
                            - 'disable'
                            - 'enable'
            web_flow_log_encoding:
                aliases: ['web-flow-log-encoding']
                type: str
                description: Log encoding in flow mode.
                choices:
                    - 'utf-8'
                    - 'punycode'
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
    - name: Configure Web filter profiles.
      fortinet.fortimanager.fmgr_webfilter_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        webfilter_profile:
          name: "your value" # Required variable, string
          # comment: <string>
          # extended_log: <value in [disable, enable]>
          # https_replacemsg: <value in [disable, enable]>
          # inspection_mode: <value in [proxy, flow-based, dns]>
          # log_all_url: <value in [disable, enable]>
          # options:
          #   - "block-invalid-url"
          #   - "jscript"
          #   - "js"
          #   - "vbs"
          #   - "unknown"
          #   - "wf-referer"
          #   - "https-scan"
          #   - "intrinsic"
          #   - "wf-cookie"
          #   - "per-user-bwl"
          #   - "activexfilter"
          #   - "cookiefilter"
          #   - "https-url-scan"
          #   - "javafilter"
          #   - "rangeblock"
          #   - "contenttype-check"
          #   - "per-user-bal"
          # ovrd_perm:
          #   - "bannedword-override"
          #   - "urlfilter-override"
          #   - "fortiguard-wf-override"
          #   - "contenttype-check-override"
          # post_action: <value in [normal, comfort, block]>
          # replacemsg_group: <string>
          # web_content_log: <value in [disable, enable]>
          # web_extended_all_action_log: <value in [disable, enable]>
          # web_filter_activex_log: <value in [disable, enable]>
          # web_filter_applet_log: <value in [disable, enable]>
          # web_filter_command_block_log: <value in [disable, enable]>
          # web_filter_cookie_log: <value in [disable, enable]>
          # web_filter_cookie_removal_log: <value in [disable, enable]>
          # web_filter_js_log: <value in [disable, enable]>
          # web_filter_jscript_log: <value in [disable, enable]>
          # web_filter_referer_log: <value in [disable, enable]>
          # web_filter_unknown_log: <value in [disable, enable]>
          # web_filter_vbs_log: <value in [disable, enable]>
          # web_ftgd_err_log: <value in [disable, enable]>
          # web_ftgd_quota_usage: <value in [disable, enable]>
          # web_invalid_domain_log: <value in [disable, enable]>
          # web_url_log: <value in [disable, enable]>
          # wisp: <value in [disable, enable]>
          # wisp_algorithm: <value in [auto-learning, primary-secondary, round-robin]>
          # wisp_servers: <list or string>
          # youtube_channel_filter:
          #   - channel_id: <string>
          #     comment: <string>
          #     id: <integer>
          # youtube_channel_status: <value in [disable, blacklist, whitelist]>
          # feature_set: <value in [proxy, flow]>
          # web_antiphishing_log: <value in [disable, enable]>
          # antiphish:
          #   check_basic_auth: <value in [disable, enable]>
          #   check_uri: <value in [disable, enable]>
          #   check_username_only: <value in [disable, enable]>
          #   custom_patterns:
          #     - category: <value in [username, password]>
          #       pattern: <string>
          #       type: <value in [regex, literal]>
          #   default_action: <value in [log, block, exempt]>
          #   domain_controller: <string>
          #   inspection_entries:
          #     - action: <value in [log, block, exempt]>
          #       fortiguard_category: <list or string>
          #       name: <string>
          #   max_body_len: <integer>
          #   status: <value in [disable, enable]>
          #   authentication: <value in [domain-controller, ldap]>
          #   ldap: <string>
          # ftgd_wf:
          #   exempt_quota: <list or string>
          #   filters:
          #     - action: <value in [block, monitor, warning, ...]>
          #       auth_usr_grp: <list or string>
          #       category: <string>
          #       id: <integer>
          #       log: <value in [disable, enable]>
          #       override_replacemsg: <string>
          #       warn_duration: <string>
          #       warning_duration_type: <value in [session, timeout]>
          #       warning_prompt: <value in [per-domain, per-category]>
          #   max_quota_timeout: <integer>
          #   options:
          #     - "error-allow"
          #     - "http-err-detail"
          #     - "rate-image-urls"
          #     - "strict-blocking"
          #     - "rate-server-ip"
          #     - "redir-block"
          #     - "connect-request-bypass"
          #     - "log-all-url"
          #     - "ftgd-disable"
          #   ovrd: <list or string>
          #   quota:
          #     - category: <list or string>
          #       duration: <string>
          #       id: <integer>
          #       override_replacemsg: <string>
          #       type: <value in [time, traffic]>
          #       unit: <value in [B, KB, MB, ...]>
          #       value: <integer>
          #   rate_crl_urls: <value in [disable, enable]>
          #   rate_css_urls: <value in [disable, enable]>
          #   rate_image_urls: <value in [disable, enable]>
          #   rate_javascript_urls: <value in [disable, enable]>
          #   category_override: <string>
          #   risk:
          #     - action: <value in [block, monitor]>
          #       id: <integer>
          #       log: <value in [disable, enable]>
          #       risk_level: <list or string>
          # override:
          #   ovrd_cookie: <value in [deny, allow]>
          #   ovrd_dur: <string>
          #   ovrd_dur_mode: <value in [constant, ask]>
          #   ovrd_scope: <value in [user, user-group, ip, ...]>
          #   ovrd_user_group: <list or string>
          #   profile: <list or string>
          #   profile_attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
          #   profile_type: <value in [list, radius]>
          # url_extraction:
          #   redirect_header: <string>
          #   redirect_no_content: <value in [disable, enable]>
          #   redirect_url: <string>
          #   server_fqdn: <string>
          #   status: <value in [disable, enable]>
          # web:
          #   blacklist: <value in [disable, enable]>
          #   bword_table: <string>
          #   bword_threshold: <integer>
          #   content_header_list: <string>
          #   keyword_match: <list or string>
          #   log_search: <value in [disable, enable]>
          #   safe_search:
          #     - "google"
          #     - "yahoo"
          #     - "bing"
          #     - "url"
          #     - "header"
          #   urlfilter_table: <string>
          #   whitelist:
          #     - "exempt-av"
          #     - "exempt-webcontent"
          #     - "exempt-activex-java-cookie"
          #     - "exempt-dlp"
          #     - "exempt-rangeblock"
          #     - "extended-log-others"
          #   youtube_restrict: <value in [strict, none, moderate]>
          #   allowlist:
          #     - "exempt-av"
          #     - "exempt-webcontent"
          #     - "exempt-activex-java-cookie"
          #     - "exempt-dlp"
          #     - "exempt-rangeblock"
          #     - "extended-log-others"
          #   blocklist: <value in [disable, enable]>
          #   vimeo_restrict: <string>
          # file_filter:
          #   entries:
          #     - action: <value in [log, block]>
          #       comment: <string>
          #       direction: <value in [any, incoming, outgoing]>
          #       encryption: <value in [any, yes]>
          #       file_type: <list or string>
          #       filter: <string>
          #       password_protected: <value in [any, yes]>
          #       protocol:
          #         - "http"
          #         - "ftp"
          #   log: <value in [disable, enable]>
          #   scan_archive_contents: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
          # web_flow_log_encoding: <value in [utf-8, punycode]>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile',
        '/pm/config/global/obj/webfilter/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'extended-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'https-replacemsg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'inspection-mode': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['proxy', 'flow-based', 'dns'], 'type': 'str'},
                'log-all-url': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'options': {
                    'type': 'list',
                    'choices': [
                        'block-invalid-url', 'jscript', 'js', 'vbs', 'unknown', 'wf-referer', 'https-scan', 'intrinsic', 'wf-cookie', 'per-user-bwl',
                        'activexfilter', 'cookiefilter', 'https-url-scan', 'javafilter', 'rangeblock', 'contenttype-check', 'per-user-bal'
                    ],
                    'elements': 'str'
                },
                'ovrd-perm': {
                    'type': 'list',
                    'choices': ['bannedword-override', 'urlfilter-override', 'fortiguard-wf-override', 'contenttype-check-override'],
                    'elements': 'str'
                },
                'post-action': {'choices': ['normal', 'comfort', 'block'], 'type': 'str'},
                'replacemsg-group': {'type': 'str'},
                'web-content-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-extended-all-action-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-activex-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-applet-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-command-block-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-cookie-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-cookie-removal-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-js-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-jscript-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-referer-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-unknown-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-filter-vbs-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-ftgd-err-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-ftgd-quota-usage': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-invalid-domain-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-url-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wisp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wisp-algorithm': {'choices': ['auto-learning', 'primary-secondary', 'round-robin'], 'type': 'str'},
                'wisp-servers': {'type': 'raw'},
                'youtube-channel-filter': {
                    'type': 'list',
                    'options': {'channel-id': {'type': 'str'}, 'comment': {'type': 'str'}, 'id': {'type': 'int'}},
                    'elements': 'dict'
                },
                'youtube-channel-status': {'choices': ['disable', 'blacklist', 'whitelist'], 'type': 'str'},
                'feature-set': {'v_range': [['6.4.0', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'web-antiphishing-log': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'antiphish': {
                    'v_range': [['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'check-basic-auth': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'check-uri': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'check-username-only': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'custom-patterns': {
                            'v_range': [['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'category': {'v_range': [['6.4.5', '']], 'choices': ['username', 'password'], 'type': 'str'},
                                'pattern': {'v_range': [['6.4.5', '']], 'type': 'str'},
                                'type': {'v_range': [['7.0.0', '']], 'choices': ['regex', 'literal'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'default-action': {'v_range': [['6.4.5', '']], 'choices': ['log', 'block', 'exempt'], 'type': 'str'},
                        'domain-controller': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'inspection-entries': {
                            'v_range': [['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.4.5', '']], 'choices': ['log', 'block', 'exempt'], 'type': 'str'},
                                'fortiguard-category': {'v_range': [['6.4.5', '']], 'type': 'raw'},
                                'name': {'v_range': [['6.4.5', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'max-body-len': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'status': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'authentication': {'v_range': [['7.0.0', '']], 'choices': ['domain-controller', 'ldap'], 'type': 'str'},
                        'ldap': {'v_range': [['7.0.0', '']], 'type': 'str'}
                    }
                },
                'ftgd-wf': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'exempt-quota': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'filters': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'action': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['block', 'monitor', 'warning', 'authenticate'],
                                    'type': 'str'
                                },
                                'auth-usr-grp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'category': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'override-replacemsg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'warn-duration': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'warning-duration-type': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['session', 'timeout'],
                                    'type': 'str'
                                },
                                'warning-prompt': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['per-domain', 'per-category'],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'max-quota-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'error-allow', 'http-err-detail', 'rate-image-urls', 'strict-blocking', 'rate-server-ip', 'redir-block',
                                'connect-request-bypass', 'log-all-url', 'ftgd-disable'
                            ],
                            'elements': 'str'
                        },
                        'ovrd': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'quota': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'category': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'duration': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'override-replacemsg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['time', 'traffic'], 'type': 'str'},
                                'unit': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['B', 'KB', 'MB', 'GB'], 'type': 'str'},
                                'value': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'rate-crl-urls': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-css-urls': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-image-urls': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-javascript-urls': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'category-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '6.4.15']], 'type': 'str'},
                        'risk': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['7.6.2', '']], 'choices': ['block', 'monitor'], 'type': 'str'},
                                'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                                'log': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'risk-level': {'v_range': [['7.6.2', '']], 'type': 'raw'}
                            },
                            'elements': 'dict'
                        }
                    }
                },
                'override': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'ovrd-cookie': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                        'ovrd-dur': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ovrd-dur-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['constant', 'ask'], 'type': 'str'},
                        'ovrd-scope': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['user', 'user-group', 'ip', 'ask', 'browser'],
                            'type': 'str'
                        },
                        'ovrd-user-group': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'profile-attribute': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                                'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression',
                                'Login-IP-Host', 'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route',
                                'Framed-IPX-Network', 'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action',
                                'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node',
                                'Login-LAT-Group', 'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type',
                                'Acct-Delay-Time', 'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time',
                                'Acct-Input-Packets', 'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count',
                                'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit', 'Login-LAT-Port'
                            ],
                            'type': 'str'
                        },
                        'profile-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['list', 'radius'], 'type': 'str'}
                    }
                },
                'url-extraction': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'redirect-header': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'redirect-no-content': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'redirect-url': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'server-fqdn': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'web': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'blacklist': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bword-table': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'bword-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'content-header-list': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'keyword-match': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'log-search': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'safe-search': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['google', 'yahoo', 'bing', 'url', 'header'],
                            'elements': 'str'
                        },
                        'urlfilter-table': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'whitelist': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp', 'exempt-rangeblock', 'extended-log-others'
                            ],
                            'elements': 'str'
                        },
                        'youtube-restrict': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['strict', 'none', 'moderate'], 'type': 'str'},
                        'allowlist': {
                            'v_range': [['7.0.0', '']],
                            'type': 'list',
                            'choices': [
                                'exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp', 'exempt-rangeblock', 'extended-log-others'
                            ],
                            'elements': 'str'
                        },
                        'blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vimeo-restrict': {'v_range': [['7.0.1', '']], 'type': 'str'}
                    }
                },
                'file-filter': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                    'type': 'dict',
                    'options': {
                        'entries': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['log', 'block'], 'type': 'str'},
                                'comment': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'str'},
                                'direction': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                                    'choices': ['any', 'incoming', 'outgoing'],
                                    'type': 'str'
                                },
                                'encryption': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'choices': ['any', 'yes'], 'type': 'str'},
                                'file-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'raw'},
                                'filter': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'str'},
                                'password-protected': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['any', 'yes'], 'type': 'str'},
                                'protocol': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                                    'type': 'list',
                                    'choices': ['http', 'ftp'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'scan-archive-contents': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'web-flow-log-encoding': {'v_range': [['7.4.2', '']], 'choices': ['utf-8', 'punycode'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile'),
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
