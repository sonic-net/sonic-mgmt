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
module: fmgr_pkg_firewall_proxypolicy
short_description: Configure proxy policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_proxypolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Accept or deny traffic matching the policy parameters.
                choices:
                    - 'accept'
                    - 'deny'
                    - 'redirect'
                    - 'isolate'
            application_list:
                aliases: ['application-list']
                type: str
                description: Name of an existing Application list.
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Name of an existing Antivirus profile.
            comments:
                type: str
                description: Optional comments.
            disclaimer:
                type: str
                description: Web proxy disclaimer setting
                choices:
                    - 'disable'
                    - 'domain'
                    - 'policy'
                    - 'user'
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: Name of an existing DLP sensor.
            dstaddr:
                type: raw
                description: (list or str) Destination address objects.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled, destination addresses match against any address EXCEPT the specified destination addresses.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: raw
                description: (list or str) IPv6 destination address objects.
            dstintf:
                type: raw
                description: (list or str) Destination interface names.
            global_label:
                aliases: ['global-label']
                type: str
                description: Global web-based manager visible label.
            groups:
                type: raw
                description: (list or str) Names of group objects.
            http_tunnel_auth:
                aliases: ['http-tunnel-auth']
                type: str
                description: Enable/disable HTTP tunnel authentication.
                choices:
                    - 'disable'
                    - 'enable'
            icap_profile:
                aliases: ['icap-profile']
                type: str
                description: Name of an existing ICAP profile.
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: raw
                description: (list or str) Custom Internet Service name.
            internet_service_id:
                aliases: ['internet-service-id']
                type: raw
                description: (list or str) Internet Service ID.
            internet_service_negate:
                aliases: ['internet-service-negate']
                type: str
                description: When enabled, Internet Services match against any internet service EXCEPT the selected Internet Service.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: Name of an existing IPS sensor.
            label:
                type: str
                description: VDOM-specific GUI visible label.
            logtraffic:
                type: str
                description: Enable/disable logging traffic through the policy.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Enable/disable policy log traffic start.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                aliases: ['mms-profile']
                type: str
                description: Name of an existing MMS profile.
            policyid:
                type: int
                description: Policy ID.
                required: true
            poolname:
                type: raw
                description: (list or str) Name of IP pool object.
            profile_group:
                aliases: ['profile-group']
                type: str
                description: Name of profile group.
            profile_protocol_options:
                aliases: ['profile-protocol-options']
                type: str
                description: Name of an existing Protocol options profile.
            profile_type:
                aliases: ['profile-type']
                type: str
                description: Determine whether the firewall policy allows security profile groups or single profiles only.
                choices:
                    - 'single'
                    - 'group'
            proxy:
                type: str
                description: Type of explicit proxy.
                choices:
                    - 'explicit-web'
                    - 'transparent-web'
                    - 'ftp'
                    - 'wanopt'
                    - 'ssh'
                    - 'ssh-tunnel'
                    - 'access-proxy'
                    - 'ztna-proxy'
            redirect_url:
                aliases: ['redirect-url']
                type: str
                description: Redirect URL for further explicit web proxy processing.
            replacemsg_override_group:
                aliases: ['replacemsg-override-group']
                type: str
                description: Authentication replacement message override group.
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Enable/disable scanning of connections to Botnet servers.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: Name of schedule object.
            service:
                type: raw
                description: (list or str) Name of service objects.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled, services match against any service EXCEPT the specified destination services.
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter_profile:
                aliases: ['spamfilter-profile']
                type: str
                description: Name of an existing Spam filter profile.
            srcaddr:
                type: raw
                description: (list or str) Source address objects
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled, source addresses match against any address EXCEPT the specified source addresses.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: raw
                description: (list or str) IPv6 source address objects.
            srcintf:
                type: raw
                description: (list or str) Source interface names.
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: str
                description: Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable/disable the active status of the policy.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Names of object-tags applied to address.
            transparent:
                type: str
                description: Enable to use the IP address of the client to connect to the server.
                choices:
                    - 'disable'
                    - 'enable'
            users:
                type: raw
                description: (list or str) Names of user objects.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable the use of UTM profiles/sensors/lists.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            waf_profile:
                aliases: ['waf-profile']
                type: str
                description: Name of an existing Web application firewall profile.
            webcache:
                type: str
                description: Enable/disable web caching.
                choices:
                    - 'disable'
                    - 'enable'
            webcache_https:
                aliases: ['webcache-https']
                type: str
                description: Enable/disable web caching for HTTPS
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Name of an existing Web filter profile.
            webproxy_forward_server:
                aliases: ['webproxy-forward-server']
                type: str
                description: Name of web proxy forward server.
            webproxy_profile:
                aliases: ['webproxy-profile']
                type: str
                description: Name of web proxy profile.
            cifs_profile:
                aliases: ['cifs-profile']
                type: str
                description: Name of an existing CIFS profile.
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: str
                description: Name of an existing email filter profile.
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: raw
                description: (list or str) Custom Internet Service group name.
            internet_service_group:
                aliases: ['internet-service-group']
                type: raw
                description: (list or str) Internet Service group name.
            session_ttl:
                aliases: ['session-ttl']
                type: raw
                description: (int or str) TTL in seconds for sessions accepted by this policy
            ssh_filter_profile:
                aliases: ['ssh-filter-profile']
                type: str
                description: Name of an existing SSH filter profile.
            ssh_policy_redirect:
                aliases: ['ssh-policy-redirect']
                type: str
                description: Redirect SSH traffic to matching transparent proxy policy.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: str
                description: Decrypted traffic mirror.
            internet_service_name:
                aliases: ['internet-service-name']
                type: raw
                description: (list or str) Internet Service name.
            file_filter_profile:
                aliases: ['file-filter-profile']
                type: str
                description: Name of an existing file-filter profile.
            name:
                type: str
                description: Policy name.
            access_proxy:
                aliases: ['access-proxy']
                type: raw
                description: (list or str) Access Proxy.
            device_ownership:
                aliases: ['device-ownership']
                type: str
                description: When enabled, the ownership enforcement will be done at policy level.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter_profile:
                aliases: ['videofilter-profile']
                type: str
                description: Name of an existing VideoFilter profile.
            voip_profile:
                aliases: ['voip-profile']
                type: str
                description: Name of an existing VoIP profile.
            ztna_ems_tag:
                aliases: ['ztna-ems-tag']
                type: raw
                description: (list or str) ZTNA EMS Tag names.
            access_proxy6:
                aliases: ['access-proxy6']
                type: raw
                description: (list or str) IPv6 access proxy.
            block_notification:
                aliases: ['block-notification']
                type: str
                description: Enable/disable block notification.
                choices:
                    - 'disable'
                    - 'enable'
            dlp_profile:
                aliases: ['dlp-profile']
                type: str
                description: Name of an existing DLP profile.
            sctp_filter_profile:
                aliases: ['sctp-filter-profile']
                type: str
                description: Name of an existing SCTP filter profile.
            ztna_tags_match_logic:
                aliases: ['ztna-tags-match-logic']
                type: str
                description: ZTNA tag matching logic.
                choices:
                    - 'or'
                    - 'and'
            casb_profile:
                aliases: ['casb-profile']
                type: str
                description: Name of an existing CASB profile.
            detect_https_in_http_request:
                aliases: ['detect-https-in-http-request']
                type: str
                description: Enable/disable detection of HTTPS in HTTP request.
                choices:
                    - 'disable'
                    - 'enable'
            diameter_filter_profile:
                aliases: ['diameter-filter-profile']
                type: str
                description: Name of an existing Diameter filter profile.
            internet_service6:
                aliases: ['internet-service6']
                type: str
                description: Enable/disable use of Internet Services IPv6 for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_custom:
                aliases: ['internet-service6-custom']
                type: raw
                description: (list) Custom Internet Service IPv6 name.
            internet_service6_custom_group:
                aliases: ['internet-service6-custom-group']
                type: raw
                description: (list) Custom Internet Service IPv6 group name.
            internet_service6_group:
                aliases: ['internet-service6-group']
                type: raw
                description: (list) Internet Service IPv6 group name.
            internet_service6_name:
                aliases: ['internet-service6-name']
                type: raw
                description: (list) Internet Service IPv6 name.
            internet_service6_negate:
                aliases: ['internet-service6-negate']
                type: str
                description: When enabled, Internet Services match against any internet service IPv6 EXCEPT the selected Internet Service IPv6.
                choices:
                    - 'disable'
                    - 'enable'
            ips_voip_filter:
                aliases: ['ips-voip-filter']
                type: str
                description: Name of an existing VoIP
            virtual_patch_profile:
                aliases: ['virtual-patch-profile']
                type: str
                description: Virtual patch profile.
            _policy_block:
                type: int
                description: Assigned policy block.
            dnsfilter_profile:
                aliases: ['dnsfilter-profile']
                type: raw
                description: (list) Name of an existing DNS filter profile.
            log_http_transaction:
                aliases: ['log-http-transaction']
                type: str
                description: Enable/disable HTTP transaction log.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_proxy:
                aliases: ['ztna-proxy']
                type: raw
                description: (list) IPv4 ZTNA traffic forward proxy.
            isolator_server:
                aliases: ['isolator-server']
                type: raw
                description: (list) Isolator server name.
            url_risk:
                aliases: ['url-risk']
                type: raw
                description: (list) URL risk level name.
            ztna_ems_tag_negate:
                aliases: ['ztna-ems-tag-negate']
                type: str
                description: When enabled, ZTNA EMS tags match against any tag EXCEPT the specified ZTNA EMS tags.
                choices:
                    - 'disable'
                    - 'enable'
            https_sub_category:
                aliases: ['https-sub-category']
                type: str
                description: Enable/disable HTTPS sub-category policy matching.
                choices:
                    - 'disable'
                    - 'enable'
            telemetry_profile:
                aliases: ['telemetry-profile']
                type: raw
                description: (list) Name of an existing telemetry profile.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure proxy policies.
      fortinet.fortimanager.fmgr_pkg_firewall_proxypolicy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_proxypolicy:
          action: accept # <value in [accept, deny, redirect]>
          comments: ansible-comment
          dstaddr: all
          dstintf: any
          policyid: 1
          schedule: always
          service: ALL
          srcaddr: all
          srcintf: any
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the proxy policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_proxypolicy"
          params:
            adom: "ansible"
            proxy_policy: "your_value"
            pkg: "ansible" # package name
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_proxypolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['accept', 'deny', 'redirect', 'isolate'], 'type': 'str'},
                'application-list': {'type': 'str'},
                'av-profile': {'type': 'str'},
                'comments': {'type': 'str'},
                'disclaimer': {'choices': ['disable', 'domain', 'policy', 'user'], 'type': 'str'},
                'dlp-sensor': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstaddr-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6': {'type': 'raw'},
                'dstintf': {'type': 'raw'},
                'global-label': {'type': 'str'},
                'groups': {'type': 'raw'},
                'http-tunnel-auth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'icap-profile': {'type': 'str'},
                'internet-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'type': 'raw'},
                'internet-service-id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'internet-service-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'type': 'str'},
                'label': {'type': 'str'},
                'logtraffic': {'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'policyid': {'required': True, 'type': 'int'},
                'poolname': {'type': 'raw'},
                'profile-group': {'type': 'str'},
                'profile-protocol-options': {'v_range': [['6.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'profile-type': {'choices': ['single', 'group'], 'type': 'str'},
                'proxy': {
                    'choices': ['explicit-web', 'transparent-web', 'ftp', 'wanopt', 'ssh', 'ssh-tunnel', 'access-proxy', 'ztna-proxy'],
                    'type': 'str'
                },
                'redirect-url': {'type': 'str'},
                'replacemsg-override-group': {'type': 'str'},
                'scan-botnet-connections': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'service-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'spamfilter-profile': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'srcaddr': {'type': 'raw'},
                'srcaddr-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr6': {'type': 'raw'},
                'srcintf': {'type': 'raw'},
                'ssl-ssh-profile': {'v_range': [['6.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'transparent': {'choices': ['disable', 'enable'], 'type': 'str'},
                'users': {'type': 'raw'},
                'utm-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'waf-profile': {'type': 'str'},
                'webcache': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache-https': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-profile': {'type': 'str'},
                'webproxy-forward-server': {'type': 'str'},
                'webproxy-profile': {'type': 'str'},
                'cifs-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'emailfilter-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'internet-service-custom-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'session-ttl': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'ssh-filter-profile': {'v_range': [['6.2.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'ssh-policy-redirect': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'file-filter-profile': {'v_range': [['6.4.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'name': {'v_range': [['6.4.2', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'access-proxy': {'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'device-ownership': {
                    'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'videofilter-profile': {'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'voip-profile': {'v_range': [['7.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'ztna-ems-tag': {'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'access-proxy6': {'v_range': [['7.0.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'block-notification': {
                    'v_range': [['7.0.3', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'dlp-profile': {'v_range': [['7.2.0', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'sctp-filter-profile': {'v_range': [['7.0.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'ztna-tags-match-logic': {
                    'v_range': [['7.0.2', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['or', 'and'],
                    'type': 'str'
                },
                'casb-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'detect-https-in-http-request': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'internet-service6': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-custom': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-custom-group': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-group': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-negate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-voip-filter': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                '_policy_block': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'dnsfilter-profile': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                'log-http-transaction': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-proxy': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                'isolator-server': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'url-risk': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'ztna-ems-tag-negate': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'https-sub-category': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'telemetry-profile': {'v_range': [['7.6.3', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_proxypolicy'),
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
