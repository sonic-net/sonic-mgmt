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
module: fmgr_pkg_firewall_policy6
short_description: Configure IPv6 policies.
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
    pkg_firewall_policy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
            app_category:
                aliases: ['app-category']
                type: raw
                description: (list or str) Application category ID list.
            application:
                type: raw
                description: (list) Application ID list.
            application_list:
                aliases: ['application-list']
                type: str
                description: Name of an existing Application list.
            auto_asic_offload:
                aliases: ['auto-asic-offload']
                type: str
                description: Enable/disable policy traffic ASIC offloading.
                choices:
                    - 'disable'
                    - 'enable'
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Name of an existing Antivirus profile.
            comments:
                type: str
                description: Comment.
            custom_log_fields:
                aliases: ['custom-log-fields']
                type: raw
                description: (list or str) Log field index numbers to append custom log fields to log messages for this policy.
            devices:
                type: raw
                description: (list or str) Names of devices or device groups that can be matched by the policy.
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Enable to change packets DiffServ values to the specified diffservcode-forward value.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Enable to change packets reverse
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Change packets DiffServ to this value.
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Change packets reverse
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: Name of an existing DLP sensor.
            dscp_match:
                aliases: ['dscp-match']
                type: str
                description: Enable DSCP check.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_negate:
                aliases: ['dscp-negate']
                type: str
                description: Enable negated DSCP match.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_value:
                aliases: ['dscp-value']
                type: str
                description: DSCP value.
            dsri:
                type: str
                description: Enable DSRI to ignore HTTP server responses.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Destination address and address group names.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            dstintf:
                type: raw
                description: (list or str) Outgoing
            firewall_session_dirty:
                aliases: ['firewall-session-dirty']
                type: str
                description: How to handle sessions if the configuration of this firewall policy changes.
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: Enable to prevent source NAT from changing a sessions source port.
                choices:
                    - 'disable'
                    - 'enable'
            global_label:
                aliases: ['global-label']
                type: str
                description: Label for the policy that appears when the GUI is in Global View mode.
            groups:
                type: raw
                description: (list or str) Names of user groups that can authenticate with this policy.
            icap_profile:
                aliases: ['icap-profile']
                type: str
                description: Name of an existing ICAP profile.
            inbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: Enable to use IP Pools for source NAT.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: Name of an existing IPS sensor.
            label:
                type: str
                description: Label for the policy that appears when the GUI is in Section View mode.
            logtraffic:
                type: str
                description: Enable or disable logging.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Record logs when a session starts and ends.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                aliases: ['mms-profile']
                type: str
                description: Name of an existing MMS profile.
            name:
                type: str
                description: Policy name.
            nat:
                type: str
                description: Enable/disable source NAT.
                choices:
                    - 'disable'
                    - 'enable'
            natinbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            natoutbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            np_accelation:
                aliases: ['np-accelation']
                type: str
                description: Enable/disable UTM Network Processor acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: str
                description: Per-IP traffic shaper.
            policyid:
                type: int
                description: Policy ID.
                required: true
            poolname:
                type: raw
                description: (list or str) IP Pool names.
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
            replacemsg_override_group:
                aliases: ['replacemsg-override-group']
                type: str
                description: Override the default replacement message group for this policy.
            rsso:
                type: str
                description: Enable/disable RADIUS single sign-on
                choices:
                    - 'disable'
                    - 'enable'
            schedule:
                type: str
                description: Schedule name.
            send_deny_packet:
                aliases: ['send-deny-packet']
                type: str
                description: Enable/disable return of deny-packet.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: raw
                description: (list or str) Service and service group names.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            session_ttl:
                aliases: ['session-ttl']
                type: raw
                description: (int or str) Session TTL in seconds for sessions accepted by this policy.
            spamfilter_profile:
                aliases: ['spamfilter-profile']
                type: str
                description: Name of an existing Spam filter profile.
            srcaddr:
                type: raw
                description: (list or str) Source address and address group names.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcintf:
                type: raw
                description: (list or str) Incoming
            ssl_mirror:
                aliases: ['ssl-mirror']
                type: str
                description: Enable to copy decrypted SSL traffic to a FortiGate interface
                choices:
                    - 'disable'
                    - 'enable'
            ssl_mirror_intf:
                aliases: ['ssl-mirror-intf']
                type: raw
                description: (list or str) SSL mirror interface name.
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: str
                description: Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Names of object-tags applied to this policy.
            tcp_mss_receiver:
                aliases: ['tcp-mss-receiver']
                type: int
                description: Receiver TCP maximum segment size
            tcp_mss_sender:
                aliases: ['tcp-mss-sender']
                type: int
                description: Sender TCP maximum segment size
            tcp_session_without_syn:
                aliases: ['tcp-session-without-syn']
                type: str
                description: Enable/disable creation of TCP session without SYN flag.
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout_send_rst:
                aliases: ['timeout-send-rst']
                type: str
                description: Enable/disable sending RST packets when TCP sessions expire.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Reverse traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: str
                description: Reverse traffic shaper.
            url_category:
                aliases: ['url-category']
                type: raw
                description: (list or str) URL category ID list.
            users:
                type: raw
                description: (list or str) Names of individual users that can authenticate with this policy.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable AV/web/ips protection profile.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            vlan_cos_fwd:
                aliases: ['vlan-cos-fwd']
                type: int
                description: VLAN forward direction user priority
            vlan_cos_rev:
                aliases: ['vlan-cos-rev']
                type: int
                description: VLAN reverse direction user priority
            voip_profile:
                aliases: ['voip-profile']
                type: str
                description: Name of an existing VoIP profile.
            vpntunnel:
                type: str
                description: Policy-based IPsec VPN
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Name of an existing Web filter profile.
            anti_replay:
                aliases: ['anti-replay']
                type: str
                description: Enable/disable anti-replay check.
                choices:
                    - 'disable'
                    - 'enable'
            app_group:
                aliases: ['app-group']
                type: raw
                description: (list or str) Application group names.
            cifs_profile:
                aliases: ['cifs-profile']
                type: str
                description: Name of an existing CIFS profile.
            dnsfilter_profile:
                aliases: ['dnsfilter-profile']
                type: str
                description: Name of an existing DNS filter profile.
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: str
                description: Name of an existing email filter profile.
            http_policy_redirect:
                aliases: ['http-policy-redirect']
                type: str
                description: Redirect HTTP
                choices:
                    - 'disable'
                    - 'enable'
            inspection_mode:
                aliases: ['inspection-mode']
                type: str
                description: Policy inspection mode
                choices:
                    - 'proxy'
                    - 'flow'
            np_acceleration:
                aliases: ['np-acceleration']
                type: str
                description: Enable/disable UTM Network Processor acceleration.
                choices:
                    - 'disable'
                    - 'enable'
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
            tos:
                type: str
                description: ToS
            tos_mask:
                aliases: ['tos-mask']
                type: str
                description: Non-zero bit positions are used for comparison while zero bit positions are ignored.
            tos_negate:
                aliases: ['tos-negate']
                type: str
                description: Enable negated TOS match.
                choices:
                    - 'disable'
                    - 'enable'
            vlan_filter:
                aliases: ['vlan-filter']
                type: str
                description: Set VLAN filters.
            waf_profile:
                aliases: ['waf-profile']
                type: str
                description: Name of an existing Web application firewall profile.
            webcache:
                type: str
                description: Enable/disable web cache.
                choices:
                    - 'disable'
                    - 'enable'
            webcache_https:
                aliases: ['webcache-https']
                type: str
                description: Enable/disable web cache for HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            webproxy_forward_server:
                aliases: ['webproxy-forward-server']
                type: str
                description: Web proxy forward server name.
            webproxy_profile:
                aliases: ['webproxy-profile']
                type: str
                description: Webproxy profile name.
            casi_profile:
                aliases: ['casi-profile']
                type: str
                description: CASI profile.
            fsso_groups:
                aliases: ['fsso-groups']
                type: raw
                description: (list or str) Names of FSSO groups.
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: str
                description: Decrypted traffic mirror.
            cgn_log_server_grp:
                aliases: ['cgn-log-server-grp']
                type: str
                description: NP log server group name
            policy_offload:
                aliases: ['policy-offload']
                type: str
                description: Enable/disable offloading policy configuration to CP processors.
                choices:
                    - 'disable'
                    - 'enable'
            _policy_block:
                type: int
                description: Assigned policy block.
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
    - name: Configure IPv6 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_policy6:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_policy6:
          action: accept # <value in [deny, accept, ipsec, ...]>
          comments: ansible-comment
          dstaddr: all
          dstintf: any
          name: ansible-test-policy6
          nat: disable
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
    - name: Retrieve all the IPv6 policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_policy6"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            policy6: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_policy6': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'action': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['deny', 'accept', 'ipsec', 'ssl-vpn'], 'type': 'str'},
                'app-category': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'application': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'application-list': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'auto-asic-offload': {
                    'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'av-profile': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'comments': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'custom-log-fields': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'devices': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                'diffserv-forward': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'diffservcode-rev': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'dscp-match': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-negate': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-value': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'dsri': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'dstaddr-negate': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstintf': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'firewall-session-dirty': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['check-all', 'check-new'], 'type': 'str'},
                'fixedport': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'global-label': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'groups': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'icap-profile': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'inbound': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ippool': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'label': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'name': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'nat': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'natinbound': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'natoutbound': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'np-accelation': {'v_range': [['6.0.0', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outbound': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'per-ip-shaper': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'policyid': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'int'},
                'poolname': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'profile-group': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'profile-protocol-options': {'v_range': [['6.0.0', '7.2.1'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'profile-type': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['single', 'group'], 'type': 'str'},
                'replacemsg-override-group': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'rsso': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'schedule': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'send-deny-packet': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'service-negate': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-ttl': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'spamfilter-profile': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'srcaddr': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'srcaddr-negate': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcintf': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'ssl-mirror': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-mirror-intf': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'ssl-ssh-profile': {'v_range': [['6.0.0', '7.2.1'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'tcp-mss-receiver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'tcp-mss-sender': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'tcp-session-without-syn': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['all', 'data-only', 'disable'], 'type': 'str'},
                'timeout-send-rst': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'traffic-shaper-reverse': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'url-category': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'users': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'utm-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'vlan-cos-fwd': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'vlan-cos-rev': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'voip-profile': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'vpntunnel': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'anti-replay': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'app-group': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                'cifs-profile': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                'dnsfilter-profile': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                'emailfilter-profile': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                'http-policy-redirect': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'inspection-mode': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'np-acceleration': {
                    'v_range': [['6.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'ssh-filter-profile': {'v_range': [['6.2.0', '7.2.1'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'ssh-policy-redirect': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                'tos-mask': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                'tos-negate': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-filter': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                'waf-profile': {'v_range': [['6.2.1', '7.6.2']], 'type': 'str'},
                'webcache': {'v_range': [['6.2.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache-https': {
                    'v_range': [['6.2.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'webproxy-forward-server': {'v_range': [['6.2.1', '7.6.2']], 'type': 'str'},
                'webproxy-profile': {'v_range': [['6.2.1', '7.6.2']], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'fsso-groups': {'v_range': [['6.2.3', '7.6.2']], 'type': 'raw'},
                'decrypted-traffic-mirror': {'v_range': [['6.4.0', '6.4.0']], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '7.6.2']], 'type': 'str'},
                'policy-offload': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_policy_block': {'v_range': [['7.0.3', '7.6.2']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_policy6'),
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
