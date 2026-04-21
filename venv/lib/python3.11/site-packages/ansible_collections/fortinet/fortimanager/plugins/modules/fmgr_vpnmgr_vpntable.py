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
module: fmgr_vpnmgr_vpntable
short_description: Vpnmgr vpntable
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
    vpnmgr_vpntable:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authmethod:
                type: str
                description: Authmethod.
                choices:
                    - 'psk'
                    - 'rsa-signature'
                    - 'signature'
            auto_zone_policy:
                aliases: ['auto-zone-policy']
                type: str
                description: Auto zone policy.
                choices:
                    - 'disable'
                    - 'enable'
            certificate:
                type: raw
                description: (list or str) Certificate.
            description:
                type: str
                description: Description.
            dpd:
                type: str
                description: Dpd.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'on-idle'
                    - 'on-demand'
            dpd_retrycount:
                aliases: ['dpd-retrycount']
                type: int
                description: Dpd retrycount.
            dpd_retryinterval:
                aliases: ['dpd-retryinterval']
                type: raw
                description: (list) Dpd retryinterval.
            fcc_enforcement:
                aliases: ['fcc-enforcement']
                type: str
                description: Fcc enforcement.
                choices:
                    - 'disable'
                    - 'enable'
            hub2spoke_zone:
                aliases: ['hub2spoke-zone']
                type: raw
                description: (list or str) Hub2spoke zone.
            ike_version:
                aliases: ['ike-version']
                type: str
                description: Ike version.
                choices:
                    - '1'
                    - '2'
            ike1dhgroup:
                type: list
                elements: str
                description: Ike1dhgroup.
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
            ike1dpd:
                type: str
                description: Ike1dpd.
                choices:
                    - 'disable'
                    - 'enable'
            ike1keylifesec:
                type: int
                description: Ike1keylifesec.
            ike1localid:
                type: str
                description: Ike1localid.
            ike1mode:
                type: str
                description: Ike1mode.
                choices:
                    - 'main'
                    - 'aggressive'
            ike1natkeepalive:
                type: int
                description: Ike1natkeepalive.
            ike1nattraversal:
                type: str
                description: Ike1nattraversal.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'forced'
            ike1proposal:
                type: str
                description: Ike1proposal.
                choices:
                    - 'des-md5'
                    - 'des-sha1'
                    - '3des-md5'
                    - '3des-sha1'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'des-sha256'
                    - '3des-sha256'
                    - 'aes128-sha256'
                    - 'aes192-sha256'
                    - 'aes256-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
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
                    - 'aes128gcm-prfsha1'
                    - 'aes128gcm-prfsha256'
                    - 'aes128gcm-prfsha384'
                    - 'aes128gcm-prfsha512'
                    - 'aes256gcm-prfsha1'
                    - 'aes256gcm-prfsha256'
                    - 'aes256gcm-prfsha384'
                    - 'aes256gcm-prfsha512'
                    - 'chacha20poly1305-prfsha1'
                    - 'chacha20poly1305-prfsha256'
                    - 'chacha20poly1305-prfsha384'
                    - 'chacha20poly1305-prfsha512'
            ike2autonego:
                type: str
                description: Ike2autonego.
                choices:
                    - 'disable'
                    - 'enable'
            ike2dhgroup:
                type: list
                elements: str
                description: Ike2dhgroup.
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
            ike2keepalive:
                type: str
                description: Ike2keepalive.
                choices:
                    - 'disable'
                    - 'enable'
            ike2keylifekbs:
                type: int
                description: Ike2keylifekbs.
            ike2keylifesec:
                type: int
                description: Ike2keylifesec.
            ike2keylifetype:
                type: str
                description: Ike2keylifetype.
                choices:
                    - 'seconds'
                    - 'kbs'
                    - 'both'
            ike2proposal:
                type: str
                description: Ike2proposal.
                choices:
                    - 'null-md5'
                    - 'null-sha1'
                    - 'des-null'
                    - '3des-null'
                    - 'des-md5'
                    - 'des-sha1'
                    - '3des-md5'
                    - '3des-sha1'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'aes128-null'
                    - 'aes192-null'
                    - 'aes256-null'
                    - 'null-sha256'
                    - 'des-sha256'
                    - '3des-sha256'
                    - 'aes128-sha256'
                    - 'aes192-sha256'
                    - 'aes256-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'null-sha384'
                    - 'null-sha512'
                    - 'aria128-null'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-null'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-null'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-null'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
                    - 'aes128gcm'
                    - 'aes256gcm'
                    - 'chacha20poly1305'
            inter_vdom:
                aliases: ['inter-vdom']
                type: str
                description: Inter vdom.
                choices:
                    - 'disable'
                    - 'enable'
            intf_mode:
                aliases: ['intf-mode']
                type: str
                description: Intf mode.
                choices:
                    - 'off'
                    - 'on'
            localid_type:
                aliases: ['localid-type']
                type: str
                description: Localid type.
                choices:
                    - 'auto'
                    - 'fqdn'
                    - 'user-fqdn'
                    - 'keyid'
                    - 'address'
                    - 'asn1dn'
            name:
                type: str
                description: Name.
                required: true
            negotiate_timeout:
                aliases: ['negotiate-timeout']
                type: int
                description: Negotiate timeout.
            npu_offload:
                aliases: ['npu-offload']
                type: str
                description: Npu offload.
                choices:
                    - 'disable'
                    - 'enable'
            pfs:
                type: str
                description: Pfs.
                choices:
                    - 'disable'
                    - 'enable'
            psk_auto_generate:
                aliases: ['psk-auto-generate']
                type: str
                description: Psk auto generate.
                choices:
                    - 'disable'
                    - 'enable'
            psksecret:
                type: raw
                description: (list) Psksecret.
            replay:
                type: str
                description: Replay.
                choices:
                    - 'disable'
                    - 'enable'
            rsa_certificate:
                aliases: ['rsa-certificate']
                type: str
                description: Rsa certificate.
            spoke2hub_zone:
                aliases: ['spoke2hub-zone']
                type: raw
                description: (list or str) Spoke2hub zone.
            topology:
                type: str
                description: Topology.
                choices:
                    - 'meshed'
                    - 'star'
                    - 'dialup'
            vpn_zone:
                aliases: ['vpn-zone']
                type: raw
                description: (list or str) Vpn zone.
            network_id:
                aliases: ['network-id']
                type: int
                description: Network id.
            network_overlay:
                aliases: ['network-overlay']
                type: str
                description: Network overlay.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Vpnmgr vpntable
      fortinet.fortimanager.fmgr_vpnmgr_vpntable:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        vpnmgr_vpntable:
          name: "your value" # Required variable, string
          # authmethod: <value in [psk, rsa-signature, signature]>
          # auto_zone_policy: <value in [disable, enable]>
          # certificate: <list or string>
          # description: <string>
          # dpd: <value in [disable, enable, on-idle, ...]>
          # dpd_retrycount: <integer>
          # dpd_retryinterval: <list or integer>
          # fcc_enforcement: <value in [disable, enable]>
          # hub2spoke_zone: <list or string>
          # ike_version: <value in [1, 2]>
          # ike1dhgroup:
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
          #   - "32"
          # ike1dpd: <value in [disable, enable]>
          # ike1keylifesec: <integer>
          # ike1localid: <string>
          # ike1mode: <value in [main, aggressive]>
          # ike1natkeepalive: <integer>
          # ike1nattraversal: <value in [disable, enable, forced]>
          # ike1proposal: <value in [des-md5, des-sha1, 3des-md5, ...]>
          # ike2autonego: <value in [disable, enable]>
          # ike2dhgroup:
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
          #   - "32"
          # ike2keepalive: <value in [disable, enable]>
          # ike2keylifekbs: <integer>
          # ike2keylifesec: <integer>
          # ike2keylifetype: <value in [seconds, kbs, both]>
          # ike2proposal: <value in [null-md5, null-sha1, des-null, ...]>
          # inter_vdom: <value in [disable, enable]>
          # intf_mode: <value in [off, on]>
          # localid_type: <value in [auto, fqdn, user-fqdn, ...]>
          # negotiate_timeout: <integer>
          # npu_offload: <value in [disable, enable]>
          # pfs: <value in [disable, enable]>
          # psk_auto_generate: <value in [disable, enable]>
          # psksecret: <list or string>
          # replay: <value in [disable, enable]>
          # rsa_certificate: <string>
          # spoke2hub_zone: <list or string>
          # topology: <value in [meshed, star, dialup]>
          # vpn_zone: <list or string>
          # network_id: <integer>
          # network_overlay: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/vpnmgr/vpntable',
        '/pm/config/global/obj/vpnmgr/vpntable'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpnmgr_vpntable': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'authmethod': {'choices': ['psk', 'rsa-signature', 'signature'], 'type': 'str'},
                'auto-zone-policy': {'choices': ['disable', 'enable'], 'type': 'str'},
                'certificate': {'type': 'raw'},
                'description': {'type': 'str'},
                'dpd': {'choices': ['disable', 'enable', 'on-idle', 'on-demand'], 'type': 'str'},
                'dpd-retrycount': {'type': 'int'},
                'dpd-retryinterval': {'type': 'raw'},
                'fcc-enforcement': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hub2spoke-zone': {'type': 'raw'},
                'ike-version': {'choices': ['1', '2'], 'type': 'str'},
                'ike1dhgroup': {
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31', '32'],
                    'elements': 'str'
                },
                'ike1dpd': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ike1keylifesec': {'no_log': True, 'type': 'int'},
                'ike1localid': {'v_range': [['6.0.0', '7.4.6'], ['7.6.0', '']], 'type': 'str'},
                'ike1mode': {'choices': ['main', 'aggressive'], 'type': 'str'},
                'ike1natkeepalive': {'type': 'int'},
                'ike1nattraversal': {'choices': ['disable', 'enable', 'forced'], 'type': 'str'},
                'ike1proposal': {
                    'choices': [
                        'des-md5', 'des-sha1', '3des-md5', '3des-sha1', 'aes128-md5', 'aes128-sha1', 'aes192-md5', 'aes192-sha1', 'aes256-md5',
                        'aes256-sha1', 'des-sha256', '3des-sha256', 'aes128-sha256', 'aes192-sha256', 'aes256-sha256', 'des-sha384', 'des-sha512',
                        '3des-sha384', '3des-sha512', 'aes128-sha384', 'aes128-sha512', 'aes192-sha384', 'aes192-sha512', 'aes256-sha384',
                        'aes256-sha512', 'aria128-md5', 'aria128-sha1', 'aria128-sha256', 'aria128-sha384', 'aria128-sha512', 'aria192-md5',
                        'aria192-sha1', 'aria192-sha256', 'aria192-sha384', 'aria192-sha512', 'aria256-md5', 'aria256-sha1', 'aria256-sha256',
                        'aria256-sha384', 'aria256-sha512', 'seed-md5', 'seed-sha1', 'seed-sha256', 'seed-sha384', 'seed-sha512', 'aes128gcm-prfsha1',
                        'aes128gcm-prfsha256', 'aes128gcm-prfsha384', 'aes128gcm-prfsha512', 'aes256gcm-prfsha1', 'aes256gcm-prfsha256',
                        'aes256gcm-prfsha384', 'aes256gcm-prfsha512', 'chacha20poly1305-prfsha1', 'chacha20poly1305-prfsha256',
                        'chacha20poly1305-prfsha384', 'chacha20poly1305-prfsha512'
                    ],
                    'type': 'str'
                },
                'ike2autonego': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ike2dhgroup': {
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31', '32'],
                    'elements': 'str'
                },
                'ike2keepalive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ike2keylifekbs': {'no_log': True, 'type': 'int'},
                'ike2keylifesec': {'no_log': True, 'type': 'int'},
                'ike2keylifetype': {'choices': ['seconds', 'kbs', 'both'], 'type': 'str'},
                'ike2proposal': {
                    'choices': [
                        'null-md5', 'null-sha1', 'des-null', '3des-null', 'des-md5', 'des-sha1', '3des-md5', '3des-sha1', 'aes128-md5', 'aes128-sha1',
                        'aes192-md5', 'aes192-sha1', 'aes256-md5', 'aes256-sha1', 'aes128-null', 'aes192-null', 'aes256-null', 'null-sha256',
                        'des-sha256', '3des-sha256', 'aes128-sha256', 'aes192-sha256', 'aes256-sha256', 'des-sha384', 'des-sha512', '3des-sha384',
                        '3des-sha512', 'aes128-sha384', 'aes128-sha512', 'aes192-sha384', 'aes192-sha512', 'aes256-sha384', 'aes256-sha512',
                        'null-sha384', 'null-sha512', 'aria128-null', 'aria128-md5', 'aria128-sha1', 'aria128-sha256', 'aria128-sha384',
                        'aria128-sha512', 'aria192-null', 'aria192-md5', 'aria192-sha1', 'aria192-sha256', 'aria192-sha384', 'aria192-sha512',
                        'aria256-null', 'aria256-md5', 'aria256-sha1', 'aria256-sha256', 'aria256-sha384', 'aria256-sha512', 'seed-null', 'seed-md5',
                        'seed-sha1', 'seed-sha256', 'seed-sha384', 'seed-sha512', 'aes128gcm', 'aes256gcm', 'chacha20poly1305'
                    ],
                    'type': 'str'
                },
                'inter-vdom': {'choices': ['disable', 'enable'], 'type': 'str'},
                'intf-mode': {'choices': ['off', 'on'], 'type': 'str'},
                'localid-type': {'choices': ['auto', 'fqdn', 'user-fqdn', 'keyid', 'address', 'asn1dn'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'negotiate-timeout': {'type': 'int'},
                'npu-offload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pfs': {'choices': ['disable', 'enable'], 'type': 'str'},
                'psk-auto-generate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'psksecret': {'no_log': True, 'type': 'raw'},
                'replay': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rsa-certificate': {'type': 'str'},
                'spoke2hub-zone': {'type': 'raw'},
                'topology': {'choices': ['meshed', 'star', 'dialup'], 'type': 'str'},
                'vpn-zone': {'type': 'raw'},
                'network-id': {'v_range': [['6.2.5', '']], 'type': 'int'},
                'network-overlay': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnmgr_vpntable'),
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
