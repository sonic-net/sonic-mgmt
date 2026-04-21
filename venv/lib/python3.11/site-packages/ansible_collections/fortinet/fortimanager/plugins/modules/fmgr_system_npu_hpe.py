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
module: fmgr_system_npu_hpe
short_description: Host protection engine configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    system_npu_hpe:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            all_protocol:
                aliases: ['all-protocol']
                type: int
                description: Maximum packet rate of each host queue except high priority traffic
            arp_max:
                aliases: ['arp-max']
                type: int
                description: Maximum ARP packet rate
            enable_shaper:
                aliases: ['enable-shaper']
                type: str
                description: Enable/Disable NPU Host Protection Engine
                choices:
                    - 'disable'
                    - 'enable'
            esp_max:
                aliases: ['esp-max']
                type: int
                description: Maximum ESP packet rate
            high_priority:
                aliases: ['high-priority']
                type: int
                description: Maximum packet rate for high priority traffic packets
            icmp_max:
                aliases: ['icmp-max']
                type: int
                description: Maximum ICMP packet rate
            ip_frag_max:
                aliases: ['ip-frag-max']
                type: int
                description: Maximum fragmented IP packet rate
            ip_others_max:
                aliases: ['ip-others-max']
                type: int
                description: Maximum IP packet rate for other packets
            l2_others_max:
                aliases: ['l2-others-max']
                type: int
                description: Maximum L2 packet rate for L2 packets that are not ARP packets
            pri_type_max:
                aliases: ['pri-type-max']
                type: int
                description: Maximum overflow rate of priority type traffic
            sctp_max:
                aliases: ['sctp-max']
                type: int
                description: Maximum SCTP packet rate
            tcp_max:
                aliases: ['tcp-max']
                type: int
                description: Maximum TCP packet rate
            tcpfin_rst_max:
                aliases: ['tcpfin-rst-max']
                type: int
                description: Maximum TCP carries FIN or RST flags packet rate
            tcpsyn_ack_max:
                aliases: ['tcpsyn-ack-max']
                type: int
                description: Maximum TCP carries SYN and ACK flags packet rate
            tcpsyn_max:
                aliases: ['tcpsyn-max']
                type: int
                description: Maximum TCP SYN packet rate
            udp_max:
                aliases: ['udp-max']
                type: int
                description: Maximum UDP packet rate
            enable_queue_shaper:
                aliases: ['enable-queue-shaper']
                type: str
                description: Enable/Disable NPU host protection engine
                choices:
                    - 'disable'
                    - 'enable'
            exception_code:
                aliases: ['exception-code']
                type: int
                description: Maximum exception code rate of traffic
            fragment_with_sess:
                aliases: ['fragment-with-sess']
                type: int
                description: Maximum fragment with session rate of traffic
            fragment_without_session:
                aliases: ['fragment-without-session']
                type: int
                description: Maximum fragment without session rate of traffic
            queue_shaper_max:
                aliases: ['queue-shaper-max']
                type: int
                description: Maximum per queue byte rate of traffic
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
    - name: Host protection engine configuration.
      fortinet.fortimanager.fmgr_system_npu_hpe:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        system_npu_hpe:
          # all_protocol: <integer>
          # arp_max: <integer>
          # enable_shaper: <value in [disable, enable]>
          # esp_max: <integer>
          # high_priority: <integer>
          # icmp_max: <integer>
          # ip_frag_max: <integer>
          # ip_others_max: <integer>
          # l2_others_max: <integer>
          # pri_type_max: <integer>
          # sctp_max: <integer>
          # tcp_max: <integer>
          # tcpfin_rst_max: <integer>
          # tcpsyn_ack_max: <integer>
          # tcpsyn_max: <integer>
          # udp_max: <integer>
          # enable_queue_shaper: <value in [disable, enable]>
          # exception_code: <integer>
          # fragment_with_sess: <integer>
          # fragment_without_session: <integer>
          # queue_shaper_max: <integer>
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
        '/pm/config/adom/{adom}/obj/system/npu/hpe',
        '/pm/config/global/obj/system/npu/hpe'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_hpe': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'all-protocol': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'arp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'enable-shaper': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'esp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'high-priority': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'icmp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'ip-frag-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'ip-others-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'l2-others-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'pri-type-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'sctp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'tcp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'tcpfin-rst-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'tcpsyn-ack-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'tcpsyn-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'udp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'enable-queue-shaper': {
                    'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'exception-code': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                'fragment-with-sess': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                'fragment-without-session': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                'queue-shaper-max': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_hpe'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
