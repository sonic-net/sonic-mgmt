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
module: fmgr_dnsfilter_profile
short_description: Configure DNS domain filter profiles.
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
    dnsfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            block_action:
                aliases: ['block-action']
                type: str
                description: Action to take for blocked domains.
                choices:
                    - 'block'
                    - 'redirect'
                    - 'block-sevrfail'
            block_botnet:
                aliases: ['block-botnet']
                type: str
                description: Enable/disable blocking botnet C&C DNS lookups.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            external_ip_blocklist:
                aliases: ['external-ip-blocklist']
                type: raw
                description: (list or str) One or more external IP block lists.
            log_all_domain:
                aliases: ['log-all-domain']
                type: str
                description: Enable/disable logging of all domains visited
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Profile name.
                required: true
            redirect_portal:
                aliases: ['redirect-portal']
                type: str
                description: IP address of the SDNS redirect portal.
            safe_search:
                aliases: ['safe-search']
                type: str
                description: Enable/disable Google, Bing, and YouTube safe search.
                choices:
                    - 'disable'
                    - 'enable'
            sdns_domain_log:
                aliases: ['sdns-domain-log']
                type: str
                description: Enable/disable domain filtering and botnet domain logging.
                choices:
                    - 'disable'
                    - 'enable'
            sdns_ftgd_err_log:
                aliases: ['sdns-ftgd-err-log']
                type: str
                description: Enable/disable FortiGuard SDNS rating error logging.
                choices:
                    - 'disable'
                    - 'enable'
            youtube_restrict:
                aliases: ['youtube-restrict']
                type: str
                description: Set safe search for YouTube restriction level.
                choices:
                    - 'strict'
                    - 'moderate'
                    - 'none'
            dns_translation:
                aliases: ['dns-translation']
                type: list
                elements: dict
                description: Dns translation.
                suboptions:
                    dst:
                        type: str
                        description: IPv4 address or subnet on the external network to substitute for the resolved address in DNS query replies.
                    id:
                        type: int
                        description: ID.
                    netmask:
                        type: str
                        description: If src and dst are subnets rather than single IP addresses, enter the netmask for both src and dst.
                    src:
                        type: str
                        description: IPv4 address or subnet on the internal network to compare with the resolved address in DNS query replies.
                    status:
                        type: str
                        description: Enable/disable this DNS translation entry.
                        choices:
                            - 'disable'
                            - 'enable'
                    addr_type:
                        aliases: ['addr-type']
                        type: str
                        description: DNS translation type
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    dst6:
                        type: str
                        description: IPv6 address or subnet on the external network to substitute for the resolved address in DNS query replies.
                    prefix:
                        type: int
                        description: If src6 and dst6 are subnets rather than single IP addresses, enter the prefix for both src6 and dst6
                    src6:
                        type: str
                        description: IPv6 address or subnet on the internal network to compare with the resolved address in DNS query replies.
            redirect_portal6:
                aliases: ['redirect-portal6']
                type: str
                description: IPv6 address of the SDNS redirect portal.
            log_all_url:
                aliases: ['log-all-url']
                type: str
                description: Enable/disable log all URLs visited.
                choices:
                    - 'disable'
                    - 'enable'
            sdns_url_log:
                aliases: ['sdns-url-log']
                type: str
                description: Enable/disable logging of URL filtering and botnet domains.
                choices:
                    - 'disable'
                    - 'enable'
            domain_filter:
                aliases: ['domain-filter']
                type: dict
                description: Domain filter.
                suboptions:
                    domain_filter_table:
                        aliases: ['domain-filter-table']
                        type: int
                        description: DNS domain filter table ID.
            ftgd_dns:
                aliases: ['ftgd-dns']
                type: dict
                description: Ftgd dns.
                suboptions:
                    filters:
                        type: list
                        elements: dict
                        description: Filters.
                        suboptions:
                            action:
                                type: str
                                description: Action to take for DNS requests matching the category.
                                choices:
                                    - 'monitor'
                                    - 'block'
                            category:
                                type: str
                                description: Category number.
                            id:
                                type: int
                                description: ID number.
                            log:
                                type: str
                                description: Enable/disable DNS filter logging for this DNS profile.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    options:
                        type: list
                        elements: str
                        description: FortiGuard DNS filter options.
                        choices:
                            - 'error-allow'
                            - 'ftgd-disable'
            urlfilter:
                type: dict
                description: Urlfilter.
                suboptions:
                    urlfilter_table:
                        aliases: ['urlfilter-table']
                        type: int
                        description: DNS URL filter table ID.
            transparent_dns_database:
                aliases: ['transparent-dns-database']
                type: raw
                description: (list) Transparent DNS database zones.
            strip_ech:
                aliases: ['strip-ech']
                type: str
                description: Enable/disable removal of the encrypted client hello service parameter from supporting DNS RRs.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure DNS domain filter profiles.
      fortinet.fortimanager.fmgr_dnsfilter_profile:
        bypass_validation: false
        adom: ansible
        state: present
        dnsfilter_profile:
          block_action: redirect
          block_botnet: disable
          comment: "ansible-test-comment"
          log_all_domain: disable
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the profiles
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dnsfilter_profile"
          params:
            adom: "ansible"
            profile: "your_value"
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
        '/pm/config/adom/{adom}/obj/dnsfilter/profile',
        '/pm/config/global/obj/dnsfilter/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dnsfilter_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'block-action': {'choices': ['block', 'redirect', 'block-sevrfail'], 'type': 'str'},
                'block-botnet': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'type': 'str'},
                'external-ip-blocklist': {'type': 'raw'},
                'log-all-domain': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'redirect-portal': {'type': 'str'},
                'safe-search': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sdns-domain-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sdns-ftgd-err-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'youtube-restrict': {'choices': ['strict', 'moderate', 'none'], 'type': 'str'},
                'dns-translation': {
                    'v_range': [['6.2.0', '']],
                    'type': 'list',
                    'options': {
                        'dst': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'id': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'netmask': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'src': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'addr-type': {'v_range': [['6.2.2', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'dst6': {'v_range': [['6.2.2', '']], 'type': 'str'},
                        'prefix': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'src6': {'v_range': [['6.2.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'redirect-portal6': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'log-all-url': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sdns-url-log': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'domain-filter': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {'domain-filter-table': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}}
                },
                'ftgd-dns': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'filters': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['monitor', 'block'], 'type': 'str'},
                                'category': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['error-allow', 'ftgd-disable'],
                            'elements': 'str'
                        }
                    }
                },
                'urlfilter': {
                    'v_range': [['6.2.8', '6.2.13']],
                    'type': 'dict',
                    'options': {'urlfilter-table': {'v_range': [['6.2.8', '6.2.13']], 'type': 'int'}}
                },
                'transparent-dns-database': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'strip-ech': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dnsfilter_profile'),
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
