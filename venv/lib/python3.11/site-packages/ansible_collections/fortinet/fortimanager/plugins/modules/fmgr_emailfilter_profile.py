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
module: fmgr_emailfilter_profile
short_description: Configure Email Filter profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    emailfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            external:
                type: str
                description: Enable/disable external Email inspection.
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
                    - 'bannedword'
                    - 'spambwl'
                    - 'spamfsip'
                    - 'spamfssubmit'
                    - 'spamfschksum'
                    - 'spamfsurl'
                    - 'spamhelodns'
                    - 'spamraddrdns'
                    - 'spamrbl'
                    - 'spamhdrcheck'
                    - 'spamfsphish'
                    - 'spambal'
                    - 'spamfgip'
                    - 'spamfgsubmit'
                    - 'spamfgchksum'
                    - 'spamfgurl'
                    - 'spamfgphish'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group.
            spam_bwl_table:
                aliases: ['spam-bwl-table']
                type: str
                description: Anti-spam black/white list table ID.
            spam_bword_table:
                aliases: ['spam-bword-table']
                type: str
                description: Anti-spam banned word table ID.
            spam_bword_threshold:
                aliases: ['spam-bword-threshold']
                type: int
                description: Spam banned word threshold.
            spam_filtering:
                aliases: ['spam-filtering']
                type: str
                description: Enable/disable spam filtering.
                choices:
                    - 'disable'
                    - 'enable'
            spam_iptrust_table:
                aliases: ['spam-iptrust-table']
                type: str
                description: Anti-spam IP trust table ID.
            spam_log:
                aliases: ['spam-log']
                type: str
                description: Enable/disable spam logging for email filtering.
                choices:
                    - 'disable'
                    - 'enable'
            spam_log_fortiguard_response:
                aliases: ['spam-log-fortiguard-response']
                type: str
                description: Enable/disable logging FortiGuard spam response.
                choices:
                    - 'disable'
                    - 'enable'
            spam_mheader_table:
                aliases: ['spam-mheader-table']
                type: str
                description: Anti-spam MIME header table ID.
            spam_rbl_table:
                aliases: ['spam-rbl-table']
                type: str
                description: Anti-spam DNSBL table ID.
            feature_set:
                aliases: ['feature-set']
                type: str
                description: Flow/proxy feature set.
                choices:
                    - 'proxy'
                    - 'flow'
            gmail:
                type: dict
                description: Gmail.
                suboptions:
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
            imap:
                type: dict
                description: Imap.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices:
                            - 'pass'
                            - 'tag'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        aliases: ['tag-msg']
                        type: str
                        description: Subject text or header added to spam email.
                    tag_type:
                        aliases: ['tag-type']
                        type: list
                        elements: str
                        description: Tag subject or header for spam email.
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            mapi:
                type: dict
                description: Mapi.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices:
                            - 'pass'
                            - 'discard'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
            msn_hotmail:
                aliases: ['msn-hotmail']
                type: dict
                description: Msn hotmail.
                suboptions:
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
            other_webmails:
                aliases: ['other-webmails']
                type: dict
                description: Other webmails.
                suboptions:
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
            pop3:
                type: dict
                description: Pop3.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices:
                            - 'pass'
                            - 'tag'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        aliases: ['tag-msg']
                        type: str
                        description: Subject text or header added to spam email.
                    tag_type:
                        aliases: ['tag-type']
                        type: list
                        elements: str
                        description: Tag subject or header for spam email.
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            smtp:
                type: dict
                description: Smtp.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices:
                            - 'pass'
                            - 'tag'
                            - 'discard'
                    hdrip:
                        type: str
                        description: Enable/disable SMTP email header IP checks for spamfsip, spamrbl and spambwl filters.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable/disable local filter to override SMTP remote check result.
                        choices:
                            - 'disable'
                            - 'enable'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_all:
                        aliases: ['log-all']
                        type: str
                        description: Enable/disable logging of all email traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        aliases: ['tag-msg']
                        type: str
                        description: Subject text or header added to spam email.
                    tag_type:
                        aliases: ['tag-type']
                        type: list
                        elements: str
                        description: Tag subject or header for spam email.
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
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
                                    - 'smtp'
                                    - 'imap'
                                    - 'pop3'
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
            spam_bal_table:
                aliases: ['spam-bal-table']
                type: str
                description: Anti-spam block/allow list table ID.
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
    - name: Configure Email Filter profiles.
      fortinet.fortimanager.fmgr_emailfilter_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        emailfilter_profile:
          name: "your value" # Required variable, string
          # comment: <string>
          # external: <value in [disable, enable]>
          # options:
          #   - "bannedword"
          #   - "spambwl"
          #   - "spamfsip"
          #   - "spamfssubmit"
          #   - "spamfschksum"
          #   - "spamfsurl"
          #   - "spamhelodns"
          #   - "spamraddrdns"
          #   - "spamrbl"
          #   - "spamhdrcheck"
          #   - "spamfsphish"
          #   - "spambal"
          #   - "spamfgip"
          #   - "spamfgsubmit"
          #   - "spamfgchksum"
          #   - "spamfgurl"
          #   - "spamfgphish"
          # replacemsg_group: <string>
          # spam_bwl_table: <string>
          # spam_bword_table: <string>
          # spam_bword_threshold: <integer>
          # spam_filtering: <value in [disable, enable]>
          # spam_iptrust_table: <string>
          # spam_log: <value in [disable, enable]>
          # spam_log_fortiguard_response: <value in [disable, enable]>
          # spam_mheader_table: <string>
          # spam_rbl_table: <string>
          # feature_set: <value in [proxy, flow]>
          # gmail:
          #   log: <value in [disable, enable]>
          #   log_all: <value in [disable, enable]>
          # imap:
          #   action: <value in [pass, tag]>
          #   log: <value in [disable, enable]>
          #   log_all: <value in [disable, enable]>
          #   tag_msg: <string>
          #   tag_type:
          #     - "subject"
          #     - "header"
          #     - "spaminfo"
          # mapi:
          #   action: <value in [pass, discard]>
          #   log: <value in [disable, enable]>
          #   log_all: <value in [disable, enable]>
          # msn_hotmail:
          #   log: <value in [disable, enable]>
          #   log_all: <value in [disable, enable]>
          # other_webmails:
          #   log_all: <value in [disable, enable]>
          # pop3:
          #   action: <value in [pass, tag]>
          #   log: <value in [disable, enable]>
          #   log_all: <value in [disable, enable]>
          #   tag_msg: <string>
          #   tag_type:
          #     - "subject"
          #     - "header"
          #     - "spaminfo"
          # smtp:
          #   action: <value in [pass, tag, discard]>
          #   hdrip: <value in [disable, enable]>
          #   local_override: <value in [disable, enable]>
          #   log: <value in [disable, enable]>
          #   log_all: <value in [disable, enable]>
          #   tag_msg: <string>
          #   tag_type:
          #     - "subject"
          #     - "header"
          #     - "spaminfo"
          # file_filter:
          #   entries:
          #     - action: <value in [log, block]>
          #       comment: <string>
          #       encryption: <value in [any, yes]>
          #       file_type: <list or string>
          #       filter: <string>
          #       password_protected: <value in [any, yes]>
          #       protocol:
          #         - "smtp"
          #         - "imap"
          #         - "pop3"
          #   log: <value in [disable, enable]>
          #   scan_archive_contents: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
          # spam_bal_table: <string>
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
        '/pm/config/adom/{adom}/obj/emailfilter/profile',
        '/pm/config/global/obj/emailfilter/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'emailfilter_profile': {
            'type': 'dict',
            'v_range': [['6.2.0', '']],
            'options': {
                'comment': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'external': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.2.0', '']], 'required': True, 'type': 'str'},
                'options': {
                    'v_range': [['6.2.0', '']],
                    'type': 'list',
                    'choices': [
                        'bannedword', 'spambwl', 'spamfsip', 'spamfssubmit', 'spamfschksum', 'spamfsurl', 'spamhelodns', 'spamraddrdns', 'spamrbl',
                        'spamhdrcheck', 'spamfsphish', 'spambal', 'spamfgip', 'spamfgsubmit', 'spamfgchksum', 'spamfgurl', 'spamfgphish'
                    ],
                    'elements': 'str'
                },
                'replacemsg-group': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'spam-bwl-table': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'spam-bword-table': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'spam-bword-threshold': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'spam-filtering': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spam-iptrust-table': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'spam-log': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spam-log-fortiguard-response': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spam-mheader-table': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'spam-rbl-table': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'feature-set': {'v_range': [['6.4.0', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'gmail': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'imap': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['pass', 'tag'], 'type': 'str'},
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag-msg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'tag-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['subject', 'header', 'spaminfo'],
                            'elements': 'str'
                        }
                    }
                },
                'mapi': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['pass', 'discard'], 'type': 'str'},
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'msn-hotmail': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'other-webmails': {
                    'v_range': [['6.4.5', '']],
                    'type': 'dict',
                    'options': {'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}}
                },
                'pop3': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['pass', 'tag'], 'type': 'str'},
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag-msg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'tag-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['subject', 'header', 'spaminfo'],
                            'elements': 'str'
                        }
                    }
                },
                'smtp': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['pass', 'tag', 'discard'], 'type': 'str'},
                        'hdrip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-all': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag-msg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'tag-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['subject', 'header', 'spaminfo'],
                            'elements': 'str'
                        }
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
                                'encryption': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'choices': ['any', 'yes'], 'type': 'str'},
                                'file-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'raw'},
                                'filter': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'str'},
                                'password-protected': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['any', 'yes'], 'type': 'str'},
                                'protocol': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                                    'type': 'list',
                                    'choices': ['smtp', 'imap', 'pop3'],
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
                'spam-bal-table': {'v_range': [['7.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'emailfilter_profile'),
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
