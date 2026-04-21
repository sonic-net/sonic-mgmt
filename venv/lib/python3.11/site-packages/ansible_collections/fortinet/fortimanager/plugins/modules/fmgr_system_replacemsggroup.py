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
module: fmgr_system_replacemsggroup
short_description: Configure replacement message groups.
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
    system_replacemsggroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admin:
                type: list
                elements: dict
                description: Admin.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            alertmail:
                type: list
                elements: dict
                description: Alertmail.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
                    id:
                        type: int
                        description: Id.
            auth:
                type: list
                elements: dict
                description: Auth.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            comment:
                type: str
                description: Comment.
            custom_message:
                aliases: ['custom-message']
                type: list
                elements: dict
                description: Custom message.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            device_detection_portal:
                aliases: ['device-detection-portal']
                type: list
                elements: dict
                description: Device detection portal.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            ec:
                type: list
                elements: dict
                description: Ec.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            fortiguard_wf:
                aliases: ['fortiguard-wf']
                type: list
                elements: dict
                description: Fortiguard wf.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            ftp:
                type: list
                elements: dict
                description: Ftp.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            group_type:
                aliases: ['group-type']
                type: str
                description: Group type.
                choices:
                    - 'default'
                    - 'utm'
                    - 'auth'
                    - 'ec'
                    - 'captive-portal'
            http:
                type: list
                elements: dict
                description: Http.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            icap:
                type: list
                elements: dict
                description: Icap.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            mail:
                type: list
                elements: dict
                description: Mail.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            mm1:
                type: list
                elements: dict
                description: Mm1.
                suboptions:
                    add_smil:
                        aliases: ['add-smil']
                        type: str
                        description: Add message encapsulation
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: Character encoding used for replacement message
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    class:
                        type: str
                        description: Message class
                        choices:
                            - 'personal'
                            - 'advertisement'
                            - 'information'
                            - 'automatic'
                            - 'not-included'
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: From address
                    from_sender:
                        aliases: ['from-sender']
                        type: str
                        description: Notification message sent from recipient
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: Message string.
                    fmgr_message:
                        type: str
                        description: Message text
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
                    priority:
                        type: str
                        description: Message priority
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    rsp_status:
                        aliases: ['rsp-status']
                        type: str
                        description: Response status code
                        choices:
                            - 'ok'
                            - 'err-unspecified'
                            - 'err-srv-denied'
                            - 'err-msg-fmt-corrupt'
                            - 'err-snd-addr-unresolv'
                            - 'err-msg-not-found'
                            - 'err-net-prob'
                            - 'err-content-not-accept'
                            - 'err-unsupp-msg'
                    rsp_text:
                        aliases: ['rsp-text']
                        type: str
                        description: Response text
                    sender_visibility:
                        aliases: ['sender-visibility']
                        type: str
                        description: Sender visibility
                        choices:
                            - 'hide'
                            - 'show'
                            - 'not-specified'
                    smil_part:
                        aliases: ['smil-part']
                        type: str
                        description: Message encapsulation text
                    subject:
                        type: str
                        description: Subject text string
            mm3:
                type: list
                elements: dict
                description: Mm3.
                suboptions:
                    add_html:
                        aliases: ['add-html']
                        type: str
                        description: Add message encapsulation
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: Character encoding used for replacement message
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: From address
                    from_sender:
                        aliases: ['from-sender']
                        type: str
                        description: Notification message sent from recipient
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    html_part:
                        aliases: ['html-part']
                        type: str
                        description: Message encapsulation text
                    image:
                        type: str
                        description: Message string.
                    fmgr_message:
                        type: str
                        description: Message text
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
                    priority:
                        type: str
                        description: Message priority
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    subject:
                        type: str
                        description: Subject text string
            mm4:
                type: list
                elements: dict
                description: Mm4.
                suboptions:
                    add_smil:
                        aliases: ['add-smil']
                        type: str
                        description: Add message encapsulation
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: Character encoding used for replacement message
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    class:
                        type: str
                        description: Message class
                        choices:
                            - 'personal'
                            - 'advertisement'
                            - 'informational'
                            - 'auto'
                            - 'not-included'
                    domain:
                        type: str
                        description: From address domain
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: From address
                    from_sender:
                        aliases: ['from-sender']
                        type: str
                        description: Notification message sent from recipient
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: Message string.
                    fmgr_message:
                        type: str
                        description: Message text
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
                    priority:
                        type: str
                        description: Message priority
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    rsp_status:
                        aliases: ['rsp-status']
                        type: str
                        description: Response status
                        choices:
                            - 'ok'
                            - 'err-unspecified'
                            - 'err-srv-denied'
                            - 'err-msg-fmt-corrupt'
                            - 'err-snd-addr-unresolv'
                            - 'err-net-prob'
                            - 'err-content-not-accept'
                            - 'err-unsupp-msg'
                    smil_part:
                        aliases: ['smil-part']
                        type: str
                        description: Message encapsulation text
                    subject:
                        type: str
                        description: Subject text string
            mm7:
                type: list
                elements: dict
                description: Mm7.
                suboptions:
                    add_smil:
                        aliases: ['add-smil']
                        type: str
                        description: Add message encapsulation
                        choices:
                            - 'disable'
                            - 'enable'
                    addr_type:
                        aliases: ['addr-type']
                        type: str
                        description: From address type
                        choices:
                            - 'rfc2822-addr'
                            - 'number'
                            - 'short-code'
                    allow_content_adaptation:
                        aliases: ['allow-content-adaptation']
                        type: str
                        description: Allow content adaptations
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: Character encoding used for replacement message
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    class:
                        type: str
                        description: Message class
                        choices:
                            - 'personal'
                            - 'advertisement'
                            - 'informational'
                            - 'auto'
                            - 'not-included'
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: From address
                    from_sender:
                        aliases: ['from-sender']
                        type: str
                        description: Notification message sent from recipient
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: Message string.
                    fmgr_message:
                        type: str
                        description: Message text
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
                    priority:
                        type: str
                        description: Message priority
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    rsp_status:
                        aliases: ['rsp-status']
                        type: str
                        description: Response status
                        choices:
                            - 'success'
                            - 'partial-success'
                            - 'client-err'
                            - 'oper-restrict'
                            - 'addr-err'
                            - 'addr-not-found'
                            - 'content-refused'
                            - 'msg-id-not-found'
                            - 'link-id-not-found'
                            - 'msg-fmt-corrupt'
                            - 'app-id-not-found'
                            - 'repl-app-id-not-found'
                            - 'srv-err'
                            - 'not-possible'
                            - 'msg-rejected'
                            - 'multiple-addr-not-supp'
                            - 'app-addr-not-supp'
                            - 'gen-service-err'
                            - 'improper-ident'
                            - 'unsupp-ver'
                            - 'unsupp-oper'
                            - 'validation-err'
                            - 'service-err'
                            - 'service-unavail'
                            - 'service-denied'
                            - 'app-denied'
                    smil_part:
                        aliases: ['smil-part']
                        type: str
                        description: Message encapsulation text
                    subject:
                        type: str
                        description: Subject text string
            mms:
                type: list
                elements: dict
                description: Mms.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    charset:
                        type: str
                        description: Character encoding used for replacement message
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: Message string.
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            nac_quar:
                aliases: ['nac-quar']
                type: list
                elements: dict
                description: Nac quar.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
                    id:
                        type: int
                        description: Id.
            name:
                type: str
                description: Group name.
                required: true
            nntp:
                type: list
                elements: dict
                description: Nntp.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            spam:
                type: list
                elements: dict
                description: Spam.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            sslvpn:
                type: list
                elements: dict
                description: Sslvpn.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            traffic_quota:
                aliases: ['traffic-quota']
                type: list
                elements: dict
                description: Traffic quota.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            utm:
                type: list
                elements: dict
                description: Utm.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            webproxy:
                type: list
                elements: dict
                description: Webproxy.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
            automation:
                type: list
                elements: dict
                description: Automation.
                suboptions:
                    buffer:
                        type: str
                        description: Message string.
                    format:
                        type: str
                        description: Format flag.
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                    header:
                        type: str
                        description: Header flag.
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg_type:
                        aliases: ['msg-type']
                        type: str
                        description: Message type.
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
    - name: Configure replacement message groups.
      fortinet.fortimanager.fmgr_system_replacemsggroup:
        bypass_validation: false
        adom: ansible
        state: present
        system_replacemsggroup:
          comment: ansible-comment
          name: ansible-test

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the replacement message groups
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_replacemsggroup"
          params:
            adom: "ansible"
            replacemsg_group: "your_value"
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
        '/pm/config/adom/{adom}/obj/system/replacemsg-group',
        '/pm/config/global/obj/system/replacemsg-group'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_replacemsggroup': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'admin': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'alertmail': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'},
                        'id': {'v_range': [['6.4.11', '6.4.15'], ['7.0.6', '7.0.14'], ['7.2.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'auth': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'comment': {'type': 'str'},
                'custom-message': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'device-detection-portal': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ec': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'format': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fortiguard-wf': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ftp': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'group-type': {'choices': ['default', 'utm', 'auth', 'ec', 'captive-portal'], 'type': 'str'},
                'http': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'icap': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mail': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm1': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'add-smil': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'class': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': ['personal', 'advertisement', 'information', 'automatic', 'not-included'],
                            'type': 'str'
                        },
                        'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'from-sender': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'fmgr_message': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'priority': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'rsp-status': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': [
                                'ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt', 'err-snd-addr-unresolv', 'err-msg-not-found',
                                'err-net-prob', 'err-content-not-accept', 'err-unsupp-msg'
                            ],
                            'type': 'str'
                        },
                        'rsp-text': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'sender-visibility': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hide', 'show', 'not-specified'], 'type': 'str'},
                        'smil-part': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'subject': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm3': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'add-html': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'from-sender': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'html-part': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'fmgr_message': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'priority': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'subject': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm4': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'add-smil': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'class': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'],
                            'type': 'str'
                        },
                        'domain': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'from-sender': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'fmgr_message': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'priority': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'rsp-status': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': [
                                'ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt', 'err-snd-addr-unresolv', 'err-net-prob',
                                'err-content-not-accept', 'err-unsupp-msg'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'subject': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mm7': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'add-smil': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'addr-type': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['rfc2822-addr', 'number', 'short-code'], 'type': 'str'},
                        'allow-content-adaptation': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'class': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'],
                            'type': 'str'
                        },
                        'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'from': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'from-sender': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'fmgr_message': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'priority': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                        'rsp-status': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': [
                                'success', 'partial-success', 'client-err', 'oper-restrict', 'addr-err', 'addr-not-found', 'content-refused',
                                'msg-id-not-found', 'link-id-not-found', 'msg-fmt-corrupt', 'app-id-not-found', 'repl-app-id-not-found', 'srv-err',
                                'not-possible', 'msg-rejected', 'multiple-addr-not-supp', 'app-addr-not-supp', 'gen-service-err', 'improper-ident',
                                'unsupp-ver', 'unsupp-oper', 'validation-err', 'service-err', 'service-unavail', 'service-denied', 'app-denied'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'subject': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mms': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                        'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'nac-quar': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'},
                        'id': {'v_range': [['6.4.11', '6.4.15'], ['7.0.6', '7.0.14'], ['7.2.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'nntp': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'spam': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'sslvpn': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'traffic-quota': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'utm': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'webproxy': {
                    'type': 'list',
                    'options': {
                        'buffer': {'type': 'str'},
                        'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                        'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'automation': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {
                        'buffer': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'format': {'v_range': [['7.0.0', '']], 'choices': ['none', 'text', 'html'], 'type': 'str'},
                        'header': {'v_range': [['7.0.0', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                        'msg-type': {'v_range': [['7.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsggroup'),
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
