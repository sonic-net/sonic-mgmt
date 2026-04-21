#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_resource_smtp
short_description: Manages resource-smtp objects on Checkpoint over Web Services API
description:
  - Manages resource-smtp objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  mail_delivery_server:
    description:
      - Specify the server to which mail is forwarded.
    type: str
  deliver_messages_using_dns_mx_records:
    description:
      - MX record resolving is used to set the destination IP address of the connection.
    type: bool
  check_rulebase_with_new_destination:
    description:
      - The Rule Base will be rechecked with the new resolved IP address for mail delivery.
    type: bool
  notify_sender_on_error:
    description:
      - Enable error mail delivery.
    type: bool
  error_mail_delivery_server:
    description:
      - Error mail delivery happens if the SMTP security server is unable to deliver the message within the abandon time, and Notify Sender on Error
        is checked.
    type: str
  error_deliver_messages_using_dns_mx_records:
    description:
      - MX record resolving will be used to set the source IP address of the connection used to send the error message.
    type: bool
  error_check_rulebase_with_new_destination:
    description:
      - The Rule Base will be rechecked with the new resolved IP address for error mail delivery.
    type: bool
  exception_track:
    description:
      - Determines if an action specified in the Action 2 and CVP categories taken as a result of a resource definition is logged.
    type: str
    choices: ['none', 'exception log', 'exception alert']
  match:
    description:
      - Set the Match properties for the SMTP resource.
    type: dict
    suboptions:
      sender:
        description:
          - Set the Match sender property for the SMTP resource.
        type: str
      recipient:
        description:
          - Set the Match recipient property for the SMTP resource.
        type: str
  action_1:
    description:
      - Use the Rewriting Rules to rewrite Sender and Recipient headers in emails, you can also rewrite other email headers by using the custom header field.
    type: dict
    suboptions:
      sender:
        description:
          - Rewrite Sender header.
        type: dict
        suboptions:
          original:
            description:
              - Original field.
            type: str
          rewritten:
            description:
              - Replacement field.
            type: str
      recipient:
        description:
          - Rewrite Recipient header.
        type: dict
        suboptions:
          original:
            description:
              - Original field.
            type: str
          rewritten:
            description:
              - Replacement field.
            type: str
      custom_field:
        description:
          - The name of the header.
        type: dict
        suboptions:
          original:
            description:
              - Original field.
            type: str
          rewritten:
            description:
              - Replacement field.
            type: str
          field:
            description:
              - The name of the header.
            type: str
  action_2:
    description:
      - Use this window to configure mail inspection for the SMTP Resource.
    type: dict
    suboptions:
      strip_mime_of_type:
        description:
          - Specifies the MIME type to strip from the message.
        type: str
      strip_file_by_name:
        description:
          - Strips file attachments of the specified name from the message.
        type: str
      mail_capacity:
        description:
          - Restrict the size (in kb) of incoming email attachments.
        type: int
      allowed_characters:
        description:
          - The MIME email headers can consist of 8 or 7 bit characters (7 ASCII and 8 for sending Binary characters) in order to encode mail data.
        type: str
        choices: ['8_bit', '7_bit']
      strip_script_tags:
        description:
          - Strip JAVA scripts.
        type: bool
      strip_applet_tags:
        description:
          - Strip JAVA applets.
        type: bool
      strip_activex_tags:
        description:
          - Strip activeX tags.
        type: bool
      strip_ftp_links:
        description:
          - Strip ftp links.
        type: bool
      strip_port_strings:
        description:
          - Strip ports.
        type: bool
  cvp:
    description:
      - Configure CVP inspection on mail messages.
    type: dict
    suboptions:
      enable_cvp:
        description:
          - Select to enable the Content Vectoring Protocol.
        type: bool
      server:
        description:
          - The UID or Name of the CVP server, make sure the CVP server is already be defined as an OPSEC Application.
        type: str
      allowed_to_modify_content:
        description:
          - Configures the CVP server to inspect but not modify content.
        type: bool
      reply_order:
        description:
          - Designates when the CVP server returns data to the Security Gateway security server.
        type: str
        choices: ['return_data_after_content_is_approved', 'return_data_before_content_is_approved']
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-resource-smtp
  cp_mgmt_resource_smtp:
    deliver_messages_using_dns_mx_records: 'true'
    exception_track: exception log
    mail_delivery_server: deliverServer
    match:
      recipient: recipientName
      sender: senderName
    name: newSmtpResource
    state: present

- name: set-resource-smtp
  cp_mgmt_resource_smtp:
    mail_delivery_server: newServer
    name: newSmtpResource
    state: present

- name: delete-resource-smtp
  cp_mgmt_resource_smtp:
    name: newSmtpResource
    state: absent
"""

RETURN = """
cp_mgmt_resource_smtp:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        mail_delivery_server=dict(type='str'),
        deliver_messages_using_dns_mx_records=dict(type='bool'),
        check_rulebase_with_new_destination=dict(type='bool'),
        notify_sender_on_error=dict(type='bool'),
        error_mail_delivery_server=dict(type='str'),
        error_deliver_messages_using_dns_mx_records=dict(type='bool'),
        error_check_rulebase_with_new_destination=dict(type='bool'),
        exception_track=dict(type='str', choices=['none', 'exception log', 'exception alert']),
        match=dict(type='dict', options=dict(
            sender=dict(type='str'),
            recipient=dict(type='str')
        )),
        action_1=dict(type='dict', options=dict(
            sender=dict(type='dict', options=dict(
                original=dict(type='str'),
                rewritten=dict(type='str')
            )),
            recipient=dict(type='dict', options=dict(
                original=dict(type='str'),
                rewritten=dict(type='str')
            )),
            custom_field=dict(type='dict', options=dict(
                original=dict(type='str'),
                rewritten=dict(type='str'),
                field=dict(type='str')
            ))
        )),
        action_2=dict(type='dict', options=dict(
            strip_mime_of_type=dict(type='str'),
            strip_file_by_name=dict(type='str'),
            mail_capacity=dict(type='int'),
            allowed_characters=dict(type='str', choices=['8_bit', '7_bit']),
            strip_script_tags=dict(type='bool'),
            strip_applet_tags=dict(type='bool'),
            strip_activex_tags=dict(type='bool'),
            strip_ftp_links=dict(type='bool'),
            strip_port_strings=dict(type='bool')
        )),
        cvp=dict(type='dict', options=dict(
            enable_cvp=dict(type='bool'),
            server=dict(type='str'),
            allowed_to_modify_content=dict(type='bool'),
            reply_order=dict(type='str', choices=['return_data_after_content_is_approved', 'return_data_before_content_is_approved'])
        )),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'resource-smtp'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
