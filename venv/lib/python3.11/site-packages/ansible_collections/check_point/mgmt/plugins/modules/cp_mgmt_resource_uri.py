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
module: cp_mgmt_resource_uri
short_description: Manages resource-uri objects on Checkpoint over Web Services API
description:
  - Manages resource-uri objects on Checkpoint devices including creating, updating and removing objects.
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
  use_this_resource_to:
    description:
      - Select the use of the URI resource.
    type: str
    choices: ['enforce_uri_capabilities', 'optimize_url_logging', 'enhance_ufp_performance']
  connection_methods:
    description:
      - Connection methods.
    type: dict
    suboptions:
      transparent:
        description:
          - The security server is invisible to the client that originates the connection, and to the server. The Transparent connection method is
            the most secure.
        type: bool
      proxy:
        description:
          - The Resource is applied when people specify the Check Point Security Gateway as a proxy in their browser.
        type: bool
      tunneling:
        description:
          - The Resource is applied when people specify the Security Gateway as a proxy in their browser, and is used for connections where
            Security Gateway cannot examine the contents of the packets, not even the URL.
        type: bool
  uri_match_specification_type:
    description:
      - The type can be Wild Cards or UFP, where a UFP server holds categories of forbidden web sites.
    type: str
    choices: ['wildcards', 'ufp']
  exception_track:
    description:
      - Configures how to track connections that match this rule but fail the content security checks. An example of an exception is a connection with
        an unsupported scheme or method.
    type: str
    choices: ['none', 'exception log', 'exception alert']
  match_ufp:
    description:
      - Match-Ufp settings.
    type: dict
    suboptions:
      server:
        description:
          - The UID or Name of the UFP server that is an OPSEC certified third party application that checks URLs against a list of permitted categories.
        type: str
      caching_control:
        description:
          - Specifies if and how caching is to be enabled.
        type: str
        choices: ['security_gateway_one_request', 'security_gateway_two_requests', 'no_caching', 'ufp_server']
      ignore_ufp_server_after_failure:
        description:
          - The UFP server will be ignored after numerous UFP server connections were unsuccessful.
        type: bool
      number_of_failures_before_ignore:
        description:
          - Signifies at what point the UFP server should be ignored.
        type: int
      timeout_before_reconnecting:
        description:
          - The amount of time that must pass before a UFP server connection should be attempted.
        type: int
  match_wildcards:
    description:
      - Match-Wildcards settings.
    type: dict
    suboptions:
      schemes:
        description:
          - Select the URI Schemes to which this resource applies.
        type: dict
        suboptions:
          http:
            description:
              - Http scheme.
            type: bool
          ftp:
            description:
              - Ftp scheme.
            type: bool
          gopher:
            description:
              - Gopher scheme.
            type: bool
          mailto:
            description:
              - Mailto scheme.
            type: bool
          news:
            description:
              - News scheme.
            type: bool
          wais:
            description:
              - Wais scheme.
            type: bool
          other:
            description:
              - You can specify another scheme in the Other field. You can use wildcards.
            type: str
      methods:
        description:
          - Select the URI Schemes to which this resource applies.
        type: dict
        suboptions:
          get:
            description:
              - GET method.
            type: bool
          post:
            description:
              - POST method.
            type: bool
          head:
            description:
              - HEAD method.
            type: bool
          put:
            description:
              - PUT method.
            type: bool
          other:
            description:
              - You can specify another method in the Other field. You can use wildcards.
            type: str
      host:
        description:
          - The functionality of the Host parameter depends on the DNS setup of the addressed server. For the host, only the IP address or the
            full DNS name should be used.
        type: str
      path:
        description:
          - Name matching is based on appending the file name in the request to the current working directory (unless the file name is already a
            full path name) and comparing the result to the path specified in the Resource definition.
        type: str
      query:
        description:
          - The parameters that are sent to the URI when it is accessed.
        type: str
  action:
    description:
      - Action settings.
    type: dict
    suboptions:
      replacement_uri:
        description:
          - If the Action in a rule which uses this resource is Drop or Reject, then the Replacement URI is displayed instead of the one requested by the user.
        type: str
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
      - CVP settings.
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
      send_http_headers_to_cvp:
        description:
          - Select, if you would like the CVP server to check the HTTP headers of the message packets.
        type: bool
      reply_order:
        description:
          - Designates when the CVP server returns data to the Security Gateway security server.
        type: str
        choices: ['return_data_after_content_is_approved', 'return_data_before_content_is_approved']
      send_http_request_to_cvp:
        description:
          - Used to protect against undesirable content in the HTTP request, for example, when inspecting peer-to-peer connections.
        type: bool
      send_only_unsafe_file_types:
        description:
          - Improves the performance of the CVP server. This option does not send to the CVP server traffic that is considered safe.
        type: bool
  soap:
    description:
      - SOAP settings.
    type: dict
    suboptions:
      inspection:
        description:
          - Allow all SOAP Requests, or Allow only SOAP requests specified in the following file-id.
        type: str
        choices: ['allow_all_soap_requests', 'allow_soap_requests_as_specified_in_file']
      file_id:
        description:
          - A file containing SOAP requests.
        type: str
        choices: ['scheme1', 'scheme2', 'scheme3', 'scheme4', 'scheme5', 'scheme6', 'scheme7', 'scheme8', 'scheme9', 'scheme10']
      track_connections:
        description:
          - The method of tracking SOAP connections.
        type: str
        choices: ['none', 'log', 'popup_alert', 'mail_alert', 'snmp_trap_alert', 'user_defined_alert_no', 'user_defined_alert_no', 'user_defined_alert_no']
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
- name: add-resource-uri
  cp_mgmt_resource_uri:
    connection_methods:
      transparent: 'false'
      tunneling: 'true'
    match_wildcards:
      host: hostName
      path: pathName
    name: newUriResource
    state: present
    uri_match_specification_type: wildcards
    use_this_resource_to: optimize_url_logging

- name: set-resource-uri
  cp_mgmt_resource_uri:
    connection_methods:
      transparent: 'false'
      tunneling: 'true'
    match_wildcards:
      host: hostName
      path: pathName
    name: newUriResource
    state: present
    uri_match_specification_type: wildcards
    use_this_resource_to: optimize_url_logging

- name: delete-resource-uri
  cp_mgmt_resource_uri:
    name: newUriResource
    state: absent
"""

RETURN = """
cp_mgmt_resource_uri:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        use_this_resource_to=dict(type='str', choices=['enforce_uri_capabilities', 'optimize_url_logging', 'enhance_ufp_performance']),
        connection_methods=dict(type='dict', options=dict(
            transparent=dict(type='bool'),
            proxy=dict(type='bool'),
            tunneling=dict(type='bool')
        )),
        uri_match_specification_type=dict(type='str', choices=['wildcards', 'ufp']),
        exception_track=dict(type='str', choices=['none', 'exception log', 'exception alert']),
        match_ufp=dict(type='dict', options=dict(
            server=dict(type='str'),
            caching_control=dict(type='str', choices=['security_gateway_one_request', 'security_gateway_two_requests', 'no_caching', 'ufp_server']),
            ignore_ufp_server_after_failure=dict(type='bool'),
            number_of_failures_before_ignore=dict(type='int'),
            timeout_before_reconnecting=dict(type='int')
        )),
        match_wildcards=dict(type='dict', options=dict(
            schemes=dict(type='dict', options=dict(
                http=dict(type='bool'),
                ftp=dict(type='bool'),
                gopher=dict(type='bool'),
                mailto=dict(type='bool'),
                news=dict(type='bool'),
                wais=dict(type='bool'),
                other=dict(type='str')
            )),
            methods=dict(type='dict', options=dict(
                get=dict(type='bool'),
                post=dict(type='bool'),
                head=dict(type='bool'),
                put=dict(type='bool'),
                other=dict(type='str')
            )),
            host=dict(type='str'),
            path=dict(type='str'),
            query=dict(type='str')
        )),
        action=dict(type='dict', options=dict(
            replacement_uri=dict(type='str'),
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
            send_http_headers_to_cvp=dict(type='bool'),
            reply_order=dict(type='str', choices=['return_data_after_content_is_approved', 'return_data_before_content_is_approved']),
            send_http_request_to_cvp=dict(type='bool'),
            send_only_unsafe_file_types=dict(type='bool')
        )),
        soap=dict(type='dict', options=dict(
            inspection=dict(type='str', choices=['allow_all_soap_requests', 'allow_soap_requests_as_specified_in_file']),
            file_id=dict(type='str', choices=['scheme1', 'scheme2', 'scheme3', 'scheme4', 'scheme5', 'scheme6', 'scheme7', 'scheme8', 'scheme9', 'scheme10']),
            track_connections=dict(type='str', choices=['none', 'log', 'popup_alert', 'mail_alert',
                                                        'snmp_trap_alert', 'user_defined_alert_no', 'user_defined_alert_no', 'user_defined_alert_no'])
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
    api_call_object = 'resource-uri'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
