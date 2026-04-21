#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_waf_profile
short_description: Configure Web application firewall configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify waf feature and profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    waf_profile:
        description:
            - Configure Web application firewall configuration.
        default: null
        type: dict
        suboptions:
            address_list:
                description:
                    - Address block and allow lists.
                type: dict
                suboptions:
                    blocked_address:
                        description:
                            - Blocked address.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    blocked_log:
                        description:
                            - Enable/disable logging on blocked addresses.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    severity:
                        description:
                            - Severity.
                        type: str
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    trusted_address:
                        description:
                            - Trusted address.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
            comment:
                description:
                    - Comment.
                type: str
            constraint:
                description:
                    - WAF HTTP protocol restrictions.
                type: dict
                suboptions:
                    content_length:
                        description:
                            - HTTP content length in request.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                description:
                                    - Length of HTTP content in bytes (0 to 2147483647).
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    exception:
                        description:
                            - HTTP constraint exception.
                        type: list
                        elements: dict
                        suboptions:
                            address:
                                description:
                                    - Host address. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                            content_length:
                                description:
                                    - HTTP content length in request.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            header_length:
                                description:
                                    - HTTP header length in request.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            hostname:
                                description:
                                    - Enable/disable hostname check.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            id:
                                description:
                                    - Exception ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            line_length:
                                description:
                                    - HTTP line length in request.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            malformed:
                                description:
                                    - Enable/disable malformed HTTP request check.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_cookie:
                                description:
                                    - Maximum number of cookies in HTTP request.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_header_line:
                                description:
                                    - Maximum number of HTTP header line.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_range_segment:
                                description:
                                    - Maximum number of range segments in HTTP range line.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_url_param:
                                description:
                                    - Maximum number of parameters in URL.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            method:
                                description:
                                    - Enable/disable HTTP method check.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            param_length:
                                description:
                                    - Maximum length of parameter in URL, HTTP POST request or HTTP body.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            pattern:
                                description:
                                    - URL pattern.
                                type: str
                            regex:
                                description:
                                    - Enable/disable regular expression based pattern match.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            url_param_length:
                                description:
                                    - Maximum length of parameter in URL.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            version:
                                description:
                                    - Enable/disable HTTP version check.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    header_length:
                        description:
                            - HTTP header length in request.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                description:
                                    - Length of HTTP header in bytes (0 to 2147483647).
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    hostname:
                        description:
                            - Enable/disable hostname check.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    line_length:
                        description:
                            - HTTP line length in request.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                description:
                                    - Length of HTTP line in bytes (0 to 2147483647).
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    malformed:
                        description:
                            - Enable/disable malformed HTTP request check.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    max_cookie:
                        description:
                            - Maximum number of cookies in HTTP request.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_cookie:
                                description:
                                    - Maximum number of cookies in HTTP request (0 to 2147483647).
                                type: int
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    max_header_line:
                        description:
                            - Maximum number of HTTP header line.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_header_line:
                                description:
                                    - Maximum number HTTP header lines (0 to 2147483647).
                                type: int
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    max_range_segment:
                        description:
                            - Maximum number of range segments in HTTP range line.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_range_segment:
                                description:
                                    - Maximum number of range segments in HTTP range line (0 to 2147483647).
                                type: int
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    max_url_param:
                        description:
                            - Maximum number of parameters in URL.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            max_url_param:
                                description:
                                    - Maximum number of parameters in URL (0 to 2147483647).
                                type: int
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    method:
                        description:
                            - Enable/disable HTTP method check.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    param_length:
                        description:
                            - Maximum length of parameter in URL, HTTP POST request or HTTP body.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                description:
                                    - Maximum length of parameter in URL, HTTP POST request or HTTP body in bytes (0 to 2147483647).
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    url_param_length:
                        description:
                            - Maximum length of parameter in URL.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                description:
                                    - Maximum length of URL parameter in bytes (0 to 2147483647).
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    version:
                        description:
                            - Enable/disable HTTP version check.
                        type: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Enable/disable the constraint.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
            extended_log:
                description:
                    - Enable/disable extended logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            external:
                description:
                    - Disable/Enable external HTTP Inspection.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            method:
                description:
                    - Method restriction.
                type: dict
                suboptions:
                    default_allowed_methods:
                        description:
                            - Methods.
                        type: list
                        elements: str
                        choices:
                            - 'get'
                            - 'post'
                            - 'put'
                            - 'head'
                            - 'connect'
                            - 'trace'
                            - 'options'
                            - 'delete'
                            - 'others'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    method_policy:
                        description:
                            - HTTP method policy.
                        type: list
                        elements: dict
                        suboptions:
                            address:
                                description:
                                    - Host address. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                            allowed_methods:
                                description:
                                    - Allowed Methods.
                                type: list
                                elements: str
                                choices:
                                    - 'get'
                                    - 'post'
                                    - 'put'
                                    - 'head'
                                    - 'connect'
                                    - 'trace'
                                    - 'options'
                                    - 'delete'
                                    - 'others'
                            id:
                                description:
                                    - HTTP method policy ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            pattern:
                                description:
                                    - URL pattern.
                                type: str
                            regex:
                                description:
                                    - Enable/disable regular expression based pattern match.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    severity:
                        description:
                            - Severity.
                        type: str
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            name:
                description:
                    - WAF Profile name.
                required: true
                type: str
            signature:
                description:
                    - WAF signatures.
                type: dict
                suboptions:
                    credit_card_detection_threshold:
                        description:
                            - The minimum number of Credit cards to detect violation.
                        type: int
                    custom_signature:
                        description:
                            - Custom signature.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                                    - 'erase'
                            case_sensitivity:
                                description:
                                    - Case sensitivity in pattern.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            direction:
                                description:
                                    - Traffic direction.
                                type: str
                                choices:
                                    - 'request'
                                    - 'response'
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            name:
                                description:
                                    - Signature name.
                                required: true
                                type: str
                            pattern:
                                description:
                                    - Match pattern.
                                type: str
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Status.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            target:
                                description:
                                    - Match HTTP target.
                                type: list
                                elements: str
                                choices:
                                    - 'arg'
                                    - 'arg-name'
                                    - 'req-body'
                                    - 'req-cookie'
                                    - 'req-cookie-name'
                                    - 'req-filename'
                                    - 'req-header'
                                    - 'req-header-name'
                                    - 'req-raw-uri'
                                    - 'req-uri'
                                    - 'resp-body'
                                    - 'resp-hdr'
                                    - 'resp-status'
                    disabled_signature:
                        description:
                            - Disabled signatures.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Signature ID. see <a href='#notes'>Notes</a>. Source waf.signature.id.
                                required: true
                                type: int
                    disabled_sub_class:
                        description:
                            - Disabled signature subclasses.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Signature subclass ID. see <a href='#notes'>Notes</a>. Source waf.sub-class.id.
                                required: true
                                type: int
                    main_class:
                        description:
                            - Main signature class.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'block'
                                    - 'erase'
                            id:
                                description:
                                    - Main signature class ID. see <a href='#notes'>Notes</a>. Source waf.main-class.id.
                                required: true
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            severity:
                                description:
                                    - Severity.
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                            status:
                                description:
                                    - Status.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
            url_access:
                description:
                    - URL access list.
                type: list
                elements: dict
                suboptions:
                    access_pattern:
                        description:
                            - URL access pattern.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - URL access pattern ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            negate:
                                description:
                                    - Enable/disable match negation.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            pattern:
                                description:
                                    - URL pattern.
                                type: str
                            regex:
                                description:
                                    - Enable/disable regular expression based pattern match.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            srcaddr:
                                description:
                                    - Source address. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'bypass'
                            - 'permit'
                            - 'block'
                    address:
                        description:
                            - Host address. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    id:
                        description:
                            - URL access ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    severity:
                        description:
                            - Severity.
                        type: str
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
"""

EXAMPLES = """
- name: Configure Web application firewall configuration.
  fortinet.fortios.fortios_waf_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      waf_profile:
          address_list:
              blocked_address:
                  -
                      name: "default_name_5 (source firewall.address.name firewall.addrgrp.name)"
              blocked_log: "enable"
              severity: "high"
              status: "enable"
              trusted_address:
                  -
                      name: "default_name_10 (source firewall.address.name firewall.addrgrp.name)"
          comment: "Comment."
          constraint:
              content_length:
                  action: "allow"
                  length: "67108864"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              exception:
                  -
                      address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                      content_length: "enable"
                      header_length: "enable"
                      hostname: "enable"
                      id: "24"
                      line_length: "enable"
                      malformed: "enable"
                      max_cookie: "enable"
                      max_header_line: "enable"
                      max_range_segment: "enable"
                      max_url_param: "enable"
                      method: "enable"
                      param_length: "enable"
                      pattern: "<your_own_value>"
                      regex: "enable"
                      url_param_length: "enable"
                      version: "enable"
              header_length:
                  action: "allow"
                  length: "8192"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              hostname:
                  action: "allow"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              line_length:
                  action: "allow"
                  length: "1024"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              malformed:
                  action: "allow"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              max_cookie:
                  action: "allow"
                  log: "enable"
                  max_cookie: "16"
                  severity: "high"
                  status: "enable"
              max_header_line:
                  action: "allow"
                  log: "enable"
                  max_header_line: "32"
                  severity: "high"
                  status: "enable"
              max_range_segment:
                  action: "allow"
                  log: "enable"
                  max_range_segment: "5"
                  severity: "high"
                  status: "enable"
              max_url_param:
                  action: "allow"
                  log: "enable"
                  max_url_param: "16"
                  severity: "high"
                  status: "enable"
              method:
                  action: "allow"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              param_length:
                  action: "allow"
                  length: "8192"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              url_param_length:
                  action: "allow"
                  length: "8192"
                  log: "enable"
                  severity: "high"
                  status: "enable"
              version:
                  action: "allow"
                  log: "enable"
                  severity: "high"
                  status: "enable"
          extended_log: "enable"
          external: "disable"
          method:
              default_allowed_methods: "get"
              log: "enable"
              method_policy:
                  -
                      address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                      allowed_methods: "get"
                      id: "113"
                      pattern: "<your_own_value>"
                      regex: "enable"
              severity: "high"
              status: "enable"
          name: "default_name_118"
          signature:
              credit_card_detection_threshold: "3"
              custom_signature:
                  -
                      action: "allow"
                      case_sensitivity: "disable"
                      direction: "request"
                      log: "enable"
                      name: "default_name_126"
                      pattern: "<your_own_value>"
                      severity: "high"
                      status: "enable"
                      target: "arg"
              disabled_signature:
                  -
                      id: "132 (source waf.signature.id)"
              disabled_sub_class:
                  -
                      id: "134 (source waf.sub-class.id)"
              main_class:
                  -
                      action: "allow"
                      id: "137 (source waf.main-class.id)"
                      log: "enable"
                      severity: "high"
                      status: "enable"
          url_access:
              -
                  access_pattern:
                      -
                          id: "143"
                          negate: "enable"
                          pattern: "<your_own_value>"
                          regex: "enable"
                          srcaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  action: "bypass"
                  address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  id: "150"
                  log: "enable"
                  severity: "high"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_waf_profile_data(json):
    option_list = [
        "address_list",
        "comment",
        "constraint",
        "extended_log",
        "external",
        "method",
        "name",
        "signature",
        "url_access",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["signature", "custom_signature", "target"],
        ["method", "default_allowed_methods"],
        ["method", "method_policy", "allowed_methods"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def waf_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    waf_profile_data = data["waf_profile"]

    filtered_data = filter_waf_profile_data(waf_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("waf", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("waf", "profile", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["waf_profile"] = filtered_data
    fos.do_member_operation(
        "waf",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("waf", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("waf", "profile", mkey=converted_data["name"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_waf(data, fos, check_mode):

    if data["waf_profile"]:
        resp = waf_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("waf_profile"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "external": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "extended_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "signature": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "disabled_sub_class": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "disabled_signature": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "credit_card_detection_threshold": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "custom_signature": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "allow"},
                                {"value": "block"},
                                {"value": "erase"},
                            ],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                        "direction": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "request"}, {"value": "response"}],
                        },
                        "case_sensitivity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "pattern": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "target": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "list",
                            "options": [
                                {"value": "arg"},
                                {"value": "arg-name"},
                                {"value": "req-body"},
                                {"value": "req-cookie"},
                                {"value": "req-cookie-name"},
                                {"value": "req-filename"},
                                {"value": "req-header"},
                                {"value": "req-header-name"},
                                {"value": "req-raw-uri"},
                                {"value": "req-uri"},
                                {"value": "resp-body"},
                                {"value": "resp-hdr"},
                                {"value": "resp-status"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "main_class": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "integer",
                            "required": True,
                        },
                        "status": {
                            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "action": {
                            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "string",
                            "options": [
                                {"value": "allow"},
                                {"value": "block"},
                                {"value": "erase"},
                            ],
                        },
                        "log": {
                            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                },
            },
        },
        "constraint": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "header_length": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "content_length": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "param_length": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "line_length": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "url_param_length": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "version": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "method": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "hostname": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "malformed": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "max_cookie": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_cookie": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "max_header_line": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_header_line": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "max_url_param": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_url_param": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "max_range_segment": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_range_segment": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "allow"}, {"value": "block"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "severity": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "high"},
                                {"value": "medium"},
                                {"value": "low"},
                            ],
                        },
                    },
                },
                "exception": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "pattern": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "regex": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "header_length": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "content_length": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "param_length": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "line_length": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "url_param_length": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "version": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "method": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "hostname": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "malformed": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_cookie": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_header_line": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_url_param": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "max_range_segment": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
        },
        "method": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "high"},
                        {"value": "medium"},
                        {"value": "low"},
                    ],
                },
                "default_allowed_methods": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "get"},
                        {"value": "post"},
                        {"value": "put"},
                        {"value": "head"},
                        {"value": "connect"},
                        {"value": "trace"},
                        {"value": "options"},
                        {"value": "delete"},
                        {"value": "others"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "method_policy": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "pattern": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "regex": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "allowed_methods": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "list",
                            "options": [
                                {"value": "get"},
                                {"value": "post"},
                                {"value": "put"},
                                {"value": "head"},
                                {"value": "connect"},
                                {"value": "trace"},
                                {"value": "options"},
                                {"value": "delete"},
                                {"value": "others"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
        },
        "address_list": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "blocked_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "high"},
                        {"value": "medium"},
                        {"value": "low"},
                    ],
                },
                "trusted_address": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "blocked_address": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
        },
        "url_access": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "permit"},
                        {"value": "block"},
                    ],
                },
                "log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "high"},
                        {"value": "medium"},
                        {"value": "low"},
                    ],
                },
                "access_pattern": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "srcaddr": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "pattern": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "regex": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "negate": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "waf_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["waf_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["waf_profile"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "waf_profile"
        )

        is_error, has_changed, result, diff = fortios_waf(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
