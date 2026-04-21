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
module: cp_mgmt_set_app_control_advanced_settings
short_description: Edit Application Control & URL Filtering Blades' Settings.
description:
  - Edit Application Control & URL Filtering Blades' Settings.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  internal_error_fail_mode:
    description:
      - In case of internal system error, allow or block all connections. This property is not available in the Global domain of an MDS machine.
    type: str
    choices: ['allow connections', 'block connections']
  url_filtering_settings:
    description:
      - In this section user can enable  URL Filtering features. This property is not available in the Global domain of an MDS machine.
    type: dict
    suboptions:
      categorize_https_websites:
        description:
          - This option lets Application and URL Filtering assign categories to HTTPS sites without activating HTTPS inspection. It assigns a site
            category based on its domain name and whether the site has a valid certificate. If the server certificate is,
            Trusted - Application and URL Filtering gets the domain name from the certificate and uses it to categorize the site.
            Not Trusted - Application and URL Filtering assigns a category based on the IP address.
            This property is not available in the Global domain of an MDS machine.
        type: bool
      enforce_safe_search:
        description:
          - Select this option to require use of the safe search feature in search engines. When activated, the URL Filtering Policy uses the
            strictest available safe search option for the specified search engine. This option overrides user specified search engine options to block
            offensive material in search results. This property is not available in the Global domain of an MDS machine.
        type: bool
      categorize_cached_and_translated_pages:
        description:
          - Select this option to assign categories to cached search engine results and translated pages. When this option is selected,
            Application and URL Filtering assigns categories based on the original Web site instead of the 'search engine pages' category.
            This property is not available in the Global domain of an MDS machine.
        type: bool
  web_browsing_services:
    description:
      - Web browsing services are the services that match a Web-based custom Application/Site.
    type: list
    elements: str
  match_application_on_any_port:
    description:
      - Match Web application on 'Any' port when used in Block rule - By default this is set to true. and so applications are matched on all services
        when used in a Block rule.
    type: bool
  enable_web_browsing:
    description:
      - If you do not enable URL Filtering on the Security Gateway, you can use a generic Web browser application called Web Browsing in the
        rule. This application includes all HTTP traffic that is not a defined application Application and URL Filtering
        assigns Web Browsing as the default application for all HTTP traffic that does not match an application in the Application and
        URL Filtering Database. This property is not available in the Global domain of an MDS machine.
    type: bool
  httpi_non_standard_ports:
    description:
      - Enable HTTP inspection on non standard ports for application and URL filtering. This property is not available in the Global domain of an
        MDS machine.
    type: bool
  block_request_when_web_service_is_unavailable:
    description:
      - Block requests when the web service is unavailable.
        When selected, requests are blocked when there is no connectivity to the Check Point Online Web Service.
        When cleared, requests are allowed when there is no connectivity.
        This property is not available in the Global domain of an MDS machine.
    type: bool
  website_categorization_mode:
    description:
      - Hold - Requests are blocked until categorization is complete.
        Background - Requests are allowed until categorization is complete.
        Custom - configure different settings depending on the service. Lets you set different modes for URL Filtering and Social Networking Widgets.
        This property is not available in the Global domain of an MDS machine.
    type: str
    choices: ['hold', 'background', 'custom']
  custom_categorization_settings:
    description:
      - Website categorization mode - select the mode that is used for website categorization.
        This property is not available in the Global domain of an MDS machine.
    type: dict
    suboptions:
      url_filtering_mode:
        description:
          - Hold - Requests are blocked until categorization is complete.
            Background - Requests are allowed until categorization is complete.
            This property is not available in the Global domain of an MDS machine.
        type: str
        choices: ['hold', 'background']
      social_network_widgets_mode:
        description:
          - Hold - Requests are blocked until categorization is complete.
            Background - Requests are allowed until categorization is complete.
            This property is not available in the Global domain of an MDS machine.
        type: str
        choices: ['hold', 'background']
  categorize_social_network_widgets:
    description:
      - When selected, the Security Gateway connects to the Check Point Online Web Service to identify social networking widgets that it does not
        recognize. When cleared or there is no connectivity between the Security Gateway and the Check Point Online Web, the unknown widget is treated as
        Web Browsing traffic. This property is not available in the Global domain of an MDS machine.
    type: bool
  domain_level_permission:
    description:
      - Allows the editing of applications, categories, and services. This property is used only in the Global Domain of an MDS machine.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-app-control-advanced-settings
  cp_mgmt_set_app_control_advanced_settings:
    block_request_when_web_service_is_unavailable: 'true'
    categorize_social_network_widgets: 'true'
    custom_categorization_settings:
      social_network_widgets_mode: background
      url_filtering_mode: hold
    enable_web_browsing: 'true'
    httpi_non_standard_ports: 'true'
    internal_error_fail_mode: block connections
    match_application_on_any_port: 'true'
    url_filtering_settings:
      categorize_cached_and_translated_pages: 'false'
      categorize_https_websites: 'true'
      enforce_safe_search: 'true'
    web_browsing_services:
      - AH
    website_categorization_mode: custom
"""

RETURN = """
cp_mgmt_set_app_control_advanced_settings:
  description: The checkpoint set-app-control-advanced-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        internal_error_fail_mode=dict(type='str', choices=['allow connections', 'block connections']),
        url_filtering_settings=dict(type='dict', options=dict(
            categorize_https_websites=dict(type='bool'),
            enforce_safe_search=dict(type='bool'),
            categorize_cached_and_translated_pages=dict(type='bool')
        )),
        web_browsing_services=dict(type='list', elements='str'),
        match_application_on_any_port=dict(type='bool'),
        enable_web_browsing=dict(type='bool'),
        httpi_non_standard_ports=dict(type='bool'),
        block_request_when_web_service_is_unavailable=dict(type='bool'),
        website_categorization_mode=dict(type='str', choices=['hold', 'background', 'custom']),
        custom_categorization_settings=dict(type='dict', options=dict(
            url_filtering_mode=dict(type='str', choices=['hold', 'background']),
            social_network_widgets_mode=dict(type='str', choices=['hold', 'background'])
        )),
        categorize_social_network_widgets=dict(type='bool'),
        domain_level_permission=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-app-control-advanced-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
