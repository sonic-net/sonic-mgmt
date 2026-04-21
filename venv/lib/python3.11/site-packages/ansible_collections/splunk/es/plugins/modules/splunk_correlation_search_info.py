#!/usr/bin/python
# -*- coding: utf-8 -*-
# https://github.com/ansible/ansible/issues/65816
# https://github.com/PyCQA/pylint/issues/214

# (c) 2018, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: correlation_search_info
short_description: Manage Splunk Enterprise Security Correlation Searches
description:
  - This module allows for the query of Splunk Enterprise Security Correlation Searches
version_added: "1.0.0"
options:
  name:
    description:
      - Name of coorelation search
    required: false
    type: str

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""
# FIXME - adaptive response action association is probaby going to need to be a separate module we stitch together in a role

EXAMPLES = """
- name: Example usage of splunk.es.correlation_search_info
  splunk.es.correlation_search_info:
    name: "Name of correlation search"
  register: scorrelation_search_info

- name: debug display information gathered
  debug:
    var: scorrelation_search_info
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.urllib.parse import quote_plus

from ansible_collections.splunk.es.plugins.module_utils.splunk import SplunkRequest


def main():
    argspec = dict(name=dict(required=False, type="str"))

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    splunk_request = SplunkRequest(
        module,
        headers={"Content-Type": "application/json"},
    )

    if module.params["name"]:
        try:
            query_dict = splunk_request.get_by_path(
                "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{0}".format(
                    quote_plus(module.params["name"]),
                ),
            )
        except HTTPError as e:
            # the data monitor doesn't exist
            query_dict = {}
    else:
        query_dict = splunk_request.get_by_path(
            "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches",
        )

    module.exit_json(changed=False, splunk_correlation_search_info=query_dict)


if __name__ == "__main__":
    main()
