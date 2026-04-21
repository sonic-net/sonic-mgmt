#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2021 Paul Armstrong
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: content_view_filter_rule_info
version_added: 3.9.0
short_description: Fetch information about a Content View Filter Rule
description:
  - Fetch information about a Content View Filter Rule
author:
  - "Paul Armstrong (@parmstro)"
options:
  content_view:
    description:
      - the name of the content view that the filter applies to
    required: true
    type: str
  content_view_filter:
    description:
      - the name of the content view filter that the rule applies to
    type: str
    required: true
  errata_id:
    description:
      - for erratum fitlers using errata_by_id, the errata id to search for
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Show a content_view_filter_rule"
  theforeman.foreman.content_view_filter_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    content_view: "SOE_RHEL9"
    content_view_filter: "NoFireFox"
    name: firefox
'''

RETURN = '''
content_view_filter_rule:
  description: Details about the found content_view_filter_rule
  returned: success and I(name) was passed
  type: dict
content_view_filter_rules:
  description: Details about the found content_view_filter_rules
  returned: success and the filter type is erratum or modulemd
  type: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    KatelloInfoAnsibleModule,
)


class KatelloContentViewFilterRuleInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloContentViewFilterRuleInfo(
        foreman_spec=dict(
            content_view=dict(type='entity', scope=['organization'], required=True),
            content_view_filter=dict(type='entity', scope=['content_view'], required=True),
            errata_id=dict(),
        ),
        entity_opts=dict(scope=['content_view_filter']),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
