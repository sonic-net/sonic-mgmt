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
module: content_view_filter_info
version_added: 3.9.0
short_description: Fetch information about a Content View Filter
description:
  - Fetch information about a Content View Filter
author:
  - "Paul Armstrong (@parmstro)"
options:
  content_view:
    description:
      - the name of the content view that the filter applies to
    required: true
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Show a content_view_filter"
  theforeman.foreman.content_view_filter_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    content_view: "SOE_RHEL9"
    name: "AllRPMNoErrata"
'''

RETURN = '''
content_view_filter:
  description: Details about the found content view filter
  returned: success and I(name) was passed
  type: dict
content_view_filters:
  description: Details about the found content view filters
  returned: success and I(search) was passed
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    KatelloInfoAnsibleModule,
)


class KatelloContentViewFilterInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloContentViewFilterInfo(
        foreman_spec=dict(
            content_view=dict(type='entity', scope=['organization'], required=True),
        ),
        entity_opts=dict(scope=['content_view']),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
