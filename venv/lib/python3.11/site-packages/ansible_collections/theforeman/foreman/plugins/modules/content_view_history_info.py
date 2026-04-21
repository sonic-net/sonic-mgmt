#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) Evgeni Golov
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
module: content_view_history_info
version_added: 5.7.0
short_description: Fetch history of a Content View
description:
  - Fetch history of a Content View
author:
  - "Evgeni Golov (@evgeni)"
options:
  content_view:
    description:
    - Content view to get the history for
    required: true
    type: str

extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodulewithoutname
'''

EXAMPLES = '''
- name: "Show history of CentOS Stream CV"
  theforeman.foreman.content_view_history_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    content_view: "CentOS Stream"
'''

RETURN = '''
content_view_histories:
  description: History of the Content View
  returned: success
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloInfoAnsibleModule


class KatelloContentViewHistoryInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloContentViewHistoryInfo(
        foreman_spec=dict(
            content_view=dict(required=True, scope=['organization'], type='entity', flat_name='id'),
            name=dict(invisible=True),
        ),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
