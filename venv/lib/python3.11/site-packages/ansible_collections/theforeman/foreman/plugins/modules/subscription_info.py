#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2021 Evgeni Golov
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
module: subscription_info
version_added: 2.1.0
short_description: Fetch information about Subscriptions
description:
  - Fetch information about Subscriptions
author:
  - "Evgeni Golov (@evgeni)"
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Show a subscription"
  theforeman.foreman.subscription_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "Red Hat Satellite Infrastructure Subscription"

- name: "Show all subscriptions with a certain name"
  theforeman.foreman.subscription_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    search: name="Red Hat Satellite Infrastructure Subscription"
'''

RETURN = '''
subscription:
  description: Details about the found subscription
  returned: success and I(name) was passed
  type: dict
subscriptions:
  description: List of all found subscriptions and their details
  returned: success and I(search) was passed
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    KatelloInfoAnsibleModule
)


class KatelloSubscriptionInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloSubscriptionInfo()

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
