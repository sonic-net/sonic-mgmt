# ovirt-hosted-engine-setup -- ovirt hosted engine setup
# Copyright (C) 2018 Red Hat, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_proxied_check
short_description: Check if a URL will be accessed through a proxy
description:
    - This module checks if a given URL is routed through a proxy based on the system's proxy configuration.
version_added: 3.2.0-1
author: "oVirt Developers (@oVirt)"
options:
    url:
        description:
            - The URL to check for proxy routing.
        required: true
        type: str
returns:
    proxied:
        description:
            - Whether the URL is routed through a proxy.
        type: bool
        returned: always
'''

try:
    from urllib import getproxies_environment
    from urllib import proxy_bypass
    from urlparse import urlparse
except ImportError:
    from urllib.request import getproxies_environment
    from urllib.request import proxy_bypass
    from urllib.parse import urlparse


def proxied(value):
    netloc = urlparse(value).netloc
    proxied = bool(getproxies_environment()) and not proxy_bypass(netloc)
    return (proxied)


class TestModule(object):
    ''' Ansible jinja2 tests '''

    def tests(self):
        return {
            'proxied': proxied,
        }
