# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Simon Dodsley <simon@purestorage.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard Pure Storage documentation fragment
    DOCUMENTATION = r"""
options:
  - See separate platform section for more details
requirements:
  - See separate platform section for more details
notes:
  - Ansible modules are available for the following Pure Storage products: FlashArray, FlashBlade
"""

    # Documentation fragment for FlashBlade
    FB = r"""
options:
  fb_url:
    description:
      - FlashBlade management IP address or Hostname.
    type: str
  api_token:
    description:
      - FlashBlade API token for admin privileged user.
    type: str
  disable_warnings:
    description:
    - Disable insecure certificate warnings
    type: bool
    default: false
    version_added: '1.18.0'
notes:
  - You must set C(PUREFB_URL) and C(PUREFB_API) environment variables
    if I(fb_url) and I(api_token) arguments are not passed to the module directly
requirements:
  - python >= 3.9
  - py-pure-client
  - netaddr
  - datetime
  - pytz
  - distro
  - pycountry
  - urllib3
"""
