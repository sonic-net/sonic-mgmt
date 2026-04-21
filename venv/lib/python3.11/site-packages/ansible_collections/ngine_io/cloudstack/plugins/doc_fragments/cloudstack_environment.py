# -*- coding: utf-8 -*-

# Copyright (c) 2015, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):

    # Additional Cloudstack Configuration with Environment Variables Mappings
    DOCUMENTATION = r'''
options:
  api_key:
    env:
      - name: CLOUDSTACK_KEY
  api_secret:
    env:
      - name: CLOUDSTACK_SECRET
  api_url:
    env:
      - name: CLOUDSTACK_ENDPOINT
  api_http_method:
    env:
      - name: CLOUDSTACK_METHOD
  api_timeout:
    env:
      - name: CLOUDSTACK_TIMEOUT
  api_verify_ssl_cert:
    env:
      - name: CLOUDSTACK_VERIFY
'''
