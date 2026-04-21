# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    # This document fragment serves as a partial base for all vmware lookups. It should be used in addition to the base fragment, vmware.vmware.base_options
    # since that contains the actual argument descriptions and defaults. This just defines the environment variables since plugins have something
    # like the module spec where that is usually done.
    DOCUMENTATION = r'''
options:
    hostname:
        env:
            - name: VMWARE_HOST
        aliases: [vcenter_hostname]
    username:
        env:
            - name: VMWARE_USER
        aliases: [vcenter_username]
    password:
        env:
            - name: VMWARE_PASSWORD
        aliases: [vcenter_password]
    validate_certs:
        env:
            - name: VMWARE_VALIDATE_CERTS
        aliases: [vcenter_validate_certs]
    port:
        env:
            - name: VMWARE_PORT
    proxy_host:
        env:
            - name: VMWARE_PROXY_HOST
    proxy_port:
        env:
            - name: VMWARE_PROXY_PORT
    fail_on_missing:
        description:
            - If true, the plugin will raise a failure if the specified path cannot be found in vCenter.
            - If false, the plugin silently continues and returns nothing if the specified path does not exist.
        default: false
        type: bool
    wantlist:
        description:
            - If true, the plugin will return a list instead of a string.
            - If multiple objects are found and wantlist is false, the values are returned as a comma
              separated string.
        default: false
        type: bool
'''
