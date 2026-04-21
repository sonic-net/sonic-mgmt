#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: network_resource
author: Ganesh B. Nalawade (@ganeshrn)
short_description: Manage resource modules
description:
- Get list of available resource modules for given os name
- Retrieve given resource module configuration facts
- Push given resource module configuration
options:
    os_name:
        type: str
        description:
        - The name of the os to manage the resource modules.
        - The name should be fully qualified collection name format,
          that is I(<namespace>.<collection-name>.<plugin-name>).
        - If value of this option is not set the os value will be
          read from I(ansible_network_os) variable.
        - If value of both I(os_name) and I(ansible_network_os)
          is not set it will result in error.
    name:
        type: str
        description:
        - The name of the resource module to manage.
        - The resource module should be supported for given I(os_name),
          if not supported it will result in error.
    config:
      description:
      - The resource module configuration. For details on the type and
        structure of this option refer the individual resource module
        platform documentation.
      type: raw
    running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the host device
        by executing the cli command to get the resource configuration on host.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    state:
      description:
        - The state the configuration should be left in.
        - For supported values refer the individual resource module
          platform documentation.
version_added: 2.4.0
notes:
- Refer the individual module documentation for the valid inputs of I(state)
  and I(config) modules.
"""

EXAMPLES = """
- name: get list of resource modules for given network_os
  ansible.netcommon.network_resource:
  register: result

- name: fetch acl config for
  ansible.netcommon.network_resource:
    os_name: cisco.ios.ios
    name: acls
    state: gathered

- name: manage acl config for cisco.ios.ios network os.
  ansible.netcommon.network_resource:
    name: acls
    config:
      - afi: ipv4
        acls:
          - name: test_acl
            acl_type: extended
            aces:
              - grant: deny
                protocol_options:
                  tcp:
                    fin: true
                source:
                  address: 192.0.2.0
                  wildcard_bits: 0.0.0.255
                destination:
                  address: 192.0.3.0
                  wildcard_bits: 0.0.0.255
                  port_protocol:
                    eq: www
                option:
                  traceroute: true
                ttl:
                  eq: 10
    state: merged
"""

RETURN = """
modules:
  description: List of resource modules supported for given OS.
  returned: When only I(os_name) or I(ansible_network_os) is set
  type: list
  sample: ["acl_interfaces", "acls", "bgp_global"]
before:
  description: The configuration as structured data prior to module invocation.
  returned: When I(state) and/or I(config) option is set
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed and  when I(state) and/or I(config) option is set
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
commands:
  description: The set of commands pushed to the remote device
  returned:  When I(state) and/or I(config) option is set
  type: list
  sample: ['ip access-list extended 110', ]
"""
