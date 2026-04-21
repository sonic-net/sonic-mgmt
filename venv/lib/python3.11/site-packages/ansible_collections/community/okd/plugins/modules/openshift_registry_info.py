#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_registry_info

short_description: Display information about the integrated registry.

version_added: "2.2.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module exposes information about the integrated registry.
  - Use C(check) to verify your local client can access the registry.
  - If the adminstrator has not configured a public hostname for the registry then
    this command may fail when run outside of the server.
  - Analogous to C(oc registry info).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  check:
    description:
    - Attempt to contact the integrated registry using local client.
    type: bool
    default: False

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
  - docker-image-py
"""

EXAMPLES = r"""
# Get registry information
- name: Read integrated registry information
  community.okd.openshift_registry_info:

# Read registry integrated information and attempt to contact using local client.
- name: Attempt to contact integrated registry using local client
  community.okd.openshift_registry_info:
    check: true
"""


RETURN = r"""
internal_hostname:
  description:
    -  The internal registry hostname.
  type: str
  returned: success
public_hostname:
  description:
    -  The public registry hostname.
  type: str
  returned: success
check:
  description:
    - Whether the local client can contact or not the registry.
  type: dict
  returned: success
  contains:
    reached:
      description: Whether the registry has been reached or not.
      returned: success
      type: str
    msg:
      description: message describing the ping operation.
      returned: always
      type: str
"""
# ENDREMOVE (downstream)

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)


def argument_spec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(dict(check=dict(type="bool", default=False)))
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_registry import (
        OpenShiftRegistry,
    )

    module = OpenShiftRegistry(argument_spec=argument_spec(), supports_check_mode=True)
    module.run_module()


if __name__ == "__main__":
    main()
