#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: helm_plugin_info
short_description: Gather information about Helm plugins
version_added: 1.0.0
author:
  - Abhijeet Kasurde (@Akasurde)
requirements:
  - "helm (https://github.com/helm/helm/releases)"
description:
  -  Gather information about Helm plugins installed in namespace.
options:
#Helm options
  plugin_name:
    description:
      - Name of Helm plugin, to gather particular plugin info.
    type: str
extends_documentation_fragment:
  - kubernetes.core.helm_common_options
"""

EXAMPLES = r"""
- name: Gather Helm plugin info
  kubernetes.core.helm_plugin_info:

- name: Gather Helm env plugin info
  kubernetes.core.helm_plugin_info:
    plugin_name: env
"""

RETURN = r"""
stdout:
  type: str
  description: Full `helm` command stdout, in case you want to display it or examine the event log
  returned: always
  sample: ''
stderr:
  type: str
  description: Full `helm` command stderr, in case you want to display it or examine the event log
  returned: always
  sample: ''
command:
  type: str
  description: Full `helm` command built by this module, in case you want to re-run the command outside the module or debug a problem.
  returned: always
  sample: helm plugin list ...
plugin_list:
  type: list
  description: Helm plugin dict inside a list
  returned: always
  sample: {
      "name": "env",
      "version": "0.1.0",
      "description": "Print out the helm environment."
  }
rc:
  type: int
  description: Helm plugin command return code
  returned: always
  sample: 1
"""

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.helm import (
    AnsibleHelmModule,
    parse_helm_plugin_list,
)
from ansible_collections.kubernetes.core.plugins.module_utils.helm_args_common import (
    HELM_AUTH_ARG_SPEC,
    HELM_AUTH_MUTUALLY_EXCLUSIVE,
)


def main():
    argument_spec = copy.deepcopy(HELM_AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            plugin_name=dict(
                type="str",
            ),
        )
    )

    module = AnsibleHelmModule(
        argument_spec=argument_spec,
        mutually_exclusive=HELM_AUTH_MUTUALLY_EXCLUSIVE,
        supports_check_mode=True,
    )

    plugin_name = module.params.get("plugin_name")

    plugin_list = []

    rc, output, err, command = module.get_helm_plugin_list()

    out = parse_helm_plugin_list(output=output.splitlines())

    for line in out:
        if plugin_name is None:
            plugin_list.append(
                {"name": line[0], "version": line[1], "description": line[2]}
            )
            continue

        if plugin_name == line[0]:
            plugin_list.append(
                {"name": line[0], "version": line[1], "description": line[2]}
            )
            break

    module.exit_json(
        changed=True,
        command=command,
        stdout=output,
        stderr=err,
        rc=rc,
        plugin_list=plugin_list,
    )


if __name__ == "__main__":
    main()
