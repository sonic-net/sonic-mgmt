#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: helm_plugin
short_description: Manage Helm plugins
version_added: 1.0.0
author:
  - Abhijeet Kasurde (@Akasurde)
requirements:
  - "helm (https://github.com/helm/helm/releases)"
description:
  -  Manages Helm plugins.
options:
#Helm options
  state:
    description:
      - If C(state=present) the Helm plugin will be installed.
      - If C(state=latest) the Helm plugin will be updated. Added in version 2.3.0.
      - If C(state=absent) the Helm plugin will be removed.
    choices: [ absent, present, latest ]
    default: present
    type: str
  plugin_name:
    description:
      - Name of Helm plugin.
      - Required only if C(state=absent) or C(state=latest).
    type: str
  plugin_path:
    description:
      - Plugin path to a plugin on your local file system or a url of a remote VCS repo.
      - If plugin path from file system is provided, make sure that tar is present on remote
        machine and not on Ansible controller.
      - Required only if C(state=present).
    type: str
  plugin_version:
    description:
      - Plugin version to install. If this is not specified, the latest version is installed.
      - Ignored when C(state=absent) or C(state=latest).
    required: false
    type: str
    version_added: 2.3.0
extends_documentation_fragment:
  - kubernetes.core.helm_common_options
"""

EXAMPLES = r"""
- name: Install Helm env plugin
  kubernetes.core.helm_plugin:
    plugin_path: https://github.com/adamreese/helm-env
    state: present

- name: Install Helm plugin from local filesystem
  kubernetes.core.helm_plugin:
    plugin_path: https://domain/path/to/plugin.tar.gz
    state: present

- name: Remove Helm env plugin
  kubernetes.core.helm_plugin:
    plugin_name: env
    state: absent

- name: Install Helm plugin with a specific version
  kubernetes.core.helm_plugin:
    plugin_version: 2.0.1
    plugin_path: https://domain/path/to/plugin.tar.gz
    state: present

- name: Update Helm plugin
  kubernetes.core.helm_plugin:
    plugin_name: secrets
    state: latest
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
msg:
  type: str
  description: Info about successful command
  returned: always
  sample: "Plugin installed successfully"
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


def argument_spec():
    arg_spec = copy.deepcopy(HELM_AUTH_ARG_SPEC)
    arg_spec.update(
        dict(
            plugin_path=dict(
                type="str",
            ),
            plugin_name=dict(
                type="str",
            ),
            plugin_version=dict(
                type="str",
            ),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent", "latest"],
            ),
        )
    )
    return arg_spec


def mutually_exclusive():
    mutually_ex = copy.deepcopy(HELM_AUTH_MUTUALLY_EXCLUSIVE)
    mutually_ex.append(("plugin_name", "plugin_path"))
    return mutually_ex


def main():
    module = AnsibleHelmModule(
        argument_spec=argument_spec(),
        supports_check_mode=True,
        required_if=[
            ("state", "present", ("plugin_path",)),
            ("state", "absent", ("plugin_name",)),
            ("state", "latest", ("plugin_name",)),
        ],
        mutually_exclusive=mutually_exclusive(),
    )

    state = module.params.get("state")

    helm_cmd_common = module.get_helm_binary() + " plugin"

    if state == "present":
        helm_cmd_common += " install %s" % module.params.get("plugin_path")
        plugin_version = module.params.get("plugin_version")
        if plugin_version is not None:
            helm_cmd_common += " --version=%s" % plugin_version
        if not module.check_mode:
            rc, out, err = module.run_helm_command(
                helm_cmd_common, fails_on_error=False
            )
        else:
            rc, out, err = (0, "", "")

        if rc == 1 and "plugin already exists" in err:
            module.exit_json(
                failed=False,
                changed=False,
                msg="Plugin already exists",
                command=helm_cmd_common,
                stdout=out,
                stderr=err,
                rc=rc,
            )
        elif rc == 0:
            module.exit_json(
                failed=False,
                changed=True,
                msg="Plugin installed successfully",
                command=helm_cmd_common,
                stdout=out,
                stderr=err,
                rc=rc,
            )
        else:
            module.fail_json(
                msg="Failure when executing Helm command.",
                command=helm_cmd_common,
                stdout=out,
                stderr=err,
                rc=rc,
            )
    elif state == "absent":
        plugin_name = module.params.get("plugin_name")
        rc, output, err, command = module.get_helm_plugin_list()
        out = parse_helm_plugin_list(output=output.splitlines())

        if not out:
            module.exit_json(
                failed=False,
                changed=False,
                msg="Plugin not found or is already uninstalled",
                command=command,
                stdout=output,
                stderr=err,
                rc=rc,
            )

        found = False
        for line in out:
            if line[0] == plugin_name:
                found = True
                break
        if not found:
            module.exit_json(
                failed=False,
                changed=False,
                msg="Plugin not found or is already uninstalled",
                command=command,
                stdout=output,
                stderr=err,
                rc=rc,
            )

        helm_uninstall_cmd = "%s uninstall %s" % (helm_cmd_common, plugin_name)
        if not module.check_mode:
            rc, out, err = module.run_helm_command(
                helm_uninstall_cmd, fails_on_error=False
            )
        else:
            rc, out, err = (0, "", "")

        if rc == 0:
            module.exit_json(
                changed=True,
                msg="Plugin uninstalled successfully",
                command=helm_uninstall_cmd,
                stdout=out,
                stderr=err,
                rc=rc,
            )
        module.fail_json(
            msg="Failed to get Helm plugin uninstall",
            command=helm_uninstall_cmd,
            stdout=out,
            stderr=err,
            rc=rc,
        )
    elif state == "latest":
        plugin_name = module.params.get("plugin_name")
        rc, output, err, command = module.get_helm_plugin_list()
        out = parse_helm_plugin_list(output=output.splitlines())

        if not out:
            module.exit_json(
                failed=False,
                changed=False,
                msg="Plugin not found",
                command=command,
                stdout=output,
                stderr=err,
                rc=rc,
            )

        found = False
        for line in out:
            if line[0] == plugin_name:
                found = True
                break
        if not found:
            module.exit_json(
                failed=False,
                changed=False,
                msg="Plugin not found",
                command=command,
                stdout=output,
                stderr=err,
                rc=rc,
            )

        helm_update_cmd = "%s update %s" % (helm_cmd_common, plugin_name)
        if not module.check_mode:
            rc, out, err = module.run_helm_command(
                helm_update_cmd, fails_on_error=False
            )
        else:
            rc, out, err = (0, "", "")

        if rc == 0:
            module.exit_json(
                changed=True,
                msg="Plugin updated successfully",
                command=helm_update_cmd,
                stdout=out,
                stderr=err,
                rc=rc,
            )
        module.fail_json(
            msg="Failed to get Helm plugin update",
            command=helm_update_cmd,
            stdout=out,
            stderr=err,
            rc=rc,
        )


if __name__ == "__main__":
    main()
