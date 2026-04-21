#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat, Inc.
# Based on the kubernetes.core.k8s_info module
# Apache License 2.0 (see LICENSE or http://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: kubevirt_vm_info

short_description: Describe KubeVirt VirtualMachines

author:
- "KubeVirt.io Project (!UNKNOWN)"

description:
  - Use the Kubernetes Python client to perform read operations on KubeVirt C(VirtualMachines).
  - Pass options to find C(VirtualMachines) as module arguments.
  - Authenticate using either a config file, certificates, password or token.
  - Supports check mode.

extends_documentation_fragment:
  - kubevirt.core.kubevirt_auth_options

options:
  api_version:
    description:
    - Use this to set the API version of KubeVirt.
    type: str
    default: kubevirt.io/v1
  name:
    description:
    - Specify the name of the C(VirtualMachine).
    type: str
  namespace:
    description:
    - Specify the namespace of C(VirtualMachines).
    type: str
  label_selectors:
    description: List of label selectors to use to filter results.
    type: list
    elements: str
    default: []
  field_selectors:
    description: List of field selectors to use to filter results.
    type: list
    elements: str
    default: []
  running:
    description:
    - Specify whether the C(VirtualMachine) should be running or not.
    - This affects the ready condition to wait for.
    - This requires O(wait=yes).
    type: bool
    version_added: 1.4.0
  wait:
    description:
    - Whether to wait for the C(VirtualMachine) to end up in the ready state.
    - By default this is waiting for the C(VirtualMachine) to be up and running.
    - Modify this behavior by setting O(running).
    type: bool
  wait_sleep:
    description:
    - Number of seconds to sleep between checks.
    - Ignored if O(wait) is not set.
    default: 5
    type: int
  wait_timeout:
    description:
    - How long in seconds to wait for the resource to end up in the ready state.
    - Ignored if O(wait) is not set.
    default: 120
    type: int
  hidden_fields:
    description:
    - Hide fields matching this option in the result.
    - An example might be O(hidden_fields=[metadata.managedFields])
      or O(hidden_fields=[metadata.annotations[kubemacpool.io/transaction-timestamp]]).
    type: list
    elements: str
    default: ['metadata.annotations[kubemacpool.io/transaction-timestamp]', metadata.managedFields]
    version_added: 2.2.0

requirements:
  - "python >= 3.9"
  - "kubernetes >= 28.1.0"
  - "PyYAML >= 3.11"
"""

EXAMPLES = """
- name: Get an existing VirtualMachine
  kubevirt.core.kubevirt_vm_info:
    name: testvm
    namespace: default
  register: default_testvm

- name: Get a list of all VirtualMachines
  kubevirt.core.kubevirt_vm_info:
    namespace: default
  register: vm_list

- name: Get a list of all VirtualMachines from any namespace
  kubevirt.core.kubevirt_vm_info:
  register: vm_list

- name: Search for all VirtualMachines labelled app=test
  kubevirt.core.kubevirt_vm_info:
    label_selectors:
      - app=test

- name: Wait until the VirtualMachine is running
  kubevirt.core.kubevirt_vm_info:
    name: testvm
    namespace: default
    wait: true

- name: Wait until the VirtualMachine is stopped
  kubevirt.core.kubevirt_vm_info:
    name: testvm
    namespace: default
    running: false
    wait: true
"""

RETURN = """
api_found:
  description:
  - Whether the specified O(api_version) and C(VirtualMachine) C(Kind) were successfully mapped to an existing API on the target cluster.
  returned: always
  type: bool
resources:
  description:
  - The C(VirtualMachines) that exist.
  returned: success
  type: complex
  contains:
    api_version:
      description: The versioned schema of this representation of an object.
      returned: success
      type: str
    kind:
      description: Represents the C(REST) resource this object represents.
      returned: success
      type: str
    metadata:
      description: Standard object metadata. Includes name, namespace, annotations, labels, etc.
      returned: success
      type: dict
    spec:
      description: Specific attributes of the C(VirtualMachine). Can vary based on the O(api_version).
      returned: success
      type: dict
    status:
      description: Current status details for the C(VirtualMachine).
      returned: success
      type: dict
"""

# Monkey patch service.diff_objects to temporarily fix the changed logic
from ansible_collections.kubevirt.core.plugins.module_utils.diff import (
    _patch_diff_objects,
)

from copy import deepcopy

from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import (
    AnsibleK8SModule,
)

from ansible_collections.kubevirt.core.plugins.module_utils.info import (
    INFO_ARG_SPEC,
    execute_info_module,
)


def arg_spec():
    """
    arg_spec defines the argument spec of this module.
    """
    spec = {
        "running": {"type": "bool"},
        "hidden_fields": {
            "type": "list",
            "elements": "str",
            "default": [
                "metadata.annotations[kubemacpool.io/transaction-timestamp]",
                "metadata.managedFields",
            ],
        },
    }
    spec.update(deepcopy(INFO_ARG_SPEC))
    spec.update(deepcopy(AUTH_ARG_SPEC))

    return spec


def main():
    """
    main instantiates the AnsibleK8SModule and runs the module.
    """
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        argument_spec=arg_spec(),
        required_by={"running": "wait"},
        supports_check_mode=True,
    )

    # Set kind to query for VirtualMachines
    kind = "VirtualMachine"

    # Set wait_condition to allow waiting for the ready state of the
    # VirtualMachine based on the running parameter.
    if module.params["running"] is None or module.params["running"]:
        wait_condition = {"type": "Ready", "status": True}
    else:
        wait_condition = {"type": "Ready", "status": False, "reason": "VMINotExists"}

    execute_info_module(module, kind, wait_condition)


if __name__ == "__main__":
    _patch_diff_objects()
    main()
