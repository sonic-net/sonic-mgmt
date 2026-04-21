#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Aubin Bikouo <@abikouo>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""

module: k8s_cp

short_description: Copy files and directories to and from pod.

version_added: 2.2.0

author:
    - Aubin Bikouo (@abikouo)

description:
  - Use the Kubernetes Python client to copy files and directories to and from containers inside a pod.

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

requirements:
  - "python >= 3.9"
  - "kubernetes >= 24.2.0"

options:
  namespace:
    description:
    - The pod namespace name.
    type: str
    required: yes
  pod:
    description:
    - The pod name.
    type: str
    required: yes
  container:
    description:
    - The name of the container in the pod to copy files/directories from/to.
    - Defaults to the only container if there is only one container in the pod.
    type: str
  remote_path:
    description:
    - Path of the file or directory to copy.
    type: path
    required: yes
  local_path:
    description:
    - Path of the local file or directory.
    - Required when I(state) is set to C(from_pod).
    - Mutually exclusive with I(content).
    type: path
  content:
    description:
    - When used instead of I(local_path), sets the contents of a local file directly to the specified value.
    - Works only when I(remote_path) is a file. Creates the file if it does not exist.
    - For advanced formatting or if the content contains a variable, use the M(ansible.builtin.template) module.
    - Mutually exclusive with I(local_path).
    type: str
  state:
    description:
    - When set to C(to_pod), the local I(local_path) file or directory will be copied to I(remote_path) into the pod.
    - When set to C(from_pod), the remote file or directory I(remote_path) from pod will be copied locally to I(local_path).
    type: str
    default: to_pod
    choices: [ to_pod, from_pod ]
  no_preserve:
    description:
    - The copied file/directory's ownership and permissions will not be preserved in the container.
    - This option is ignored when I(content) is set or when I(state) is set to C(from_pod).
    type: bool
    default: False

notes:
    - the tar binary is required on the container when copying from local filesystem to pod.
    - the (init) container has to be started before you copy files or directories to it.
"""

EXAMPLES = r"""
# kubectl cp /tmp/foo some-namespace/some-pod:/tmp/bar
- name: Copy /tmp/foo local file to /tmp/bar in a remote pod
  kubernetes.core.k8s_cp:
    namespace: some-namespace
    pod: some-pod
    remote_path: /tmp/bar
    local_path: /tmp/foo

# kubectl cp /tmp/foo_dir some-namespace/some-pod:/tmp/bar_dir
- name: Copy /tmp/foo_dir local directory to /tmp/bar_dir in a remote pod
  kubernetes.core.k8s_cp:
    namespace: some-namespace
    pod: some-pod
    remote_path: /tmp/bar_dir
    local_path: /tmp/foo_dir

# kubectl cp /tmp/foo some-namespace/some-pod:/tmp/bar -c some-container
- name: Copy /tmp/foo local file to /tmp/bar in a remote pod in a specific container
  kubernetes.core.k8s_cp:
    namespace: some-namespace
    pod: some-pod
    container: some-container
    remote_path: /tmp/bar
    local_path: /tmp/foo
    no_preserve: True
    state: to_pod

# kubectl cp some-namespace/some-pod:/tmp/foo /tmp/bar
- name: Copy /tmp/foo from a remote pod to /tmp/bar locally
  kubernetes.core.k8s_cp:
    namespace: some-namespace
    pod: some-pod
    remote_path: /tmp/foo
    local_path: /tmp/bar
    state: from_pod

# copy content into a file in the remote pod
- name: Copy content into a file in the remote pod
  kubernetes.core.k8s_cp:
    state: to_pod
    namespace: some-namespace
    pod: some-pod
    remote_path: /tmp/foo.txt
    content: "This content will be copied into remote file"
"""


RETURN = r"""
result:
  description:
  - message describing the copy operation successfully done.
  returned: success
  type: str
"""

import copy

from ansible.module_utils._text import to_native
from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)
from ansible_collections.kubernetes.core.plugins.module_utils.copy import (
    K8SCopyFromPod,
    K8SCopyToPod,
    check_pod,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import (
    AnsibleK8SModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    K8sService,
)


def argspec():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec["namespace"] = {"type": "str", "required": True}
    argument_spec["pod"] = {"type": "str", "required": True}
    argument_spec["container"] = {}
    argument_spec["remote_path"] = {"type": "path", "required": True}
    argument_spec["local_path"] = {"type": "path"}
    argument_spec["content"] = {"type": "str"}
    argument_spec["state"] = {
        "type": "str",
        "default": "to_pod",
        "choices": ["to_pod", "from_pod"],
    }
    argument_spec["no_preserve"] = {"type": "bool", "default": False}
    return argument_spec


def execute_module(module):
    client = get_api_client(module=module)
    svc = K8sService(client, module)
    containers = check_pod(svc)
    if len(containers) > 1 and module.params.get("container") is None:
        module.fail_json(
            msg="Pod contains more than 1 container, option 'container' should be set"
        )

    state = module.params.get("state")
    if state == "to_pod":
        k8s_copy = K8SCopyToPod(module, client.client)
    else:
        k8s_copy = K8SCopyFromPod(module, client.client)

    try:
        k8s_copy.run()
    except Exception as e:
        module.fail_json("Failed to copy object due to: {0}".format(to_native(e)))


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        argument_spec=argspec(),
        check_pyyaml=False,
        mutually_exclusive=[("local_path", "content")],
        required_if=[("state", "from_pod", ["local_path"])],
        required_one_of=[["local_path", "content"]],
        supports_check_mode=True,
    )

    try:
        execute_module(module)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
