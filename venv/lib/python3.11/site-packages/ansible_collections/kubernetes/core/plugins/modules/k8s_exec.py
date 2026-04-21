#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""

module: k8s_exec

short_description: Execute command in Pod

version_added: 0.10.0

author: "Tristan de Cacqueray (@tristanC)"

description:
  - Use the Kubernetes Python client to execute command on K8s pods.

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

requirements:
  - "python >= 3.9"
  - "kubernetes >= 24.2.0"
  - "PyYAML >= 3.11"

notes:
  - Return code C(rc) for the command executed is added in output in version 2.2.0, and deprecates return code C(return_code).
  - Return code C(return_code) for the command executed is added in output in version 1.0.0.
  - The authenticated user must have at least read access to the pods resource and write access to the pods/exec resource.

options:
  proxy:
    description:
    - The URL of an HTTP proxy to use for the connection.
    - Can also be specified via I(K8S_AUTH_PROXY) environment variable.
    - Please note that this module does not pick up typical proxy settings from the environment (for example, HTTP_PROXY).
    type: str
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
    - The name of the container in the pod to connect to.
    - Defaults to only container if there is only one container in the pod.
    - If not specified, will choose the first container from the given pod as kubectl cmdline does.
    type: str
    required: no
  command:
    description:
    - The command to execute.
    type: str
    required: yes
"""

EXAMPLES = r"""
- name: Execute a command
  kubernetes.core.k8s_exec:
    namespace: myproject
    pod: zuul-scheduler
    command: zuul-scheduler full-reconfigure

- name: Check RC status of command executed
  kubernetes.core.k8s_exec:
    namespace: myproject
    pod: busybox-test
    command: cmd_with_non_zero_exit_code
  register: command_status
  ignore_errors: True

- name: Check last command status
  debug:
    msg: "cmd failed"
  when: command_status.rc != 0

- name: Specify a container name to execute the command on
  kubernetes.core.k8s_exec:
    namespace: myproject
    pod: busybox-test
    container: manager
    command: echo "hello"
"""

RETURN = r"""
result:
  description:
  - The command object
  returned: success
  type: complex
  contains:
     stdout:
       description: The command stdout
       type: str
     stdout_lines:
       description: The command stdout
       type: str
     stderr:
       description: The command stderr
       type: str
     stderr_lines:
       description: The command stderr
       type: str
     rc:
       description: The command status code
       type: int
       version_added: 2.2.0
     return_code:
       description: The command status code. This attribute is deprecated and will be removed in a future release. Please use rc instead.
       type: int
"""

import copy
import shlex

try:
    import yaml
except ImportError:
    # ImportError are managed by the common module already.
    pass

from ansible.module_utils._text import to_native
from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
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

try:
    from kubernetes.client.apis import core_v1_api
    from kubernetes.client.exceptions import ApiException
    from kubernetes.stream import stream
except ImportError:
    # ImportError are managed by the common module already.
    pass


def argspec():
    spec = copy.deepcopy(AUTH_ARG_SPEC)
    spec["namespace"] = dict(type="str", required=True)
    spec["pod"] = dict(type="str", required=True)
    spec["container"] = dict(type="str")
    spec["command"] = dict(type="str", required=True)
    return spec


def execute_module(module, client):
    # Load kubernetes.client.Configuration
    api = core_v1_api.CoreV1Api(client.client)

    # hack because passing the container as None breaks things
    optional_kwargs = {}
    if module.params.get("container"):
        optional_kwargs["container"] = module.params["container"]
    else:
        # default to the first container available on pod
        resp = None
        try:
            resp = api.read_namespaced_pod(
                name=module.params["pod"], namespace=module.params["namespace"]
            )
        except ApiException:
            pass

        if resp and len(resp.spec.containers) >= 1:
            optional_kwargs["container"] = resp.spec.containers[0].name

    try:
        resp = stream(
            api.connect_get_namespaced_pod_exec,
            module.params["pod"],
            module.params["namespace"],
            command=shlex.split(module.params["command"]),
            stdout=True,
            stderr=True,
            stdin=False,
            tty=False,
            _preload_content=False,
            **optional_kwargs
        )
    except Exception as e:
        module.fail_json(
            msg="Failed to execute on pod %s"
            " due to : %s" % (module.params.get("pod"), to_native(e))
        )
    stdout, stderr, rc = [], [], 0
    while resp.is_open():
        resp.update(timeout=1)
        if resp.peek_stdout():
            stdout.append(resp.read_stdout())
        if resp.peek_stderr():
            stderr.append(resp.read_stderr())
    err = resp.read_channel(3)
    err = yaml.safe_load(err)
    if err["status"] == "Success":
        rc = 0
    else:
        rc = int(err["details"]["causes"][0]["message"])

    module.exit_json(
        # Some command might change environment, but ultimately failing at end
        changed=True,
        stdout="".join(stdout),
        stderr="".join(stderr),
        rc=rc,
        return_code=rc,
    )


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        check_pyyaml=False,
        argument_spec=argspec(),
        supports_check_mode=True,
    )

    try:
        client = get_api_client(module)
        execute_module(module, client.client)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
