#
#  Copyright 2021 Red Hat | Ansible
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
    name: kustomize

    short_description: Build a set of kubernetes resources using a 'kustomization.yaml' file.

    version_added: 2.2.0

    author:
      - Aubin Bikouo (@abikouo)
    notes:
      - If both kustomize and kubectl are part of the PATH, kustomize will be used by the plugin.
    description:
      - Uses the kustomize or the kubectl tool.
      - Return the result of C(kustomize build) or C(kubectl kustomize).
    options:
      dir:
        description:
        - The directory path containing 'kustomization.yaml',
          or a git repository URL with a path suffix specifying same with respect to the repository root.
        - If omitted, '.' is assumed.
        default: "."
      binary_path:
        description:
        - The path of a kustomize or kubectl binary to use.
      opt_dirs:
        description:
        - An optional list of directories to search for the executable in addition to PATH.
      enable_helm:
        description:
        - Enable the helm chart inflation generator
        default: "False"
      environment:
        description:
        - The environment variables to pass to the kustomize or kubectl command.
        - This can be a dictionary or a string in the format key=value, multiple pairs separated by space.
        type: raw
        default: {}
        version_added: 6.2.0

    requirements:
      - "python >= 3.6"
"""

EXAMPLES = """
- name: Run lookup using kustomize
  ansible.builtin.set_fact:
    resources: "{{ lookup('kubernetes.core.kustomize', binary_path='/path/to/kustomize') }}"

- name: Run lookup using kubectl kustomize
  ansible.builtin.set_fact:
    resources: "{{ lookup('kubernetes.core.kustomize', binary_path='/path/to/kubectl') }}"

- name: Create kubernetes resources for lookup output
  kubernetes.core.k8s:
    definition: "{{ lookup('kubernetes.core.kustomize', dir='/path/to/kustomization') }}"

- name: Create kubernetes resources for lookup output with `--enable-helm` set
  kubernetes.core.k8s:
    definition: "{{ lookup('kubernetes.core.kustomize', dir='/path/to/kustomization', enable_helm=True) }}"

- name: Create kubernetes resources for lookup output with environment variables in string format
  kubernetes.core.k8s:
    definition: "{{ lookup('kubernetes.core.kustomize', binary_path='/path/to/kubectl', environment='HTTP_PROXY=http://proxy.example.com:3128') }}"

- name: Create kubernetes resources for lookup output with environment variables in dict format
  kubernetes.core.k8s:
    definition: "{{ lookup('kubernetes.core.kustomize', binary_path='/path/to/kubectl', environment={'HTTP_PROXY': 'http://proxy.example.com:3128'}) }}"
"""

RETURN = """
  _list:
    description:
      - YAML string for the object definitions returned from the tool execution.
    type: str
    sample:
      kind: ConfigMap
      apiVersion: v1
      metadata:
        name: my-config-map
        namespace: default
      data:
        key1: val1
"""

import os
import subprocess

from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.process import get_bin_path
from ansible.plugins.lookup import LookupBase


def get_binary_from_path(name, opt_dirs=None):
    opt_arg = {}
    try:
        if opt_dirs is not None:
            if not isinstance(opt_dirs, list):
                opt_dirs = [opt_dirs]
            opt_arg["opt_dirs"] = opt_dirs
        bin_path = get_bin_path(name, **opt_arg)
        return bin_path
    except ValueError:
        return None


def run_command(command, environ=None):
    cmd = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environ
    )
    stdout, stderr = cmd.communicate()
    return cmd.returncode, stdout, stderr


class LookupModule(LookupBase):
    def run(
        self,
        terms,
        variables=None,
        dir=".",
        binary_path=None,
        opt_dirs=None,
        enable_helm=False,
        environment=None,
        **kwargs
    ):
        executable_path = binary_path
        if executable_path is None:
            executable_path = get_binary_from_path(name="kustomize", opt_dirs=opt_dirs)
            if executable_path is None:
                executable_path = get_binary_from_path(
                    name="kubectl", opt_dirs=opt_dirs
                )

            # validate that at least one tool was found
            if executable_path is None:
                raise AnsibleLookupError(
                    "Failed to find required executable 'kubectl' and 'kustomize' in paths"
                )

        # check input directory
        kustomization_dir = dir

        command = [executable_path]
        if executable_path.endswith("kustomize"):
            command += ["build", kustomization_dir]
        elif executable_path.endswith("kubectl"):
            command += ["kustomize", kustomization_dir]
        else:
            raise AnsibleLookupError(
                "unexpected tool provided as parameter {0}, expected one of kustomize, kubectl.".format(
                    executable_path
                )
            )

        if enable_helm:
            command += ["--enable-helm"]

        environ = None
        if environment:
            environ = os.environ.copy()
            if isinstance(environment, str):
                if not all(env.count("=") == 1 for env in environment.split(" ")):
                    raise AnsibleLookupError(
                        "environment should be dict or string in the format key=value, multiple pairs separated by space"
                    )
                for env in environment.split(" "):
                    key, value = env.split("=")
                    environ[key] = value
            if isinstance(environment, dict):
                environ.update(environment)

        (ret, out, err) = run_command(command, environ=environ)
        if ret != 0:
            if err:
                raise AnsibleLookupError(
                    "kustomize command failed. exit code: {0}, error: {1}".format(
                        ret, err.decode("utf-8")
                    )
                )
            else:
                raise AnsibleLookupError(
                    "kustomize command failed with unknown error. exit code: {0}".format(
                        ret
                    )
                )
        return [out.decode("utf-8")]
