#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: helm_repository

short_description: Manage Helm repositories.

version_added: 0.11.0

author:
  - Lucas Boisserie (@LucasBoisserie)

requirements:
  - "helm (https://github.com/helm/helm/releases)"
  - "yaml (https://pypi.org/project/PyYAML/)"

description:
  -  Manage Helm repositories.

options:
  binary_path:
    description:
      - The path of a helm binary to use.
    required: false
    type: path
  repo_name:
    description:
      - Chart repository name.
    required: true
    type: str
    aliases: [ name ]
  repo_url:
    description:
      - Chart repository url
    type: str
    aliases: [ url ]
  repo_username:
    description:
      - Chart repository username for repository with basic auth.
      - Required if chart_repo_password is specified.
    required: false
    type: str
    aliases: [ username ]
  repo_password:
    description:
      - Chart repository password for repository with basic auth.
      - Required if chart_repo_username is specified.
    required: false
    type: str
    aliases: [ password ]
  repo_state:
    choices: ['present', 'absent']
    description:
      - Desired state of repository.
    required: false
    default: present
    aliases: [ state ]
    type: str
  pass_credentials:
    description:
      - Pass credentials to all domains.
    required: false
    default: false
    type: bool
    version_added: 2.3.0
  host:
    description:
    - Provide a URL for accessing the API. Can also be specified via C(K8S_AUTH_HOST) environment variable.
    type: str
    version_added: 2.3.0
  api_key:
    description:
    - Token used to authenticate with the API. Can also be specified via C(K8S_AUTH_API_KEY) environment variable.
    type: str
    version_added: 2.3.0
  validate_certs:
    description:
    - Whether or not to verify the API server's SSL certificates. Can also be specified via C(K8S_AUTH_VERIFY_SSL)
      environment variable.
    type: bool
    aliases: [ verify_ssl ]
    default: True
    version_added: 2.3.0
  ca_cert:
    description:
    - Path to a CA certificate used to authenticate with the API. The full certificate chain must be provided to
      avoid certificate validation errors. Can also be specified via C(K8S_AUTH_SSL_CA_CERT) environment variable.
    type: path
    aliases: [ ssl_ca_cert ]
    version_added: 2.3.0
  context:
    description:
      - Helm option to specify which kubeconfig context to use.
      - If the value is not specified in the task, the value of environment variable C(K8S_AUTH_CONTEXT) will be used instead.
    type: str
    aliases: [ kube_context ]
    version_added: 2.4.0
  kubeconfig:
    description:
      - Helm option to specify kubeconfig path to use.
      - If the value is not specified in the task, the value of environment variable C(K8S_AUTH_KUBECONFIG) will be used instead.
      - The configuration can be provided as dictionary.
    type: raw
    aliases: [ kubeconfig_path ]
    version_added: 2.4.0
  force_update:
    description:
    - Whether or not to replace (overwrite) the repo if it already exists.
    type: bool
    aliases: [ force ]
    default: False
    version_added: 2.4.0
  insecure_skip_tls_verify:
    description:
      - Skip tls certificate checks for the repository url.
    type: bool
    default: False
    aliases: [ skip_tls_certs_check ]
    version_added: "5.3.0"
"""

EXAMPLES = r"""
- name: Add a repository
  kubernetes.core.helm_repository:
    name: stable
    repo_url: https://kubernetes.github.io/ingress-nginx

- name: Add Red Hat Helm charts repository
  kubernetes.core.helm_repository:
    name: redhat-charts
    repo_url: https://redhat-developer.github.com/redhat-helm-charts
"""

RETURN = r"""
stdout:
  type: str
  description: Full `helm` command stdout, in case you want to display it or examine the event log
  returned: always
  sample: '"bitnami" has been added to your repositories'
stdout_lines:
  type: list
  description: Full `helm` command stdout in list, in case you want to display it or examine the event log
  returned: always
  sample: ["\"bitnami\" has been added to your repositories"]
stderr:
  type: str
  description: Full `helm` command stderr, in case you want to display it or examine the event log
  returned: always
  sample: ''
stderr_lines:
  type: list
  description: Full `helm` command stderr in list, in case you want to display it or examine the event log
  returned: always
  sample: [""]
command:
  type: str
  description: Full `helm` command built by this module, in case you want to re-run the command outside the module or debug a problem.
  returned: always
  sample: '/usr/local/bin/helm repo add bitnami https://charts.bitnami.com/bitnami'
msg:
  type: str
  description: Error message returned by `helm` command
  returned: on failure
  sample: 'Repository already have a repository named bitnami'
"""

import copy
import traceback

try:
    import yaml

    IMP_YAML = True
    IMP_YAML_ERR = None
except ImportError:
    IMP_YAML_ERR = traceback.format_exc()
    IMP_YAML = False

from ansible.module_utils.basic import missing_required_lib
from ansible_collections.kubernetes.core.plugins.module_utils.helm import (
    AnsibleHelmModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.helm_args_common import (
    HELM_AUTH_ARG_SPEC,
    HELM_AUTH_MUTUALLY_EXCLUSIVE,
)


# Get repository from all repositories added
def get_repository(state, repo_name):
    if state is not None:
        for repository in state:
            if repository["name"] == repo_name:
                return repository
    return None


# Get repository status
def get_repository_status(module, repository_name):
    list_command = module.get_helm_binary() + " repo list --output=yaml"

    rc, out, err = module.run_helm_command(list_command, fails_on_error=False)

    # no repo => rc=1 and 'no repositories to show' in output
    if rc == 1 and "no repositories to show" in err:
        return None
    elif rc != 0:
        module.fail_json(
            msg="Failure when executing Helm command. Exited {0}.\nstdout: {1}\nstderr: {2}".format(
                rc, out, err
            ),
            command=list_command,
        )

    return get_repository(yaml.safe_load(out), repository_name)


# Install repository
def install_repository(
    command,
    repository_name,
    repository_url,
    repository_username,
    repository_password,
    pass_credentials,
    force_update,
    insecure_skip_tls_verify,
):
    install_command = command + " repo add " + repository_name + " " + repository_url

    if repository_username is not None and repository_password is not None:
        install_command += " --username=" + repository_username
        install_command += " --password=" + repository_password

    if pass_credentials:
        install_command += " --pass-credentials"

    if force_update:
        install_command += " --force-update"

    if insecure_skip_tls_verify:
        install_command += " --insecure-skip-tls-verify"

    return install_command


# Delete repository
def delete_repository(command, repository_name):
    remove_command = command + " repo rm " + repository_name

    return remove_command


def argument_spec():
    arg_spec = copy.deepcopy(HELM_AUTH_ARG_SPEC)
    arg_spec.update(
        dict(
            repo_name=dict(type="str", aliases=["name"], required=True),
            repo_url=dict(type="str", aliases=["url"]),
            repo_username=dict(type="str", aliases=["username"]),
            repo_password=dict(type="str", aliases=["password"], no_log=True),
            repo_state=dict(
                default="present", choices=["present", "absent"], aliases=["state"]
            ),
            pass_credentials=dict(type="bool", default=False, no_log=True),
            force_update=dict(type="bool", default=False, aliases=["force"]),
            insecure_skip_tls_verify=dict(
                type="bool", default=False, aliases=["skip_tls_certs_check"]
            ),
        )
    )
    return arg_spec


def main():
    global module

    module = AnsibleHelmModule(
        argument_spec=argument_spec(),
        required_together=[["repo_username", "repo_password"]],
        required_if=[("repo_state", "present", ["repo_url"])],
        mutually_exclusive=HELM_AUTH_MUTUALLY_EXCLUSIVE,
        supports_check_mode=True,
    )

    if not IMP_YAML:
        module.fail_json(msg=missing_required_lib("yaml"), exception=IMP_YAML_ERR)

    changed = False

    repo_name = module.params.get("repo_name")
    repo_url = module.params.get("repo_url")
    repo_username = module.params.get("repo_username")
    repo_password = module.params.get("repo_password")
    repo_state = module.params.get("repo_state")
    pass_credentials = module.params.get("pass_credentials")
    force_update = module.params.get("force_update")
    insecure_skip_tls_verify = module.params.get("insecure_skip_tls_verify")

    helm_cmd = module.get_helm_binary()

    repository_status = get_repository_status(module, repo_name)

    if repo_state == "absent" and repository_status is not None:
        helm_cmd = delete_repository(helm_cmd, repo_name)
        changed = True
    elif repo_state == "present":
        if repository_status is None or force_update:
            helm_cmd = install_repository(
                helm_cmd,
                repo_name,
                repo_url,
                repo_username,
                repo_password,
                pass_credentials,
                force_update,
                insecure_skip_tls_verify,
            )
            changed = True
        elif repository_status["url"] != repo_url:
            module.fail_json(
                msg="Repository already have a repository named {0}".format(repo_name)
            )

    if module.check_mode:
        module.exit_json(changed=changed)
    elif not changed:
        module.exit_json(changed=False, repo_name=repo_name, repo_url=repo_url)

    rc, out, err = module.run_helm_command(helm_cmd)

    if repo_password is not None:
        helm_cmd = helm_cmd.replace(repo_password, "******")

    if rc != 0:
        module.fail_json(
            msg="Failure when executing Helm command. Exited {0}.\nstdout: {1}\nstderr: {2}".format(
                rc, out, err
            ),
            command=helm_cmd,
        )

    module.exit_json(changed=changed, stdout=out, stderr=err, command=helm_cmd)


if __name__ == "__main__":
    main()
