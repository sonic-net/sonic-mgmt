#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: helm

short_description: Manages Kubernetes packages with the Helm package manager

version_added: 0.11.0

author:
  - Lucas Boisserie (@LucasBoisserie)
  - Matthieu Diehr (@d-matt)

requirements:
  - "helm (https://github.com/helm/helm/releases)"
  - "yaml (https://pypi.org/project/PyYAML/)"

description:
  - Install, upgrade, delete packages with the Helm package manager.

notes:
  - The default idempotency check can fail to report changes when C(release_state) is set to C(present)
    and C(chart_repo_url) is defined. Install helm diff >= 3.4.1 for better results.

options:
  chart_ref:
    description:
      - chart_reference on chart repository.
      - path to a packaged chart.
      - path to an unpacked chart directory.
      - absolute URL.
      - Required when I(release_state) is set to C(present).
    required: false
    type: path
  chart_repo_url:
    description:
      - Chart repository URL where to locate the requested chart.
    required: false
    type: str
  chart_version:
    description:
      - Chart version to install. If this is not specified, the latest version is installed.
    required: false
    type: str
  dependency_update:
    description:
      - Run standalone C(helm dependency update CHART) before the operation.
      - Run inline C(--dependency-update) with C(helm install) command. This feature is not supported yet with the C(helm upgrade) command.
      - So we should consider to use I(dependency_update) options with I(replace) option enabled when specifying I(chart_repo_url).
      - The I(dependency_update) option require the add of C(dependencies) block in C(Chart.yaml/requirements.yaml) file.
      - For more information please visit U(https://helm.sh/docs/helm/helm_dependency/)
    default: false
    type: bool
    aliases: [ dep_up ]
    version_added: 2.4.0
  release_name:
    description:
      - Release name to manage.
    required: true
    type: str
    aliases: [ name ]
  release_namespace:
    description:
      - Kubernetes namespace where the chart should be installed.
    required: true
    type: str
    aliases: [ namespace ]
  release_state:
    choices: ['present', 'absent']
    description:
      - Desirated state of release.
    required: false
    default: present
    aliases: [ state ]
    type: str
  release_values:
    description:
        - Value to pass to chart.
    required: false
    default: {}
    aliases: [ values ]
    type: dict
  values_files:
    description:
        - Value files to pass to chart.
        - Paths will be read from the target host's filesystem, not the host running ansible.
        - values_files option is evaluated before values option if both are used.
        - Paths are evaluated in the order the paths are specified.
    required: false
    default: []
    type: list
    elements: str
    version_added: 1.1.0
  update_repo_cache:
    description:
      - Run C(helm repo update) before the operation. Can be run as part of the package installation or as a separate step (see Examples).
    default: false
    type: bool
  set_values:
    description:
      - Values to pass to chart configuration
    required: false
    type: list
    elements: dict
    suboptions:
      value:
        description:
          - Value to pass to chart configuration (e.g phase=prod).
        type: str
        required: true
      value_type:
        description:
          - Use C(raw) set individual value.
          - Use C(string) to force a string for an individual value.
          - Use C(file) to set individual values from a file when the value itself is too long for the command line or is dynamically generated.
          - Use C(json) to set json values (scalars/objects/arrays). This feature requires helm>=3.10.0.
        default: raw
        choices:
          - raw
          - string
          - json
          - file
    version_added: 2.4.0
  reuse_values:
    description:
      - When upgrading package, specifies wether to reuse the last release's values and merge in any overrides from parameters I(release_values),
        I(values_files) or I(set_values).
      - If I(reset_values) is set to C(True), this is ignored.
    type: bool
    required: false
    version_added: 3.0.0
  reset_values:
    description:
      - When upgrading package, reset the values to the ones built into the chart.
    type: bool
    required: false
    default: True
    version_added: 3.0.0
  reset_then_reuse_values:
    description:
      - When upgrading package, reset the values to the ones built into the chart, apply the last release's values and merge in any overrides from
        parameters O(release_values), O(values_files) or O(set_values).
      - If O(reset_values) or O(reuse_values) is set to V(True), this is ignored.
      - This feature requires helm diff >= 3.9.12.
    type: bool
    required: false
    default: False
    version_added: 6.0.0

#Helm options
  disable_hook:
    description:
      - Helm option to disable hook on install/upgrade/delete.
    default: False
    type: bool
  force:
    description:
      - Helm option to force reinstall, ignore on new install.
    default: False
    type: bool
  purge:
    description:
      - Remove the release from the store and make its name free for later use.
    default: True
    type: bool
  wait:
    description:
      - When I(release_state) is set to C(present), wait until all Pods, PVCs, Services,
        and minimum number of Pods of a Deployment are in a ready state before marking the release as successful.
      - When I(release_state) is set to C(absent), will wait until all the resources are deleted before returning.
        It will wait for as long as I(wait_timeout). This feature requires helm>=3.7.0. Added in version 2.3.0.
    default: False
    type: bool
  wait_timeout:
    description:
      - Timeout when wait option is enabled (helm2 is a number of seconds, helm3 is a duration).
      - The use of I(wait_timeout) to wait for kubernetes commands to complete has been deprecated and will be removed after 2022-12-01.
    type: str
  timeout:
    description:
      - A Go duration (described here I(https://pkg.go.dev/time#ParseDuration)) value to wait for Kubernetes commands to complete. This defaults to 5m0s.
      - similar to C(wait_timeout) but does not required C(wait) to be activated.
      - Mutually exclusive with C(wait_timeout).
    type: str
    version_added: 2.3.0
  atomic:
    description:
      - If set, the installation process deletes the installation on failure.
    type: bool
    default: False
  create_namespace:
    description:
      - Create the release namespace if not present.
    type: bool
    default: False
    version_added: 0.11.1
  post_renderer:
    description:
      - Path to an executable to be used for post rendering.
    type: str
    version_added: 2.4.0
  replace:
    description:
      - Reuse the given name, only if that name is a deleted release which remains in the history.
      - This is unsafe in production environment.
      - mutually exclusive with with C(history_max).
    type: bool
    default: False
    version_added: 1.11.0
  skip_crds:
    description:
      - Skip custom resource definitions when installing or upgrading.
    type: bool
    default: False
    version_added: 1.2.0
  history_max:
    description:
      - Limit the maximum number of revisions saved per release.
      - mutually exclusive with with C(replace).
    type: int
    version_added: 2.2.0
  insecure_skip_tls_verify:
    description:
      - Skip tls certificate checks for the chart download.
      - Do not confuse with the C(validate_certs) option.
      - This option is only available for helm >= 3.16.0.
    type: bool
    default: False
    aliases: [ skip_tls_certs_check ]
    version_added: 5.3.0
  plain_http:
    description:
      - Use HTTP instead of HTTPS when working with OCI registries
      - Requires Helm >= 3.13.0
    type: bool
    default: False
    version_added: 6.1.0
  take_ownership:
    description:
      - When upgrading, Helm will ignore the check for helm annotations and take ownership of the existing resources
      - This feature requires helm >= 3.17.0
    type: bool
    default: False
    version_added: 6.1.0
  skip_schema_validation:
    description:
      - Disables JSON schema validation for Chart and values.
      - This feature requires helm >= 3.16.0
    type: bool
    default: False
    version_added: 6.2.0
extends_documentation_fragment:
  - kubernetes.core.helm_common_options
"""

EXAMPLES = r"""
- name: Deploy latest version of Prometheus chart inside monitoring namespace (and create it)
  kubernetes.core.helm:
    name: test
    chart_ref: stable/prometheus
    release_namespace: monitoring
    create_namespace: true

# From repository
- name: Add stable chart repo
  kubernetes.core.helm_repository:
    name: stable
    repo_url: "https://kubernetes.github.io/ingress-nginx"

- name: Deploy latest version of Grafana chart inside monitoring namespace with values
  kubernetes.core.helm:
    name: test
    chart_ref: stable/grafana
    release_namespace: monitoring
    values:
      replicas: 2

- name: Deploy Grafana chart on 5.0.12 with values loaded from template
  kubernetes.core.helm:
    name: test
    chart_ref: stable/grafana
    chart_version: 5.0.12
    values: "{{ lookup('template', 'somefile.yaml') | from_yaml }}"

- name: Deploy Grafana chart using values files on target
  kubernetes.core.helm:
    name: test
    chart_ref: stable/grafana
    release_namespace: monitoring
    values_files:
      - /path/to/values.yaml

- name: Remove test release and waiting suppression ending
  kubernetes.core.helm:
    name: test
    state: absent
    wait: true

- name: Separately update the repository cache
  kubernetes.core.helm:
    name: dummy
    namespace: kube-system
    state: absent
    update_repo_cache: true

- name: Deploy Grafana chart using set values on target
  kubernetes.core.helm:
    name: test
    chart_ref: stable/grafana
    release_namespace: monitoring
    set_values:
      - value: phase=prod
        value_type: string

# From git
- name: Git clone stable repo on HEAD
  ansible.builtin.git:
    repo: "http://github.com/helm/charts.git"
    dest: /tmp/helm_repo

- name: Deploy Grafana chart from local path
  kubernetes.core.helm:
    name: test
    chart_ref: /tmp/helm_repo/stable/grafana
    release_namespace: monitoring

# From url
- name: Deploy Grafana chart on 5.6.0 from url
  kubernetes.core.helm:
    name: test
    chart_ref: "https://github.com/grafana/helm-charts/releases/download/grafana-5.6.0/grafana-5.6.0.tgz"
    release_namespace: monitoring

- name: Deploy Bitnami's MongoDB latest chart from OCI registry
  kubernetes.core.helm:
    name: test
    chart_ref: "oci://registry-1.docker.io/bitnamicharts/mongodb"
    release_namespace: database

# Using complex Values
- name: Deploy new-relic client chart
  kubernetes.core.helm:
    name: newrelic-bundle
    chart_ref: newrelic/nri-bundle
    release_namespace: default
    force: True
    wait: True
    replace: True
    update_repo_cache: True
    disable_hook: True
    values:
      global:
        licenseKey: "{{ nr_license_key }}"
        cluster: "{{ site_name }}"
      newrelic-infrastructure:
        privileged: True
      ksm:
        enabled: True
      prometheus:
        enabled: True
      kubeEvents:
        enabled: True
      logging:
        enabled: True

# Deploy latest version
- name: Deploy latest version of Grafana chart using reuse_values
  kubernetes.core.helm:
    name: test
    chart_ref: stable/grafana
    release_namespace: monitoring
    reuse_values: true
    values:
      replicas: 2
      version: 3e8ec0b2dffa40fb97d5342e4af887de95faa8c61a62480dd7f8aa03dffcf533
"""

RETURN = r"""
status:
  type: complex
  description: A dictionary of status output
  returned: on success Creation/Upgrade/Already deploy
  contains:
    appversion:
      type: str
      returned: always
      description: Version of app deployed
    chart:
      type: str
      returned: always
      description: Chart name and chart version
    name:
      type: str
      returned: always
      description: Name of the release
    namespace:
      type: str
      returned: always
      description: Namespace where the release is deployed
    revision:
      type: str
      returned: always
      description: Number of time where the release has been updated
    status:
      type: str
      returned: always
      description: Status of release (can be DEPLOYED, FAILED, ...)
    updated:
      type: str
      returned: always
      description: The Date of last update
    values:
      type: str
      returned: always
      description: Dict of Values used to deploy
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
  sample: helm upgrade ...
"""

import copy
import re
import tempfile
import traceback

from ansible_collections.kubernetes.core.plugins.module_utils.version import (
    LooseVersion,
)

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
    parse_helm_plugin_list,
)
from ansible_collections.kubernetes.core.plugins.module_utils.helm_args_common import (
    HELM_AUTH_ARG_SPEC,
)


def get_release(state, release_name):
    """
    Get Release from all deployed releases
    """

    if state is not None:
        for release in state:
            if release["name"] == release_name:
                return release
    return None


def get_release_status(module, release_name, all_status=False):
    """
    Get Release state from all release status (deployed, failed, pending-install, etc)
    """

    list_command = [
        module.get_helm_binary(),
        "list",
        "--output=yaml",
        "--filter",
        release_name,
    ]
    if all_status:
        list_command.append("--all")

    rc, out, err = module.run_helm_command(list_command)

    release = get_release(yaml.safe_load(out), release_name)

    if release is None:  # not install
        return None

    release["values"] = module.get_values(release_name)

    return release


def run_repo_update(module):
    """
    Run Repo update
    """
    repo_update_command = module.get_helm_binary() + " repo update"
    rc, out, err = module.run_helm_command(repo_update_command)


def run_dep_update(module, chart_ref):
    """
    Run dependency update
    """
    dep_update = module.get_helm_binary() + f" dependency update '{chart_ref}'"
    rc, out, err = module.run_helm_command(dep_update)


def fetch_chart_info(
    module, command, chart_ref, insecure_skip_tls_verify=False, plain_http=False
):
    """
    Get chart info
    """
    inspect_command = command + f" show chart '{chart_ref}'"

    if insecure_skip_tls_verify:
        inspect_command += " --insecure-skip-tls-verify"

    if plain_http:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.13.0"):
            module.fail_json(
                msg="plain_http requires helm >= 3.13.0, current version is {0}".format(
                    helm_version
                )
            )
        else:
            inspect_command += " --plain-http"

    rc, out, err = module.run_helm_command(inspect_command)

    return yaml.safe_load(out)


def deploy(
    module,
    command,
    release_name,
    release_values,
    chart_name,
    wait,
    wait_timeout,
    disable_hook,
    force,
    values_files,
    history_max,
    atomic=False,
    create_namespace=False,
    replace=False,
    post_renderer=None,
    skip_crds=False,
    timeout=None,
    dependency_update=None,
    set_value_args=None,
    reuse_values=None,
    reset_values=True,
    reset_then_reuse_values=False,
    insecure_skip_tls_verify=False,
    plain_http=False,
    take_ownership=False,
    skip_schema_validation=False,
):
    """
    Install/upgrade/rollback release chart
    """
    if replace:
        # '--replace' is not supported by 'upgrade -i'
        deploy_command = command + " install"
        if dependency_update:
            deploy_command += " --dependency-update"
    else:
        deploy_command = command + " upgrade -i"  # install/upgrade
        if reset_values:
            deploy_command += " --reset-values"
        if take_ownership:
            deploy_command += " --take-ownership"

    if reuse_values is not None:
        deploy_command += " --reuse-values=" + str(reuse_values)

    if reset_then_reuse_values:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.14.0"):
            module.fail_json(
                msg="reset_then_reuse_values requires helm >= 3.14.0, current version is {0}".format(
                    helm_version
                )
            )
        else:
            deploy_command += " --reset-then-reuse-values"

    if wait:
        deploy_command += " --wait"
        if wait_timeout is not None:
            deploy_command += " --timeout " + wait_timeout

    if atomic:
        deploy_command += " --atomic"

    if timeout:
        deploy_command += " --timeout " + timeout

    if force:
        deploy_command += " --force"

    if replace:
        deploy_command += " --replace"

    if disable_hook:
        deploy_command += " --no-hooks"

    if create_namespace:
        deploy_command += " --create-namespace"

    if insecure_skip_tls_verify:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.16.0"):
            module.fail_json(
                msg="insecure_skip_tls_verify requires helm >= 3.16.0, current version is {0}".format(
                    helm_version
                )
            )
        else:
            deploy_command += " --insecure-skip-tls-verify"

    if plain_http:
        deploy_command += " --plain-http"

    if values_files:
        for value_file in values_files:
            deploy_command += " --values=" + value_file

    if release_values != {}:
        fd, path = tempfile.mkstemp(suffix=".yml")
        with open(path, "w") as yaml_file:
            yaml.dump(release_values, yaml_file, default_flow_style=False)
        deploy_command += " -f=" + path
        module.add_cleanup_file(path)

    if post_renderer:
        deploy_command += " --post-renderer=" + post_renderer

    if skip_crds:
        deploy_command += " --skip-crds"

    if history_max is not None:
        deploy_command += " --history-max=%s" % str(history_max)

    if set_value_args:
        deploy_command += " " + set_value_args

    if skip_schema_validation:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.16.0"):
            module.fail_json(
                msg="skip_schema_validation requires helm >= 3.16.0, current version is {0}".format(
                    helm_version
                )
            )
        else:
            deploy_command += " --skip-schema-validation"

    deploy_command += " " + release_name + f" '{chart_name}'"
    return deploy_command


def delete(command, release_name, purge, disable_hook, wait, wait_timeout):
    """
    Delete release chart
    """

    delete_command = command + " uninstall "

    if not purge:
        delete_command += " --keep-history"

    if disable_hook:
        delete_command += " --no-hooks"

    if wait:
        delete_command += " --wait"

    if wait_timeout is not None:
        delete_command += " --timeout " + wait_timeout

    delete_command += " " + release_name

    return delete_command


def load_values_files(values_files):
    values = {}
    for values_file in values_files or []:
        with open(values_file, "r") as fd:
            content = yaml.safe_load(fd)
            if not isinstance(content, dict):
                continue
            for k, v in content.items():
                values[k] = v
    return values


def get_plugin_version(plugin):
    """
    Check if helm plugin is installed and return corresponding version
    """

    rc, output, err, command = module.get_helm_plugin_list()
    out = parse_helm_plugin_list(output=output.splitlines())

    if not out:
        return None

    for line in out:
        if line[0] == plugin:
            return line[1]
    return None


def helmdiff_check(
    module,
    release_name,
    chart_ref,
    release_values,
    values_files=None,
    chart_version=None,
    replace=False,
    chart_repo_url=None,
    post_renderer=False,
    set_value_args=None,
    reuse_values=None,
    reset_values=True,
    reset_then_reuse_values=False,
    insecure_skip_tls_verify=False,
    plain_http=False,
    skip_schema_validation=False,
):
    """
    Use helm diff to determine if a release would change by upgrading a chart.
    """
    cmd = module.get_helm_binary() + " diff upgrade"
    cmd += " " + release_name
    cmd += " " + chart_ref

    if chart_repo_url is not None:
        cmd += " " + "--repo=" + chart_repo_url
    if chart_version is not None:
        cmd += " " + "--version=" + chart_version
    if not replace:
        cmd += " " + "--reset-values=" + str(reset_values)
    if post_renderer:
        cmd += " --post-renderer=" + post_renderer

    if values_files:
        for value_file in values_files:
            cmd += " --values=" + value_file

    if release_values != {}:
        fd, path = tempfile.mkstemp(suffix=".yml")
        with open(path, "w") as yaml_file:
            yaml.dump(release_values, yaml_file, default_flow_style=False)
        cmd += " -f=" + path
        module.add_cleanup_file(path)

    if set_value_args:
        cmd += " " + set_value_args

    if reuse_values:
        cmd += " --reuse-values"

    if reset_then_reuse_values:
        helm_diff_version = get_plugin_version("diff")
        helm_version = module.get_helm_version()
        fail_msg = ""
        if LooseVersion(helm_diff_version) < LooseVersion("3.9.12"):
            fail_msg = "reset_then_reuse_values requires helm diff >= 3.9.12, current version is {0}\n".format(
                helm_diff_version
            )
        if LooseVersion(helm_version) < LooseVersion("3.14.0"):
            fail_msg += "reset_then_reuse_values requires helm >= 3.14.0, current version is {0}\n".format(
                helm_version
            )

        if fail_msg:
            module.fail_json(msg=fail_msg)
        else:
            cmd += " --reset-then-reuse-values"

    if insecure_skip_tls_verify:
        cmd += " --insecure-skip-tls-verify"

    if skip_schema_validation:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.16.0"):
            module.fail_json(
                msg="skip_schema_validation requires helm >= 3.16.0, current version is {0}".format(
                    helm_version
                )
            )
        else:
            cmd += " --skip-schema-validation"

    if plain_http:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.13.0"):
            module.fail_json(
                msg="plain_http requires helm >= 3.13.0, current version is {0}".format(
                    helm_version
                )
            )
        else:
            cmd += " --plain-http"

    rc, out, err = module.run_helm_command(cmd)
    return (len(out.strip()) > 0, out.strip())


def default_check(release_status, chart_info, values=None, values_files=None):
    """
    Use default check to determine if release would change by upgrading a chart.
    """
    # the 'appVersion' specification is optional in a chart
    chart_app_version = chart_info.get("appVersion", None)
    released_app_version = release_status.get("app_version", None)

    # when deployed without an 'appVersion' chart value the 'helm list' command will return the entry `app_version: ""`
    appversion_is_same = (chart_app_version == released_app_version) or (
        chart_app_version is None and released_app_version == ""
    )

    if values_files:
        values_match = release_status["values"] == load_values_files(values_files)
    else:
        values_match = release_status["values"] == values
    return (
        not values_match
        or (chart_info["name"] + "-" + chart_info["version"]) != release_status["chart"]
        or not appversion_is_same
    )


def argument_spec():
    arg_spec = copy.deepcopy(HELM_AUTH_ARG_SPEC)
    arg_spec.update(
        dict(
            chart_ref=dict(type="path"),
            chart_repo_url=dict(type="str"),
            chart_version=dict(type="str"),
            dependency_update=dict(type="bool", default=False, aliases=["dep_up"]),
            release_name=dict(type="str", required=True, aliases=["name"]),
            release_namespace=dict(type="str", required=True, aliases=["namespace"]),
            release_state=dict(
                default="present", choices=["present", "absent"], aliases=["state"]
            ),
            release_values=dict(type="dict", default={}, aliases=["values"]),
            values_files=dict(type="list", default=[], elements="str"),
            update_repo_cache=dict(type="bool", default=False),
            disable_hook=dict(type="bool", default=False),
            force=dict(type="bool", default=False),
            purge=dict(type="bool", default=True),
            wait=dict(type="bool", default=False),
            wait_timeout=dict(type="str"),
            timeout=dict(type="str"),
            atomic=dict(type="bool", default=False),
            create_namespace=dict(type="bool", default=False),
            post_renderer=dict(type="str"),
            replace=dict(type="bool", default=False),
            skip_crds=dict(type="bool", default=False),
            history_max=dict(type="int"),
            set_values=dict(type="list", elements="dict"),
            reuse_values=dict(type="bool"),
            reset_values=dict(type="bool", default=True),
            reset_then_reuse_values=dict(type="bool", default=False),
            insecure_skip_tls_verify=dict(
                type="bool", default=False, aliases=["skip_tls_certs_check"]
            ),
            plain_http=dict(type="bool", default=False),
            take_ownership=dict(type="bool", default=False),
            skip_schema_validation=dict(type="bool", default=False),
        )
    )
    return arg_spec


def main():
    global module
    module = AnsibleHelmModule(
        argument_spec=argument_spec(),
        required_if=[
            ("release_state", "present", ["release_name", "chart_ref"]),
            ("release_state", "absent", ["release_name"]),
        ],
        mutually_exclusive=[
            ("context", "ca_cert"),
            ("replace", "history_max"),
            ("wait_timeout", "timeout"),
        ],
        supports_check_mode=True,
    )

    if not IMP_YAML:
        module.fail_json(msg=missing_required_lib("yaml"), exception=IMP_YAML_ERR)

    changed = False

    chart_ref = module.params.get("chart_ref")
    chart_repo_url = module.params.get("chart_repo_url")
    chart_version = module.params.get("chart_version")
    dependency_update = module.params.get("dependency_update")
    release_name = module.params.get("release_name")
    release_state = module.params.get("release_state")
    release_values = module.params.get("release_values")
    values_files = module.params.get("values_files")
    update_repo_cache = module.params.get("update_repo_cache")

    # Helm options
    disable_hook = module.params.get("disable_hook")
    force = module.params.get("force")
    purge = module.params.get("purge")
    wait = module.params.get("wait")
    wait_timeout = module.params.get("wait_timeout")
    atomic = module.params.get("atomic")
    create_namespace = module.params.get("create_namespace")
    post_renderer = module.params.get("post_renderer")
    replace = module.params.get("replace")
    skip_crds = module.params.get("skip_crds")
    history_max = module.params.get("history_max")
    timeout = module.params.get("timeout")
    set_values = module.params.get("set_values")
    reuse_values = module.params.get("reuse_values")
    reset_values = module.params.get("reset_values")
    reset_then_reuse_values = module.params.get("reset_then_reuse_values")
    insecure_skip_tls_verify = module.params.get("insecure_skip_tls_verify")
    plain_http = module.params.get("plain_http")
    take_ownership = module.params.get("take_ownership")
    skip_schema_validation = module.params.get("skip_schema_validation")

    if update_repo_cache:
        run_repo_update(module)

    # Get real/deployed release status
    all_status = release_state == "absent"
    release_status = get_release_status(module, release_name, all_status=all_status)

    helm_cmd = module.get_helm_binary()

    if plain_http:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.13.0"):
            module.fail_json(
                msg="plain_http requires helm >= 3.13.0, current version is {0}".format(
                    helm_version
                )
            )
    if take_ownership:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.17.0"):
            module.fail_json(
                msg="take_ownership requires helm >= 3.17.0, current version is {0}".format(
                    helm_version
                )
            )

    if skip_schema_validation:
        helm_version = module.get_helm_version()
        if LooseVersion(helm_version) < LooseVersion("3.16.0"):
            module.fail_json(
                msg="skip_schema_validation requires helm >= 3.16.0, current version is {0}".format(
                    helm_version
                )
            )

    opt_result = {}
    if release_state == "absent" and release_status is not None:
        # skip release statuses 'uninstalled' and 'uninstalling'
        if not release_status["status"].startswith("uninstall"):
            if replace:
                module.fail_json(msg="replace is not applicable when state is absent")

            if wait:
                helm_version = module.get_helm_version()
                if LooseVersion(helm_version) < LooseVersion("3.7.0"):
                    opt_result["warnings"] = []
                    opt_result["warnings"].append(
                        "helm uninstall support option --wait for helm release >= 3.7.0"
                    )
                    wait = False

            helm_cmd = delete(
                helm_cmd, release_name, purge, disable_hook, wait, wait_timeout
            )
            changed = True
    elif release_state == "present":
        if chart_version is not None:
            helm_cmd += " --version=" + chart_version

        if chart_repo_url is not None:
            helm_cmd += " --repo=" + chart_repo_url

        # Fetch chart info to have real version and real name for chart_ref from archive, folder or url
        chart_info = fetch_chart_info(
            module, helm_cmd, chart_ref, insecure_skip_tls_verify, plain_http
        )

        if dependency_update:
            if chart_info.get("dependencies"):
                # Can't use '--dependency-update' with 'helm upgrade' that is the
                # default chart install method, so if chart_repo_url is defined
                # we can't use the dependency update command. But, in the near future
                # we can get rid of this method and use only '--dependency-update'
                # option. Please see https://github.com/helm/helm/pull/8810
                if not chart_repo_url and not re.fullmatch(
                    r"^http[s]*://[\w.:/?&=-]+$", chart_ref
                ):
                    run_dep_update(module, chart_ref)

                    # To not add --dependency-update option in the deploy function
                    dependency_update = False
                else:
                    module.warn(
                        "This is a not stable feature with 'chart_repo_url'. Please consider to use dependency update with on-disk charts"
                    )
                    if not replace:
                        msg_fail = (
                            "'--dependency-update' hasn't been supported yet with 'helm upgrade'. "
                            "Please use 'helm install' instead by adding 'replace' option"
                        )
                        module.fail_json(msg=msg_fail)
            else:
                module.warn(
                    "There is no dependencies block defined in Chart.yaml. Dependency update will not be performed. "
                    "Please consider add dependencies block or disable dependency_update to remove this warning."
                )

        set_value_args = None
        if set_values:
            set_value_args = module.get_helm_set_values_args(set_values)

        if release_status is None:  # Not installed
            helm_cmd = deploy(
                module,
                helm_cmd,
                release_name,
                release_values,
                chart_ref,
                wait,
                wait_timeout,
                disable_hook,
                False,
                values_files=values_files,
                atomic=atomic,
                create_namespace=create_namespace,
                post_renderer=post_renderer,
                replace=replace,
                dependency_update=dependency_update,
                skip_crds=skip_crds,
                history_max=history_max,
                timeout=timeout,
                set_value_args=set_value_args,
                reuse_values=reuse_values,
                reset_values=reset_values,
                reset_then_reuse_values=reset_then_reuse_values,
                insecure_skip_tls_verify=insecure_skip_tls_verify,
                plain_http=plain_http,
                skip_schema_validation=skip_schema_validation,
            )
            changed = True

        else:
            helm_diff_version = get_plugin_version("diff")
            if helm_diff_version and (
                not chart_repo_url
                or (
                    chart_repo_url
                    and LooseVersion(helm_diff_version) >= LooseVersion("3.4.1")
                )
            ):
                (would_change, prepared) = helmdiff_check(
                    module,
                    release_name,
                    chart_ref,
                    release_values,
                    values_files,
                    chart_version,
                    replace,
                    chart_repo_url,
                    post_renderer,
                    set_value_args,
                    reuse_values=reuse_values,
                    reset_values=reset_values,
                    reset_then_reuse_values=reset_then_reuse_values,
                    insecure_skip_tls_verify=insecure_skip_tls_verify,
                    plain_http=plain_http,
                    skip_schema_validation=skip_schema_validation,
                )
                if would_change and module._diff:
                    opt_result["diff"] = {"prepared": prepared}
            else:
                module.warn(
                    "The default idempotency check can fail to report changes in certain cases. "
                    "Install helm diff >= 3.4.1 for better results."
                )
                would_change = default_check(
                    release_status, chart_info, release_values, values_files
                )

            if force or would_change:
                helm_cmd = deploy(
                    module,
                    helm_cmd,
                    release_name,
                    release_values,
                    chart_ref,
                    wait,
                    wait_timeout,
                    disable_hook,
                    force,
                    values_files=values_files,
                    atomic=atomic,
                    create_namespace=create_namespace,
                    post_renderer=post_renderer,
                    replace=replace,
                    skip_crds=skip_crds,
                    history_max=history_max,
                    timeout=timeout,
                    dependency_update=dependency_update,
                    set_value_args=set_value_args,
                    reuse_values=reuse_values,
                    reset_values=reset_values,
                    reset_then_reuse_values=reset_then_reuse_values,
                    insecure_skip_tls_verify=insecure_skip_tls_verify,
                    plain_http=plain_http,
                    take_ownership=take_ownership,
                    skip_schema_validation=skip_schema_validation,
                )
                changed = True

    if module.check_mode:
        check_status = {"values": {"current": {}, "declared": {}}}
        if release_status:
            check_status["values"]["current"] = release_status["values"]
            check_status["values"]["declared"] = release_status

        module.exit_json(
            changed=changed,
            command=helm_cmd,
            status=check_status,
            stdout="",
            stderr="",
            **opt_result,
        )
    elif not changed:
        module.exit_json(
            changed=False,
            status=release_status,
            stdout="",
            stderr="",
            command=helm_cmd,
            **opt_result,
        )

    rc, out, err = module.run_helm_command(helm_cmd)

    module.exit_json(
        changed=changed,
        stdout=out,
        stderr=err,
        status=get_release_status(module, release_name, all_status=True),
        command=helm_cmd,
        **opt_result,
    )


if __name__ == "__main__":
    main()
