# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


import copy
import json
import os
import re
import tempfile
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.kubernetes.core.plugins.module_utils.version import (
    LooseVersion,
)

try:
    import yaml

    HAS_YAML = True
    YAML_IMP_ERR = None
except ImportError:
    YAML_IMP_ERR = traceback.format_exc()
    HAS_YAML = False


def parse_helm_plugin_list(output=None):
    """
    Parse `helm plugin list`, return list of plugins
    """
    ret = []
    if not output:
        return ret

    for line in output:
        if line.startswith("NAME"):
            continue
        name, version, description = line.split("\t", 3)
        name = name.strip()
        version = version.strip()
        description = description.strip()
        if name == "":
            continue
        ret.append((name, version, description))

    return ret


def write_temp_kubeconfig(server, validate_certs=True, ca_cert=None, kubeconfig=None):
    # Workaround until https://github.com/helm/helm/pull/8622 is merged
    content = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"cluster": {"server": server}, "name": "generated-cluster"}],
        "contexts": [
            {"context": {"cluster": "generated-cluster"}, "name": "generated-context"}
        ],
        "current-context": "generated-context",
    }
    if kubeconfig:
        content = copy.deepcopy(kubeconfig)

    for cluster in content["clusters"]:
        if server:
            cluster["cluster"]["server"] = server
        if not validate_certs:
            cluster["cluster"]["insecure-skip-tls-verify"] = True
        if ca_cert:
            cluster["cluster"]["certificate-authority"] = ca_cert
    return content


class AnsibleHelmModule(object):
    """
    An Ansible module class for Kubernetes.core helm modules
    """

    def __init__(self, **kwargs):
        self._module = None
        if "module" in kwargs:
            self._module = kwargs.get("module")
        else:
            self._module = AnsibleModule(**kwargs)

        self.helm_env = None

    def __getattr__(self, name):
        return getattr(self._module, name)

    @property
    def params(self):
        return self._module.params

    def _prepare_helm_environment(self):
        param_to_env_mapping = [
            ("context", "HELM_KUBECONTEXT"),
            ("release_namespace", "HELM_NAMESPACE"),
            ("api_key", "HELM_KUBETOKEN"),
            ("host", "HELM_KUBEAPISERVER"),
        ]

        env_update = {}
        for p, env in param_to_env_mapping:
            if self.params.get(p):
                env_update[env] = self.params.get(p)

        kubeconfig_content = None
        kubeconfig = self.params.get("kubeconfig")
        if kubeconfig:
            if isinstance(kubeconfig, str):
                with open(os.path.expanduser(kubeconfig)) as fd:
                    kubeconfig_content = yaml.safe_load(fd)
            elif isinstance(kubeconfig, dict):
                kubeconfig_content = kubeconfig

        if self.params.get("ca_cert"):
            ca_cert = self.params.get("ca_cert")
            if LooseVersion(self.get_helm_version()) < LooseVersion("3.5.0"):
                # update certs from kubeconfig
                kubeconfig_content = write_temp_kubeconfig(
                    server=self.params.get("host"),
                    ca_cert=ca_cert,
                    kubeconfig=kubeconfig_content,
                )
            else:
                env_update["HELM_KUBECAFILE"] = ca_cert

        if self.params.get("validate_certs") is False:
            validate_certs = self.params.get("validate_certs")
            if LooseVersion(self.get_helm_version()) < LooseVersion("3.10.0"):
                # update certs from kubeconfig
                kubeconfig_content = write_temp_kubeconfig(
                    server=self.params.get("host"),
                    validate_certs=validate_certs,
                    kubeconfig=kubeconfig_content,
                )
            else:
                env_update["HELM_KUBEINSECURE_SKIP_TLS_VERIFY"] = "true"

        if kubeconfig_content:
            fd, kubeconfig_path = tempfile.mkstemp()
            with os.fdopen(fd, "w") as fp:
                json.dump(kubeconfig_content, fp)

            env_update["KUBECONFIG"] = kubeconfig_path
            self.add_cleanup_file(kubeconfig_path)

        return env_update

    @property
    def env_update(self):
        if self.helm_env is None:
            self.helm_env = self._prepare_helm_environment()
        return self.helm_env

    def run_helm_command(self, command, fails_on_error=True, data=None):
        if not HAS_YAML:
            self.fail_json(msg=missing_required_lib("PyYAML"), exception=YAML_IMP_ERR)

        rc, out, err = self.run_command(
            command, environ_update=self.env_update, data=data
        )
        if fails_on_error and rc != 0:
            self.fail_json(
                msg="Failure when executing Helm command. Exited {0}.\nstdout: {1}\nstderr: {2}".format(
                    rc, out, err
                ),
                stdout=out,
                stderr=err,
                command=command,
            )
        return rc, out, err

    def get_helm_binary(self):
        return self.params.get("binary_path") or self.get_bin_path(
            "helm", required=True
        )

    def get_helm_version(self):
        command = self.get_helm_binary() + " version"
        rc, out, err = self.run_command(command)
        m = re.match(r'version.BuildInfo{Version:"v(.*?)",', out)
        if m:
            return m.group(1)
        m = re.match(r'Client: &version.Version{SemVer:"v(.*?)", ', out)
        if m:
            return m.group(1)
        return None

    def get_values(self, release_name, get_all=False):
        """
        Get Values from deployed release
        """
        if not HAS_YAML:
            self.fail_json(msg=missing_required_lib("PyYAML"), exception=YAML_IMP_ERR)

        get_command = (
            self.get_helm_binary() + " get values --output=yaml " + release_name
        )

        if get_all:
            get_command += " -a"

        rc, out, err = self.run_helm_command(get_command)
        # Helm 3 return "null" string when no values are set
        if out.rstrip("\n") == "null":
            return {}
        return yaml.safe_load(out)

    def parse_yaml_content(self, content):
        if not HAS_YAML:
            self.fail_json(msg=missing_required_lib("yaml"), exception=HAS_YAML)

        try:
            return list(yaml.safe_load_all(content))
        except (IOError, yaml.YAMLError) as exc:
            self.fail_json(
                msg="Error parsing YAML content: {0}".format(exc), raw_data=content
            )

    def get_manifest(self, release_name):
        command = [
            self.get_helm_binary(),
            "get",
            "manifest",
            release_name,
        ]
        rc, out, err = self.run_helm_command(" ".join(command))
        if rc != 0:
            self.fail_json(msg=err)
        return self.parse_yaml_content(out)

    def get_notes(self, release_name):
        command = [
            self.get_helm_binary(),
            "get",
            "notes",
            release_name,
        ]
        rc, out, err = self.run_helm_command(" ".join(command))
        if rc != 0:
            self.fail_json(msg=err)
        return out

    def get_hooks(self, release_name):
        command = [
            self.get_helm_binary(),
            "get",
            "hooks",
            release_name,
        ]
        rc, out, err = self.run_helm_command(" ".join(command))
        if rc != 0:
            self.fail_json(msg=err)
        return self.parse_yaml_content(out)

    def get_helm_plugin_list(self):
        """
        Return `helm plugin list`
        """
        helm_plugin_list = self.get_helm_binary() + " plugin list"
        rc, out, err = self.run_helm_command(helm_plugin_list)
        if rc != 0 or (out == "" and err == ""):
            self.fail_json(
                msg="Failed to get Helm plugin info",
                command=helm_plugin_list,
                stdout=out,
                stderr=err,
                rc=rc,
            )
        return (rc, out, err, helm_plugin_list)

    def get_helm_set_values_args(self, set_values):
        if any(v.get("value_type") == "json" for v in set_values):
            if LooseVersion(self.get_helm_version()) < LooseVersion("3.10.0"):
                self.fail_json(
                    msg="This module requires helm >= 3.10.0, to use set_values parameter with value type set to 'json'. current version is {0}".format(
                        self.get_helm_version()
                    )
                )

        options = []
        for opt in set_values:
            value_type = opt.get("value_type", "raw")
            value = opt.get("value")

            if value_type == "raw":
                options.append("--set " + value)
            else:
                options.append("--set-{0} '{1}'".format(value_type, value))

        return " ".join(options)
