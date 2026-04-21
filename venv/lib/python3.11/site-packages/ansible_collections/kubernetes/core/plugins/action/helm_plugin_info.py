# Copyright (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
# Copyright (c) 2017, Toshio Kuratomi <tkuraotmi@ansible.com>
# Copyright (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import os
import platform
import traceback
from contextlib import contextmanager

from ansible.config.manager import ensure_type
from ansible.errors import (
    AnsibleAction,
    AnsibleActionFail,
    AnsibleError,
    AnsibleFileNotFound,
)
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.plugins.action import ActionBase

try:
    from ansible.template import trust_as_template
except ImportError:
    trust_as_template = None


def _from_yaml_to_definition(buffer):
    try:
        import yaml
    except ImportError:
        raise AnsibleError("Failed to import the required Python library (PyYAML).")
    return list(yaml.safe_load_all(buffer))


ENV_KUBECONFIG_PATH_SEPARATOR = ";" if platform.system() == "Windows" else ":"


class ActionModule(ActionBase):
    TRANSFERS_FILES = True
    DEFAULT_NEWLINE_SEQUENCE = "\n"

    def _ensure_invocation(self, result):
        # NOTE: adding invocation arguments here needs to be kept in sync with
        # any no_log specified in the argument_spec in the module.
        if "invocation" not in result:
            if self._play_context.no_log:
                result["invocation"] = "CENSORED: no_log is set"
            else:
                result["invocation"] = self._task.args.copy()
                result["invocation"]["module_args"] = self._task.args.copy()

        return result

    @contextmanager
    def get_template_data(self, template_path):
        try:
            source = self._find_needle("templates", template_path)
        except AnsibleError as e:
            raise AnsibleActionFail(to_text(e))

        # Get vault decrypted tmp file
        try:
            tmp_source = self._loader.get_real_file(source)
        except AnsibleFileNotFound as e:
            raise AnsibleActionFail(
                "could not find template=%s, %s" % (source, to_text(e))
            )
        b_tmp_source = to_bytes(tmp_source, errors="surrogate_or_strict")

        try:
            with open(b_tmp_source, "rb") as f:
                try:
                    template_data = to_text(f.read(), errors="surrogate_or_strict")
                except UnicodeError:
                    raise AnsibleActionFail(
                        "Template source files must be utf-8 encoded"
                    )
            yield template_data
        except AnsibleAction:
            raise
        except Exception as e:
            raise AnsibleActionFail("%s: %s" % (type(e).__name__, to_text(e)))
        finally:
            self._loader.cleanup_tmp_file(b_tmp_source)

    def get_template_args(self, template):
        template_param = {
            "newline_sequence": self.DEFAULT_NEWLINE_SEQUENCE,
            "variable_start_string": None,
            "variable_end_string": None,
            "block_start_string": None,
            "block_end_string": None,
            "trim_blocks": True,
            "lstrip_blocks": False,
        }
        if isinstance(template, str):
            # treat this as raw_params
            template_param["path"] = template
        elif isinstance(template, dict):
            template_args = template
            template_path = template_args.get("path", None)
            if not template_path:
                raise AnsibleActionFail("Please specify path for template.")
            template_param["path"] = template_path

            # Options type validation strings
            for s_type in (
                "newline_sequence",
                "variable_start_string",
                "variable_end_string",
                "block_start_string",
                "block_end_string",
            ):
                if s_type in template_args:
                    value = ensure_type(template_args[s_type], "string")
                    if value is not None and not isinstance(value, str):
                        raise AnsibleActionFail(
                            "%s is expected to be a string, but got %s instead"
                            % (s_type, type(value))
                        )
            try:
                template_param.update(
                    {
                        "trim_blocks": boolean(
                            template_args.get("trim_blocks", True), strict=False
                        ),
                        "lstrip_blocks": boolean(
                            template_args.get("lstrip_blocks", False), strict=False
                        ),
                    }
                )
            except TypeError as e:
                raise AnsibleActionFail(to_native(e))

            template_param.update(
                {
                    "newline_sequence": template_args.get(
                        "newline_sequence", self.DEFAULT_NEWLINE_SEQUENCE
                    ),
                    "variable_start_string": template_args.get(
                        "variable_start_string", None
                    ),
                    "variable_end_string": template_args.get(
                        "variable_end_string", None
                    ),
                    "block_start_string": template_args.get("block_start_string", None),
                    "block_end_string": template_args.get("block_end_string", None),
                }
            )
        else:
            raise AnsibleActionFail(
                "Error while reading template file - "
                "a string or dict for template expected, but got %s instead"
                % type(template)
            )
        return template_param

    def import_jinja2_lstrip(self, templates):
        # Option `lstrip_blocks' was added in Jinja2 version 2.7.
        if any(tmp["lstrip_blocks"] for tmp in templates):
            try:
                import jinja2.defaults
            except ImportError:
                raise AnsibleError(
                    "Unable to import Jinja2 defaults for determining Jinja2 features."
                )

            try:
                jinja2.defaults.LSTRIP_BLOCKS
            except AttributeError:
                raise AnsibleError(
                    "Option `lstrip_blocks' is only available in Jinja2 versions >=2.7"
                )

    def load_template(self, template, new_module_args, task_vars):
        # template is only supported by k8s module.
        if self._task.action not in (
            "k8s",
            "kubernetes.core.k8s",
            "community.okd.k8s",
            "redhat.openshift.k8s",
            "community.kubernetes.k8s",
            "openshift_adm_groups_sync",
            "community.okd.openshift_adm_groups_sync",
            "redhat.openshift.openshift_adm_groups_sync",
        ):
            raise AnsibleActionFail(
                "'template' is only a supported parameter for the 'k8s' module."
            )

        template_params = []
        if isinstance(template, str) or isinstance(template, dict):
            template_params.append(self.get_template_args(template))
        elif isinstance(template, list):
            for element in template:
                template_params.append(self.get_template_args(element))
        else:
            raise AnsibleActionFail(
                "Error while reading template file - "
                "a string or dict for template expected, but got %s instead"
                % type(template)
            )

        self.import_jinja2_lstrip(template_params)

        wrong_sequences = ["\\n", "\\r", "\\r\\n"]
        allowed_sequences = ["\n", "\r", "\r\n"]

        result_template = []
        old_vars = self._templar.available_variables

        default_environment = {}
        if trust_as_template is None:
            for key in (
                "newline_sequence",
                "variable_start_string",
                "variable_end_string",
                "block_start_string",
                "block_end_string",
                "trim_blocks",
                "lstrip_blocks",
            ):
                if hasattr(self._templar.environment, key):
                    default_environment[key] = getattr(self._templar.environment, key)
        for template_item in template_params:
            # We need to convert unescaped sequences to proper escaped sequences for Jinja2
            newline_sequence = template_item["newline_sequence"]
            if newline_sequence in wrong_sequences:
                template_item["newline_sequence"] = allowed_sequences[
                    wrong_sequences.index(newline_sequence)
                ]
            elif newline_sequence not in allowed_sequences:
                raise AnsibleActionFail(
                    "newline_sequence needs to be one of: \n, \r or \r\n"
                )

            # template the source data locally & get ready to transfer
            with self.get_template_data(template_item["path"]) as template_data:
                # add ansible 'template' vars
                temp_vars = copy.deepcopy(task_vars)
                overrides = {}
                for key, value in template_item.items():
                    if hasattr(self._templar.environment, key):
                        if value is not None:
                            overrides[key] = value
                            if trust_as_template is None:
                                setattr(self._templar.environment, key, value)
                        elif trust_as_template is None:
                            setattr(
                                self._templar.environment,
                                key,
                                default_environment.get(key),
                            )
                self._templar.available_variables = temp_vars
                if trust_as_template:
                    template_data = trust_as_template(template_data)
                    result = self._templar.template(
                        template_data,
                        preserve_trailing_newlines=True,
                        escape_backslashes=False,
                        overrides=overrides,
                    )
                else:
                    result = self._templar.do_template(
                        template_data,
                        preserve_trailing_newlines=True,
                        escape_backslashes=False,
                    )
                result_template.extend(_from_yaml_to_definition(result))
        self._templar.available_variables = old_vars
        resource_definition = self._task.args.get("definition", None)
        if not resource_definition:
            new_module_args.pop("template")
        new_module_args["definition"] = result_template

    def get_file_realpath(self, local_path):
        # local_path is only supported by k8s_cp module.
        if self._task.action not in (
            "k8s_cp",
            "kubernetes.core.k8s_cp",
            "community.kubernetes.k8s_cp",
        ):
            raise AnsibleActionFail(
                "'local_path' is only supported parameter for 'k8s_cp' module."
            )

        if os.path.exists(local_path):
            return local_path

        try:
            # find in expected paths
            return self._find_needle("files", local_path)
        except AnsibleError:
            raise AnsibleActionFail(
                "%s does not exist in local filesystem" % local_path
            )

    def get_kubeconfig(self, kubeconfig, remote_transport, new_module_args):
        if isinstance(kubeconfig, str):
            # find the kubeconfig in the expected search path
            if not remote_transport:
                # kubeconfig is local
                # find in expected paths
                configs = []
                for config in kubeconfig.split(ENV_KUBECONFIG_PATH_SEPARATOR):
                    config = self._find_needle("files", config)

                    # decrypt kubeconfig found
                    configs.append(self._loader.get_real_file(config, decrypt=True))
                new_module_args["kubeconfig"] = ENV_KUBECONFIG_PATH_SEPARATOR.join(
                    configs
                )

        elif isinstance(kubeconfig, dict):
            new_module_args["kubeconfig"] = kubeconfig
        else:
            raise AnsibleActionFail(
                "Error while reading kubeconfig parameter - "
                "a string or dict expected, but got %s instead" % type(kubeconfig)
            )

    def run(self, tmp=None, task_vars=None):
        """handler for k8s options"""
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        # Check current transport connection and depending upon
        # look for kubeconfig and src
        # 'local' => look files on Ansible Controller
        # Transport other than 'local' => look files on remote node
        remote_transport = self._connection.transport != "local"

        new_module_args = copy.deepcopy(self._task.args)

        kubeconfig = self._task.args.get("kubeconfig", None)
        if kubeconfig:
            try:
                self.get_kubeconfig(kubeconfig, remote_transport, new_module_args)
            except AnsibleError as e:
                result["failed"] = True
                result["msg"] = to_text(e)
                result["exception"] = traceback.format_exc()
                return result

        # find the file in the expected search path
        src = self._task.args.get("src", None)

        if src and not src.startswith(("http://", "https://", "ftp://")):
            if remote_transport:
                # src is on remote node
                result.update(
                    self._execute_module(
                        module_name=self._task.action, task_vars=task_vars
                    )
                )
                return self._ensure_invocation(result)

            # src is local
            try:
                # find in expected paths
                src = self._find_needle("files", src)
            except AnsibleError as e:
                result["failed"] = True
                result["msg"] = to_text(e)
                result["exception"] = traceback.format_exc()
                return result

        if src:
            new_module_args["src"] = src

        template = self._task.args.get("template", None)
        if template:
            self.load_template(template, new_module_args, task_vars)

        local_path = self._task.args.get("local_path")
        state = self._task.args.get("state", None)
        if local_path and state == "to_pod" and not remote_transport:
            new_module_args["local_path"] = self.get_file_realpath(local_path)

        # Execute the k8s_* module.
        module_return = self._execute_module(
            module_name=self._task.action,
            module_args=new_module_args,
            task_vars=task_vars,
        )

        # Delete tmp path
        self._remove_tmp_path(self._connection._shell.tmpdir)

        result.update(module_return)

        return self._ensure_invocation(result)
