#
# Copyright 2021 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import copy
import glob
import os

from importlib import import_module


try:
    import yaml

    # use C version if possible for speedup
    try:
        from yaml import CSafeLoader as SafeLoader
    except ImportError:
        from yaml import SafeLoader
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from ansible.errors import AnsibleActionFail, AnsibleError
from ansible.module_utils.common.text.converters import to_text
from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.action.network import (
    ActionModule as ActionNetworkModule,
)


display = Display()


class RunMode:
    RM_LIST = 0  # get list of supported resource modules for given os_name
    RM_GET = 1  # get resource module facts for given host
    RM_CONFIG = 1  # push resource module configuration


class ActionModule(ActionNetworkModule):
    def run(self, task_vars=None):
        run_mode = None
        self._task_vars = task_vars

        self._rm_play_context = copy.deepcopy(self._play_context)
        self._os_name = self._task.args.get("os_name") or self._get_os_name()
        if not self._os_name:
            return {"error": "either value of 'os_name' or 'ansible_network_os' should be set"}

        if len(self._os_name.split(".")) != 3:
            msg = (
                "OS value name should a fully qualified collection name in the format"
                " <org-name>.<collection-name>.<plugin-name>"
            )
            return {"error": msg}

        self._rm_play_context.network_os = self._os_name

        self._name = self._task.args.get("name")
        self._config = self._task.args.get("config")
        self._running_config = self._task.args.get("running_config")
        self._state = self._task.args.get("state")

        run_mode = self._get_run_mode()

        result = {}
        if run_mode == RunMode.RM_LIST:
            result = self._list_resource_modules()
        elif run_mode in [RunMode.RM_GET, RunMode.RM_CONFIG]:
            try:
                result = self._run_resource_module()
            except AnsibleError as exc:
                # handle short name redirection not working for ansible-2.9
                if "was not found" in to_text(exc):
                    result = self._run_resource_module(prefix_os_name=True)
                else:
                    raise

        result.update(
            {
                "ansible_network_os": self._task_vars.get("ansible_network_os"),
                "ansible_connection": self._task_vars.get("ansible_connection"),
            }
        )
        return result

    def _run_resource_module(self, prefix_os_name=False):
        new_task = self._task.copy()

        self._module = self._get_resource_module(prefix_os_name=prefix_os_name)
        if not self._module:
            msg = "Could not find resource module '%s' for os name '%s'" % (
                self._name,
                self._os_name,
            )
            raise AnsibleActionFail(msg)

        new_task.action = self._module
        action = self._shared_loader_obj.action_loader.get(
            self._rm_play_context.network_os,
            task=new_task,
            connection=self._connection,
            play_context=self._rm_play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj,
        )
        display.vvvv("Running resource module %s" % self._module)
        for option in ["os_name", "name"]:
            if option in new_task.args:
                new_task.args.pop(option)

        result = action.run(task_vars=self._task_vars)
        result.update({"resource_module_name": self._module})
        return result

    def _get_resource_module(self, prefix_os_name=False):
        if "." in self._name:
            if len(self._name.split(".")) != 3:
                msg = (
                    "name should a fully qualified collection name in the format"
                    " <org-name>.<collection-name>.<resource-module-name>"
                )
                raise AnsibleActionFail(msg)
            fqcn_module_name = self._name
        else:
            if prefix_os_name:
                module_name = self._os_name.split(".")[1] + "_" + self._name
            else:
                module_name = self._name

            fqcn_module_name = ".".join(self._os_name.split(".")[:2] + [module_name])

        return fqcn_module_name

    def _get_os_name(self):
        os_name = None
        if "network_os" in self._task.args and self._task.args["network_os"]:
            display.vvvv("Getting OS name from task argument")
            os_name = self._task.args["network_os"]
        elif self._play_context.network_os:
            display.vvvv("Getting OS name from inventory")
            os_name = self._play_context.network_os
        elif (
            "network_os" in self._task_vars.get("ansible_facts", {})
            and self._task_vars["ansible_facts"]["network_os"]
        ):
            display.vvvv("Getting OS name from fact")
            os_name = self._task_vars["ansible_facts"]["network_os"]

        return os_name

    def _is_resource_module(self, docs):
        doc_obj = yaml.load(docs, SafeLoader)
        if "config" in doc_obj["options"] and "state" in doc_obj["options"]:
            return True

    def _get_run_mode(self):
        error_msg = None
        if self._config or self._running_config:
            if not self._name:
                error_msg = "'name' is required if 'config' option is set"
            if not self._state:
                error_msg = "'state' is required if 'config' option is set"
            run_mode = RunMode.RM_CONFIG
        elif self._state:
            if not self._name:
                error_msg = "'name' is required if 'state' option is set"
            run_mode = RunMode.RM_GET
        elif self._name:
            if not any([self._config, self._running_config, self._state]):
                error_msg = (
                    "If 'name' is set atleast one of 'config', "
                    "'running_config' or 'state' is required"
                )
        else:
            run_mode = RunMode.RM_LIST

        if error_msg:
            raise AnsibleActionFail(error_msg)
        return run_mode

    def _list_resource_modules(self):
        result = {}
        resource_modules = []

        self._cref = dict(zip(["corg", "cname", "plugin"], self._os_name.split(".")))

        fact_modulelib = "ansible_collections.{corg}.{cname}.plugins.module_utils.network.{plugin}.facts.facts".format(
            corg=self._cref["corg"],
            cname=self._cref["cname"],
            plugin=self._cref["plugin"],
        )

        try:
            display.vvvv("fetching facts list from path %s" % (fact_modulelib))
            facts_resource_subset = getattr(import_module(fact_modulelib), "FACT_RESOURCE_SUBSETS")
            resource_modules = sorted(facts_resource_subset.keys())
        except ModuleNotFoundError:
            display.vvvv("'%s' is not defined" % (fact_modulelib))
        except AttributeError:
            display.vvvv("'FACT_RESOURCE_SUBSETS is not defined in '%s'" % (fact_modulelib))

        # parse module docs to check for 'config' and 'state' options to identify it as resource module
        if not resource_modules:
            modulelib = "ansible_collections.{corg}.{cname}.plugins.modules".format(
                corg=self._cref["corg"], cname=self._cref["cname"]
            )

            module_dir_path = os.path.dirname(import_module(modulelib).__file__)
            module_paths = glob.glob(
                "{module_dir_path}/[!_]*.py".format(module_dir_path=module_dir_path)
            )

            for module_path in module_paths:
                module_name = os.path.basename(module_path).split(".")[0]
                docs = None
                try:
                    display.vvvv("reading 'DOCUMENTATION' from path %s" % (module_path))
                    docs = getattr(
                        import_module("%s.%s" % (modulelib, module_name)),
                        "DOCUMENTATION",
                    )
                except ModuleNotFoundError:
                    display.vvvv("'%s' is not defined" % (fact_modulelib))
                except AttributeError:
                    display.vvvv("'DOCUMENTATION is not defined in '%s'" % (fact_modulelib))

                if docs:
                    if self._is_resource_module(docs):
                        resource_modules.append(module_name.split("_", 1)[1])
                    else:
                        display.vvvvv(
                            "module in path '%s' is not a resource module" % (module_path)
                        )

        result.update({"modules": sorted(resource_modules)})
        return result
