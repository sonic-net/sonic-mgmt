"""Basic classes and functions for running ansible modules on devices by python.

This idea is mainly inspired by the pytest-ansible project. With the classes and functions defined here, we can run any
ansible modules on any hosts defined in inventory file.

Instead of writing ansible playbook to operate on the testbed devices, we can just write python.

Comparing with ansible playbook, we can take advantage of a real programming language. The drawback is that python
programming experience is required.

Comparing with pytest-ansible, we do not need pytest. This design supports some ansible features not supported by
pytest-ansible:
* fork: Pytest-ansible does not support running ansible modules in parallel. This design uses ansible's builtin forking
    capability to run modules in parallel.
* module attributes: Ansible supports additional module attributes that can be specified for each task in playbook.
    These module attributes can affect execution of the modules, for example "become", "async", etc. Pytest-ansible
    does not support these attributes. With this design, we can use keyword argument `module_attrs` to specify
    module attributes while calling an ansible module.

Not all ansible's builtin features are supported by this design. For example:
* Notify and event handler. (We can use python's libs to support that)

This idea is still new. I haven't figured out all of its potentials and limitations. Feedbacks, suggestions and
contributions are more than welcomed.
"""
import copy
import inspect
import json
import logging
import os

import six

from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.playbook.play import Play

from ansible.plugins.callback import CallbackBase
from ansible.plugins.loader import module_loader
from ansible import context
from ansible.module_utils.common.collections import ImmutableDict

if six.PY2:
    FileNotFoundError = IOError

logger = logging.getLogger("ansible_hosts")

try:
    from ansible.executor import task_result
    task_result._IGNORE = ("skipped", )
except Exception as e:
    logging.error("Hack for https://github.com/ansible/pytest-ansible/issues/47 failed: {}".format(repr(e)))


class UnsupportedAnsibleModule(Exception):
    pass


class RunAnsibleModuleFailed(Exception):
    pass


class NoAnsibleHostError(Exception):
    pass


class MultipleAnsibleHostsError(Exception):
    pass


class ResultCollector(CallbackBase):
    """Call back for getting single ansible module execution result on ansible hosts.

    Args:
        CallbackBase (class): Base class for all callbacks defined in ansible.
    """
    def __init__(self, *args, **kwargs):
        super(ResultCollector, self).__init__(*args, **kwargs)
        self._results = {}

    def v2_runner_on_ok(self, result):
        hostname = result._host.get_name()

        res = dict(hostname=hostname, reachable=True, failed=False)
        res.update(result._result)
        self._results[hostname] = res

    def v2_runner_on_failed(self, result, *args, **kwargs):
        hostname = result._host.get_name()

        res = dict(hostname=hostname, reachable=True, failed=True)
        res.update(result._result)
        self._results[hostname] = res

    def v2_runner_on_unreachable(self, result, *args, **kwargs):
        hostname = result._host.get_name()

        res = dict(hostname=hostname, reachable=False, failed=True)
        res.update(result._result)
        self._results[hostname] = res

    @property
    def results(self):
        """Property for returning execution result of single ansible module on ansible hosts.

        The result is a dict keyed by hostname. Value is the ansible module execution result on that host.

        Returns:
            dict: Result is a dict. Key is hostname. Value is ansible module execution result on that host.
        """
        return self._results


class BatchResultsCollector(CallbackBase):
    """Call back for getting multiple ansible module execution results on ansible hosts.

    Args:
        CallbackBase (class): Base class for all callbacks defined in ansible.
    """
    def __init__(self, *args, **kwargs):
        super(BatchResultsCollector, self).__init__(*args, **kwargs)
        self._results = {}

    def v2_runner_on_ok(self, result, *args, **kwargs):
        hostname = result._host.get_name()
        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(hostname=hostname, reachable=True, failed=False)
        res.update(result._result)
        self._results[hostname].append(res)

    def v2_runner_on_failed(self, result, *args, **kwargs):
        hostname = result._host.get_name()
        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(hostname=hostname, reachable=True, failed=True)
        res.update(result._result)
        self._results[hostname].append(res)

    def v2_runner_on_unreachable(self, result):
        hostname = result._host.get_name()
        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(hostname=hostname, reachable=False, failed=True)
        res.update(result._result)
        self._results[hostname].append(result._result)

    @property
    def results(self):
        """Property for returning multiple ansible module execution results of multiple ansible hosts.

        The result is a dict keyed by hostname. Value is list of the ansible module execution results on that host.

        Returns:
            dict: Result is a dict. Key is hostname. Value is ansible module execution result.
        """
        return self._results


class AnsibleHostsBase(object):
    """Base class for running ansible modules on hosts defined in ansible inventory file.

    This class defines the basic methods for running ansible modules on hosts defined in ansible inventory file.

    DO NOT use this class directly. Use AnsibleHosts or AnsibleHostsParallel instead.
    """
    def __init__(
            self,
            inventories,
            host_pattern,
            loader=None,
            inventory_manager=None,
            variable_manager=None,
            options={},
            hostvars={}):
        """Constructor for AnsibleHostsBase.

        Args:
            inventories (str or list): Path to ansible inventory file or list of inventory files.
            host_pattern (str or list): Host pattern string or list of host pattern strings. Interpreted by ansible.
                Follow the same rules of specifying ansible hosts in ansible play book.
                Examples:
                    "vlab-01"
                    "VM0100, VM0101"
                    ["VM0100", "VM0101"]
                    "server_1:&vm_host"
            loader (DataLoader, optional): Ansible DataLoader. Defaults to None.
            inventory_manager (InventoryManager, optional): Ansible InventoryManager. Defaults to None.
            variable_manager (VariableManager, optional): Ansible VariableManager. Defaults to None.
            options (dict, optional): Options affecting ansible execution. Supports options that can be passed in from
                ansible-playbook command line. Defaults to {}.
                Examples:
                    options={"become": True, "forks": 10}
            hostvars (dict, optional): Additional ansible variables for ansible hosts. Similar as using `-e` argument
                of ansible-playbook command line to specify additional host variables. Defaults to {}.
        """
        self.inventories = inventories

        # Check existence of inventories only when host_pattern is not "localhost"
        if host_pattern != "localhost":
            if isinstance(self.inventories, list):
                for inventory in self.inventories:
                    if not os.path.exists(inventory):
                        raise FileNotFoundError("Inventory file {} not found.".format(inventory))
            else:
                if not os.path.exists(self.inventories):
                    raise FileNotFoundError("Inventory file {} not found.".format(self.inventories))

        self.host_pattern = host_pattern
        if loader:
            self.loader = loader
        else:
            self.loader = DataLoader()

        if inventory_manager:
            if isinstance(self.inventories, list):
                sources = self.inventories
            else:
                sources = [self.inventories]
            if set(sources) != set(inventory_manager._sources):
                inventory_manager._sources = sources
                inventory_manager.parse_sources()
            self.im = inventory_manager
        else:
            self.im = InventoryManager(loader=self.loader, sources=self.inventories)

        if variable_manager:
            self.vm = variable_manager
        else:
            self.vm = VariableManager(loader=self.loader, inventory=self.im)

        self.options = {
            "forks": 6,
            "connection": "smart",
            "verbosity": 2,
            "become_method": "sudo"
        }
        if options:
            self.options.update(options)

        if hostvars:
            self.vm.extra_vars.update(hostvars)

        # Ansible inventory hosts, list of <class 'ansible.inventory.host.Host'>
        self.ans_inv_hosts = self.im.get_hosts(self.host_pattern)
        if len(self.ans_inv_hosts) == 0:
            raise NoAnsibleHostError(
                "No host '{}' in inventory files '{}'".format(self.host_pattern, self.inventories)
            )
        self.hostnames = [host.name for host in self.ans_inv_hosts]
        self.hosts_count = len(self.hostnames)
        self.ips = [host.get_vars().get("ansible_host", None) for host in self.ans_inv_hosts]

        self._loaded_modules = []

    @staticmethod
    def build_task(module_name, args=[], kwargs={}, module_attrs={}):
        """Build a dict represents a task in ansible playbook.

        Args:
            module_name (str): Name of the ansible module to be executed in the task.
            args (list, optional): Positional arguments of ansible module. Enclosed in a list. Defaults to [].
            kwargs (dict, optional): Keyword arguments of ansible module. Enclosed in a dict. Defaults to {}.
            module_attrs (dict, optional): Attributes affect module execution, eg: become, async, poll, etc.
                Check ansible module reference documentation for module attributes applicable to modules.
                * https://docs.ansible.com/ansible/2.9/modules/list_of_all_modules.html
                * https://docs.ansible.com/ansible/latest/collections/index.html

        Returns:
            dict: A dict represents a task in ansible playbook.
        """
        kwargs = copy.deepcopy(kwargs)  # Copy to avoid argument passed by reference issue
        if args:
            kwargs["_raw_params"] = " ".join(args)

        task_data = {
            "action": {
                "module": module_name,
                "args": kwargs
            },
        }
        if module_attrs:
            task_data.update(module_attrs)

        return task_data

    @staticmethod
    def run_tasks(
            hosts,
            loader,
            inventory_manager,
            variable_manager,
            options={
                "forks": 6,
                "connection": "smart",
                "verbosity": 2,
                "become_method": "sudo"
            },
            passwords={"vault_pass": "any"},
            gather_facts=False,
            tasks=[]):
        """Use ansible's TaskQueueManager to run tasks on hosts.

        Defined this method as a static method on purpose so that scripts may use this method to run ansible tasks
        without initializing instances of AnsibleHosts or AnsibleHost.

        Args:
            hosts (str or list): Host pattern string or list of host pattern strings. Interpreted by ansible.
            loader (DataLoader): Ansible DataLoader.
            inventory_manager (InventoryManager): Ansible InventoryManager.
            variable_manager (VariableManager): Ansible VariableManager.
            options (dict, optional): Options affecting ansible execution. Supports options that can be passed in from
                ansible-playbook command line. Defaults to {}.
            passwords (dict, optional): Passwords for ansible. Defaults to {"vault_pass": "any"}.
            gather_facts (bool, optional): Whether to gather facts before running tasks. Defaults to False.
            tasks (list, optional): List of tasks to be run on hosts. Defaults to [].

        Returns:
            dict: Results of running ansible modules in playbook. If task list length is 1, ResultCollector is used
                as result collector callback. If task list length is greater than 1, BatchResultsCollector is used as
                result collector callback.
        """
        tqm = None
        try:
            context.CLIARGS = ImmutableDict(**options)

            play = Play().load(
                {
                    "hosts": hosts,
                    "gather_facts": "yes" if gather_facts else "no",
                    "tasks": tasks,
                },
                variable_manager=variable_manager,
                loader=loader,
            )

            play_tasks = play.get_tasks()[0]

            if len(play_tasks) > 1:
                callback = BatchResultsCollector()
            else:
                callback = ResultCollector()

            tqm = TaskQueueManager(
                inventory=inventory_manager,
                variable_manager=variable_manager,
                loader=loader,
                passwords=passwords,
                stdout_callback=callback,
                forks=options.get("forks")
            )
            tqm.run(play)
            return callback.results
        finally:
            if tqm is not None:
                tqm.cleanup()

    def _log_modules(self, caller_info, module_info, verbosity):
        """Log ansible modules to be executed.

        Args:
            caller_info (tuple): Caller information. Tuple of (filename, line_number, function_name, lines, index) got
                from inspect.stack().
            module_info (dict or list): Information of ansible modules to be executed. If only one module is executed,
                module_info is a dict. If multiple modules are executed, module_info is a list of dicts.
            verbosity (int): Verbosity level. If verbosity is 0, no log will be printed.
        """
        if verbosity <= 0:      # Do not log anything
            return

        filename, line_number, function_name, lines, index = caller_info

        if isinstance(self, AnsibleHosts):
            hosts_str = json.dumps(self.hostnames)
        elif isinstance(self, AnsibleHost):
            hosts_str = json.dumps(self.hostnames[0])
        else:
            raise TypeError("Unsupported type of object: {}".format(type(self)))

        if isinstance(module_info, dict):
            module_names = json.dumps(module_info.get("module_name", ""))
            hint_str = "AnsibleModule::{}".format(module_names)
        elif isinstance(module_info, list):
            module_names = ", ".join([module_item.get("module_name", "") for module_item in module_info])
            hint_str = "AnsibleModules::{}".format(json.dumps(module_names))
        else:
            raise TypeError("Got {}, expected tuple or list of tuples, tuple items: "
                            "module_name, module_args, module_kwargs, module_attrs".format(type(module_info)))

        task_headline = "===== {} -> {} ".format(self.host_pattern, module_names)
        task_headline += "=" * (120 - len(task_headline))
        logger.debug(task_headline)

        caller_str = "{}::{}#{}".format(filename, function_name, line_number)

        if verbosity == 1:          # Log module name only. Do not log args.
            logger.debug("{}: {} {}".format(
                caller_str,
                hosts_str,
                hint_str,
            ))
        elif verbosity >= 2:
            if verbosity == 2:      # Log module name and args without indention
                indent = None
                newline = ""
            elif verbosity >= 3:    # Log module name and args with indention
                indent = 4
                newline = "\n"

            logger.debug("{}: {} -> {}, {}{}{}".format(
                caller_str,
                hosts_str,
                hint_str,
                newline,
                json.dumps(module_info, indent=indent),
                newline
            ))

    def _log_results(self, caller_info, module_info, results, verbosity):
        """Log ansible module results.

        Args:
            caller_info (tuple): Caller information. Tuple of (filename, line_number, function_name, lines, index) got
                from inspect.stack().
            module_info (dict or list): Information of ansible modules to be executed. If only one module is executed,
                module_info is a dict. If multiple modules are executed, module_info is a list of dicts.
            results (dict): Results of ansible modules.
            verbosity (int): Verbosity level. If verbosity is 0, no log will be printed.
        """
        if verbosity <= 0:      # Do not log anything
            return

        if isinstance(self, AnsibleHosts):
            hosts_str = json.dumps(self.hostnames)
        elif isinstance(self, AnsibleHost):
            hosts_str = json.dumps(self.hostnames[0])
            results = results.get(self.hostnames[0], {})
        else:
            raise TypeError("Unsupported type of object: {}".format(type(self)))

        filename, line_number, function_name, lines, index = caller_info
        caller_str = "{}::{}#{}".format(filename, function_name, line_number)

        if isinstance(module_info, dict):
            module_names = json.dumps(module_info.get("module_name", ""))
            hint_str = "AnsibleModule::{}".format(module_names)
        elif isinstance(module_info, list):
            module_names = ", ".join([module_item.get("module_name", "") for module_item in module_info])
            hint_str = "AnsibleModules::{}".format(json.dumps(module_names))
        else:
            raise TypeError("Got {}, expected tuple or list of tuples, tuple items: "
                            "module_name, module_args, module_kwargs, module_attrs".format(type(module_info)))

        if verbosity == 1:      # Log module only
            logger.debug("{}: {} -> {} executed".format(
                caller_str,
                hosts_str,
                hint_str
            ))
        elif verbosity >= 2:    # Log result without indention
            if verbosity == 2:
                indent = None
                newline = ""
            elif verbosity >= 3:
                indent = 4
                newline = "\n"

            logger.debug("{}: {} -> {} | Results =>{}{}{}".format(
                caller_str,
                hosts_str,
                hint_str,
                newline,
                json.dumps(results, indent=indent),
                newline
            ))

    def _check_results(self, caller_info, module_info, results, module_ignore_errors, verbosity):
        """Check ansible module results.

        Args:
            caller_info (tuple): Caller information. Tuple of (filename, line_number, function_name, lines, index) got
                from inspect.stack().
            module_info (dict or list): Information of ansible modules to be executed. If only one module is executed,
                module_info is a dict. If multiple modules are executed, module_info is a list of dicts.
            results (dict): Results of ansible modules.
            module_ignore_errors (bool): Ignore module errors or not. If True, no error will be raised even if module
                execution failed.
            verbosity (int): Verbosity level. If verbosity is 0, details of failed modules will not be included in the
                error message.
        """
        if module_ignore_errors:
            return

        filename, line_number, function_name, lines, index = caller_info
        caller_str = "{}::{}#{}".format(filename, function_name, line_number)

        if isinstance(self, AnsibleHosts):
            hosts_str = json.dumps(self.hostnames)
        elif isinstance(self, AnsibleHost):
            hosts_str = json.dumps(self.hostnames[0])
            results = results.get(self.hostnames[0], {})
        else:
            raise TypeError("Unsupported type of object: {}".format(type(self)))

        if isinstance(module_info, dict):
            module_names = json.dumps(module_info.get("module_name", ""))
            hint_str = "AnsibleModule::{}".format(module_names)
        elif isinstance(module_info, list):
            module_names = ", ".join([module_item.get("module_name", "") for module_item in module_info])
            hint_str = "AnsibleModules::{}".format(json.dumps(module_names))
        else:
            raise TypeError("Got {}, expected tuple or list of tuples, tuple items: "
                            "module_name, module_args, module_kwargs, module_attrs".format(type(module_info)))

        err_msg = ""
        if verbosity <= 0:      # No information of module and result
            err_msg = "Run ansible module failed"
        elif verbosity == 1:    # Log module name only. Do not log args and result
            err_msg = "{}: {} -> {} failed".format(
                caller_str,
                hosts_str,
                hint_str
            )
        elif verbosity >= 2:    # Log module name, args and result
            if verbosity == 2:
                indent = None
            elif verbosity >= 3:
                indent = 4

            err_msg = "{}: {} -> {} failed, Results => {}".format(
                caller_str,
                hosts_str,
                hint_str,
                json.dumps(results, indent=indent)
            )

        if isinstance(self, AnsibleHosts):
            if isinstance(module_info, dict):
                failed = any([res["failed"] for res in results.values()])
            else:
                failed = any([any([res["failed"] for res in module_results]) for module_results in results.values()])
        elif isinstance(self, AnsibleHost):
            if isinstance(module_info, dict):
                failed = results["failed"]
            else:
                failed = any([res["failed"] for res in results])
        if failed:
            raise RunAnsibleModuleFailed(err_msg)

    def _run_ansible_module(self, *args, **kwargs):
        """Run ansible module.

        DO NOT call this function directly. Use instance_name.<ansible_module_name>() instead.

        This class has "__getattr__" defined. This function will be called when an attribute is not found in the
        instance. This function will parse the attribute name and consider the attribute name as an Ansible module name.
        Then it will call this function to run the Ansible module.

        Special keyword arguments:
            module_ignore_errors: If this argument is set to True, no RunAnsibleModuleFailed exception will be raised.
            module_attrs: A dict for specifying module attributes that may affect execution of the ansible module.
                Reference documents:
                * https://docs.ansible.com/ansible/2.9/modules/list_of_all_modules.html
                * https://docs.ansible.com/ansible/latest/collections/index.html
            verbosity: integer from 0-3.

        Raises:
            RunAnsibleModuleFailed: Raise this exception if result is failed AND keyword argument
                `module_ignore_errors` is False.

        Args:
            *args: Positional arguments of ansible module.
            **kwargs: Keyword arguments of ansible module.

        Returns:
            dict: Ansible module execution result. If this function is executed on AnsibleHosts instance, the result
                is a dict of dicts. Key is hostname, value is ansible module execution result on that host. If this
                function is executed on AnsibleHost instance (for single host), the result is a dict, which is ansible
                module execution result on the host of AnsibleHost instance.

            Sample result for AnsibleHosts:
                {
                    "VM0100": {
                        "stderr_lines": [],
                        "cmd": "pwd",
                        "stdout": "/root",
                        "delta": "0:00:00.001744",
                        "stdout_lines": [
                            "/root"
                        ],
                        "ansible_facts": {
                            "discovered_interpreter_python": "/usr/bin/python"
                        },
                        "end": "2023-03-20 01:11:01.748306",
                        "_ansible_no_log": false,
                        "start": "2023-03-20 01:11:01.746562",
                        "changed": true,
                        "failed": false,
                        "reachable": true,
                        "stderr": "",
                        "rc": 0,
                        "hostname": "VM0100",
                        "invocation": {
                            "module_args": {
                                "warn": true,
                                "executable": null,
                                "_uses_shell": true,
                                "strip_empty_ends": true,
                                "_raw_params": "pwd",
                                "removes": null,
                                "argv": null,
                                "creates": null,
                                "chdir": null,
                                "stdin_add_newline": true,
                                "stdin": null
                            }
                        }
                    },
                    "VM0101": {
                        "stderr_lines": [],
                        "cmd": "pwd",
                        "stdout": "/root",
                        "delta": "0:00:00.001764",
                        "stdout_lines": [
                            "/root"
                        ],
                        "ansible_facts": {
                            "discovered_interpreter_python": "/usr/bin/python"
                        },
                        "end": "2023-03-20 01:11:01.748302",
                        "_ansible_no_log": false,
                        "start": "2023-03-20 01:11:01.746538",
                        "changed": true,
                        "failed": false,
                        "reachable": true,
                        "stderr": "",
                        "rc": 0,
                        "hostname": "VM0101",
                        "invocation": {
                            "module_args": {
                                "warn": true,
                                "executable": null,
                                "_uses_shell": true,
                                "strip_empty_ends": true,
                                "_raw_params": "pwd",
                                "removes": null,
                                "argv": null,
                                "creates": null,
                                "chdir": null,
                                "stdin_add_newline": true,
                                "stdin": null
                            }
                        }
                    }
                }

            Sample result for AnsibleHost:
                {
                    "stderr_lines": [],
                    "cmd": [
                        "pwd"
                    ],
                    "stdout": "/home/admin",
                    "delta": "0:00:00.002754",
                    "stdout_lines": [
                        "/home/admin"
                    ],
                    "ansible_facts": {
                        "discovered_interpreter_python": "/usr/bin/python"
                    },
                    "end": "2023-03-20 01:17:02.602775",
                    "_ansible_no_log": false,
                    "start": "2023-03-20 01:17:02.600021",
                    "changed": true,
                    "failed": false,
                    "reachable": true,
                    "stderr": "",
                    "rc": 0,
                    "hostname": "vlab-01",
                    "invocation": {
                        "module_args": {
                            "creates": null,
                            "executable": null,
                            "_uses_shell": false,
                            "strip_empty_ends": true,
                            "_raw_params": "pwd",
                            "removes": null,
                            "argv": null,
                            "warn": true,
                            "chdir": null,
                            "stdin_add_newline": true,
                            "stdin": null
                        }
                    }
                }
        """
        caller_info = kwargs.pop("caller_info", None)
        if not caller_info:
            previous_frame = inspect.currentframe().f_back
            caller_info = inspect.getframeinfo(previous_frame)

        module_args = copy.deepcopy(args)
        module_kwargs = copy.deepcopy(kwargs)

        verbosity = module_kwargs.pop("verbosity", None)
        if not verbosity:
            verbosity = self.options.get("verbosity", 2)
        module_ignore_errors = module_kwargs.pop("module_ignore_errors", False)
        module_attrs = module_kwargs.pop("module_attrs", {})

        module_info = {
            "module_name": self.module_name,
            "args": module_args,
            "kwargs": module_kwargs,
            "module_attrs": module_attrs
        }
        self._log_modules(caller_info, module_info, verbosity)

        task = self.build_task(**module_info)
        results = self.run_tasks(self.host_pattern, self.loader, self.im, self.vm, self.options, tasks=[task])

        self._log_results(caller_info, module_info, results, verbosity)
        self._check_results(caller_info, module_info, results, module_ignore_errors, verbosity)

        if isinstance(self, AnsibleHost):
            results = results[self.hostnames[0]]

        return results

    def __getattr__(self, attr):
        """For finding ansible module and return a function for running that ansible module.

        Args:
            attr (str): Attribute name of current object. Usually ansible module name.

        Raises:
            UnsupportedAnsibleModule: Unable to find ansible module specified by `attr` from ansible builtin modules
                or current visible customized modules.

        Returns:
            callable: A function for running ansible module specified by `attr`.
        """
        if not module_loader.has_plugin(attr):
            raise UnsupportedAnsibleModule("Unsupported ansible module \"{}\"".format(attr))
        self.module_name = attr

        return self._run_ansible_module

    def run_module(self, module_name, args=[], kwargs={}):
        """Run ansible module specified by `module_name`.

        Special keyword arguments:
            module_ignore_errors: If this argument is set to True, no RunAnsibleModuleFailed exception will be raised.
            module_attrs: A dict for specifying module attributes that may affect execution of the ansible module.
                Reference documents:
                * https://docs.ansible.com/ansible/2.9/modules/list_of_all_modules.html
                * https://docs.ansible.com/ansible/latest/collections/index.html
            verbosity: integer from 0-3.

        Args:
            module_name (str): Ansible module name.
            args (list): Ansible module arguments.
            kwargs (dict): Ansible module keyword arguments.

        Raises:
            UnsupportedAnsibleModule: Unable to find ansible module specified by `module_name` from ansible builtin

        Returns:
            dict: A dict for ansible module execution result. Same as the result of `self._run_ansible_module`.
        """
        if not module_loader.has_plugin(module_name):
            raise UnsupportedAnsibleModule("Unsupported ansible module \"{}\"".format(module_name))
        self.module_name = module_name

        previous_frame = inspect.currentframe().f_back
        caller_info = inspect.getframeinfo(previous_frame)
        kwargs.update({"caller_info": caller_info})

        return self._run_ansible_module(*args, **kwargs)

    def load_module(self, module_name, args=[], kwargs={}, module_attrs={}):
        """Load a module with arguments into a list.

        This method load a module with arguments into a list. Method `self.run_loaded_modules` can run the loaded
        modules in a single play.

        Comparing with `self.run_module` or `self._run_ansible_module`, special keyword arguments are not supported
        in `kwargs` of `self.load_module`. The special keyword arguments are supported by the `self.run_loaded_modules`
        method.

        Args:
            module_name (str): Ansible module name. Can be builtin module or customized module.
            args (list, optional): Positional arguments of ansible module. Defaults to [].
            kwargs (dict, optional): Keyword arguments of ansible module. Defaults to {}.
            module_attrs (dict, optional): Module attributes affect module execution.
        """
        self._loaded_modules.append(
            {
                "module_name": module_name,
                "args": args,
                "kwargs": kwargs,
                "module_attrs": module_attrs
            }
        )

    def clear_loaded_modules(self):
        """Clear the list of loaded ansible modules.
        """
        self._loaded_modules = []

    def run_loaded_modules(self, module_ignore_errors=False, verbosity=2):
        """Run the list of loaded ansible modules.

        Args:
            verbosity (int): Verbosity value from 0-3.

        Returns:
            dict: Ansible module execution results. Sample result:
                {
                    "vlab-01": [
                        {
                            "stderr_lines": [],
                            "cmd": [
                                "pwd"
                            ],
                            "stdout": "/home/admin",
                            "delta": "0:00:00.002754",
                            "stdout_lines": [
                                "/home/admin"
                            ],
                            "ansible_facts": {
                                "discovered_interpreter_python": "/usr/bin/python"
                            },
                            "end": "2023-03-20 01:17:02.602775",
                            "_ansible_no_log": false,
                            "start": "2023-03-20 01:17:02.600021",
                            "changed": true,
                            "failed": false,
                            "reachable": true,
                            "stderr": "",
                            "rc": 0,
                            "hostname": "vlab-01",
                            "invocation": {
                                "module_args": {
                                    "creates": null,
                                    "executable": null,
                                    "_uses_shell": false,
                                    "strip_empty_ends": true,
                                    "_raw_params": "pwd",
                                    "removes": null,
                                    "argv": null,
                                    "warn": true,
                                    "chdir": null,
                                    "stdin_add_newline": true,
                                    "stdin": null
                                }
                            }
                        },
                        {
                            "stderr_lines": [],
                            "cmd": "ls",
                            "end": "2023-03-20 01:17:02.812231",
                            "_ansible_no_log": false,
                            "stdout": "config.json\nmyfile",
                            "changed": true,
                            "rc": 0,
                            "failed": false,
                            "reachable": true,
                            "stderr": "",
                            "delta": "0:00:00.003928",
                            "hostname": "vlab-01",
                            "invocation": {
                                "module_args": {
                                    "creates": null,
                                    "executable": null,
                                    "_uses_shell": true,
                                    "strip_empty_ends": true,
                                    "_raw_params": "ls",
                                    "removes": null,
                                    "argv": null,
                                    "warn": true,
                                    "chdir": null,
                                    "stdin_add_newline": true,
                                    "stdin": null
                                }
                            },
                            "stdout_lines": [
                                "config.json",
                                "myfile"
                            ],
                            "start": "2023-03-20 01:17:02.808303"
                        }
                    ]
                }
        """
        if len(self._loaded_modules) == 0:
            logger.info("No loaded task.")
            return {}

        previous_frame = inspect.currentframe().f_back
        caller_info = inspect.getframeinfo(previous_frame)

        loaded_modules = copy.deepcopy(self._loaded_modules)
        self.clear_loaded_modules()
        self._log_modules(caller_info, self._loaded_modules, verbosity)

        tasks = [
            self.build_task(**module) for module in loaded_modules
        ]
        results = self.run_tasks(self.host_pattern, self.loader, self.im, self.vm, self.options, tasks=tasks)

        self._log_results(caller_info, loaded_modules, results, verbosity)
        self._check_results(caller_info, loaded_modules, results, module_ignore_errors, verbosity)

        return results

    def get_inv_host(self, hostname, strict=False):
        """Tool for getting ansible.inventory.host.Host object from self.inventories using ansible inventory manager.

        Args:
            hostname (str): Hostname
            strict (bool, optional): If strict==True, only get host with hostname matching self.host_pattern in
                self.inventories. If strict=False, get any host with hostname from self.inventories. Defaults to False.

        Returns:
            ansible.inventory.host.Host or None: Object of class ansible.inventory.host.Host or None.
        """
        if strict:
            # Only get host with hostname from self.ans_inv_hosts
            for _host in self.ans_inv_hosts:
                if _host.name == hostname:
                    return _host
            else:
                return None
        else:
            # Get host with hostname from whole inventory
            return self.im.get_host(hostname)

    def get_inv_hosts(self, host_pattern):
        """Tool for getting list of ansible.inventory.host.Host objects from self.inventories using ansible inventory
        manager. Ansible inventory manager is used under the hood.

        Args:
            host_pattern (str or list): Host pattern string or list of host pattern strings. Interpreted by ansible.
                Follow the same rules of specifying ansible hosts in ansible play book.

        Returns:
            list: List of ansible.inventory.host.Host objects.
        """
        return self.im.get_hosts(host_pattern)

    def get_host_vars(self, hostname, strict=False):
        """Tool for getting variables of specified host from self.inventories. Variables defined in group_vars and
        host_vars are not included. Only ansible inventory manager is used under the hood.

        Args:
            hostname (str): Hostname.
            strict (bool, optional): If strict==True, only get variables of host with hostname from hosts matching
                self.host_pattern in self.inventories. If strict=False, get variables of any host with hostname from
                self.inventories. Defaults to False.

        Returns:
            dict: Dict of variables. Key is variable name. Value is variable value.
        """
        _host = self.get_inv_host(hostname, strict=strict)
        if not _host:
            return {}
        return _host.get_vars()

    def get_host_var(self, hostname, var, strict=False):
        """Tool for getting variable value of specified host from self.inventories. Variables defined in group_vars and
        host_vars are not included. Only ansible inventory manager is used under the hood.

        Args:
            hostname (str): Hostname.
            var (str): Variable name.
            strict (bool, optional): If strict==True, only get variable value of host with hostname from hosts matching
                self.host_pattern in self.inventories. If strict=False, get variable value of any host with hostname
                from self.inventories. Defaults to False.

        Returns:
            Any: Variable value, possible types: str, int, bool, list, dict.
        """
        return self.get_host_vars(hostname, strict).get(var, None)

    def get_host_visible_vars(self, hostname, strict=False):
        """Tool for getting visible variables of specified host. Variables may be defined in inventory files, any
        group_vars and host_vars files. Both ansible inventory manager and variable managers are used under the hood.

        Args:
            hostname (str): Hostname.
            strict (bool, optional): If strict==True, only get visible variables of host with hostname from hosts
                matching self.host_pattern in self.inventories. If strict=False, get visible variables of any host
                with hostname from self.inventories. Defaults to False.

        Returns:
            dict: Dict of variables. Key is variable name. Value is variable value.
        """
        _host = self.get_inv_host(hostname, strict=strict)
        if not _host:
            return {}
        return self.vm.get_vars(host=_host)

    def get_host_visible_var(self, hostname, var, strict=False):
        """Tool for getting visible variable value of specified host. Variable may be defined in inventory files, any
        group_vars and host_vars files. Both ansible inventory manager and variable managers are used under the hood.

        Args:
            hostname (str): Hostname.
            var (str): Variable name.
            strict (bool, optional): If strict==True, only get visible variable value of host with hostname from hosts
                matching self.host_pattern in self.inventories. If strict=False, get visible variable value of any host
                with hostname from self.inventories. Defaults to False.

        Returns:
            Any: Variable value, possible types: str, int, bool, list, dict.
        """
        return self.get_host_visible_vars(hostname, strict=strict).get(var, None)


class AnsibleHosts(AnsibleHostsBase):

    def __init__(
            self,
            inventories,
            host_pattern,
            loader=None,
            inventory_manager=None,
            variable_manager=None,
            options={},
            hostvars={}):

        super(AnsibleHosts, self).__init__(
            inventories,
            host_pattern,
            loader=loader,
            inventory_manager=inventory_manager,
            variable_manager=variable_manager,
            options=options,
            hostvars=hostvars
        )

        self.ans_hosts = [
            AnsibleHost(
                inventories,
                hostname,
                self.loader,
                self.im,
                self.vm,
                self.options,
                hostvars,
            ) for hostname in self.hostnames
        ]

    # implement a list like interface based on attribute self.ans_hosts
    def __len__(self):
        return len(self.ans_hosts)

    def __iter__(self):
        return iter(self.ans_hosts)

    def __getitem__(self, index):

        if isinstance(index, int):
            if index < 0:
                index = len(self.ans_hosts) + index
            if index < 0 or index >= len(self.ans_hosts):
                raise IndexError("AnsibleHosts index out of range")
            return self.ans_hosts[index]
        elif isinstance(index, str):
            for ans_host in self.ans_hosts:
                if ans_host.hostname == index:
                    return ans_host
            raise KeyError("AnsibleHost with hostname '{}' not found".format(index))
        else:
            raise TypeError("AnsibleHosts indices must be integers or strings, not {}".format(type(index)))

    def __str__(self):
        return "<AnsibleHosts {} in {}>".format(self.hostnames, self.inventories)

    def __repr__(self):
        return self.__str__()


class AnsibleHost(AnsibleHostsBase):

    def __init__(
            self,
            inventories,
            host_pattern,
            loader=None,
            inventory_manager=None,
            variable_manager=None,
            options={},
            hostvars={}):

        super(AnsibleHost, self).__init__(
            inventories,
            host_pattern,
            loader=loader,
            inventory_manager=inventory_manager,
            variable_manager=variable_manager,
            options=options,
            hostvars=hostvars
        )

        if len(self.ans_inv_hosts) > 1:
            raise MultipleAnsibleHostsError(
                "More than one host match '{}' in inventory files '{}'".format(self.host_pattern, self.inventories)
            )
        self.ans_inv_host = self.ans_inv_hosts[0]
        self.hostname = self.ans_inv_host.name
        self.ip = self.ans_inv_host.get_vars().get("ansible_host", None)

    def __str__(self):
        return "<AnsibleHost {} in {}>".format(self.hostname, self.inventories)

    def __repr__(self):
        return self.__str__()
