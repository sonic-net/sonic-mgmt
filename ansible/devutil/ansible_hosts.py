"""Basic classes and functions for running ansible modules on devices by python.

This idea is mainly inspired by the pytest-ansible plugin. With the classes and functions defined here, we can run any
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

from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.playbook.play import Play

from ansible.plugins.callback import CallbackBase
from ansible.plugins.loader import module_loader
from ansible import context
from ansible.module_utils.common.collections import ImmutableDict

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

        res = dict(reachable=True, failed=False)
        res.update(result._result)
        self._results[hostname] = res

    def v2_runner_on_failed(self, result, *args, **kwargs):
        hostname = result._host.get_name()

        res = dict(reachable=True, failed=True)
        res.update(result._result)
        self._results[hostname] = res

    def v2_runner_on_unreachable(self, result, *args, **kwargs):
        hostname = result._host.get_name()

        res = dict(reachable=False, failed=True)
        res.update(result._result)
        self._results[hostname] = res

    @property
    def results(self):
        """Property for returning execution result of single ansible module on ansible hosts.

        The result is a dict keyed by hostname. Value is the ansible module execution result on that host.
        Sample result:
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

        res = dict(reachable=True, failed=False)
        res.update(result._result)
        self._results[hostname].append(res)

    def v2_runner_on_failed(self, result, *args, **kwargs):
        hostname = result._host.get_name()
        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(reachable=True, failed=True)
        res.update(result._result)
        self._results[hostname].append(res)

    def v2_runner_on_unreachable(self, result):
        hostname = result._host.get_name()
        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(reachable=False, failed=True)
        res.update(result._result)
        self._results[hostname].append(result._result)

    @property
    def results(self):
        """Property for returning multiple ansible module execution results of multiple ansible hosts.

        The result is a dict keyed by hostname. Value is list of the ansible module execution results on that host.
        Sample result:
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

        Returns:
            dict: Result is a dict. Key is hostname. Value is ansible module execution result.
        """
        return self._results


class AnsibleHosts(object):
    """Basic class for running ansible modules on hosts defined in ansible inventory file.

    Instance of this class is for running ansible modules on hosts defined in ansible inventory file. The class
    instance is not a python list. It represents a list of hosts matching specified pattern in specified ansible
    inventory file.
    """
    def __init__(
            self,
            inventories,
            hosts_pattern,
            options={},
            hostvars={}):
        """Constructor of AnsibleHosts.

        Args:
            inventories (str or list): Inventory file or a list of inventory files. Consumed by ansible under the hood.
            hosts_pattern (str or list): Host pattern string or list of host pattern strings. Interpreted by ansible.
                Follow the same rules of specifying ansible hosts in ansible play book.
                Examples:
                    "vlab-01"
                    "VM0100, VM0101"
                    ["VM0100", "VM0101"]
                    "server_1:&vm_host"
            options (dict, optional): Options affecting ansible execution. Supports options that can be passed in from
                ansible-playbook command line. Defaults to {}.
                Examples:
                    options={"become": True, "forks": 10}
            hostvars (dict, optional): Additional ansible variables for ansible hosts. Similar as using `-e` argument
                of ansible-playbook command line to specify additional host variables. Defaults to {}.

        Raises:
            NoAnsibleHostError: Raise this exception when no host matching specified pattern in inventory file.
        """
        self.inventories = inventories
        self.hosts_pattern = hosts_pattern

        # Default options
        self._options = {
            "forks": 5,
            "connection": "smart",
            "verbosity": 2,
            "become_method": "sudo"
        }
        if options:
            self._options.update(options)

        context.CLIARGS = ImmutableDict(**self._options)

        self.loader = DataLoader()
        self.im = InventoryManager(loader=self.loader, sources=self.inventories)
        self.vm = VariableManager(loader=self.loader, inventory=self.im)

        self.hosts = self.im.get_hosts(self.hosts_pattern)      # List of <class 'ansible.inventory.host.Host'>
        if len(self.hosts) == 0:
            raise NoAnsibleHostError(
                "No hosts '{}' in inventory files '{}'".format(self.hosts_pattern, self.inventories)
            )
        self.hosts_count = len(self.hosts)
        self.hostnames = [_host.name for _host in self.hosts]                       # List of hostname (str)
        self.ipaddrs = [_host.vars.get("ansible_host") for _host in self.hosts]     # List of IPs (str)

        if hostvars:
            self.vm.extra_vars.update(hostvars)

        self._loaded_tasks = []

    def get_host(self, hostname, strict=False):
        """Tool for getting ansible.inventory.host.Host object from self.inventories using ansible inventory manager.

        Args:
            hostname (str): Hostname
            strict (bool, optional): If strict==True, only get host with hostname from hosts matching
                self.hosts_pattern in self.inventories. If strict=False, get any host with hostname from
                self.inventories. Defaults to False.

        Returns:
            ansible.inventory.host.Host or None: Object of class ansible.inventory.host.Host or None.
        """
        if strict:
            # Only get host with hostname from self.hosts
            for _host in self.hosts:
                if _host.name == hostname:
                    return _host
            else:
                return None
        else:
            # Get host with hostname from whole inventory
            return self.im.get_host(hostname)

    def get_hosts(self, hosts_pattern):
        """Tool for getting list of ansible.inventory.host.Host objects from self.inventories using ansible inventory
        manager. Ansible inventory manager is used under the hood.

        Args:
            hosts_pattern (str or list): Host pattern string or list of host pattern strings. Interpreted by ansible.
                Follow the same rules of specifying ansible hosts in ansible play book.

        Returns:
            list: List of ansible.inventory.host.Host objects.
        """
        return self.im.get_hosts(hosts_pattern)

    def get_host_vars(self, hostname, strict=False):
        """Tool for getting variables of specified host from self.inventories. Variables defined in group_vars and
        host_vars are not included. Only ansible inventory manager is used under the hood.

        Args:
            hostname (str): Hostname.
            strict (bool, optional): If strict==True, only get variables of host with hostname from hosts matching
                self.hosts_pattern in self.inventories. If strict=False, get variables of any host with hostname from
                self.inventories. Defaults to False.

        Returns:
            dict: Dict of variables. Key is variable name. Value is variable value.
        """
        _host = self.get_host(hostname, strict=strict)
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
                self.hosts_pattern in self.inventories. If strict=False, get variable value of any host with hostname
                from self.inventories. Defaults to False.

        Returns:
            Any: Variable value, possible types: str, int, bool, list, dict.
        """
        return self.get_host_vars(hostname, strict=strict).get(var, None)

    def get_host_visible_vars(self, hostname, strict=False):
        """Tool for getting visible variables of specified host. Variables may be defined in inventory files, any
        group_vars and host_vars files. Both ansible inventory manager and variable managers are used under the hood.

        Args:
            hostname (str): Hostname.
            strict (bool, optional): If strict==True, only get visible variables of host with hostname from hosts
                matching self.hosts_pattern in self.inventories. If strict=False, get visible variables of any host
                with hostname from self.inventories. Defaults to False.

        Returns:
            dict: Dict of variables. Key is variable name. Value is variable value.
        """
        _host = self.get_host(hostname, strict=strict)
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
                matching self.hosts_pattern in self.inventories. If strict=False, get visible variable value of any host
                with hostname from self.inventories. Defaults to False.

        Returns:
            Any: Variable value, possible types: str, int, bool, list, dict.
        """
        return self.get_host_visible_vars(hostname, strict=strict).get(var, None)

    def __getattr__(self, attr):
        """For finding ansible module and return a function for running that ansible module.

        Args:
            attr (str): Name of an attribute of current object. Usually ansible module name.

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

    def _build_task(self, module_name, args=[], kwargs={}, module_attrs={}):
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
        kwargs = copy.deepcopy(kwargs)  # Avoid argument passed by reference issue
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

    def _build_play(self, tasks=[]):
        """Build a dict represents an ansible playbook.

        The list of tasks may include single or multiple tasks.

        Args:
            tasks (list, optional): List of dict represents task in ansible playbook. Defaults to [].

        Returns:
            dict: A dict represents an ansible playbook.
        """
        return Play().load(
            {
                "hosts": self.hosts_pattern,    # Playbook will be executed on hosts matching `self.hosts_pattern`
                "gather_facts": "no",
                "tasks": tasks,
            },
            variable_manager=self.vm,
            loader=self.loader,
        )

    def _run_play(self, play):
        """Use ansible's TaskQueueManager to run a playbook described in a dict.

        Args:
            play (dict): A dict represents an ansible playbook.

        Returns:
            dict: Results of running ansible modules in playbook. If task list length is 1, ResultCollector is used
                as result collector callback. If task list length is greater than 1, BatchResultsCollector is used as
                result collector callback.
        """
        play_tasks = play.get_tasks()[0]

        if len(play_tasks) > 1:
            callback = BatchResultsCollector()
        else:
            callback = ResultCollector()

        tqm = TaskQueueManager(
            inventory=self.im,
            variable_manager=self.vm,
            loader=self.loader,
            passwords=dict(vault_pass="secret"),
            stdout_callback=callback,
            forks=self._options.get("forks")
        )
        tqm.run(play)

        return callback.results

    def _run_ansible_module(self, *args, **kwargs):
        """Function for running ansible module.

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

        Returns:
            dict: Ansible module execution result. Sample result:
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
        """
        previous_frame = inspect.currentframe().f_back
        filename, line_number, function_name, lines, index = inspect.getframeinfo(previous_frame)

        verbosity = kwargs.pop("verbosity", self._options.get("verbosity"))
        module_ignore_errors = kwargs.pop("module_ignore_errors", False)
        module_attrs = kwargs.pop("module_attrs", {})

        task_headline = "===== [{}] {} ".format(self.hosts_pattern, self.module_name)
        task_headline_suffix = "=" * (120 - len(task_headline))
        task_headline += task_headline_suffix

        if verbosity <= 0:          # Do not log module calls at all.
            pass
        elif verbosity == 1:        # Log module name only. Do not log args.
            logger.debug(task_headline)
            logger.debug("{}::{}#{}: [{}] AnsibleModule::{}".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name
            ))
        elif verbosity == 2:        # Log args without indention.
            logger.debug(task_headline)
            logger.debug("{}::{}#{}: [{}] AnsibleModule::{}, args={}, kwargs={}".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name,
                json.dumps(args),
                json.dumps(kwargs)
            ))
        elif verbosity >= 3:        # Log args with indention.
            logger.debug(task_headline)
            logger.debug("{}::{}#{}: [{}] AnsibleModule::{},\nargs={},\nkwargs={}\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name,
                json.dumps(args, indent=4),
                json.dumps(kwargs, indent=4)
            ))

        # Build task/play, run the play, get results
        task = self._build_task(self.module_name, args=args, kwargs=kwargs, module_attrs=module_attrs)
        play = self._build_play(tasks=[task])
        res = self._run_play(play)

        if verbosity <= 0:          # Do not log module results at all
            pass
        elif verbosity == 1:        # Log module name only. Do not log module results.
            logger.debug("{}::{}#{}: [{}] AnsibleModule::{} executed\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name
            ))
        elif verbosity == 2:        # Log module results without indention.
            logger.debug("{}::{}#{}: [{}] AnsibleModule::{} Result => {}\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name,
                json.dumps(res)
            ))
        elif verbosity >= 3:        # Log module results with indention.
            logger.debug("{}::{}#{}: [{}] AnsibleModule::{} Result =>\n{}\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name,
                json.dumps(res, indent=4)
            ))

        if not module_ignore_errors and any([host_result["failed"] for host_result in res.values()]):
            raise RunAnsibleModuleFailed("{}::{}#{}: [{}] AnsibleModule::{} failed".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                self.module_name
            ))

        return res

    def run_module(self, module_name, args=[], kwargs={}):
        """Run ansible module in an explicit way.

        Method `self.__getattr__` combined with `self._run_ansible_module` supports call ansible module in an
        implicit way like below:
            myhost.<module_name>(*args, **kwargs)
        We directly use the `.` operator to get a function for running ansible module specified by `module_name`.

        Since "Zen of python" prefers explicit over implicit, this method is to support running ansible module
        in an explicit way.

        Args:
            module_name (str): Ansible module name. Can be builtin module or customized module.
            args (list, optional): Positional arguments of ansible module. Enclosed in a list. Defaults to [].
            kwargs (dict, optional): Keyword arguments of ansible module. Enclosed in a dict. Defaults to {}.
                Supports special keyword arguments like:
                    * "module_ignore_errors"


        Raises:
            UnsupportedAnsibleModule: Unable to find ansible module specified by `module_name` from ansible builtin
                modules or current visible customized modules.

        Returns:
            dict: Ansible module execution result.
        """
        if not module_loader.has_plugin(module_name):
            raise UnsupportedAnsibleModule("Unsupported ansible module \"{}\"".format(module_name))
        self.module_name = module_name

        return self._run_ansible_module(*args, **kwargs)

    def load_module(self, module_name, args=[], kwargs={}, module_attrs={}):
        """Load a module with arguments into a task list.

        This method load a module with arguments into a task list. Method `self.run_loaded_modules` can run the loaded
        modules in a single play.

        Args:
            module_name (str): Ansible module name. Can be builtin module or customized module.
            args (list, optional): Positional arguments of ansible module. Defaults to [].
            kwargs (dict, optional): Keyword arguments of ansible module. Defaults to {}.
            module_attrs (dict, optional): Module attributes affect module execution.
        """
        self._loaded_tasks.append(self._build_task(module_name, args=args, kwargs=kwargs, module_attrs=module_attrs))

    def clear_loaded_modules(self):
        """Clear the list of loaded ansible modules.
        """
        self._loaded_tasks = []

    def run_loaded_modules(self, verbosity=2):
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
        if len(self._loaded_tasks) == 0:
            logger.info("No loaded task.")
            return {}

        previous_frame = inspect.currentframe().f_back
        filename, line_number, function_name, lines, index = inspect.getframeinfo(previous_frame)

        tasks = self._loaded_tasks[:]
        self.clear_loaded_modules()

        task_names = [task["action"]["module"] for task in tasks]

        if len(task_names) > 100:
            truncated_task_names = task_names[:100] + "..."
        else:
            truncated_task_names = task_names

        play_headline = "===== [{}] {} ".format(self.hosts_pattern, ",".join(truncated_task_names))
        play_headline_suffix = "=" * (120 - len(play_headline))
        play_headline += play_headline_suffix

        if verbosity <= 0:
            pass
        elif verbosity == 1:
            logger.debug(play_headline)
            logger.debug("{}::{}#{}: [{}] Tasks: {}".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                task_names
            ))
        elif verbosity == 2:
            logger.debug(play_headline)
            logger.debug("{}::{}#{}: [{}] Tasks: {}".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                json.dumps(tasks)
            ))
        elif verbosity >= 3:
            logger.debug(play_headline)
            logger.debug("{}::{}#{}: [{}] Tasks:\n{}".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                json.dumps(tasks, indent=4)
            ))

        play = self._build_play(tasks=tasks)
        results = self._run_play(play)

        if verbosity <= 0:
            pass
        elif verbosity == 1:
            logger.debug("{}::{}#{}: [{}] Executed tasks: {}\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                task_names
            ))
        elif verbosity == 2:
            logger.debug("{}::{}#{}: [{}] Results => {}\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                json.dumps(results)
            ))
        elif verbosity >= 3:
            logger.debug("{}::{}#{}: [{}] Results =>\n{}\n".format(
                filename,
                function_name,
                line_number,
                self.hosts_pattern,
                json.dumps(results, indent=4)
            ))

        return results


class AnsibleHost(AnsibleHosts):
    """Basic class for running ansible modules on single host defined in ansible inventory file.

    Parent class AnsibleHosts supports running ansible module on hosts matching hosts_pattern, which could be single
    or multiple hosts.

    This class ensures that the pattern only matches single host in inventory file. If the pattern matches more than
    one host, `__init__` will raise exception MultipleAnsibleHostsError.

    Args:
        AnsibleHosts (_type_): _description_
    """
    def __init__(
            self,
            inventories,
            host_pattern,
            options={},
            hostvars={}):
        super(AnsibleHost, self).__init__(inventories, host_pattern, options=options, hostvars=hostvars)
        if self.hosts_count > 1:
            raise MultipleAnsibleHostsError("'{}' matches more than 1 host in '{}'".format(host_pattern, inventories))
        self.host = self.hosts[0]
        self.hostvars = self.host.get_vars()
        self.hostname = self.hostvars.get("inventory_hostname")
        self.ipaddr = self.hostvars.get("ansible_host")
        self.host_visible_vars = self.vm.get_vars(host=self.host)
