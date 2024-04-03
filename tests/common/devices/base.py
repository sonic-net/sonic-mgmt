import inspect
import json
import logging

from multiprocessing.pool import ThreadPool

from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)

# HACK: This is a hack for issue https://github.com/sonic-net/sonic-mgmt/issues/1941 and issue
# https://github.com/ansible/pytest-ansible/issues/47
# Detailed root cause analysis of the issue: https://github.com/sonic-net/sonic-mgmt/issues/1941#issuecomment-670434790
# Before calling callback function of plugins to return ansible module result, ansible calls the
# ansible.executor.task_result.TaskResult.clean_copy method to remove some keys like 'failed' and 'skipped' in the
# result dict. The keys to be removed are defined in module variable ansible.executor.task_result._IGNORE. The trick
# of this hack is to override this pre-defined key list. When the 'failed' key is not included in the list, ansible
# will not remove it before returning the ansible result to plugins (pytest_ansible in our case)
try:
    from ansible.executor import task_result
    task_result._IGNORE = ('skipped', )
except Exception as e:
    logger.error("Hack for https://github.com/ansible/pytest-ansible/issues/47 failed: {}".format(repr(e)))


class AnsibleHostBase(object):
    """
    @summary: The base class for various objects.

    This class filters an object from the ansible_adhoc fixture by hostname. The object can be considered as an
    ansible host object although it is not under the hood. Anyway, we can use this object to run ansible module
    on the host.
    """

    class CustomEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, bytes):
                return obj.decode('utf-8')
            return super().default(obj)

    def __init__(self, ansible_adhoc, hostname, *args, **kwargs):
        if hostname == 'localhost':
            self.host = ansible_adhoc(connection='local', host_pattern=hostname)[hostname]
        else:
            self.host = ansible_adhoc(become=True, *args, **kwargs)[hostname]
            self.mgmt_ip = self.host.options["inventory_manager"].get_host(hostname).vars["ansible_host"]
            if "ansible_hostv6" in self.host.options["inventory_manager"].get_host(hostname).vars:
                self.mgmt_ipv6 = self.host.options["inventory_manager"].get_host(hostname).vars["ansible_hostv6"]
            else:
                self.mgmt_ipv6 = None
        self.hostname = hostname

    def __getattr__(self, module_name):
        if self.host.has_module(module_name):
            self.module_name = module_name
            self.module = getattr(self.host, module_name)

            return self._run
        raise AttributeError(
            "'%s' object has no attribute '%s'" % (self.__class__, module_name)
            )

    def _run(self, *module_args, **complex_args):

        previous_frame = inspect.currentframe().f_back
        filename, line_number, function_name, lines, index = inspect.getframeinfo(previous_frame)

        verbose = complex_args.pop('verbose', True)

        if verbose:
            logger.debug(
                "{}::{}#{}: [{}] AnsibleModule::{}, args={}, kwargs={}".format(
                    filename,
                    function_name,
                    line_number,
                    self.hostname,
                    self.module_name,
                    json.dumps(module_args, cls=AnsibleHostBase.CustomEncoder),
                    json.dumps(complex_args, cls=AnsibleHostBase.CustomEncoder)
                )
            )
        else:
            logger.debug(
                "{}::{}#{}: [{}] AnsibleModule::{} executing...".format(
                    filename,
                    function_name,
                    line_number,
                    self.hostname,
                    self.module_name
                )
            )

        module_ignore_errors = complex_args.pop('module_ignore_errors', False)
        module_async = complex_args.pop('module_async', False)

        if module_async:
            def run_module(module_args, complex_args):
                return self.module(*module_args, **complex_args)[self.hostname]
            pool = ThreadPool()
            result = pool.apply_async(run_module, (module_args, complex_args))
            return pool, result

        module_args = json.loads(json.dumps(module_args, cls=AnsibleHostBase.CustomEncoder))
        complex_args = json.loads(json.dumps(complex_args, cls=AnsibleHostBase.CustomEncoder))
        res = self.module(*module_args, **complex_args)[self.hostname]

        if verbose:
            logger.debug(
                "{}::{}#{}: [{}] AnsibleModule::{} Result => {}".format(
                    filename,
                    function_name,
                    line_number,
                    self.hostname,
                    self.module_name, json.dumps(res, cls=AnsibleHostBase.CustomEncoder)
                )
            )
        else:
            logger.debug(
                "{}::{}#{}: [{}] AnsibleModule::{} done, is_failed={}, rc={}".format(
                    filename,
                    function_name,
                    line_number,
                    self.hostname,
                    self.module_name,
                    res.is_failed,
                    res.get('rc', None)
                )
            )

        if (res.is_failed or 'exception' in res) and not module_ignore_errors:
            raise RunAnsibleModuleFail("run module {} failed".format(self.module_name), res)

        return res


class NeighborDevice(dict):
    def __str__(self):
        return str(self["host"])

    def __repr__(self):
        return self.__str__()
