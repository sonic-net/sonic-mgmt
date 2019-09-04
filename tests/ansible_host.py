from ansible.plugins import callback_loader
from ansible.errors import AnsibleError

def dump_ansible_results(results, stdout_callback='yaml'):
    cb = callback_loader.get(stdout_callback)
    return cb._dump_results(results) if cb else results

class AnsibleModuleException(AnsibleError):

    """Sub-class AnsibleError when module exceptions occur."""

    def __init__(self, msg, results=None):
        super(AnsibleModuleException, self).__init__(msg)
        self.results = results

    def __str__(self):
        return "{}\nAnsible Results => {}".format(self.message, dump_ansible_results(self.results))

class AnsibleHost(object):
    """ wrapper for ansible host object """

    def __init__(self, ansible_adhoc, hostname, is_local=False):
        if is_local:
            self.host = ansible_adhoc(inventory='localhost', connection='local')[hostname]
        else:
            self.host = ansible_adhoc(become=True)[hostname]
        self.hostname = hostname

    def __getattr__(self, item):
        self.module_name = item
        self.module = getattr(self.host, item)

        return self._run

    def _run(self, *module_args, **complex_args):

        module_ignore_errors = complex_args.pop('module_ignore_errors', False)

        res = self.module(*module_args, **complex_args)[self.hostname]
        if res.is_failed and not module_ignore_errors:
            raise AnsibleModuleException("run module {} failed".format(self.module_name), res)

        return res
