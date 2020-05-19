"""
Customize exceptions
"""
from ansible.plugins.loader import callback_loader
from ansible.errors import AnsibleError


class UnsupportedAnsibleModule(Exception):
    pass


def dump_ansible_results(results, stdout_callback='yaml'):
    cb = callback_loader.get(stdout_callback)
    return cb._dump_results(results) if cb else results


class RunAnsibleModuleFail(AnsibleError):

    """Sub-class AnsibleError when module exceptions occur."""

    def __init__(self, msg, results=None):
        super(RunAnsibleModuleFail, self).__init__(msg)
        self.results = results

    def __str__(self):
        return "{}\nAnsible Results => {}".format(self.message, dump_ansible_results(self.results))
