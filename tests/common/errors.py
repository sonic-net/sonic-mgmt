"""
Customize exceptions
"""
from ansible.errors import AnsibleError
from ansible.plugins.loader import callback_loader


class UnsupportedAnsibleModule(Exception):
    pass


def dump_ansible_results(results, stdout_callback='json'):
    try:
        cb = callback_loader.get(stdout_callback)
        return cb._dump_results(results) if cb else results
    except Exception:
        return str(results)


class RunAnsibleModuleFail(AnsibleError):

    """Sub-class AnsibleError when module exceptions occur."""

    def __init__(self, msg, results=None):
        super(RunAnsibleModuleFail, self).__init__(msg)
        self.results = results

    def _to_string(self):
        return "{}, Ansible Results =>\n{}".format(self.message, dump_ansible_results(self.results)).encode().decode("utf-8")

    def __str__(self):
        return self._to_string()

    def __repr__(self):
        return self._to_string()


class MissingInputError(Exception):
    pass
