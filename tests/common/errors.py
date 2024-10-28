"""
Customize exceptions
"""
from ansible.errors import AnsibleError


class UnsupportedAnsibleModule(Exception):
    pass


def dump_ansible_results(results, stdout_callback='json'):
    simple_attrs = ""
    stdout = "stdout =\n"
    stderr = "stderr =\n"
    for key in results:
        if key in ['stdout', 'stderr', 'stdout_lines', 'stderr_lines']:
            if '_lines' in key:
                text = "\n".join(results[key])
            else:
                if str(key) + "_lines" in results:
                    # Skip when _lines is present
                    continue
                text = str(results[key])
            if "err" in key:
                stderr += text
            else:
                stdout += text
        else:
            simple_attrs += "{} = {}\n".format(key, results[key])
    return "{}\n\n{}\n\n{}".format(simple_attrs, stdout, stderr)


class RunAnsibleModuleFail(AnsibleError):

    """Sub-class AnsibleError when module exceptions occur."""

    def __init__(self, msg, results=None):
        super(RunAnsibleModuleFail, self).__init__(msg)
        self.results = results

    def _to_string(self):
        return "{}, Ansible Results =>\n{}".format(self.message,
                                                   dump_ansible_results(self.results)).encode().decode("utf-8")

    def __str__(self):
        return self._to_string()

    def __repr__(self):
        return self._to_string()


class MissingInputError(Exception):
    pass
