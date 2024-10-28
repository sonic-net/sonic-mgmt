"""
Customize exceptions
"""
from ansible.errors import AnsibleError


class UnsupportedAnsibleModule(Exception):
    pass


def dump_ansible_results(results):
    """Dump ansible results in a clean format.
    Prints simple attributes printed first, followed by the stdout and stderr."""
    simple_attrs = ""
    stdout = "stdout =\n"
    stderr = "stderr =\n"
    for key in results:
        if key in ['stdout', 'stderr']:
            # Use stdout_lines and stderr_lines instead
            continue
        if '_lines' in key:
            text = "\n".join(results[key])
            if key == 'stdout_lines':
                stdout += text
            else:
                stderr += text
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
