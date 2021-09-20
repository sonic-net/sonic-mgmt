from tests.common.helpers.assertions import pytest_assert


def check_output(output, exp_val1, exp_val2):
    pytest_assert(not output['failed'], output['stderr'])
    for l in output['stdout_lines']:
        fds = l.split(':')
        if fds[0] == exp_val1:
            pytest_assert(fds[4] == exp_val2)