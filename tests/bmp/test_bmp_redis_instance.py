"""
Test the database intance
"""
import logging
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def ps_check_bmp_redis(duthost):

    cmd_ps = 'docker exec database supervisorctl status'
    logging.debug("ps_check_bmp_redis command is: {}".format(cmd_ps))
    ret = duthost.command(cmd_ps, module_ignore_errors=True)
    logging.debug("ps_check_bmp_redis output is: {}".format(ret))
    return ret


def test_bmp_redis_instance(duthosts, rand_one_dut_hostname):
    """
    @summary: Test that redis has bmp instance
    """
    duthost = duthosts[rand_one_dut_hostname]
    output = ps_check_bmp_redis(duthost)
    stdout_lines = output['stdout'].split('\n')

    for line in stdout_lines:
        if 'redis_bmp' in line and 'RUNNING' in line:
            assert True, "redis_bmp is in RUNNING status"
            break
    else:
        assert False, "redis_bmp is not in RUNNING status"
