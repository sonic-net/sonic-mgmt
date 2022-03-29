import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import SONIC_SSH_PORT, SONIC_SSH_REGEX

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def test_memory_exhaustion(duthosts, enum_frontend_dut_hostname, localhost):
    """validate kernel will panic and reboot the DUT when runs out of memory and hits oom event"""

    duthost = duthosts[enum_frontend_dut_hostname]
    dut_ip = duthost.mgmt_ip
    hostname = duthost.hostname
    dut_datetime = duthost.get_now_time()

    # Use `tail /dev/zero` to run out of memory completely. Since this command will cause DUT reboot,
    # we need to run it in the background (using &) to avoid pytest getting stuck. We also need to
    # add `nohup` to protect it.
    cmd = 'nohup tail /dev/zero &'
    res = duthost.shell(cmd)
    if not res.is_successful:
        raise Exception('DUT {} run command {} failed'.format(hostname, cmd))

    logging.info('waiting for ssh to drop on {}'.format(hostname))
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=10,
                             timeout=120,
                             module_ignore_errors=True)
    pytest_assert(not res.is_failed and 'Timeout' not in res.get('msg', ''),
                  'DUT {} did not shutdown'.format(hostname))

    logging.info('waiting for ssh to startup on {}'.format(hostname))
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=10,
                             timeout=120,
                             module_ignore_errors=True)
    pytest_assert(not res.is_failed and 'Timeout' not in res.get('msg', ''),
                  'DUT {} did not startup'.format(hostname))

    # Wait until all critical processes are healthy.
    wait_critical_processes(duthost)

    # Verify DUT uptime is later than the time when the test case started running.
    dut_uptime = duthost.get_up_time()
    pytest_assert(dut_uptime > dut_datetime, "Device {} did not reboot".format(hostname))
