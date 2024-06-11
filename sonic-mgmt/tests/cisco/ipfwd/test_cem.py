import ipaddr
import logging
import os
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.cisco.common.utils import skip_if_sim

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope='module', autouse=True)
def common_setup_teardown(duthost):
    result = duthost.shell("sudo config platform cisco sdk-debug enable", module_ignore_errors=True)
    logging.info(result['stdout_lines'])
    assert "Enabling sdk-debug on all ASICs" in result['stdout'], "debug shell not started"
    time.sleep(120)

    yield

    result = duthost.shell("sudo config platform cisco sdk-debug disable", module_ignore_errors=True)
    logging.info(result['stdout_lines'])
    assert "Disabling sdk-debug on all ASICs" in result['stdout'], "debug shell is not stopped"
    time.sleep(60)

class CEM:
    """
    Program Host /32 /128 routes and check the Central Exact Match CEM table programming
    """
    def __init__(self, duthost, asic):
        self.asic = asic
        self.duthost = duthost

    def get_cem_report(self):
        cmd = "show platform npu cem-db -n asic{}".format(self.asic.asic_index)
        self.cem_report = self.duthost.shell(cmd)["stdout_lines"] 

    def get_cem_resource_usage_stats(self):
        keys = ['BFD', 'RPF', 'IPV4 DIP / SIP (/32)', 'IPV6 DIP / SIP (/128)', 'SRAM Single Entries', 'SRAM Double Entries']

        self.get_cem_report()
        result = {}

        for line in self.cem_report:
            if line:
                line = line.split('|')
                if len(line) < 18:
                    continue 
                line = list(map(str.strip, line))
                if line[1] in keys:
                    counters = line[18]
                    result[line[1]] = counters
                    keys.remove(line[1])
                    if not keys:
                        break
        pytest_assert(keys == [], "Failed to get CEM resource for {}".format(str(keys)))
        return result

def test_cem_infra(duthost, tbinfo, skip_if_sim):
    """
    Test validate basic CEM output
    - Creates CEM instance
    - Gets CEM report using show platform dshell cmd
    - Parses the CEM report and generates a result
    - Prints the resource usage stats
    """

    asic = duthost.asic_instance()

    # generate CEM report
    cem = CEM(duthost, asic)
    result = cem.get_cem_resource_usage_stats()

    for x in result:
        print("Resource: {} Usage: {}". format(x, result[x]))
