import ipaddr
import logging
import os
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.cisco.common.utils import skip_if_sim
from tests.cisco.common.utils import get_asic_type

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
        if self.duthost.sonichost.is_multi_asic :
            cmd="show platform npu cem-db -n asic{}".format(self.asic.asic_index)
        else:
            cmd = "show platform npu cem-db"
        self.cem_report = self.duthost.shell(cmd)["stdout_lines"] 

    def get_cem_resource_usage_stats(self):

        asic_type = get_asic_type(self,self.duthost)
        if asic_type=='Gr2':
            keys = ['IPv4 DIP / SIP Unicast (/32); IPv4 OG PCL; IPv4 SGT', 'IPv6 DIP / SIP Unicast (/128); IPv6 OG PCL; IPv6 SGT', 'SRAM Single Entries', 'SRAM Double Entries']
        else:
            keys = ['BFD', 'MOFRR GID to RPF', 'IPv4 DIP / SIP Unicast (/32); IPv4 OG PCL; IPv4 SGT', 'IPv6 DIP / SIP Unicast (/128); IPv6 OG PCL; IPv6 SGT', 'SRAM Single Entries', 'SRAM Double Entries']

        self.get_cem_report()
        result = {}

        for line in self.cem_report:
            if line:
                line = line.split('|')
                if len(line) < 4:
                    continue
                line = list(map(str.strip, line))
                if line[1] in keys:
                    counters = line[-2]
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
