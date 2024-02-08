import ipaddr
import logging
import os
import pytest

from collections import namedtuple
from collections import defaultdict

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.cisco_data import is_cisco_device
from tests.common.utilities import wait_until
from tests.cisco.common.utils import skip_if_sim

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)

class LPM:
    """
    Program IP routes with next hops on to the DUT
    """
    def __init__(self, duthost, asic):
        self.asic = asic
        self.duthost = duthost

    def get_lpm_report(self):
        cmd = "show platform npu lpm-db -n asic{}".format(self.asic.asic_index)
        self.lpm_report = self.duthost.shell(cmd)["stdout_lines"] 

    def get_lpm_resource_usage_stats(self):
        keys = ['IPv4 Entries', 'IPv6 Entries', "IPv4 SRAM Entries", "IPv4 HBM Entries", "IPv6 SRAM Entries", "IPv6 HBM Entries",
                "TCAM Occupied Rows", "TCAM Free Rows", "IPv4 TCAM Entries", "IPv6 double TCAM Entries", "IPv6 quad TCAM Entries",
                'L1 Rows', "L1 Entries", "L2 SRAM Rows", "L2 HBM Rows", "L2 SRAM Single Entries", "L2 SRAM Wide Entries",
                "L2 HBM Single Entries", "L2 HBM Wide Entries"]

        self.get_lpm_report()
        result = {}

        for line in self.lpm_report:
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
        pytest_assert(keys == [], "Failed to get LPM resource for {}".format(str(keys)))
        return result

def test_lpm_infra(duthost, tbinfo, skip_if_sim):
    """
    Test validate basic LPM output
    - Creates LPM instance
    - Gets LPM report using show platform dshell cmd
    - Parses the LPM report and generates a result
    - Prints the resource usage stats
    """

    asic = duthost.asic_instance()

    # generate LPM report
    lpm = LPM(duthost, asic)
    result = lpm.get_lpm_resource_usage_stats()

    for x in result:
        print("Resource: {} Usage: {}". format(x, result[x]))
