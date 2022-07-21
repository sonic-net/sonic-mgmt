# Helper Functions
import pytest
import json
from tests.common.helpers.assertions import pytest_assert

import logging

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1')
]

as_path = '54321'

def asn_num(duthost):
    bgp_summary = json.loads(duthost.shell('vtysh -c "show bgp summary json"')['stdout'])
    bgp_num = bgp_summary['ipv4Unicast']['as']
    return bgp_num

def ipadd(duthost):
    bgp_summary = json.loads(duthost.shell('vtysh -c "show bgp summary json"')['stdout'])
    peer_key=bgp_summary['ipv4Unicast']['peers'].keys()
    peer_list = list(peer_key)
    ip_value = peer_list[-1]
    return ip_value

# Test Functions
def test_show_aspath_pre(duthosts, enum_dut_hostname):
    #Collect Baseline BGP Routes on DUT

    logger.info("Collect Baseline BGP Routes on DUT")
    duthost = duthosts[enum_dut_hostname]
    succeeded = duthost.get_show(duthost, ipadd(duthost), as_path, 0)
    pytest_assert(succeeded, "AS-path already exists")

# Test Functions
def test_aspath_config(duthosts, enum_dut_hostname):
    #Configure route-map for AS-path prepend

    logger.info("Configure route-map for AS-path prepend")
    duthost = duthosts[enum_dut_hostname]
    succeeded = duthost.aspath_config(as_path, asn_num(duthost), 0)
    pytest_assert(succeeded, "failed to configure route-map for AS-path prepend")

# Test Functions
def test_show_aspath_post(duthosts, enum_dut_hostname):
    #Verify route-map for AS-path is working correctly

    logger.info("Verify route-map for AS-path is working correctly")
    duthost = duthosts[enum_dut_hostname]
    succeeded = duthost.get_show(duthost, ipadd(duthost), as_path, 1)
    pytest_assert(succeeded, "Configured route-map for AS-path prepend does not match")

# Test Functions
def test_aspath_no_config(duthosts, enum_dut_hostname):
    #Remove route-map for AS-path prepend

    logger.info("Remove route-map for AS-path prepend")
    duthost = duthosts[enum_dut_hostname]
    succeeded = duthost.aspath_config(as_path, asn_num(duthost), 1)
    pytest_assert(succeeded, "failed to remove route-map for AS-path prepend")

# Test Functions
def test_show_aspath_final(duthosts, enum_dut_hostname):
    #Final check for Baseline BGP Routes on DUT

    logger.info("Final check for Baseline BGP Routes on DUT")
    duthost = duthosts[enum_dut_hostname]
    succeeded = duthost.get_show(duthost, ipadd(duthost), as_path, 0)
    pytest_assert(succeeded, "AS-path still exists")
