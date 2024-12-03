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
    logger.info("Configure route-map for AS-path prepend")
    succeeded = duthost.aspath_config(as_path, asn_num(duthost), 0)
    pytest_assert(succeeded, "failed to configure route-map for AS-path prepend")
    logger.info("Verify route-map for AS-path is working correctly")
    succeeded = duthost.get_show(duthost, ipadd(duthost), as_path, 1)
    pytest_assert(succeeded, "Configured route-map for AS-path prepend does not match")
    logger.info("Remove route-map for AS-path prepend")
    succeeded = duthost.aspath_config(as_path, asn_num(duthost), 1)
    pytest_assert(succeeded, "failed to remove route-map for AS-path prepend")
    logger.info("Final check for Baseline BGP Routes on DUT")
    succeeded = duthost.get_show(duthost, ipadd(duthost), as_path, 0)
    pytest_assert(succeeded, "AS-path still exists")