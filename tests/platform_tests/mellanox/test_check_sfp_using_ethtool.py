"""
Check SFP using ethtool

This script covers the test case 'Check SFP using ethtool' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import json
import pytest
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.platform_tests.sfp.util import get_dev_conn
from tests.common.platform.interface_utils import get_port_map, check_interface_status
from tests.common.mellanox_data import SPC3_HWSKUS
from check_hw_mgmt_service import check_hw_management_service

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]


def test_check_sfp_using_ethtool(duthosts, rand_one_dut_hostname, conn_graph_facts, tbinfo, enum_frontend_asic_index):
    """This test case is to check SFP using the ethtool.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ports_config = {}
    ports_config_output = duthost.command("sudo sonic-cfggen -d --var-json PORT")["stdout"]
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)
    if ports_config_output:
        # in the case of zero ports the json output can be none
        ports_config = json.loads(ports_config_output)
    logging.info("Use the ethtool to check SFP information")
    if duthost.facts["hwsku"] in SPC3_HWSKUS:
        lanes_divider = 8
    else:
        lanes_divider = 4
    for intf in dev_conn:
        intf_lanes = ports_config[intf]["lanes"]
        sfp_id = int(intf_lanes.split(",")[0])/lanes_divider + 1

        ethtool_sfp_output = duthost.command("sudo ethtool -m sfp%s" % str(sfp_id))
        assert ethtool_sfp_output["rc"] == 0, "Failed to read eeprom of sfp%s using ethtool" % str(sfp_id)
        # QSFP-DD cable case (currenly ethtool not supporting a full parser)
        if len(ethtool_sfp_output["stdout_lines"]) == 1:
            assert '0x18' in str(ethtool_sfp_output["stdout_lines"]), \
                "Does the ethtool output look normal? " + str(ethtool_sfp_output["stdout_lines"])
        else:
            assert len(ethtool_sfp_output["stdout_lines"]) >= 5, \
                "Does the ethtool output look normal? " + str(ethtool_sfp_output["stdout_lines"])
            for line in ethtool_sfp_output["stdout_lines"]:
                assert len(line.split(":")) >= 2, \
                    "Unexpected line %s in %s" % (line, str(ethtool_sfp_output["stdout_lines"]))

    logging.info("Check interface status")
    for asic_index in duthost.get_frontend_asic_ids():
        interface_list = get_port_map(duthost, asic_index)
        assert check_interface_status(duthost, asic_index, interface_list, []), "Not all interfaces are up"

    check_hw_management_service(duthost)
