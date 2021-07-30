"""
Cross check show sfp presence with qsfp_status
"""
import logging
import os
import json
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

def test_check_sfp_presence(duthosts, rand_one_dut_hostname, conn_graph_facts):
    """This test case is to check SFP presence status with CLI and sysfs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ports_config = json.loads(duthost.command("sudo sonic-cfggen -d --var-json PORT")["stdout"])
    check_intf_presence_command = 'show interface transceiver presence {}'

    logging.info("Use show interface status information")
    for intf in conn_graph_facts["device_conn"][duthost.hostname]:
        check_presence_output = duthost.command(check_intf_presence_command.format(intf))
        assert check_presence_output["rc"] == 0, "Failed to read interface %s transceiver presence" % intf
        logging.info(str(check_presence_output["stdout_lines"][2]))
        presence_list = check_presence_output["stdout_lines"][2].split()
        logging.info(str(presence_list))
        assert intf in presence_list, "Wrong interface name in the output %s" % str(presence_list)
        assert 'Present' in presence_list, "Status is not expected, output %s" % str(presence_list)

