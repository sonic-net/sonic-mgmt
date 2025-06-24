"""
Cross check show sfp presence with qsfp_status
"""
import logging
import json
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa: F401

pytestmark = [
    pytest.mark.asic('mellanox', 'nvidia-bluefield'),
    pytest.mark.topology('any')
]


def test_check_sfp_presence(duthosts, rand_one_dut_hostname, conn_graph_facts, dpu_npu_port_list):     # noqa: F811
    """This test case is to check SFP presence status with CLI and sysfs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ports_config = json.loads(duthost.command("sudo sonic-cfggen -d --var-json PORT")["stdout"])    # noqa: F841
    check_intf_presence_command = 'show interface transceiver presence {}'

    logging.info("Use show interface status information")
    check_presence_output = duthost.command(check_intf_presence_command)
    assert check_presence_output["rc"] == 0, \
        f"Command '{check_intf_presence_command}' failed with return code {check_presence_output['rc']}"

    presence_stdout_lines = check_presence_output["stdout_lines"]
    presence_dict = parse_sfp_presence_output(presence_stdout_lines)
    logging.info(f"Found {len(presence_dict)} interfaces with presence status: {presence_dict}")
    intfs = conn_graph_facts["device_conn"][duthost.hostname]
    intf_list_to_check = {intf for intf in intfs if intf not in dpu_npu_port_list[duthost.hostname]}
    logging.info(f"Interfaces to check: {intf_list_to_check}")
    intf_not_present = intf_list_to_check - set(presence_dict.keys())
    assert len(intf_not_present) == 0, \
        f"Missing interfaces in presence output: {intf_not_present}"
    logging.info("All expected interfaces are present in the output")
