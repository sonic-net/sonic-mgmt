import logging
import re
import json
import pytest
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# CLI commands to obtain drop counters.
NAMESPACE_PREFIX = "sudo ip netns exec {} "
NAMESPACE_SUFFIX = "-n {} "
GET_L2_COUNTERS = "portstat -j "
GET_L3_COUNTERS = "intfstat -j "
ACL_COUNTERS_UPDATE_INTERVAL = 10
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"
LOG_EXPECT_PORT_ADMIN_DOWN_RE = ".*Configure {} admin status to down.*"
LOG_EXPECT_PORT_ADMIN_UP_RE = ".*Port {} oper state set from down to up.*"
RX_DRP = "RX_DRP"
RX_ERR = "RX_ERR"

COMBINED_L2L3_DROP_COUNTER = False
COMBINED_ACL_DROP_COUNTER = False


def get_pkt_drops(duthost, cli_cmd, asic_index):
    """
    @summary: Parse output of "portstat" or "intfstat" commands and convert it to the dictionary.
    @param module: The AnsibleModule object
    @param cli_cmd: one of supported CLI commands - "portstat -j" or "intfstat -j"
    @return: Return dictionary of parsed counters
    """
    # Get namespace from asic_index.
    namespace = duthost.get_namespace_from_asic_id(asic_index)

    # Frame the correct cli command
    # the L2 commands need _SUFFIX and L3 commands need _PREFIX
    if cli_cmd == GET_L3_COUNTERS:
        CMD_PREFIX = NAMESPACE_PREFIX if duthost.is_multi_asic else ''
        cli_cmd = CMD_PREFIX + cli_cmd
    elif cli_cmd == GET_L2_COUNTERS:
        CMD_SUFFIX = NAMESPACE_SUFFIX if duthost.is_multi_asic else ''
        cli_cmd = cli_cmd + CMD_SUFFIX

    stdout = duthost.command(cli_cmd.format(namespace))
    stdout = stdout["stdout"]
    match = re.search("Last cached time was.*\n", stdout)
    if match:
        stdout = re.sub("Last cached time was.*\n", "", stdout)

    try:
        return json.loads(stdout)
    except Exception as err:
        raise Exception("Failed to parse output of '{}', err={}".format(cli_cmd, str(err)))


def ensure_no_l3_drops(duthost, asic_index, packets_count):
    """ Verify L3 drop counters were not incremented """
    intf_l3_counters = get_pkt_drops(duthost, GET_L3_COUNTERS, asic_index)
    unexpected_drops = {}
    for iface, value in intf_l3_counters.items():
        try:
            rx_err_value = int(value[RX_ERR])
        except ValueError as err:
            logger.info("Unable to verify L3 drops on iface {}, L3 counters may not be supported on this platform\n{}".format(iface, err))
            continue
        if rx_err_value >= packets_count:
            unexpected_drops[iface] = rx_err_value
    if unexpected_drops:
        pytest.fail("L3 'RX_ERR' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def ensure_no_l2_drops(duthost, asic_index, packets_count):
    """ Verify L2 drop counters were not incremented """
    intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS, asic_index)
    unexpected_drops = {}
    for iface, value in intf_l2_counters.items():
        try:
            rx_drp_value = int(value[RX_DRP])
        except ValueError as err:
            logger.warning("Unable to verify L2 drops on iface {}\n{}".format(iface, err))
            continue
        if rx_drp_value >= packets_count:
            unexpected_drops[iface] = rx_drp_value
    if unexpected_drops:
        pytest.fail("L2 'RX_DRP' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def verify_drop_counters(duthosts, asic_index, dut_iface, get_cnt_cli_cmd, column_key, packets_count):
    """ Verify drop counter incremented on specific interface """
    def get_drops_across_all_duthosts():
        drop_list = [] 
        for duthost in duthosts:
            drop_list.append(int(get_pkt_drops(duthost, get_cnt_cli_cmd, asic_index)[dut_iface][column_key].replace(",", "")))
        return drop_list
    check_drops_on_dut = lambda: packets_count in get_drops_across_all_duthosts()
    if not wait_until(25, 1, check_drops_on_dut):
        # The actual Drop count should always be equal or 1 or 2 packets more than what is expected due to some other drop may occur
        # over the interface being examined. When that happens if looking onlyu for exact count it will be a false positive failure.
        # So do one more check to allow up to 2 packets more dropped than what was expected as an allowed case.
        actual_drop = get_drops_across_all_duthosts()
        if ((packets_count+2) in actual_drop) or ((packets_count+1) in actual_drop):
            logger.warning("Actual drops {} exceeded expected drops {} on iface {}\n".format(actual_drop, packets_count, dut_iface))
        else:
            fail_msg = "'{}' drop counter was not incremented on iface {}. DUT {} == {}; Sent == {}".format(
                column_key, dut_iface, column_key, actual_drop, packets_count)
            pytest.fail(fail_msg)
