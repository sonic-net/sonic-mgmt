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


def get_pkt_drops(duthost, cli_cmd, asic_index=None):
    """
    @summary: Parse output of "portstat" or "intfstat" commands and convert it to the dictionary.
    @param module: The AnsibleModule object
    @param cli_cmd: one of supported CLI commands - "portstat -j" or "intfstat -j"
    @return: Return dictionary of parsed counters
    """
    # Get namespace from asic_index.
    result = {}
    for asic_id in duthost.get_asic_ids():
        if asic_index is not None and asic_index != asic_id:
            continue
        namespace = duthost.get_namespace_from_asic_id(asic_id)

        # Frame the correct cli command
        # the L2 commands need _SUFFIX and L3 commands need _PREFIX
        if cli_cmd == GET_L3_COUNTERS:
            CMD_PREFIX = NAMESPACE_PREFIX if (namespace is not None and duthost.is_multi_asic) else ''
            cli_cmd = CMD_PREFIX + cli_cmd
        elif cli_cmd == GET_L2_COUNTERS:
            CMD_SUFFIX = NAMESPACE_SUFFIX if (namespace is not None and duthost.is_multi_asic) else ''
            cli_cmd = cli_cmd + CMD_SUFFIX

        stdout = duthost.command(cli_cmd.format(namespace))
        stdout = stdout["stdout"]
        match = re.search("Last cached time was.*\n", stdout)
        if match:
            stdout = re.sub("Last cached time was.*\n", "", stdout)

        try:
            namespace_result = json.loads(stdout)
            result.update(namespace_result)
        except Exception as err:
            raise Exception("Failed to parse output of '{}', err={}".format(cli_cmd, str(err)))
    return result


def ensure_no_l3_drops(duthost, packets_count):
    """ Verify L3 drop counters were not incremented """
    intf_l3_counters = get_pkt_drops(duthost, GET_L3_COUNTERS)
    unexpected_drops = {}
    for iface, value in list(intf_l3_counters.items()):
        try:
            rx_err_value = int(value[RX_ERR])
        except ValueError as err:
            logger.info("Unable to verify L3 drops on iface {}, L3 counters may not be supported on this platform\n{}"
                        .format(iface, err))
            continue
        if rx_err_value >= packets_count:
            unexpected_drops[iface] = rx_err_value
    if unexpected_drops:
        pytest.fail("L3 'RX_ERR' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def ensure_no_l2_drops(duthost, packets_count):
    """ Verify L2 drop counters were not incremented """
    intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
    unexpected_drops = {}
    for iface, value in list(intf_l2_counters.items()):
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
    def _get_drops_across_all_duthosts():
        drop_list = []
        for duthost in duthosts.frontend_nodes:
            pkt_drops = get_pkt_drops(duthost, get_cnt_cli_cmd)
            # we cannot assume the iface name will be same on all the devices for SONiC chassis
            # if the dut_iface is not found ignore this device
            if dut_iface not in pkt_drops:
                continue
            try:
                drop_list.append(int(pkt_drops[dut_iface][column_key].replace(",", "")))
            except ValueError:
                # Catch error invalid literal for int() with base 10: 'N/A'
                drop_list.append(0)
        return drop_list

    def _check_drops_on_dut():
        return packets_count in _get_drops_across_all_duthosts()

    if not wait_until(25, 1, 0, _check_drops_on_dut):
        # We were seeing a few more drop counters than expected, so we are allowing a small margin of error
        DEOP_MARGIN = 10
        actual_drop = _get_drops_across_all_duthosts()
        for drop in actual_drop:
            if drop >= packets_count and drop <= packets_count + DEOP_MARGIN:
                logger.warning("Actual drops {} exceeded expected drops {} on iface {}\n".format(
                    actual_drop, packets_count, dut_iface))
                break
        else:
            fail_msg = "'{}' drop counter was not incremented on iface {}. DUT {} == {}; Sent == {}".format(
                column_key, dut_iface, column_key, actual_drop, packets_count)
            pytest.fail(fail_msg)
