import logging

import pytest

from tests.common.constants import CounterpollConstants
from tests.common.helpers.counterpoll_helper import ConterpollHelper

logger = logging.getLogger(__name__)

WRED_ECN_COUNTERPOLLS = [
    (CounterpollConstants.WRED_ECN_QUEUE_STAT_TYPE, CounterpollConstants.WRED_QUEUE),
    (CounterpollConstants.WRED_ECN_PORT_STAT_TYPE, CounterpollConstants.WRED_PORT),
]


def unique_dut_asic_pairs_from_snappi_ports(snappi_ports):
    """
    Return unique (duthost, asic_instance) pairs referenced by snappi_ports.

    A snappi port's 'asic_value' is the ASIC namespace on multi-ASIC and None
    on single-ASIC, which is what asic_instance_from_namespace() expects.
    """
    seen = set()
    pairs = []
    for port in snappi_ports:
        duthost = port['duthost']
        asic_inst = duthost.asic_instance_from_namespace(port.get('asic_value'))
        key = (duthost.hostname, asic_inst.asic_index)
        if key in seen:
            continue
        seen.add(key)
        pairs.append((duthost, asic_inst))
    return pairs


def _get_parsed_counterpoll_show(asic_inst):
    counterpoll_show = ConterpollHelper.get_counterpoll_show_output(asic_inst)
    return ConterpollHelper.get_parsed_counterpoll_show(counterpoll_show)


def is_wred_ecn_counterpoll_enabled(parsed_counterpoll_show, stat_type):
    """
    Return True when stat_type is present in parsed counterpoll show output and
    its status is enable. Missing entries are treated as not enabled.

    Args:
        parsed_counterpoll_show (dict): output of _get_parsed_counterpoll_show()
        stat_type (str): counterpoll stat type, e.g. WRED_ECN_QUEUE_STAT
    """
    if stat_type not in parsed_counterpoll_show:
        return False
    return parsed_counterpoll_show[stat_type][CounterpollConstants.STATUS] == 'enable'


def _ensure_wred_ecn_counterpoll_available(duthost):
    available = set(ConterpollHelper.get_available_counterpoll_types(duthost))
    missing = [
        cli_type for _, cli_type in WRED_ECN_COUNTERPOLLS
        if cli_type not in available
    ]
    if missing:
        pytest.skip(
            "WRED ECN counterpoll not supported on {}: missing {}".format(
                duthost.hostname, missing))


def enable_wred_ecn_counterpoll_for_snappi_ports(snappi_ports):
    """
    Enable wredqueue/wredport counterpoll for ASICs used by snappi_ports.

    Counter types already enabled are left unchanged and are not tracked for teardown.

    Returns:
        list of (duthost, asic_inst, cli_counter_type) enabled by this call.
    """
    enabled_by_us = []
    checked_duts = set()

    for duthost, asic_inst in unique_dut_asic_pairs_from_snappi_ports(snappi_ports):
        if duthost.hostname not in checked_duts:
            _ensure_wred_ecn_counterpoll_available(duthost)
            checked_duts.add(duthost.hostname)

        parsed_counterpoll_show = _get_parsed_counterpoll_show(asic_inst)
        to_enable = []
        for stat_type, cli_type in WRED_ECN_COUNTERPOLLS:
            if is_wred_ecn_counterpoll_enabled(parsed_counterpoll_show, stat_type):
                logger.info(
                    "WRED ECN %s already enabled on %s asic%s",
                    cli_type, duthost.hostname, asic_inst.asic_index)
            else:
                to_enable.append(cli_type)

        if to_enable:
            ConterpollHelper.enable_counterpoll(asic_inst, to_enable)
            for cli_type in to_enable:
                enabled_by_us.append((duthost, asic_inst, cli_type))
                logger.info(
                    "Enabled WRED ECN %s on %s asic%s",
                    cli_type, duthost.hostname, asic_inst.asic_index)

    return enabled_by_us


def disable_wred_ecn_counterpoll_entries(enabled_by_us):
    """Disable only the counter types that were enabled by the fixture/helper."""
    disabled = set()
    for duthost, asic_inst, cli_type in enabled_by_us:
        key = (duthost.hostname, asic_inst.asic_index, cli_type)
        if key in disabled:
            continue
        disabled.add(key)
        ConterpollHelper.disable_counterpoll(asic_inst, [cli_type])
        logger.info(
            "Disabled WRED ECN %s on %s asic%s",
            cli_type, duthost.hostname, asic_inst.asic_index)
