import logging

import pytest

from tests.common.constants import CounterpollConstants
from tests.common.helpers.counterpoll_helper import ConterpollHelper

logger = logging.getLogger(__name__)

WRED_ECN_COUNTERPOLLS = [
    (CounterpollConstants.WRED_ECN_QUEUE_STAT_TYPE, CounterpollConstants.WRED_QUEUE),
    (CounterpollConstants.WRED_ECN_PORT_STAT_TYPE, CounterpollConstants.WRED_PORT),
]


def _asic_instance_from_snappi_port(duthost, port):
    if not duthost.is_multi_asic:
        return duthost.asic_instance()
    asic_value = port.get('asic_value')
    if asic_value:
        asic_index = int(str(asic_value).replace('asic', ''))
        return duthost.asic_instance(asic_index)
    return duthost.get_port_asic_instance(port['peer_port'])


def unique_dut_asic_pairs_from_snappi_ports(snappi_ports):
    """
    Return unique (duthost, asic_instance) pairs referenced by snappi_ports.
    """
    seen = set()
    pairs = []
    for port in snappi_ports:
        duthost = port['duthost']
        asic_inst = _asic_instance_from_snappi_port(duthost, port)
        key = (duthost.hostname, asic_inst.asic_index if duthost.is_multi_asic else 0)
        if key in seen:
            continue
        seen.add(key)
        pairs.append((duthost, asic_inst))
    return pairs


def _resolve_asic_instance(duthost, asic=None):
    if asic is None:
        return duthost.asic_instance()
    if hasattr(asic, "asic_index"):
        return asic
    return duthost.asic_instance(asic)


def _counterpoll_target(duthost, asic_inst):
    """Return SonicHost or SonicAsic for ConterpollHelper on master API."""
    return asic_inst if duthost.is_multi_asic else duthost


def _get_parsed_counterpoll_show(duthost, asic_inst):
    target = _counterpoll_target(duthost, asic_inst)
    counterpoll_show = ConterpollHelper.get_counterpoll_show_output(target)
    return ConterpollHelper.get_parsed_counterpoll_show(counterpoll_show)


def is_wred_ecn_counterpoll_enabled(duthost, asic_inst, stat_type):
    """
    Return True when stat_type is present in counterpoll show and status is enable.
    Missing entries are treated as not enabled.
    """
    parsed = _get_parsed_counterpoll_show(duthost, asic_inst)
    if stat_type not in parsed:
        return False
    return parsed[stat_type][CounterpollConstants.STATUS] == 'enable'


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

        target = _counterpoll_target(duthost, asic_inst)
        to_enable = []
        for stat_type, cli_type in WRED_ECN_COUNTERPOLLS:
            if is_wred_ecn_counterpoll_enabled(duthost, asic_inst, stat_type):
                logger.info(
                    "WRED ECN %s already enabled on %s asic%s",
                    cli_type, duthost.hostname, asic_inst.asic_index)
            else:
                to_enable.append(cli_type)

        if to_enable:
            ConterpollHelper.enable_counterpoll(target, to_enable)
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
        target = _counterpoll_target(duthost, asic_inst)
        ConterpollHelper.disable_counterpoll(target, [cli_type])
        logger.info(
            "Disabled WRED ECN %s on %s asic%s",
            cli_type, duthost.hostname, asic_inst.asic_index)


def disable_wred_ecn_counterpoll(duthost, asic=None):
    """
    Explicitly disable wredqueue and wredport counterpoll on a DUT/ASIC.
    """
    _ensure_wred_ecn_counterpoll_available(duthost)
    counter_types = [cli_type for _, cli_type in WRED_ECN_COUNTERPOLLS]

    if asic is not None:
        asic_inst = _resolve_asic_instance(duthost, asic)
        ConterpollHelper.disable_counterpoll(
            _counterpoll_target(duthost, asic_inst), counter_types)
        return

    if duthost.is_multi_asic:
        for asic_inst in duthost.asics:
            ConterpollHelper.disable_counterpoll(asic_inst, counter_types)
    else:
        ConterpollHelper.disable_counterpoll(duthost, counter_types)
