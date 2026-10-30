"""
PSU output overcurrent (OCP) fault recovery over PMBus.

A PSU that trips its output overcurrent protection latches the fault and stays off
until AC is cycled, unless its firmware clears the latch when the PMBus OPERATION
command is cycled off and on. This test induces an OCP fault on one PSU at a time by
lowering IOUT_OC_WARN_LIMIT / IOUT_OC_FAULT_LIMIT below the measured load, restores
the limits, recovers the PSU with an OPERATION off/on cycle and verifies it is back
to power good.

Only PSU models known to support OCP recovery over PMBus are exercised. The PSU is
accessed with i2ctransfer while its PDDF subtree is detached, using the bus/address
declared in pddf-device.json.
"""

import json
import logging
import re
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers import pmbus
from tests.common.utilities import wait_until
from tests.platform_tests.cli.util import get_skip_mod_list

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
]

# PSU models whose firmware clears a latched output OCP fault on an OPERATION
# off/on cycle. Older firmware keeps the fault latched until AC is cycled, so a
# PSU below min_fw is skipped. rated_power_w is only used to confirm the
# remaining PSUs can carry the load before one is tripped.
SUPPORTED_PSU_MODELS = {
    # Murata 2400W AC. OCP recovery over PMBus was added in FW 0.1.2.
    "D1U74T-W-2400-12-HB4C": {"min_fw": (0, 1, 2), "rated_power_w": 2400},
    # AcBel 2400W DC-DC.
    "NWR002000": {"min_fw": None, "rated_power_w": 2400},
}

PDDF_DEVICE_JSON_PATH = "/usr/share/sonic/platform/pddf/pddf-device.json"
PDDFPARSE_TIMEOUT_SEC = 30

# Any of these in STATUS_WORD means the PSU output is not healthy.
STATUS_WORD_FAULT_MASK = pmbus.STATUS_WORD_OFF | pmbus.STATUS_WORD_POWER_GOOD_N | pmbus.STATUS_WORD_IOUT_OC_FAULT

FAULT_TIMEOUT_SEC = 15
RECOVERY_TIMEOUT_SEC = 30
PSUD_REFRESH_TIMEOUT_SEC = 90
LOAD_HEADROOM = 1.25


class PsuNotTestable(Exception):
    """The PSU is healthy but the fault cannot be induced safely or at all right now."""


def _read_pddf_device_json(duthost):
    res = duthost.shell("cat {}".format(PDDF_DEVICE_JSON_PATH), module_ignore_errors=True)
    if res['rc'] != 0:
        pytest.skip("{} not found on DUT, PDDF is required".format(PDDF_DEVICE_JSON_PATH))
    try:
        data = json.loads(res['stdout'])
    except ValueError as e:
        pytest.fail("Failed to parse {}: {}".format(PDDF_DEVICE_JSON_PATH, e))
    return data


def _pddfparse_subtree(duthost, action, node):
    """Create or delete a pddf-device.json node and its descendants in the I2C topology."""
    cmd = "timeout {}s sudo pddfparse.py --{}-subtree {}".format(PDDFPARSE_TIMEOUT_SEC, action, node)
    res = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(res['rc'] == 0, "'{}' failed (rc={}): {}\n{}".format(cmd, res['rc'], res['stdout'], res['stderr']))


def _get_psu_status(duthost):
    """{psu name: entry} from `show platform psu --json`."""
    output = duthost.shell("show platform psu --json")['stdout']
    try:
        status = {psu['name']: psu for psu in json.loads(output)}
    except (ValueError, KeyError, TypeError) as e:
        pytest.fail("Failed to parse 'show platform psu --json': {}\n{}".format(e, output))
    return status


def _get_pddf_psu_pmbus_topology(pddf_device_data):
    """{psu name: (bus, addr)} for every PSU in pddf-device.json with a PMBus interface."""
    topology = {}
    for name, dev in pddf_device_data.items():
        if not re.fullmatch(r'PSU\d+', name):
            continue
        for interface in dev.get('i2c', {}).get('interface', []):
            pmbus_dev = interface.get('dev')
            if interface.get('itf') != 'pmbus' or not pmbus_dev:
                continue
            topo_info = pddf_device_data.get(pmbus_dev, {}).get('i2c', {}).get('topo_info', {})
            if 'parent_bus' in topo_info and 'dev_addr' in topo_info:
                topology[name] = (int(topo_info['parent_bus'], 0), int(topo_info['dev_addr'], 0))
    return topology


def _parse_psu_fw_version(text):
    """(major, minor, patch) from the PDDF psu_fw_version attribute, or None.

    Older pddf_psu drivers report "major.minor.patch". Newer ones report the raw
    0xD9 payload as hex (e.g. "010100"): byte 0 is patch, byte 1 is minor and
    bits 0-6 of byte 2 are major.
    """
    text = text.strip()
    if '.' in text:
        digits = re.findall(r'\d+', text)
        return tuple(int(d) for d in digits) if digits else None
    try:
        data = bytes.fromhex(text)
    except ValueError:
        return None
    return (data[2] & 0x7F, data[1], data[0]) if len(data) >= 3 else None


def _get_psu_fw_version(duthost, bus, addr):
    """Firmware version tuple from the PDDF sysfs attribute, or None if unavailable."""
    path = "/sys/bus/i2c/devices/{}-{:04x}/psu_fw_version".format(bus, addr)
    res = duthost.shell("cat {}".format(path), module_ignore_errors=True)
    if res['rc'] != 0:
        return None
    return _parse_psu_fw_version(res['stdout'])


def _select_psus(duthost, psu_status, topology):
    skip_list = get_skip_mod_list(duthost, ['psus'])
    selected = []
    for name, (bus, addr) in sorted(topology.items()):
        if name in skip_list:
            logger.info("Skipping %s: listed in the inventory's skip_modules", name)
            continue
        status = psu_status.get(name)
        if status is None:
            pytest.fail("PDDF PSU {} is not reported by 'show platform psu'".format(name))
        if status['status'] != 'OK':
            logger.info("Skipping %s: status is %s", name, status['status'])
            continue
        model = (status.get('model') or '').strip()
        support = SUPPORTED_PSU_MODELS.get(model)
        if support is None:
            logger.info("Skipping %s: model '%s' is not known to support OCP recovery over PMBus", name, model)
            continue
        if support['min_fw'] is not None:
            fw_version = _get_psu_fw_version(duthost, bus, addr)
            if fw_version is None or fw_version < support['min_fw']:
                logger.info("Skipping %s: firmware %s is below %s", name, fw_version, support['min_fw'])
                continue
        selected.append(name)
    return selected


def _check_remaining_psus_can_carry_load(psu_status, target):
    """Raise PsuNotTestable unless the other healthy PSUs have enough rated capacity
    for the current system load. Tripping the target would otherwise take the system down."""
    healthy = {name: psu for name, psu in psu_status.items() if psu['status'] == 'OK'}
    pytest_assert(target in healthy, "{} is no longer OK: {}".format(target, psu_status.get(target)))

    load_w = 0.0
    for name, psu in healthy.items():
        try:
            load_w += float(psu['power'])
        except (TypeError, ValueError):
            raise PsuNotTestable("{} reports no numeric power ({}); cannot size the load".format(name, psu['power']))

    capacity_w = sum(
        SUPPORTED_PSU_MODELS.get((psu.get('model') or '').strip(), {}).get('rated_power_w', 0)
        for name, psu in healthy.items() if name != target)
    if capacity_w < load_w * LOAD_HEADROOM:
        raise PsuNotTestable("remaining PSUs ({}W of known capacity) cannot carry {:.0f}W x {} with {} tripped".format(
            capacity_w, load_w, LOAD_HEADROOM, target))


def _low_oc_limit(fault_limit, iout):
    """IOUT limit word at about half the measured output current, keeping the PSU's
    own LINEAR11 exponent."""
    exponent = pmbus.linear11_exponent(fault_limit)
    mantissa = max(1, int((iout / 2.0) / 2.0 ** exponent))
    pytest_assert(mantissa <= pmbus.LINEAR11_MAX_MANTISSA,
                  "Cannot encode an IOUT limit below {:.2f}A with exponent {}".format(iout, exponent))
    limit = pmbus.linear11_encode(mantissa, exponent)
    if pmbus.linear11_decode(limit) >= iout:
        raise PsuNotTestable("output current {:.2f}A is too low to induce an OCP fault (lowest limit {:.2f}A)".format(
            iout, pmbus.linear11_decode(limit)))
    return limit


def _write_oc_limits(psu, warn_limit, fault_limit):
    # Keep warn <= fault throughout: lower warn first, raise fault first.
    if pmbus.linear11_decode(fault_limit) <= pmbus.linear11_decode(psu.read_word(pmbus.PMBUS_IOUT_OC_FAULT_LIMIT)):
        psu.write_word(pmbus.PMBUS_IOUT_OC_WARN_LIMIT, warn_limit)
        psu.write_word(pmbus.PMBUS_IOUT_OC_FAULT_LIMIT, fault_limit)
    else:
        psu.write_word(pmbus.PMBUS_IOUT_OC_FAULT_LIMIT, fault_limit)
        psu.write_word(pmbus.PMBUS_IOUT_OC_WARN_LIMIT, warn_limit)
    warn_readback = psu.read_word(pmbus.PMBUS_IOUT_OC_WARN_LIMIT)
    fault_readback = psu.read_word(pmbus.PMBUS_IOUT_OC_FAULT_LIMIT)
    pytest_assert(pmbus.linear11_equal(warn_readback, warn_limit) and pmbus.linear11_equal(fault_readback, fault_limit),
                  "{}: IOUT OC limits read back as warn=0x{:04x} fault=0x{:04x}, expected warn=0x{:04x} fault=0x{:04x}"
                  .format(psu.name, warn_readback, fault_readback, warn_limit, fault_limit))


def _recover_with_operation_cycle(psu):
    logger.info("%s: OPERATION before recovery: 0x%02x", psu.name, psu.read_byte(pmbus.PMBUS_OPERATION))
    psu.write_byte(pmbus.PMBUS_OPERATION, pmbus.PMBUS_OPERATION_OFF)
    time.sleep(1)
    psu.write_byte(pmbus.PMBUS_OPERATION, pmbus.PMBUS_OPERATION_ON)
    return wait_until(RECOVERY_TIMEOUT_SEC, 1, 0, psu.output_is_up)


def _trip_and_recover(psu):
    status_word = psu.read_word(pmbus.PMBUS_STATUS_WORD)
    status_iout = psu.read_byte(pmbus.PMBUS_STATUS_IOUT)
    logger.info("%s: initial STATUS_WORD=0x%04x STATUS_IOUT=0x%02x", psu.name, status_word, status_iout)
    pytest_assert(not status_word & STATUS_WORD_FAULT_MASK
                  and not status_iout & pmbus.STATUS_IOUT_OC_FAULT,
                  "{}: PSU is not healthy before the test (STATUS_WORD=0x{:04x} STATUS_IOUT=0x{:02x})".format(
                      psu.name, status_word, status_iout))

    iout = pmbus.linear11_decode(psu.read_word(pmbus.PMBUS_READ_IOUT))
    orig_warn = psu.read_word(pmbus.PMBUS_IOUT_OC_WARN_LIMIT)
    orig_fault = psu.read_word(pmbus.PMBUS_IOUT_OC_FAULT_LIMIT)
    low_limit = _low_oc_limit(orig_fault, iout)
    logger.info("%s: READ_IOUT=%.2fA, IOUT_OC_WARN_LIMIT=%.2fA (0x%04x), IOUT_OC_FAULT_LIMIT=%.2fA (0x%04x), "
                "lowering both to %.2fA (0x%04x)", psu.name, iout, pmbus.linear11_decode(orig_warn), orig_warn,
                pmbus.linear11_decode(orig_fault), orig_fault, pmbus.linear11_decode(low_limit), low_limit)

    recovered = None
    try:
        _write_oc_limits(psu, low_limit, low_limit)
        tripped = wait_until(FAULT_TIMEOUT_SEC, 1, 0,
                             lambda: psu.oc_fault_latched() and not psu.output_is_up())
        status_word = psu.read_word(pmbus.PMBUS_STATUS_WORD)
        status_iout = psu.read_byte(pmbus.PMBUS_STATUS_IOUT)
        logger.info("%s: after lowering limits STATUS_WORD=0x%04x STATUS_IOUT=0x%02x",
                    psu.name, status_word, status_iout)
        pytest_assert(tripped, "{}: no OCP shutdown within {}s (STATUS_WORD=0x{:04x} STATUS_IOUT=0x{:02x})".format(
            psu.name, FAULT_TIMEOUT_SEC, status_word, status_iout))
    finally:
        try:
            _write_oc_limits(psu, orig_warn, orig_fault)
        finally:
            if psu.oc_fault_latched() or not psu.output_is_up():
                logger.info("%s: fault still present after restoring limits STATUS_WORD=0x%04x STATUS_IOUT=0x%02x",
                            psu.name, psu.read_word(pmbus.PMBUS_STATUS_WORD), psu.read_byte(pmbus.PMBUS_STATUS_IOUT))
                recovered = _recover_with_operation_cycle(psu)

    pytest_assert(recovered is not None,
                  "{}: fault cleared on its own once limits were restored; OPERATION recovery was not exercised"
                  .format(psu.name))
    status_word = psu.read_word(pmbus.PMBUS_STATUS_WORD)
    pytest_assert(recovered, "{}: output not back up within {}s of the OPERATION cycle (STATUS_WORD=0x{:04x})".format(
        psu.name, RECOVERY_TIMEOUT_SEC, status_word))

    psu.send_byte(pmbus.PMBUS_CLEAR_FAULTS)
    status_word = psu.read_word(pmbus.PMBUS_STATUS_WORD)
    status_iout = psu.read_byte(pmbus.PMBUS_STATUS_IOUT)
    logger.info("%s: after recovery STATUS_WORD=0x%04x STATUS_IOUT=0x%02x", psu.name, status_word, status_iout)
    pytest_assert(not status_word & STATUS_WORD_FAULT_MASK
                  and not status_iout & pmbus.STATUS_IOUT_OC_FAULT,
                  "{}: OCP fault still reported after recovery (STATUS_WORD=0x{:04x} STATUS_IOUT=0x{:02x})".format(
                      psu.name, status_word, status_iout))


def _summarize_psu_status(psu_status):
    """One line of status/power/current per PSU, e.g. 'PSU1=OK/71.88/5.88 PSU2=NOT PRESENT/N/A/N/A'."""
    return " ".join("{}={}/{}/{}".format(name, psu.get('status'), psu.get('power'), psu.get('current'))
                    for name, psu in sorted(psu_status.items()))


def _psu_reports_ok(duthost, name):
    return _get_psu_status(duthost).get(name, {}).get('status') == 'OK'


def test_psu_ocp_recovery_over_pmbus(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    For every healthy PSU whose model supports OCP recovery over PMBus:
    1. Detach its PDDF subtree so the PSU can be driven with i2ctransfer.
    2. Lower IOUT_OC_WARN_LIMIT / IOUT_OC_FAULT_LIMIT below the measured output
       current and verify the PSU reports IOUT_OC_FAULT and shuts its output off.
    3. Restore the original limits.
    4. Cycle OPERATION off/on and verify the output comes back with power good.
    5. Reattach the PDDF subtree and verify `show platform psu` reports OK again.

    A PSU that cannot be faulted safely (too little headroom on the others) or at
    all (too little output current) is logged and left alone; the test only skips
    when that is true of every candidate.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    topology = _get_pddf_psu_pmbus_topology(_read_pddf_device_json(duthost))
    if not topology:
        pytest.skip("No PSU with a PMBus interface declared in pddf-device.json")

    psu_status = _get_psu_status(duthost)
    selected = _select_psus(duthost, psu_status, topology)
    if not selected:
        pytest.skip("No healthy PSU with a model/firmware known to support OCP recovery over PMBus")

    tested = []
    not_testable = {}
    for name in selected:
        bus, addr = topology[name]
        # Re-read: tripping the previous PSU shifted load onto the others.
        live_status = _get_psu_status(duthost)
        logger.info("PSU status/power(W)/current(A) before %s: %s", name, _summarize_psu_status(live_status))
        try:
            _check_remaining_psus_can_carry_load(live_status, name)
        except PsuNotTestable as e:
            # The same PSUs and load are in play for every iteration, so once one PSU
            # has been tripped and recovered this check cannot start failing on its own.
            pytest_assert(not tested, "{}: {} (the check passed for {} earlier in this run)".format(name, e, tested))
            logger.warning("Not testing %s: %s", name, e)
            not_testable[name] = str(e)
            continue

        try:
            logger.info("Testing OCP recovery on %s (model %s, i2c bus %d addr 0x%02x)",
                        name, live_status[name]['model'], bus, addr)
            _pddfparse_subtree(duthost, "delete", name)
            try:
                _trip_and_recover(pmbus.PmbusPsu(duthost, name, bus, addr))
            finally:
                _pddfparse_subtree(duthost, "create", name)
        except PsuNotTestable as e:
            logger.warning("Not testing %s: %s", name, e)
            not_testable[name] = str(e)
            continue

        pytest_assert(wait_until(PSUD_REFRESH_TIMEOUT_SEC, 5, 0, _psu_reports_ok, duthost, name),
                      "{} did not return to OK in 'show platform psu' within {}s: {}".format(
                          name, PSUD_REFRESH_TIMEOUT_SEC, _get_psu_status(duthost).get(name)))
        tested.append(name)

    if not tested:
        pytest.skip("No PSU could be faulted safely: {}".format(not_testable))
    logger.info("OCP recovery verified on %s", tested)
