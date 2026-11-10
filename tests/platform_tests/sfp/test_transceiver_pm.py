"""
Check performance monitoring (PM) of coherent C-CMIS transceivers (400ZR/ZR+).

xcvrd fills STATE_DB TRANSCEIVER_PM from the module's C-CMIS PM pages (34h/35h).
A module only latches those pages when the host freezes its VDM statistics, so
if xcvrd never freezes, the entry is still published but with placeholders:
pre-FEC BER 1.0 and every other value 0. Checking that the table exists is not
enough; these tests check that the values are real, that they refresh, and that
the CLI shows them.

Coherent ports are discovered from TRANSCEIVER_INFO application advertisement,
so every ZR module plugged into the DUT is covered without per-optic inventory.
Only ports whose module is ModuleReady and whose link is oper up are checked.
"""

import logging
import math
import re

import pytest
from natsort import natsorted

from tests.common.utilities import wait_until
from tests.transceiver.common.db_helpers import get_db_table, parse_numeric

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

COHERENT_MEDIA_PATTERN = re.compile(r"ZR", re.IGNORECASE)

# get_pm_all() reports exactly this when the module's PM counters are zero.
PM_PLACEHOLDER_BER = 1.0
# Above the 400ZR cFEC/oFEC correction limit the link could not be up.
PREFEC_BER_LIMIT = 1.25e-2
PREFEC_BER_FIELDS = ("prefec_ber_min", "prefec_ber_avg", "prefec_ber_max")
POSITIVE_PM_FIELDS = ("osnr_avg", "esnr_avg")
# (TRANSCEIVER_PM field, TRANSCEIVER_DOM_SENSOR field)
PM_DOM_POWER_FIELDS = (
    ("tx_power_avg", "tx1power"),
    ("rx_tot_power_avg", "rx1power"),
)
POWER_TOLERANCE_DB = 2.0

# xcvrd's default DOM/PM polling period is 60s; allow a few cycles.
PM_REFRESH_TIMEOUT_SEC = 200
PM_REFRESH_INTERVAL_SEC = 20

CLI_PM_CMD = "sudo show interfaces transceiver pm {}"
CLI_NOT_APPLICABLE = "not applicable"
CLI_PREFEC_BER_PATTERN = re.compile(r"^\s*Pre-FEC BER\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)", re.MULTILINE)


def _read_table(duthost, db, table, namespace, sep="|"):
    entries, err = get_db_table(duthost, db, table, namespace=namespace, sep=sep)
    if err:
        pytest.fail("Failed to read {} {} in namespace {}: {}".format(db, table, namespace or "default", err))
    return entries


def _numeric_pm(pm_entry):
    values = {}
    for field, raw in pm_entry.items():
        value = parse_numeric(raw)
        if value is not None and math.isfinite(value):
            values[field] = value
    return values


def _discover_coherent_ports(duthost, skip_ports):
    """Return ``(ready_ports, not_ready)``.

    ``ready_ports`` maps port -> namespace for coherent ports that are
    ModuleReady and oper up; ``not_ready`` maps the remaining coherent ports to
    the reason they were not checked.
    """
    ready_ports = {}
    not_ready = {}

    for namespace in duthost.get_frontend_asic_namespace_list():
        info_table = _read_table(duthost, "STATE_DB", "TRANSCEIVER_INFO", namespace)
        status_table = _read_table(duthost, "STATE_DB", "TRANSCEIVER_STATUS", namespace)
        port_table = _read_table(duthost, "APPL_DB", "PORT_TABLE", namespace, sep=":")

        for port, info in info_table.items():
            if port in skip_ports:
                continue
            if not COHERENT_MEDIA_PATTERN.search(info.get("application_advertisement", "")):
                continue

            module_state = status_table.get(port, {}).get("module_state")
            oper_status = port_table.get(port, {}).get("oper_status")
            if module_state != "ModuleReady":
                not_ready[port] = "module_state={}".format(module_state)
            elif oper_status != "up":
                not_ready[port] = "oper_status={}".format(oper_status)
            else:
                ready_ports[port] = namespace

            logger.info(
                "Coherent port %s (%s %s, namespace %s): module_state=%s oper_status=%s",
                port, info.get("manufacturer", "").strip(), info.get("model", "").strip(),
                namespace or "default", module_state, oper_status,
            )

    return ready_ports, not_ready


@pytest.fixture(scope="module")
def coherent_pm_ports(duthosts, enum_frontend_dut_hostname, xcvr_skip_list):
    duthost = duthosts[enum_frontend_dut_hostname]
    ready_ports, not_ready = _discover_coherent_ports(duthost, set(xcvr_skip_list.get(duthost.hostname, [])))

    for port, reason in natsorted(not_ready.items()):
        logger.warning("Coherent port %s not checked for PM: %s", port, reason)
    if not ready_ports:
        pytest.skip("No coherent (ZR) transceiver that is ModuleReady and oper up on {}".format(duthost.hostname))

    logger.info("Coherent ports under PM test on %s: %s", duthost.hostname, natsorted(ready_ports))
    return duthost, ready_ports


def _read_pm_by_port(duthost, ports):
    pm_by_port = {}
    for namespace in set(ports.values()):
        pm_table = _read_table(duthost, "STATE_DB", "TRANSCEIVER_PM", namespace)
        for port, port_ns in ports.items():
            if port_ns == namespace:
                pm_by_port[port] = pm_table.get(port, {})
    return pm_by_port


def _check_pm_values(pm_entry, dom_entry):
    if not pm_entry:
        return ["no TRANSCEIVER_PM entry"]

    failures = []
    pm = _numeric_pm(pm_entry)

    for field in PREFEC_BER_FIELDS:
        value = pm.get(field)
        if value is None:
            failures.append("{} missing or not numeric ({!r})".format(field, pm_entry.get(field)))
        elif value == PM_PLACEHOLDER_BER:
            failures.append("{} is the placeholder {} (module PM counters never latched)".format(
                field, PM_PLACEHOLDER_BER))
        elif not 0 <= value <= PREFEC_BER_LIMIT:
            failures.append("{}={} outside [0, {}]".format(field, value, PREFEC_BER_LIMIT))

    ber = [pm.get(field) for field in PREFEC_BER_FIELDS]
    if None not in ber and not ber[0] <= ber[1] <= ber[2]:
        failures.append("pre-FEC BER not ordered min <= avg <= max: {}".format(ber))

    for field in POSITIVE_PM_FIELDS:
        value = pm.get(field)
        if value is None or value <= 0:
            failures.append("{}={!r}, expected > 0".format(field, pm_entry.get(field)))

    for pm_field, dom_field in PM_DOM_POWER_FIELDS:
        pm_value = pm.get(pm_field)
        dom_value = parse_numeric(dom_entry.get(dom_field))
        if pm_value is None:
            failures.append("{} missing or not numeric ({!r})".format(pm_field, pm_entry.get(pm_field)))
        elif dom_value is None or not math.isfinite(dom_value):
            failures.append("DOM {} unavailable ({!r}) to cross-check {}".format(
                dom_field, dom_entry.get(dom_field), pm_field))
        elif abs(pm_value - dom_value) > POWER_TOLERANCE_DB:
            failures.append("{}={} dBm differs from DOM {}={} dBm by more than {} dB".format(
                pm_field, pm_value, dom_field, dom_value, POWER_TOLERANCE_DB))

    return failures


def test_coherent_pm_values(coherent_pm_ports):
    """PM of every ready coherent port holds real values, not placeholders."""
    duthost, ports = coherent_pm_ports
    pm_by_port = _read_pm_by_port(duthost, ports)

    all_failures = []
    for namespace in set(ports.values()):
        dom_table = _read_table(duthost, "STATE_DB", "TRANSCEIVER_DOM_SENSOR", namespace)
        for port in natsorted(p for p, ns in ports.items() if ns == namespace):
            failures = _check_pm_values(pm_by_port[port], dom_table.get(port, {}))
            if failures:
                all_failures.append("{}:\n  {}".format(port, "\n  ".join(failures)))
            else:
                logger.info("PM values PASS %s: prefec_ber_avg=%s osnr_avg=%s tx_power_avg=%s",
                            port, pm_by_port[port].get("prefec_ber_avg"),
                            pm_by_port[port].get("osnr_avg"), pm_by_port[port].get("tx_power_avg"))

    _fail_if_any(all_failures, "TRANSCEIVER_PM value check failed on {}".format(duthost.hostname))


def test_coherent_pm_refresh(coherent_pm_ports):
    """PM of every ready coherent port changes between xcvrd polling cycles."""
    duthost, ports = coherent_pm_ports
    baseline = {port: _numeric_pm(entry) for port, entry in _read_pm_by_port(duthost, ports).items()}
    stale = set(ports)

    def _all_refreshed():
        current = _read_pm_by_port(duthost, {port: ports[port] for port in stale})
        for port, entry in current.items():
            if entry and _numeric_pm(entry) != baseline[port]:
                logger.info("PM refreshed on %s", port)
                stale.discard(port)
        return not stale

    wait_until(PM_REFRESH_TIMEOUT_SEC, PM_REFRESH_INTERVAL_SEC, PM_REFRESH_INTERVAL_SEC, _all_refreshed)

    _fail_if_any(
        ["{}: TRANSCEIVER_PM unchanged for {}s".format(port, PM_REFRESH_TIMEOUT_SEC) for port in natsorted(stale)],
        "TRANSCEIVER_PM did not refresh on {}".format(duthost.hostname),
    )


def test_coherent_pm_cli(coherent_pm_ports):
    """'show interfaces transceiver pm' displays real PM, with and without -n."""
    duthost, ports = coherent_pm_ports

    all_failures = []
    for port in natsorted(ports):
        namespace = ports[port]
        commands = [CLI_PM_CMD.format(port)]
        if namespace:
            commands.append(CLI_PM_CMD.format(port) + " -n {}".format(namespace))

        for cmd in commands:
            result = duthost.shell(cmd, module_ignore_errors=True)
            output = result.get("stdout", "")
            if result.get("rc") != 0:
                all_failures.append("{}: rc={} stderr={}".format(
                    cmd, result.get("rc"), result.get("stderr", "").strip()))
                continue
            if CLI_NOT_APPLICABLE in output.lower():
                all_failures.append("{}: reports '{}'".format(cmd, output.strip()))
                continue

            match = CLI_PREFEC_BER_PATTERN.search(output)
            if not match:
                all_failures.append("{}: no Pre-FEC BER row in output".format(cmd))
                continue
            ber_avg = parse_numeric(match.group(2))
            if ber_avg is None or ber_avg == PM_PLACEHOLDER_BER:
                all_failures.append("{}: Pre-FEC BER avg is {}".format(cmd, match.group(2)))
                continue
            logger.info("PM CLI PASS '%s': Pre-FEC BER min/avg/max %s", cmd, match.groups())

    _fail_if_any(all_failures, "PM CLI check failed on {}".format(duthost.hostname))


def _fail_if_any(failures, summary):
    if failures:
        pytest.fail("{}:\n{}".format(summary, "\n".join(failures)))
