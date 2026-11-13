"""
Shared discovery / verification helpers for the CPO Fault Indication tests.

Keeps ``test_cpo_fault_indication.py`` declarative by centralizing vModule /
logical-port discovery and STATE_DB fault-token reads.
"""
import logging
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.helpers.sonic_db import STATE_DB, redis_hget
from tests.platform_tests.mellanox.conftest import CPO_PORT_TYPE
from tests.platform_tests.mellanox.interface_utils import get_interfaces_info

logger = logging.getLogger(__name__)

# STATE_DB table + field the platform-code (interrupt) path writes into.
#
# The CPO Fault Indication feature writes a dedicated field ``xcvr_fault`` on
# the existing TRANSCEIVER_STATUS_SW|<port> row and is the *sole writer* of
# this field; xcvrd continues to own ``status``,
# ``cmis_state`` and ``error`` (never touched by this feature). The field is
# absent until the feature writes it for the first time (no ``N/A`` sentinel
# is pre-populated), but we still tolerate an ``N/A`` value for robustness.
TRANSCEIVER_STATUS_SW_TABLE = "TRANSCEIVER_STATUS_SW"
FAULT_FIELD = "xcvr_fault"
# Field owned exclusively by xcvrd; asserted untouched by this feature.
XCVRD_ERROR_FIELD = "error"
FAULT_NONE = "N/A"
FAULT_SEP = "|"

# CPO vModule topology on SN6810_LD:
#
#     1 vModule = 4 banks (sub_modules) = 8 ELS lasers = 32 lanes
#               = 8 logical ports (1x2 breakout, 4 lanes each)
#
#     16 vModules x 32 lanes = 512 lanes = 128 CPO ports.
#
# Each ELS laser serves 4 lanes; the lane -> laser assignment is in
# /sys/module/sx_core/asic0/module<N>/module_cpo_info.
BANKS_PER_VMODULE = 4

# Numeric STATE_DB index, for redis-cli invocations on the DUT.
STATE_DB_INDEX = 6
LASERS_PER_VMODULE = 8
LANES_PER_LASER = 4


# ---------------------------------------------------------------------------
# vModule / logical-port discovery
# ---------------------------------------------------------------------------
def get_cpo_logical_ports(state_db_snapshot):
    """Return the list of CPO logical ports from STATE_DB TRANSCEIVER_INFO."""
    info_table = state_db_snapshot.get("TRANSCEIVER_INFO", {})
    return [
        port for port, fields in info_table.items()
        if fields.get("type") == CPO_PORT_TYPE
    ]


def _parse_config_index(raw_index, port):
    """Parse a CONFIG_DB ``PORT.index`` value into a single one-based index.

    On CPO platforms the index is a per-lane list (e.g. ``"1,1,1,1,1,1,1,1"``)
    while on non-CPO platforms it is a scalar (e.g. ``"1"``). All lanes of a
    logical port share one index, so the first element is authoritative.
    """
    pytest_assert(raw_index not in (None, ""),
                  "CONFIG_DB PORT|{} has no 'index' field".format(port))
    first = str(raw_index).split(",")[0].strip()
    pytest_assert(first.isdigit(),
                  "Unexpected CONFIG_DB index {!r} for {}".format(raw_index, port))
    return int(first)


def get_bank_port_groups(duthost, cpo_logical_ports):
    """Group CPO logical ports by their shared *bank* (SDK module) index.

    All logical ports that are breakout splits of the same physical port
    share one CONFIG_DB ``PORT|<port>.index``. That index identifies a
    **bank** (one SDK module / one ``CpoPort`` object), NOT a vModule --
    on SN6810_LD a vModule spans four banks. CPO port indices are
    one-based; SDK module indices are zero-based.

    Returns:
        dict: ``{sdk_module_index(int): [logical_port, ...]}`` sorted by
              port number within each group.
    """
    interfaces_info = get_interfaces_info(duthost)
    cpo_port_set = set(cpo_logical_ports)
    groups = {}
    for port, info in interfaces_info.items():
        if port not in cpo_port_set:
            continue
        config_index = _parse_config_index(info.get("index"), port)
        pytest_assert(config_index > 0,
                      "Invalid one-based CPO port index {} for {}".format(config_index, port))
        groups.setdefault(config_index - 1, []).append(port)
    for ports in groups.values():
        ports.sort(key=lambda p: int(p.replace("Ethernet", "")))
    logger.info("CPO bank -> logical ports: %s", groups)
    return groups


def get_vmodule_port_groups(duthost, cpo_logical_ports):
    """Group CPO logical ports by the **ELS index** that owns them.

    This is the grouping that matters for fault injection and for the
    fan-out the feature performs, and it is deliberately *not* the
    CONFIG_DB ``index`` grouping:

      * CONFIG_DB ``index``            -> one bank (one SDK module).
      * ELS index (this function)      -> one vModule = ``BANKS_PER_VMODULE``
                                          consecutive banks.

    On SN6810_LD, 64 ``CpoPort`` objects with
    ``sdk_index`` 0..63 map onto ELS 0..15, i.e. four banks per vModule.
    Each vModule carries ``LASERS_PER_VMODULE`` ELS lasers serving
    ``LANES_PER_LASER`` lanes each -- 32 lanes, surfacing as eight
    logical ports under 1x2 breakout (e.g. ELS 0 owns lanes 0..31 =
    Ethernet0..Ethernet28). The ELS index is also what
    ``mlxreg --reg_name PMFT`` takes as its ``module_index`` and what the
    kernel exposes as
    ``/sys/module/sx_core/asic0/module<els_index>/interrupt``.

    Returns:
        dict: ``{els_index(int): [logical_port, ...]}`` sorted by port
              number within each group.
    """
    bank_groups = get_bank_port_groups(duthost, cpo_logical_ports)
    groups = {}
    for bank_index, ports in bank_groups.items():
        groups.setdefault(bank_index // BANKS_PER_VMODULE, []).extend(ports)
    for ports in groups.values():
        ports.sort(key=lambda p: int(p.replace("Ethernet", "")))
    logger.info("CPO vModule (ELS) -> logical ports: %s", groups)
    return groups


# ---------------------------------------------------------------------------
# STATE_DB fault-token verification
# ---------------------------------------------------------------------------
def read_xcvr_fault(duthost, port):
    """Read TRANSCEIVER_STATUS_SW|<port>.xcvr_fault (stripped str).

    The field is absent until the feature writes it; ``redis_hget`` then
    returns ``None`` / empty, which downstream helpers treat as "no fault".
    """
    key = "{}|{}".format(TRANSCEIVER_STATUS_SW_TABLE, port)
    return redis_hget(duthost, STATE_DB, key, FAULT_FIELD)


def read_xcvrd_error(duthost, port):
    """Read TRANSCEIVER_STATUS_SW|<port>.error (owned by xcvrd, not us)."""
    key = "{}|{}".format(TRANSCEIVER_STATUS_SW_TABLE, port)
    return redis_hget(duthost, STATE_DB, key, XCVRD_ERROR_FIELD)


def fault_tokens(fault_value):
    """Split a TRANSCEIVER_STATUS_SW.xcvr_fault value into its token set.

    Absent field (``None``) / empty / ``N/A`` -> empty set.
    """
    if not fault_value or fault_value == FAULT_NONE:
        return set()
    return {t for t in fault_value.split(FAULT_SEP) if t and t != FAULT_NONE}


def split_xcvr_fault(fault_value):
    """Split a TRANSCEIVER_STATUS_SW.xcvr_fault value into its token list.

    Unlike ``fault_tokens`` this keeps order and duplicates, so callers can
    assert on the exact number of tokens written.
    Absent field (``None``) / empty / ``N/A`` -> empty list.
    """
    if not fault_value or fault_value == FAULT_NONE:
        return []
    return [t for t in fault_value.split(FAULT_SEP) if t and t != FAULT_NONE]


def assert_fault_token_count(duthost, port, expected_count):
    """Assert <port>.xcvr_fault holds exactly ``expected_count`` tokens.

    Each injected fault must produce exactly one token, so a stray extra
    token (or a duplicate) fails here even when the expected one is present.
    Returns the token list for further checks.
    """
    raw = read_xcvr_fault(duthost, port)
    tokens = split_xcvr_fault(raw)
    pytest_assert(
        len(tokens) == expected_count,
        "{}|{}.{} expected {} token(s), got {}: {!r}".format(
            TRANSCEIVER_STATUS_SW_TABLE, port, FAULT_FIELD,
            expected_count, len(tokens), raw),
    )
    return tokens


def clear_xcvr_fault(duthost, ports):
    """Reset a non-empty xcvr_fault field to "" on every port.

    The feature is append-only: it only ever calls
    ``Table.set()`` / ``Table.get()`` on TRANSCEIVER_STATUS_SW and has no
    delete path, so a token written by one test -- or by a manual
    injection -- stays in STATE_DB for the lifetime of the pmon container.
    ``sfputil reset`` clears the hardware latch but not the DB row.

    Without an explicit clear the suite is therefore not idempotent: the
    second run sees the first run's tokens and fails its baseline check.

    The field is reset to "" rather than deleted (HDEL). A field-level gNMI
    subscription only resolves ``<port>/xcvr_fault`` as a field
    when the field exists at subscribe time; once it is deleted, sonic-gnmi
    falls back to the non-existent key ``<port>|xcvr_fault`` and never
    streams the next fault. "" reads as "no fault" for both the feature's
    token merge and ``fault_tokens``. Absent or already-empty fields are
    left untouched.
    """
    cleared = 0
    for port in ports:
        if not read_xcvr_fault(duthost, port):
            continue
        duthost.shell(
            "redis-cli -n {db} HSET '{table}|{port}' {field} ''".format(
                db=STATE_DB_INDEX, table=TRANSCEIVER_STATUS_SW_TABLE,
                port=port, field=FAULT_FIELD),
            module_ignore_errors=True,
        )
        cleared += 1
    logger.info("Reset %s on %d of %d port(s)", FAULT_FIELD, cleared, len(ports))


def ensure_xcvr_fault_field(duthost, port):
    """Create <port>.xcvr_fault as "" if it does not exist yet (HSETNX).

    A field-level gNMI subscription to ``<port>/xcvr_fault`` only streams
    updates if the field already exists when the client subscribes.
    """
    duthost.shell(
        "redis-cli -n {db} HSETNX '{table}|{port}' {field} ''".format(
            db=STATE_DB_INDEX, table=TRANSCEIVER_STATUS_SW_TABLE,
            port=port, field=FAULT_FIELD))


def reset_baseline(duthost, ports):
    """Clear xcvr_fault on ``ports`` and assert the clear took effect.

    Use this instead of asserting the baseline is already clean: the field
    never clears on its own (see ``clear_xcvr_fault``), so a bare
    assertion makes every run after the first one fail.
    """
    clear_xcvr_fault(duthost, ports)
    assert_baseline_clean(duthost, ports)


def assert_baseline_clean(duthost, ports):
    """Assert every port's xcvr_fault field is absent (or empty / N/A)."""
    dirty = {}
    for p in ports:
        val = read_xcvr_fault(duthost, p)
        if fault_tokens(val):
            dirty[p] = val
    pytest_assert(
        not dirty,
        "Baseline not clean; TRANSCEIVER_STATUS_SW.xcvr_fault already set: {}".format(dirty),
    )


def wait_fault_token(duthost, port, token):
    """wait_until predicate: token is present in <port>.xcvr_fault."""
    return token in fault_tokens(read_xcvr_fault(duthost, port))


def wait_all_tokens(duthost, port, tokens):
    """wait_until predicate: every token in ``tokens`` present, |-separated."""
    present = fault_tokens(read_xcvr_fault(duthost, port))
    return set(tokens).issubset(present)


# ---------------------------------------------------------------------------
# DUT-local gNMI (for testbeds without a PTF host)
# ---------------------------------------------------------------------------
# On a testbed without a PTF host the community gNMI helpers -- which install client certs onto
# PTF and run py_gnmicli.py there -- cannot be used. The DUT itself already
# ships a gNMI client (`gnmi_cli` inside the gnmi container) and
# ``copy_certificate_to_dut`` already places the client cert alongside the
# server one, so the subscription can run entirely on the DUT.
GNMI_CERT_DIR = "/etc/sonic/telemetry"
# CN of the client cert the shared helpers generate; apply_cert_config
# registers it in CONFIG_DB GNMI_CLIENT_CERT.
GNMI_CLIENT_CN = "test.client.gnmi.sonic"
# Address the DUT-local client dials. The server cert is signed with this as
# its SAN IP (see the dut_ip argument threaded through prepare_server_cert),
# so the client verifies the server by that IP.
#
# Deliberately no -server_name override: the shared helpers build the server
# cert with SAN "DNS:hostname.com, IP:127.0.0.1" and CN
# test.server.gnmi.sonic. Passing -server_name test.server.gnmi.sonic makes
# gnmi_cli verify that name against the SAN, which does not list it, so the
# dial hangs until its timeout, while the identical command minus
# -server_name returns the row immediately.
GNMI_LOCAL_ADDR = "127.0.0.1"


def gnmi_subscribe_onchange_on_dut(duthost, path, update_count, timeout_s=120):
    """Run an ON_CHANGE gNMI subscription from inside the DUT's gnmi container.

    Mirrors ``tests.gnmi.helper.gnmi_subscribe_streaming_onchange`` but dials
    the DUT's own telemetry endpoint over loopback instead of shelling out to
    a PTF host, so it works on testbeds without one.

    ``-timestamp on`` is required: without it the patched gnmi_cli tries to
    parse string values as JSON and renders ``"1"``/``"0"``/``""`` as ``{}``.
    ``-expected_event`` is deliberately not used -- it only matches the
    top-level key (``STATE_DB``), so it never fires. The outer ``timeout``
    may kill the client before it closes the JSON array, so callers must
    parse the output tolerantly (see ``extract_gnmi_values``).

    Args:
        duthost: the DUT host object.
        path: STATE_DB query path, e.g. ``TRANSCEIVER_STATUS_SW/Ethernet0``.
        update_count: number of updates to consume before returning. Pass a
            value larger than any plausible update count so the client runs
            for the whole ``timeout_s`` (0 makes it exit after ~1s).
        timeout_s: client-side subscription timeout, in seconds.

    Returns:
        ``(stdout, stderr)`` of the client, matching the community helper's
        return shape so assertions can be written the same way.
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    cmd = (
        "docker exec {container} timeout {hard_timeout} gnmi_cli"
        " -address {addr}:{port}"
        " -target STATE_DB -query_type s -streaming_type ON_CHANGE"
        " -timestamp on"
        " -expected_count {count} -streaming_timeout {timeout} -timeout {timeout}s"
        " -ca_crt {certs}/gnmiCA.pem"
        " -client_crt {certs}/gnmiclient.crt"
        " -client_key {certs}/gnmiclient.key"
        " -q {path}"
    ).format(
        container=env.gnmi_container, hard_timeout=timeout_s + 20,
        addr=GNMI_LOCAL_ADDR, port=env.gnmi_port, count=update_count,
        timeout=timeout_s, certs=GNMI_CERT_DIR, path=path,
    )
    logger.info("DUT-local gNMI subscribe: %s", cmd)
    result = duthost.shell(cmd, module_ignore_errors=True)
    return result.get("stdout", ""), result.get("stderr", "")


def extract_gnmi_values(output):
    """Return every string ``"value"`` seen in ``gnmi_cli -timestamp on`` output.

    Tolerant of a truncated output (no closing ``]``), which is what an outer
    ``timeout`` leaves behind, so it scans with a regex rather than json.
    """
    return re.findall(r'"value"\s*:\s*"((?:[^"\\]|\\.)*)"', output or "")
