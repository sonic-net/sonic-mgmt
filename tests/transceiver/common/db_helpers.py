"""Centralized CONFIG_DB / STATE_DB / APPL_DB query wrappers for transceiver tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for
"CONFIG_DB, STATE_DB, APPL_DB query wrappers".

These wrappers exist so the ``sonic-db-cli`` invocation details — the ``|``
Redis-key quoting (SONiC tables are keyed ``TABLE|key``), the rc / stderr
handling, and the "field absent vs. command failed" semantics — live in one
place instead of being re-implemented per test.

Per-port query wrappers mirror the ``cli_helpers`` contract: they run the query
with ``module_ignore_errors=True`` and return a ``(value, err)`` tuple where
``err`` is ``None`` on success and a short, single-line string on command
failure, so callers can use the suite-wide per-port aggregation pattern:

    value, err = db_helpers.get_state_db_hash_field(
        duthost, "TRANSCEIVER_INFO", port, "vdm_supported")
    if err:
        all_failures.append(f"{port}: {err}")
        continue

Bulk/once-per-test accessors read many rows in one shot:
:func:`get_config_db_port_table` and :func:`get_config_db_port_names` return
their values directly, while :func:`get_state_db_table` keeps the ``(value,
err)`` tuple so a dump failure can be surfaced as a clean per-test failure.
"""
import ast
import json
import logging
import re
from datetime import datetime

from tests.common.helpers.sonic_db import STATE_DB
from tests.transceiver.common.cli_parser_helper import RC_FAILURE

logger = logging.getLogger(__name__)


STATE_DB_UPDATE_TIME_FIELD = "last_update_time"
STATE_DB_UPDATE_TIME_FUTURE_TOLERANCE_MIN = 0.1
XCVRD_UPDATE_TIME_FORMAT = "%a %b %d %H:%M:%S %Y"

_FLOAT_PATTERN = re.compile(
    r"[-+]?(?:inf(?:inity)?|\d*\.?\d+(?:[eE][-+]?\d+)?)",
    re.IGNORECASE,
)


def parse_numeric(value):
    """Parse the first numeric token from a DB value.

    Supports regular floats plus ``inf`` / ``-inf`` forms such as ``-infdBm``.
    Returns ``None`` for absent, N/A-like, or unparseable values.
    """
    if value is None:
        return None

    text = str(value).strip()
    if not text or text.upper() in ("N/A", "NA", "NONE"):
        return None

    match = _FLOAT_PATTERN.search(text)
    if not match:
        logger.debug("Could not parse numeric value from %r", value)
        return None

    token = match.group(0).lower()
    if token in ("inf", "+inf", "infinity", "+infinity"):
        return float("inf")
    if token in ("-inf", "-infinity"):
        return float("-inf")

    try:
        return float(match.group(0))
    except ValueError:
        logger.debug(
            "Could not convert numeric token %r from %r",
            match.group(0),
            value,
        )
        return None


def parse_update_time(value):
    """Parse an xcvrd UTC update timestamp."""
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    normalized = " ".join(raw.split())
    try:
        return datetime.strptime(normalized, XCVRD_UPDATE_TIME_FORMAT)
    except ValueError:
        logger.debug(
            "Could not parse xcvrd update timestamp %r with format %s",
            raw,
            XCVRD_UPDATE_TIME_FORMAT,
        )
        return None


def resolve_port_namespace(duthost, port):
    """Return the ASIC namespace for a logical port, or ``None`` on single-ASIC."""
    return duthost.get_port_asic_instance(port).namespace


def _entry_field_age_minutes(entry, now_utc):
    """Return the configured update timestamp age in minutes, or ``None``."""
    if not entry:
        return None

    parsed_time = parse_update_time(entry.get(STATE_DB_UPDATE_TIME_FIELD))
    if parsed_time is None:
        return None

    return (now_utc - parsed_time).total_seconds() / 60.0


def check_entry_freshness(
    entry,
    max_age_min,
    now_utc,
    table_name="STATE_DB entry",
):
    """Validate entry freshness and return failures plus the computed age.

    The timestamp is parsed once, and callers can use the returned age for
    logging without re-parsing the same entry value.
    """
    result = {
        "failures": [],
        "age_minutes": _entry_field_age_minutes(entry, now_utc),
    }

    if max_age_min is None:
        return result

    if not entry:
        result["failures"].append(
            "missing {} data for {} freshness check".format(
                table_name,
                STATE_DB_UPDATE_TIME_FIELD,
            )
        )
        return result

    try:
        max_age = float(max_age_min)
    except (TypeError, ValueError):
        result["failures"].append(
            "invalid data_max_age_min={!r}".format(max_age_min)
        )
        return result

    age_minutes = result["age_minutes"]
    if age_minutes is None:
        result["failures"].append(
            "{} missing or unparsable while data_max_age_min is configured".format(
                STATE_DB_UPDATE_TIME_FIELD
            )
        )
        return result

    if age_minutes < -float(STATE_DB_UPDATE_TIME_FUTURE_TOLERANCE_MIN):
        result["failures"].append(
            "{} is in the future (age_min={:.2f}, tolerance_min={:.2f})".format(
                STATE_DB_UPDATE_TIME_FIELD,
                age_minutes,
                float(STATE_DB_UPDATE_TIME_FUTURE_TOLERANCE_MIN),
            )
        )
    elif age_minutes > max_age:
        result["failures"].append(
            "{} too old (age_min={:.2f}, limit={})".format(
                STATE_DB_UPDATE_TIME_FIELD,
                age_minutes,
                max_age_min,
            )
        )

    return result


def parse_state_db_bool(value):
    """Parse a STATE_DB string into a Python bool, or ``None`` if unrecognized.

    xcvrd (and other daemons) write Python bools into Redis as the strings
    ``"True"`` / ``"False"`` (Redis stores everything as strings); the numeric
    forms ``"1"`` / ``"0"`` are accepted too for robustness.

    Returns ``None`` for any unrecognized value — deliberately tri-state — so a
    caller can flag a malformed STATE_DB value as a parse failure rather than
    silently treating it as ``False``.  This is why it is NOT the shared
    ``str2bool`` helpers in ``tests/common``: those collapse unrecognized input
    into a bool, which would mask exactly the malformed-value case STATE_DB
    consistency checks need to catch.  Lives here so "how daemons encode bools
    in Redis" sits next to the STATE_DB read helpers.
    """
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in ("true", "1"):
        return True
    if normalized in ("false", "0"):
        return False
    return None


def get_bool_field_from_entry(entry, field):
    """Extract a tri-state bool ``field`` from a STATE_DB entry dict → ``(value, err)``.

    ``entry`` is one port's already-dumped hash (e.g. a value from
    :func:`get_state_db_table`), so this is a pure dict accessor — it does NOT
    issue a DB query and composes with the single bulk ``sonic-db-dump`` rather
    than reintroducing a per-port read.

    Mirrors the module's ``(value, err)`` contract, distinguishing the two
    failure modes a capability-flag check needs to tell apart:
      - ``(True/False, None)`` when ``field`` is present and a recognized bool.
      - ``(None, "no '<field>' field ...")`` when ``field`` is absent.
      - ``(None, "'<field>' has unrecognized value ...")`` when present but not a
        recognized bool (see :func:`parse_state_db_bool`).

    The error strings are deliberately generic; callers prefix the port (and any
    other) context and aggregate per the suite-wide per-port failure pattern.
    """
    raw = entry.get(field)
    if raw is None:
        return None, f"no '{field}' field in STATE_DB entry"
    parsed = parse_state_db_bool(raw)
    if parsed is None:
        return None, f"'{field}' has unrecognized value '{raw}' (expected 'True'/'False')"
    return parsed, None


def hgetall_dict(duthost, db, key, namespace=None):
    """Run ``sonic-db-cli [-n <ns>] <db> hgetall "<key>"`` and parse the dict literal.

    ``key`` is the full Redis key including its table separator
    (e.g. ``"TRANSCEIVER_STATUS|Ethernet0"`` or ``"PORT_TABLE:Ethernet0"``); it is
    double-quoted because ``|`` would otherwise be a shell pipe.

    ``namespace`` scopes the query to one ASIC on a multi-ASIC DUT: ``-n <ns>``
    is emitted only when ``namespace`` is truthy (``asicN``, e.g. from
    ``duthost.get_namespace_from_asic_id``).  On a single-ASIC DUT the value is
    ``None``/``""`` and no flag is emitted, so the command stays byte-identical to
    the pre-namespace form.

    Returns an empty dict when the key is missing or the command failed.  Unlike
    the ``(value, err)`` wrappers above this is a best-effort read: callers
    (Standard Port Recovery, state restoration, link-baseline snapshots) treat an
    absent key as "nothing published yet" rather than an error to surface, so an
    empty dict is the natural "not present" signal.
    """
    ns_flag = f" -n {namespace}" if namespace else ""
    cmd = f'sonic-db-cli{ns_flag} {db} hgetall "{key}"'
    out = duthost.shell(cmd, module_ignore_errors=True)
    if out.get("rc", RC_FAILURE) != 0:
        return {}
    stdout = (out.get("stdout") or "").strip()
    if not stdout or stdout == "{}":
        return {}
    try:
        parsed = ast.literal_eval(stdout)
    except (SyntaxError, ValueError):
        logger.warning("Failed to parse hgetall output for %s %s: %r", db, key, stdout)
        return {}
    if not isinstance(parsed, dict):
        # Parsed cleanly but isn't a dict -- an unexpected sonic-db-cli output
        # shape.  Warn (mirroring the parse-failure branch above) so a shape
        # regression is visible instead of being silently swallowed as {}.
        logger.warning(
            "hgetall for %s %s returned non-dict %s: %r",
            db, key, type(parsed).__name__, stdout,
        )
        return {}
    return parsed


def get_db_hash_field(duthost, db, table, key, field, namespace=None, sep="|"):
    """Read one hash field from ``db`` → ``(value, err)``.

    Runs ``sonic-db-cli [-n <ns>] <db> hget "<table><sep><key>" <field>``.  The
    Redis key is double-quoted because it contains ``sep``, which the shell would
    otherwise treat as a pipe (``|``) or otherwise mangle.

    ``sep`` is the table/key separator: ``"|"`` for STATE_DB and CONFIG_DB,
    ``":"`` for APPL_DB.

    ``namespace`` scopes the query to one ASIC on a multi-ASIC DUT: ``-n <ns>``
    is emitted only when ``namespace`` is truthy (``asicN``, e.g. from
    ``duthost.get_namespace_from_asic_id``).  ``sonic-db-cli`` takes the namespace
    as ``-n`` with the database as a positional arg, so this is a plain flag
    prepend.  On a single-ASIC DUT the value is ``None``/``""`` and no flag is
    emitted, so the command stays byte-identical to the pre-namespace form.

    Returns ``(value, err)``:
      - ``(field_value_str, None)`` when the field is present.
      - ``(None, None)`` when the field (or key) is absent — sonic-db-cli prints
        an empty line with rc 0 in that case; every caller treats ``None`` as
        "not published".
      - ``(None, "<cmd> failed with rc=... stderr=...")`` on non-zero rc.
    """
    ns_flag = f" -n {namespace}" if namespace else ""
    cmd = f'sonic-db-cli{ns_flag} {db} hget "{table}{sep}{key}" {field}'
    # shell (not command) because the quoted "<table><sep><key>" needs shell parsing.
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        return None, (
            f"{cmd} failed with rc={result.get('rc')}, "
            f"stderr: {(result.get('stderr') or '').strip()}"
        )
    value = (result.get("stdout") or "").strip()
    return (value or None), None


def get_state_db_hash_field(duthost, table, key, field, namespace=None):
    """Read one hash field from STATE_DB → ``(value, err)``.

    Thin wrapper over :func:`get_db_hash_field` pinned to ``STATE_DB`` (``|``
    separator).  See that function for the ``namespace`` and ``(value, err)``
    semantics; this preserves the existing STATE_DB call sites unchanged.
    """
    return get_db_hash_field(duthost, STATE_DB, table, key, field, namespace=namespace)


def get_db_table(duthost, db, table, namespace=None, sep="|"):
    """Read every ``<table><sep>*`` entry in ``db`` in a single ``sonic-db-dump`` call.

    This replaces one per-key read (``hget``/``hgetall``) per port with one bulk
    dump — the right shape when a test/poll needs many ports' entries (e.g.
    verifying ``vdm_supported`` across the whole ``TRANSCEIVER_INFO`` table, or
    polling ``LLDP_ENTRY_TABLE`` presence across a batch of ports) instead of one
    round-trip per port.

    ``sep`` is the table/key separator: ``"|"`` for STATE_DB and CONFIG_DB,
    ``":"`` for APPL_DB (see :func:`get_db_hash_field`).

    ``namespace`` scopes the dump to one ASIC on a multi-ASIC DUT.  NOTE the
    mechanism differs from :func:`get_db_hash_field`: ``sonic-db-dump``'s own
    ``-n`` is the *database* name (here ``db``), not a namespace, so a namespaced
    read is done by running the dump inside the ASIC's network namespace via
    ``sudo ip netns exec <ns> ...`` — the same wrapper the framework's ASIC host
    uses (see ``sonic_asic.py`` ``ns_arg``).  The prefix is added only when
    ``namespace`` is truthy (``asicN``, e.g. from
    ``duthost.get_namespace_from_asic_id``); on a single-ASIC DUT the value is
    ``None``/``""`` and the command stays byte-identical to the pre-namespace form.

    Returns ``(by_key, err)``:
      - ``({key_suffix: {field: value}}, None)`` on success.  The ``<table><sep>``
        prefix is stripped, so for ``TRANSCEIVER_INFO`` ``key_suffix`` is the
        port name and the value is that port's published field map (an empty
        dict if the entry carries no fields). Redis never stores an empty hash,
        so ``key_suffix in by_key`` is equivalent to "that key's hash is
        non-empty" — the same truth a per-key ``if entry:`` test gives.
      - ``(None, "<cmd> failed ...")`` on a non-zero rc or unparseable output.

    ``sonic-db-dump -y`` emits JSON keyed by full Redis key, with the hash fields
    nested under each key's ``"value"`` block; this unwraps that into a flat
    ``{key_suffix: {field: value}}`` map.
    """
    ns_prefix = f"sudo ip netns exec {namespace} " if namespace else ""
    cmd = f"{ns_prefix}sonic-db-dump -n {db} -y -k '{table}{sep}*'"
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        return None, (
            f"{cmd} failed with rc={result.get('rc')}, "
            f"stderr: {(result.get('stderr') or '').strip()}"
        )
    try:
        raw = json.loads(result.get("stdout") or "{}")
    except ValueError as exc:
        return None, f"{cmd}: could not parse sonic-db-dump JSON ({exc})"
    prefix = f"{table}{sep}"
    return {
        full_key[len(prefix):]: entry.get("value", {})
        for full_key, entry in raw.items()
        if full_key.startswith(prefix)
    }, None


def get_state_db_table(duthost, table, namespace=None):
    """Thin wrapper over :func:`get_db_table` pinned to ``STATE_DB`` (``|`` separator).

    See that function for the ``namespace``/``(by_key, err)`` semantics; this
    preserves the existing STATE_DB call sites unchanged.
    """
    return get_db_table(duthost, "STATE_DB", table, namespace=namespace, sep="|")


def get_config_db_port_table(duthost):
    """Return the merged CONFIG_DB PORT table from running config facts.

    Reads every frontend ASIC namespace so multi-ASIC DUTs include front-panel
    Ethernet ports whose PORT entries live in per-ASIC CONFIG_DB instances. On
    single-ASIC DUTs, ``get_frontend_asic_namespace_list`` returns ``[None]``,
    so this keeps the default-namespace behavior.

    This is a once-per-test bulk read (not a per-port query), so it returns the
    table directly rather than the ``(value, err)`` tuple the per-port wrappers
    use; a facts-gather failure is an infra-level error and is allowed to raise.
    """
    port_table = {}
    for namespace in duthost.get_frontend_asic_namespace_list():
        config_facts = duthost.config_facts(
            host=duthost.hostname,
            source="running",
            namespace=namespace,
        )["ansible_facts"]
        port_table.update(config_facts.get("PORT") or {})
    return port_table


def get_config_db_port_names(duthost):
    """Return the set of port names in the CONFIG_DB PORT table."""
    return set(get_config_db_port_table(duthost).keys())
