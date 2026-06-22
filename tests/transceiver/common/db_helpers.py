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
:func:`get_config_db_port_names` returns its value directly, while
:func:`get_state_db_table` keeps the ``(value, err)`` tuple so a dump failure can
be surfaced as a clean per-test failure.
"""
import json

from tests.transceiver.common.cli_parser_helper import RC_FAILURE


# sonic-db-cli database identifiers (the first positional arg to sonic-db-cli).
STATE_DB = "STATE_DB"


def get_state_db_hash_field(duthost, table, key, field):
    """Read one hash field from STATE_DB.

    Runs ``sonic-db-cli STATE_DB hget "<table>|<key>" <field>`` (the Redis key is
    double-quoted because table keys contain ``|``, which the shell would
    otherwise treat as a pipe).

    Returns ``(value, err)``:
      - ``(field_value_str, None)`` when the field is present.
      - ``(None, None)`` when the field (or key) is absent — sonic-db-cli prints
        an empty line with rc 0 in that case; every caller treats ``None`` as
        "not published".
      - ``(None, "<cmd> failed with rc=... stderr=...")`` on non-zero rc.
    """
    cmd = f'sonic-db-cli {STATE_DB} hget "{table}|{key}" {field}'
    # shell (not command) because the quoted "<table>|<key>" needs shell parsing.
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        return None, (
            f"{cmd} failed with rc={result.get('rc')}, "
            f"stderr: {(result.get('stderr') or '').strip()}"
        )
    value = (result.get("stdout") or "").strip()
    return (value or None), None


def get_state_db_table(duthost, table):
    """Read every STATE_DB ``<table>|*`` entry in a single ``sonic-db-dump`` call.

    This replaces one ``hget`` per port with one bulk dump — the right shape when
    a test needs many ports' fields (e.g. verifying ``vdm_supported`` across the
    whole ``TRANSCEIVER_INFO`` table) instead of a single field.

    Returns ``(by_key, err)``:
      - ``({key_suffix: {field: value}}, None)`` on success.  The ``<table>|``
        prefix is stripped, so for ``TRANSCEIVER_INFO`` ``key_suffix`` is the
        port name and the value is that port's published field map (an empty
        dict if the entry carries no fields).
      - ``(None, "<cmd> failed ...")`` on a non-zero rc or unparseable output.

    ``sonic-db-dump -y`` emits JSON keyed by full Redis key, with the hash fields
    nested under each key's ``"value"`` block; this unwraps that into a flat
    ``{port: {field: value}}`` map.
    """
    cmd = f"sonic-db-dump -n {STATE_DB} -y -k '{table}|*'"
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
    prefix = f"{table}|"
    return {
        full_key[len(prefix):]: entry.get("value", {})
        for full_key, entry in raw.items()
        if full_key.startswith(prefix)
    }, None


def get_config_db_port_names(duthost):
    """Return the set of port names in the CONFIG_DB PORT table.

    Thin accessor over ``duthost.get_running_config_facts()`` (the ansible-facts
    path SONiC exposes for the running CONFIG_DB).  Returns an empty set when the
    PORT table is absent/empty so the caller can decide whether that is a skip or
    a failure.

    This is a once-per-test bulk read (not a per-port query), so it returns the
    set directly rather than the ``(value, err)`` tuple the per-port wrappers
    use; a facts-gather failure is an infra-level error and is allowed to raise.
    """
    config_facts = duthost.get_running_config_facts()
    return set(config_facts.get("PORT", {}).keys())
