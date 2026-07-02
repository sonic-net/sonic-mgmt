"""CONFIG_DB PORT-table read helpers for the Port Config tests.

All Port Config test cases are read-only CONFIG_DB queries.  Reading the whole
PORT table once (via ``get_running_config_facts``) and looking each port up in
the returned dict is far cheaper than one ``sonic-db-cli hgetall`` per port on a
fully-broken-out chassis with hundreds of logical ports, so the bulk reader is
the primary entry point and the per-port helper is a thin lookup over it.

Kept as a standalone module (not in a test file or conftest) so the pure logic
can be unit-tested in isolation and reused across every Port Config test.
"""
import logging

logger = logging.getLogger(__name__)


def get_config_db_port_table(duthost):
    """Return the entire CONFIG_DB PORT table as ``{port_name: {field: value}}``.

    Uses ``duthost.get_running_config_facts()`` (the ansible-facts view SONiC
    exposes for the running CONFIG_DB) rather than a shell ``sonic-db-cli`` so
    the whole table is read in one call and multi-ASIC config is already merged.

    Returns an empty dict when the PORT table is absent/empty; the caller
    decides whether that is a skip or a failure.
    """
    config_facts = duthost.get_running_config_facts()
    port_table = config_facts.get("PORT", {})
    logger.info("Read CONFIG_DB PORT table: %d port(s)", len(port_table))
    return port_table


def get_port_config(port_table, port):
    """Return one port's CONFIG_DB field map, or ``{}`` if the port is absent.

    Pure dict accessor over the bulk table from :func:`get_config_db_port_table`
    so callers never issue a per-port DB query.
    """
    return port_table.get(port, {})
