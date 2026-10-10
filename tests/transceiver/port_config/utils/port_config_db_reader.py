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

    Uses ansible ``config_facts(source="running")`` (the SONiC running CONFIG_DB view)
    rather than per-port ``sonic-db-cli`` calls so the whole table is read in bulk.
    On multi-ASIC devices, merges the PORT tables from all frontend ASIC namespaces.

    Returns an empty dict when the PORT table is absent/empty; the caller
    decides whether that is a skip or a failure.
    """
    if getattr(duthost, "is_multi_asic", False):
        asics = getattr(duthost, "frontend_asics", None) or getattr(duthost, "asics", [])
        port_table = {}
        for asic in asics:
            asic_facts = asic.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
            port_table.update(asic_facts.get("PORT", {}))
        logger.info(
            "Read CONFIG_DB PORT table from %d ASIC namespace(s): %d port(s)",
            len(asics),
            len(port_table),
        )
        return port_table

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
