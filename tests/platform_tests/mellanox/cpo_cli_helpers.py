"""
CPO helpers shared by the SW-controlled CPO suites.

  * ``dump_transceiver_state_db``   -- STATE_DB snapshot of the
                                       ``TRANSCEIVER_*`` tables
                                       (``test_cpo_dom_state_db``).
"""
import json
import logging
import uuid

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# STATE_DB snapshot helper
# ---------------------------------------------------------------------------

def dump_transceiver_state_db(duthost):
    """Bulk-fetch all ``TRANSCEIVER_*|Ethernet*`` entries from STATE_DB.

    The dump is redirected into a temp file on the DUT and pulled back
    via ``duthost.fetch`` (Ansible fetch module). Two reasons we avoid
    the obvious ``duthost.shell('sonic-db-dump ...')["stdout"]`` pattern:

      * Without ``-y`` the JSON is compact (3-5x smaller on disk).
      * ``fetch`` does not log the file contents at DEBUG; running
        ``sonic-db-dump`` (or ``cat``) and reading ``["stdout"]`` would
        cause ``tests/common/devices/base.py::_run_wrapper`` to log the
        entire payload, bloating the captured pytest log by tens of MB
        on CPO platforms.

    Any failure -- ``sonic-db-dump`` non-zero exit, fetch error, malformed
    JSON -- propagates the underlying Ansible / JSON exception unchanged
    so the developer sees the real root cause in the traceback.

    Returns:
        dict: ``{table_name: {port: {field: value}}}``.
    """
    remote_path = "/tmp/cpo_state_db_snap_{}.json".format(uuid.uuid4().hex)
    try:
        duthost.shell(
            "sonic-db-dump -n STATE_DB -k 'TRANSCEIVER_*|Ethernet*' > {}"
            .format(remote_path)
        )
        local_path = duthost.fetch(
            src=remote_path, dest="/tmp/", flat=True
        )["dest"]
    finally:
        duthost.shell("rm -f {}".format(remote_path), module_ignore_errors=True)

    with open(local_path) as fh:
        parsed = json.load(fh)

    snapshot = {}
    for key, entry in parsed.items():
        table, _, port = key.partition("|")
        snapshot.setdefault(table, {})[port] = entry.get("value", {})
    logger.info(
        "[%s] STATE_DB snapshot: %d tables, %d (table,port) entries",
        duthost.hostname, len(snapshot),
        sum(len(p) for p in snapshot.values()),
    )
    return snapshot
