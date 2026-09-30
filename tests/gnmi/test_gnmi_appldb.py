import logging
import re
import shlex

import grpc
import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.sonic_db import APPL_DB, redis_exists, redis_sismember, redis_srem
from tests.common.pygnmi_client import PygnmiClientCallError
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("rand_one_dut_hostname"),
]

PREFIX = "sonic-db:APPL_DB/localhost"
TABLES = ("DASH_VNET_TABLE", "_DASH_VNET_TABLE")
VNET = "Vnet1"


def _vnet_exists(duthost):
    return bool(redis_exists(duthost, APPL_DB, *("{}:{}".format(table, VNET) for table in TABLES)))


def _read_vni(client, table):
    path = "{}/{}/vni".format(table, VNET)
    try:
        response = client.get(path, prefix=PREFIX)
    except PygnmiClientCallError as error:
        # pygnmi wraps the original gRPC status; message matching alone is unsafe.
        cause = error.__cause__
        rpc_error = getattr(cause, "orig_exc", cause)
        if isinstance(rpc_error, grpc.RpcError) and rpc_error.code() == grpc.StatusCode.NOT_FOUND:
            details = rpc_error.details()
            if (details.startswith("No valid entry found for path ")
                    and re.findall(r'name:\s*"([^"]+)"', details) == [table, VNET, "vni"]):
                return None
        raise
    assert isinstance(response, dict), "Invalid gNMI Get response: {!r}".format(response)
    updates = [update for notification in response.get("notification", [])
               for update in notification.get("update", [])]
    if not updates:
        return None
    assert len(updates) == 1 and updates[0]["path"].strip("/") == path, \
        "Unexpected gNMI updates for {}: {!r}".format(path, updates)
    assert isinstance(updates[0]["val"], str), "Invalid VNI value: {!r}".format(updates[0])
    return updates[0]["val"]


def _vni_present(client):
    values = [_read_vni(client, table) for table in TABLES]
    assert all(value in (None, "1000") for value in values), "Unexpected VNI values: {!r}".format(values)
    return "1000" in values


def _vnet_absent(duthost):
    return not _vnet_exists(duthost)


def test_gnmi_appldb_01(gnmi_tls):  # noqa: F811
    """Verify native APPL_DB Set/Get/Delete through managed TLS."""
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    # Do not overwrite an existing entry, including a staged ProducerStateTable write.
    if _vnet_exists(duthost):
        pytest.skip("Preserving pre-existing APPL_DB Vnet1")
    for suffix in ("KEY_SET", "DEL_SET"):
        if redis_sismember(duthost, APPL_DB, "DASH_VNET_TABLE_{}".format(suffix), VNET):
            pytest.skip("Preserving pending APPL_DB Vnet1 operation")

    try:
        client.set(update=[(TABLES[0], {VNET: {
            "vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2",
        }})], prefix=PREFIX)
        assert wait_until(10, 1, 0, _vni_present, client), "Neither DASH VNET table returned VNI 1000"
        assert _vnet_exists(duthost), "gNMI Vnet1 is missing from fixture-selected DUT APPL_DB"

        client.set(delete=["{}/{}".format(TABLES[0], VNET)], prefix=PREFIX)
        assert wait_until(10, 1, 0, _vnet_absent, duthost), "Vnet1 remains in APPL_DB after gNMI Delete"
        for table in TABLES:
            assert _read_vni(client, table) is None, "Vnet1 remains readable in {}".format(table)
    finally:
        # CONFIG_DB rollback cannot clean APPL_DB; use the producer even if TLS failed.
        script = (
            "from swsscommon import swsscommon; "
            "db = swsscommon.DBConnector('APPL_DB', 0, True); "
            "table = swsscommon.ProducerStateTable(db, 'DASH_VNET_TABLE'); "
            "table._del('Vnet1')"
        )
        result = duthost.shell("sudo python3 -c {}".format(shlex.quote(script)))
        assert result["rc"] == 0, "APPL_DB Vnet1 cleanup failed"
        assert wait_until(10, 1, 0, _vnet_absent, duthost), "APPL_DB Vnet1 cleanup did not converge"
        # A non-DASH DUT may have no consumer to drain the producer's tombstone.
        for suffix in ("KEY_SET", "DEL_SET"):
            redis_srem(duthost, APPL_DB, "DASH_VNET_TABLE_{}".format(suffix), VNET)
        logger.info("APPLDB_CLEANUP_VERIFIED dut=%s Vnet1 absent from both tables", duthost.hostname)

    logger.info("APPLDB_MANAGED_TLS_VERIFIED dut=%s VNI=1000 Set/Get/Delete and cleanup verified", duthost.hostname)
