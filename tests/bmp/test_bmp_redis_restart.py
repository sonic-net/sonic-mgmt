"""
Regression test: openbmpd must survive a BMP_STATE_DB (redis) restart.

When the BMP_STATE_DB redis instance is restarted under a running openbmpd and
openbmpd then writes onto the dropped connection, stock openbmpd aborts with an
uncaught swss::RedisError (SIGABRT). This test restarts the BMP redis instance
under load and asserts openbmpd does not crash and the BMP tables repopulate.

See the fix in sonic-net/sonic-bmp#45 (issue sonic-net/sonic-bmp#44).
"""
import logging
import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bmp_utils import BMPEnvironment
from tests.bmp.helper import (
    enable_bmp_feature,
    enable_bmp_rib_in_table,
    check_bmp_status,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]

BMP_STATE_DB = "BMP_STATE_DB"
RIB_IN_TABLE = "BGP_RIB_IN_TABLE"


def _bmp_container_running(duthost):
    return duthost.shell("docker ps | grep -w bmp",
                         module_ignore_errors=True)["rc"] == 0


def _rib_in_count(duthost):
    out = duthost.shell(
        "sonic-db-cli {} keys '{}|*' | wc -l".format(BMP_STATE_DB, RIB_IN_TABLE),
        module_ignore_errors=True)["stdout"].strip()
    return int(out) if out.isdigit() else 0


def _openbmpd_pid(duthost, bmp_container):
    out = duthost.shell(
        "docker exec {} supervisorctl status openbmpd".format(bmp_container),
        module_ignore_errors=True)["stdout"]
    # e.g. "openbmpd    RUNNING   pid 24, uptime 1:02:03"
    tokens = out.replace(",", " ").split()
    if "pid" in tokens:
        return tokens[tokens.index("pid") + 1]
    return None


def test_openbmpd_survives_bmp_state_db_restart(
        duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Restart the BMP_STATE_DB redis instance under a running openbmpd, drive BGP
    route churn, and verify openbmpd neither crashes nor stops populating.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Enable BMP first so the bmp container is up before we inspect it.
    enable_bmp_feature(duthost)
    pytest_assert(wait_until(120, 5, 0, _bmp_container_running, duthost),
                  "bmp container did not start after enabling the bmp feature")
    bmp_container = BMPEnvironment(duthost).bmp_container
    pytest_assert(wait_until(60, 5, 0, check_bmp_status, duthost),
                  "openbmpd is not running after enabling the bmp feature")

    # Enable the rib-in table and wait for openbmpd to populate it.
    enable_bmp_rib_in_table(duthost)
    pytest_assert(wait_until(180, 10, 0, lambda: _rib_in_count(duthost) > 0),
                  "BMP_STATE_DB {} was not populated".format(RIB_IN_TABLE))

    pid_before = _openbmpd_pid(duthost, bmp_container)
    logger.info("openbmpd pid before=%s rib-in keys=%d",
                pid_before, _rib_in_count(duthost))

    # Drop the BMP state-DB connection under openbmpd, then force writes so it
    # writes onto the now-dead connection (the crash trigger).
    duthost.shell("docker exec database supervisorctl restart redis_bmp",
                  module_ignore_errors=True)
    duthost.shell("docker exec bgp vtysh -c 'clear bgp *'",
                  module_ignore_errors=True)

    # openbmpd must stay up: still RUNNING and the same pid (no crash/restart).
    pytest_assert(wait_until(60, 5, 0, check_bmp_status, duthost),
                  "openbmpd is not running after the redis_bmp restart")
    pid_after = _openbmpd_pid(duthost, bmp_container)
    pytest_assert(pid_after is not None and pid_after == pid_before,
                  "openbmpd restarted (crashed) across the redis_bmp restart: "
                  "pid {} -> {}".format(pid_before, pid_after))

    # ... and it must reconnect and repopulate the table.
    pytest_assert(wait_until(240, 10, 0, lambda: _rib_in_count(duthost) > 0),
                  "BMP_STATE_DB {} did not repopulate after the redis_bmp "
                  "reconnect".format(RIB_IN_TABLE))
    logger.info("openbmpd survived; rib-in keys after=%d", _rib_in_count(duthost))
