"""
Tests related to L2 configuration
"""
import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_expect
from tests.common.checkpoint import (
    create_checkpoint,
    delete_checkpoint,
    rollback,
)

logger = logging.getLogger(__name__)

DUT_SONIC_IMAGE = "/tmp/sonic_image.bin"
DUT_SONIC_CFG = "/tmp/sonic-cfg.json"
DUT_ORIGIN_CFG = "/tmp/sonic-cfg-orig.json"

DUMP_DB_CMD = "sonic-db-dump -y -n CONFIG_DB -k 'TELEMETRY|*'"
DB_DUMP_IGNORE = ["expireat"]

pytestmark = [
    pytest.mark.topology('any')
]


def compare_db_dump(db_before, db_after):
    """
    Compare two db dumps and after the L2 configuration steps.
    Assert there are no additional configuration coming from minigraph.
    For example, TELEMETRY shouldn't change.
    """
    lines1 = db_before.splitlines()
    lines2 = db_after.splitlines()

    pytest_expect(len(lines1) == len(lines2),
                  "Dumps are of different length " +
                  f" {len(lines1)} != {len(lines2)}")

    for line1, line2 in zip(lines1, lines2):
        if (not any(ignore in line1 for ignore in DB_DUMP_IGNORE) and
                not any(ignore in line2 for ignore in DB_DUMP_IGNORE)):
            pytest_expect(line1 == line2, "Unequal lines " +
                          line1 + " != " + line2)


def test_l2_configure(request, duthosts, rand_one_dut_hostname, localhost):
    """
    @summary: Test we can configure dut as a L2 switch.

    Args:
        duthosts: set of DUTs.
        localhost: localhost object.
    """
    # Setup.
    duthost = duthosts[rand_one_dut_hostname]
    hwsku = duthost.facts["hwsku"]
    db_before = duthost.shell(DUMP_DB_CMD)["stdout"]
    create_checkpoint(duthost)

    # Perform L2 configuration
    l2_cfg = "sudo sonic-cfggen --preset l2 -p -H -k {}" \
        " | sudo config load /dev/stdin -y".format(hwsku)
    duthost.shell(l2_cfg)
    duthost.command("sudo config qos reload --no-dynamic-buffer")
    duthost.command("sudo config save -y")
    db_after = duthost.shell(DUMP_DB_CMD)["stdout"]
    compare_db_dump(db_before, db_after)

    # Cleanup and restore.
    rollback(duthost)
    time.sleep(40)
    delete_checkpoint(duthost)
