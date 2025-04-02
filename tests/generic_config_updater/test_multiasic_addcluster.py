import json
import logging
import os
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

from .util.process_minigraph import MinigraphRefactor

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

MINIGRAPH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP = "/etc/sonic/minigraph.xml.backup"
TARGET_LEAF = "ARISTA01T1"
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(THIS_DIR, "templates")
ADDCLUSTER_FILE = os.path.join(TEMPLATES_DIR, "addcluster.json")


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)
    yield
    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def create_table_if_not_exist(duthost, tables):
    """
    Create tables in CONFIG_DB if they do not exist.
    :param duthost: DUT host object
    :param tables: List of table names to check and create
    """
    for table in tables:
        result = duthost.shell(f"sonic-db-cli -n asic0 CONFIG_DB keys '{table}|*'")["stdout"]
        if not result:
            logger.info(f"Table {table} does not exist, creating it")
            json_patch = {
                "op": "add",
                "path": "/asic0/{}".format(table),
                "value": {}
            }
            tmpfile = generate_tmpfile(duthost)
            try:
                apply_patch_result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
                if apply_patch_result['rc'] != 0 or "Patch applied successfully" not in apply_patch_result['stdout']:
                    pytest.fail(f"Failed to apply patch: {apply_patch_result['stdout']}")
            finally:
                delete_tmpfile(duthost, tmpfile)


def test_addcluster_workflow(duthost):
    # Step 1: Backup minigraph
    logger.info(f"Backing up current minigraph from {MINIGRAPH} to {MINIGRAPH_BACKUP}")
    if not duthost.stat(path=MINIGRAPH)["stat"]["exists"]:
        pytest.fail(f"{MINIGRAPH} not found on DUT")
    duthost.shell(f"sudo cp {MINIGRAPH} {MINIGRAPH_BACKUP}")

    # Step 2: Generate new minigraph without ARISTA01T1
    logger.info(f"Modifying minigraph to remove {TARGET_LEAF}")
    local_dir = "/tmp/minigraph_modified"
    local_minigraph = os.path.join(local_dir, f"{duthost.hostname}-minigraph.xml")
    duthost.fetch(src=MINIGRAPH, dest=local_minigraph, flat=True)
    refactor = MinigraphRefactor(TARGET_LEAF)
    refactor.process_minigraph(local_minigraph, local_minigraph)
    duthost.copy(src=local_minigraph, dest=MINIGRAPH)

    # Step 3: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)

    # Step 3.1 check corresponding tables in CONFIG_DB, if not, create them by mini patch.
    check_tables = ["BGP_NEIGHBOR", "PFC_WD", "CABLE_LENGTH", "BUFFER_PG", "PORT_QOS_MAP", "DEVICE_NEIGHBOR_METADATA"]
    logger.info(f"Checking and creating tables: {check_tables}")
    create_table_if_not_exist(duthost, check_tables)

    # Step 4: Apply addcluster.json
    logger.info("Applying addcluster.json patch")
    with open(ADDCLUSTER_FILE) as file:
        json_patch = json.load(file)
    tmpfile = generate_tmpfile(duthost)
    try:
        apply_patch_result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if apply_patch_result['rc'] != 0 or "Patch applied successfully" not in apply_patch_result['stdout']:
            pytest.fail(f"Failed to apply patch: {apply_patch_result['stdout']}")
    finally:
        delete_tmpfile(duthost, tmpfile)

    # Step 5: Check port status
    for port in ["Ethernet16", "Ethernet24"]:
        result = duthost.shell(f"show interface status {port}", module_ignore_errors=False)["stdout"]
        pytest_assert("up" in result, f"{port} is not up")

    # Step 6: Check PortChannel exists
    result = duthost.shell("show interfaces portchannel", module_ignore_errors=False)["stdout"]
    pytest_assert("PortChannel101" in result, "PortChannel101 not found in portchannel list")

    # Step 7: Check BGP session
    result = duthost.shell("show ip bgp summary", module_ignore_errors=False)["stdout"]
    pytest_assert("10.0.0.13" in result and "Estab" in result,
                  "BGP session with 10.0.0.13 not established")

    # Step 8: Verify all addcluster.json changes are reflected in CONFIG_DB
    keys_to_check = [
        # PORT entries
        "PORT|Ethernet16",
        "PORT|Ethernet24",

        # PortChannel entries
        "PORTCHANNEL|PortChannel101",
        "PORTCHANNEL_MEMBER|PortChannel101|Ethernet16",
        "PORTCHANNEL_MEMBER|PortChannel101|Ethernet24",
        "PORTCHANNEL_INTERFACE|PortChannel101",
        "PORTCHANNEL_INTERFACE|PortChannel101|10.0.0.12/31",
        "PORTCHANNEL_INTERFACE|PortChannel101|fc00::19/126",

        # BGP neighbors
        "BGP_NEIGHBOR|10.0.0.13",
        "BGP_NEIGHBOR|fc00::1a",

        # ACL table entries
        "ACL_TABLE|EVERFLOW",
        "ACL_TABLE|EVERFLOWV6",

        # DEVICE_NEIGHBOR_METADATA entries
        "DEVICE_NEIGHBOR_METADATA|Ethernet3~11",
        "DEVICE_NEIGHBOR_METADATA|Ethernet4~11",

        # CABLE_LENGTH entries
        "CABLE_LENGTH|AZURE|Ethernet16",
        "CABLE_LENGTH|AZURE|Ethernet24",

        # BUFFER_PG entries
        "BUFFER_PG|Ethernet16|0",
        "BUFFER_PG|Ethernet16|3-4",
        "BUFFER_PG|Ethernet24|0",
        "BUFFER_PG|Ethernet24|3-4",

        # PORT_QOS_MAP entries
        "PORT_QOS_MAP|Ethernet16",
        "PORT_QOS_MAP|Ethernet24",

        # PFC_WD entries
        "PFC_WD|Ethernet16",
        "PFC_WD|Ethernet24"
    ]

    for key in keys_to_check:
        redis_key = f'sonic-db-cli -n asic0 CONFIG_DB keys "{key}"'
        redis_value = duthost.shell(redis_key, module_ignore_errors=False)['stdout'].strip()
        pytest_assert(redis_value == key,
                      f"Key {key} missing or incorrect in CONFIG_DB. Got: {redis_value}")
