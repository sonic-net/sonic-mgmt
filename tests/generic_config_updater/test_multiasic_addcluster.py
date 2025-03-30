import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

from process_minigraph import MinigraphRefactor

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

MINIGRAPH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP = "/etc/sonic/minigraph.xml.backup"
TARGET_LEAF = "ARISTA01T1"
ADDCLUSTER_FILE = "/tmp/addcluster.json"


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


def test_addcluster_workflow(duthost):
    # Step 1: Backup minigraph
    logger.info(f"Backing up current minigraph from {MINIGRAPH} to {MINIGRAPH_BACKUP}")
    if not duthost.stat(path=MINIGRAPH)["stat"]["exists"]:
        pytest.fail(f"{MINIGRAPH} not found on DUT")
    duthost.shell(f"sudo cp {MINIGRAPH} {MINIGRAPH_BACKUP}")

    # Step 2: Generate new minigraph without ARISTA01T1
    logger.info(f"Modifying minigraph to remove {TARGET_LEAF}")
    local_tmp = "/tmp/minigraph_modified.xml"
    duthost.fetch(src=MINIGRAPH, dest=local_tmp)
    refactor = MinigraphRefactor(TARGET_LEAF)
    refactor.process_minigraph(local_tmp, local_tmp)
    duthost.copy(src=local_tmp, dest=MINIGRAPH)

    # Step 3: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)

    # Step 4: Apply addcluster.json
    logger.info("Applying addcluster.json patch")
    duthost.copy(src="templates/addcluster.json", dest=ADDCLUSTER_FILE)
    json_patch = json.loads(open("addcluster.json").read())
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

    # Step 8: Verify other config in Redis
    keys_to_check = [
        "PORT|Ethernet16",
        "PORT|Ethernet24",
        "PORTCHANNEL|PortChannel101",
        "PORTCHANNEL_MEMBER|PortChannel101|Ethernet16",
        "PORTCHANNEL_MEMBER|PortChannel101|Ethernet24",
        "BGP_NEIGHBOR|10.0.0.13",
        "BGP_NEIGHBOR|fc00::1a"
    ]
    for key in keys_to_check:
        redis_key = f'sonic-db-cli -n asic0 CONFIG_DB keys "{key}"'
        redis_value = duthost.shell(redis_key, module_ignore_errors=False)['stdout'].strip()
        pytest_assert(redis_value == key,
                      f"Key {key} missing or incorrect in CONFIG_DB. Got: {redis_value}")
