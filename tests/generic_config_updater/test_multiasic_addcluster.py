import json
import logging
import os
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until
from tests.generic_config_updater.util.generate_patch import generate_config_patch

from .util.process_minigraph import MinigraphRefactor

pytestmark = [
    pytest.mark.topology('t2'),
]

logger = logging.getLogger(__name__)

MINIGRAPH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP = "/etc/sonic/minigraph.xml.backup"
TARGET_LEAF = "ARISTA01T1"
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(THIS_DIR, "templates")
ADDCLUSTER_FILE = os.path.join(TEMPLATES_DIR, "addcluster.json")
ASICID = "asic0"


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
        result = duthost.shell(f"sonic-db-cli -n {ASICID} CONFIG_DB keys '{table}|*'")["stdout"]
        if not result:
            logger.info(f"Table {table} does not exist, creating it")
            json_patch = [
                {
                    "op": "add",
                    "path": "/{}/{}".format(ASICID, table),
                    "value": {}
                }
            ]
            tmpfile = generate_tmpfile(duthost)
            try:
                apply_patch_result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
                if (apply_patch_result['rc'] != 0 or
                        "Patch applied successfully"not in apply_patch_result['stdout']):
                    pytest.fail(f"Failed to apply patch: {apply_patch_result['stdout']}")
            finally:
                delete_tmpfile(duthost, tmpfile)


def test_addcluster_workflow(duthost):
    # Step 1: Backup minigraph
    logger.info(f"Backing up current minigraph from {MINIGRAPH} to {MINIGRAPH_BACKUP}")
    if not duthost.stat(path=MINIGRAPH)["stat"]["exists"]:
        pytest.fail(f"{MINIGRAPH} not found on DUT")
    duthost.shell(f"sudo cp {MINIGRAPH} {MINIGRAPH_BACKUP}")

    # Step 1.1: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        pytest.fail("Critical services not fully started after minigraph reload")

    # Step 2: Capture full running configuration
    logger.info("Capturing full running configuration")
    dut_config_path = "/tmp/all.json"
    full_config_path = os.path.join(THIS_DIR, "backup", f"{duthost.hostname}-all.json")
    os.makedirs(os.path.dirname(full_config_path), exist_ok=True)
    duthost.shell(f"show runningconfiguration all > {dut_config_path}")

    duthost.fetch(src=dut_config_path, dest=full_config_path, flat=True)
    logger.info(f"Saved full configuration backup to {full_config_path}")
    duthost.shell(f"rm -f {dut_config_path}")

    # Step 3: Modify minigraph to remove TARGET_LEAF
    logger.info(f"Modifying minigraph to remove {TARGET_LEAF}")
    local_dir = "/tmp/minigraph_modified"
    local_minigraph = os.path.join(local_dir, f"{duthost.hostname}-minigraph.xml")
    duthost.fetch(src=MINIGRAPH, dest=local_minigraph, flat=True)
    refactor = MinigraphRefactor(TARGET_LEAF)
    if not refactor.process_minigraph(local_minigraph, local_minigraph):
        logger.info(f"Skipping test - testbed topology does not match required conditions for {TARGET_LEAF}")
        pytest.skip(f"Testbed topology does not match required conditions for {TARGET_LEAF}")
    duthost.copy(src=local_minigraph, dest=MINIGRAPH)

    # Step 4: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        pytest.fail("Critical services not fully started after minigraph reload")

    # Step 5: Capture full running configuration without TARGET_LEAF
    logger.info("Capturing full running configuration without TARGET_LEAF")
    dut_config_path = "/tmp/all-no-leaf.json"
    no_leaf_config_path = os.path.join(THIS_DIR, "backup", f"{duthost.hostname}-all-no-leaf.json")
    os.makedirs(os.path.dirname(no_leaf_config_path), exist_ok=True)
    duthost.shell(f"show runningconfiguration all > {dut_config_path}")

    duthost.fetch(src=dut_config_path, dest=no_leaf_config_path, flat=True)
    logger.info(f"Saved full configuration without TARGET_LEAF backup to {no_leaf_config_path}")
    duthost.shell(f"rm -f {dut_config_path}")

    # step 6: Generate patch file
    logger.info("Generating patch file")
    patch_file = generate_config_patch(full_config_path, no_leaf_config_path)

    # Step 7 check corresponding tables in CONFIG_DB, if not, create them by mini patch.
    check_tables = ["BGP_NEIGHBOR", "CABLE_LENGTH", "BUFFER_PG", "PORT_QOS_MAP", "DEVICE_NEIGHBOR_METADATA"]
    logger.info(f"Checking and creating tables: {check_tables}")
    create_table_if_not_exist(duthost, check_tables)

    # Step 8: Apply addcluster.json
    logger.info("Applying addcluster.json patch")
    with open(patch_file) as file:
        json_patch = json.load(file)
    tmpfile = generate_tmpfile(duthost)

    # Extract information to check from patch
    ports_to_check = set()
    portchannels_to_check = set()
    bgp_neighbors_to_check = set()
    config_entries_to_check = {
        'DEVICE_NEIGHBOR_METADATA': set(),
        'CABLE_LENGTH': set(),
        'BUFFER_PG': set(),
        'PORT_QOS_MAP': set(),
        'PFC_WD': set()
    }
    for patch_entry in json_patch:
        path = patch_entry.get('path', '')
        if path.startswith('/{ASICID}/PORT/'):
            port = path.split('/')[-1]
            ports_to_check.add(port)
        elif path.startswith('/{ASICID}/PORTCHANNEL/'):
            portchannel = path.split('/')[-1]
            portchannels_to_check.add(portchannel)
        elif path.startswith('/{ASICID}/BGP_NEIGHBOR/'):
            neighbor = path.split('/')[-1]
            bgp_neighbors_to_check.add(neighbor)
        # Extract other configuration entries
        elif path.startswith('/{ASICID}/DEVICE_NEIGHBOR_METADATA/'):
            entry = path.split('/')[-1]
            config_entries_to_check['DEVICE_NEIGHBOR_METADATA'].add(f"DEVICE_NEIGHBOR_METADATA|{entry}")
        elif path.startswith('/{ASICID}/CABLE_LENGTH/AZURE/'):
            entry = path.split('/')[-1]
            config_entries_to_check['CABLE_LENGTH'].add(f"CABLE_LENGTH|AZURE|{entry}")
        elif path.startswith('/{ASICID}/BUFFER_PG/'):
            entry = '|'.join(path.split('/')[-2:])
            config_entries_to_check['BUFFER_PG'].add(f"BUFFER_PG|{entry}")
        elif path.startswith('/{ASICID}/PORT_QOS_MAP/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PORT_QOS_MAP'].add(f"PORT_QOS_MAP|{entry}")
        elif path.startswith('/{ASICID}/PFC_WD/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PFC_WD'].add(f"PFC_WD|{entry}")

    try:
        apply_patch_result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if apply_patch_result['rc'] != 0 or "Patch applied successfully" not in apply_patch_result['stdout']:
            pytest.fail(f"Failed to apply patch: {apply_patch_result['stdout']}")
    finally:
        delete_tmpfile(duthost, tmpfile)

    # Step 9: Check port status dynamically
    if not ports_to_check:
        pytest.fail("No ports found in patch to verify")

    for port in ports_to_check:
        logger.info(f"Checking status for port {port}")
        result = duthost.shell(f"show interface status {port}", module_ignore_errors=False)["stdout"]
        pytest_assert("up" in result, f"{port} is not up")

    # Step 10: Check PortChannel exists
    if portchannels_to_check:
        result = duthost.shell(f"show interfaces portchannel -n {ASICID}", module_ignore_errors=False)["stdout"]
        for portchannel in portchannels_to_check:
            logger.info(f"Checking portchannel {portchannel}")

            # First check if portchannel exists
            pytest_assert(portchannel in result, f"{portchannel} not found in portchannel list")

            # Parse the output to check status
            for line in result.splitlines():
                if portchannel in line:
                    # Check if status is LACP(A)(Up)
                    pytest_assert("LACP(A)(Up)" in line,
                                  f"{portchannel} is not up. Current status: {line}")
                    break

    # Step 11: Check BGP sessions
    if bgp_neighbors_to_check:
        # Check IPv4 BGP sessions
        result_v4 = duthost.shell(f"show ip bgp summary -n {ASICID}", module_ignore_errors=False)["stdout"]
        # Check IPv6 BGP sessions
        result_v6 = duthost.shell(f"show ipv6 bgp summary -n {ASICID}", module_ignore_errors=False)["stdout"]

        def check_bgp_status(output, neighbor):
            """Helper function to check BGP neighbor status.

            Example output format:
            admin@bjw-can-7250-lc2-1:~$ show ip bgp sum -n asic0

            IPv4 Unicast Summary:
            asic0: BGP router identifier 192.0.0.6, local AS number 65100 vrf-id 0
            BGP table version 26
            RIB entries 27, using 6048 bytes of memory
            Peers 5, using 3709880 KiB of memory
            Peer groups 4, using 256 bytes of memory

            Neighbhor   V   AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd Neightbor
            --------- --- ---- -------- -------- ------- ---- ----- -------- ------------- ---------
            10.0.0.13   4  65000   0        0        0     0     0   never    Idle (Admin) ARISTA01T1
            10.0.0.17   4  65001   0        0        0     0     0   never    Idle (Admin) ARISTA03T1

            Total number of neighbors 2
            """
            for line in output.splitlines():
                if neighbor in line:
                    # Split line into fields
                    fields = line.strip().split()
                    if len(fields) >= 10:
                        state = fields[9]  # State/PfxRcd field
                        # Check if state is a number (indicating received prefixes)
                        if state.isdigit() and int(state) > 0:
                            logger.info(f"BGP neighbor {neighbor} is established with {state} prefixes")
                            return True
                    logger.error(f"BGP neighbor {neighbor} not established. Status line: {line}")
                    return False
            logger.error(f"BGP neighbor {neighbor} not found in output")
            return False

        for neighbor in bgp_neighbors_to_check:
            logger.info(f"Checking BGP neighbor {neighbor}")
            if ':' in neighbor:  # IPv6 address
                pytest_assert(check_bgp_status(result_v6, neighbor),
                              f"IPv6 BGP session with {neighbor} not established")
            else:  # IPv4 address
                pytest_assert(check_bgp_status(result_v4, neighbor),
                              f"IPv4 BGP session with {neighbor} not established")

    # Step 12: Verify all addcluster.json changes are reflected in CONFIG_DB
    for table, entries in config_entries_to_check.items():
        for entry in entries:
            redis_key = f'sonic-db-cli -n {ASICID} CONFIG_DB keys "{entry}"'
            redis_value = duthost.shell(redis_key, module_ignore_errors=False)['stdout'].strip()
            pytest_assert(redis_value == entry,
                          f"Key {entry} missing or incorrect in CONFIG_DB. Got: {redis_value}")
            logger.info(f"Verified {entry} exists in CONFIG_DB")
