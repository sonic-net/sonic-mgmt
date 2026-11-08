import json
import logging
import os
import shlex
import pytest

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
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
def setup_env(duthost):
    """Restore minigraph, running/startup state, traffic shift and BGP readiness."""
    pytest_assert(not duthost.stat(path=MINIGRAPH_BACKUP)["stat"]["exists"],
                  f"Refusing to overwrite a leftover restoration artifact: {MINIGRAPH_BACKUP}")

    configs = [(None, "config_db.json")]
    if duthost.is_multi_asic:
        asic_ids = duthost.get_asic_ids()
        pytest_assert(asic_ids and all(asic_id is not None for asic_id in asic_ids),
                      "Cannot preserve multi-ASIC configuration without the present ASIC IDs")
        configs.extend((f"asic{asic_id}", f"config_db{asic_id}.json") for asic_id in asic_ids)

    established_bgp_neighbors = duthost.get_bgp_neighbors_per_asic(state="established")

    def get_traffic_shift_states():
        states = {}
        for namespace, _ in configs:
            namespace_arg = f"-n {namespace}" if namespace else ""
            states[namespace] = duthost.shell(
                f'sonic-db-cli {namespace_arg} CONFIG_DB hget "BGP_DEVICE_GLOBAL|STATE" tsa_enabled'
            )["stdout"].strip()
        return states

    traffic_shift_states = get_traffic_shift_states()
    backup_dir = duthost.tempfile(state="directory", prefix="addcluster-restore-")["path"]
    logger.info("Preserving pre-test host and ASIC configurations in %s", backup_dir)
    snapshots = []
    for namespace, filename in configs:
        config_db = f"/etc/sonic/{filename}"
        saved_config = f"{backup_dir}/{filename}"
        running_config = f"{backup_dir}/running_{filename}"
        namespace_arg = f"-n {namespace}" if namespace else ""
        duthost.shell(f"cp -p {config_db} {saved_config}")
        duthost.shell(f"sonic-cfggen {namespace_arg} -d --print-data > {running_config}")
        snapshots.append((config_db, saved_config, running_config))

    try:
        yield
    finally:
        config_reloaded = False
        try:
            if duthost.stat(path=MINIGRAPH_BACKUP)["stat"]["exists"]:
                logger.info("Restoring original minigraph from %s", MINIGRAPH_BACKUP)
                duthost.shell(f"cp -p {MINIGRAPH_BACKUP} {MINIGRAPH}")
                duthost.shell_cmds(
                    cmds=[f"cp {running} {config_db}" for config_db, _, running in snapshots],
                    continue_on_fail=False)
                config_reload(duthost, config_source="config_db", safe_reload=True)
                config_reloaded = True
        finally:
            # Attempt every startup-file restoration even if one copy fails.
            duthost.shell_cmds(
                cmds=[f"cp -p {saved} {config_db}" for config_db, saved, _ in snapshots],
                continue_on_fail=True)

        if config_reloaded:
            # Startup traffic shift can outlast BGP convergence; preserve the original intent.
            logger.info("Waiting for pre-test traffic-shift state after cleanup")
            pytest_assert(
                wait_until(1200, 10, 0, lambda: get_traffic_shift_states() == traffic_shift_states),
                "Pre-test traffic-shift state did not recover after cleanup")
            logger.info("Waiting for pre-test established BGP sessions after cleanup")
            pytest_assert(
                wait_until(300, 10, 0, duthost.check_bgp_session_state_all_asics, established_bgp_neighbors),
                "Pre-test established BGP sessions did not recover after cleanup")

        # Failed restoration keeps both the minigraph backup and private snapshots.
        duthost.file(path=MINIGRAPH_BACKUP, state="absent")
        duthost.file(path=backup_dir, state="absent")


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


def get_port_profiles(duthost, from_minigraph=False):
    """Read port profiles without letting a minigraph render reuse live PORT entries."""
    namespaces = [f"asic{index}" for index in duthost.get_asic_ids()] if duthost.is_multi_asic else [None]
    profiles = {}
    init_config = from_minigraph and duthost.stat(path="/etc/sonic/init_cfg.json")["stat"]["exists"]
    for namespace in namespaces:
        namespace_arg = f"-n {namespace}" if namespace else ""
        source_args = "-d"
        if from_minigraph:
            asic_id = namespace[4:] if namespace else None
            script = ("from sonic_py_common import device_info; "
                      f"print(device_info.get_path_to_port_config_file(None, {asic_id!r}))")
            port_config = duthost.shell("python3 -c " + shlex.quote(script))["stdout"].strip()
            pytest_assert(port_config not in ("", "None"), f"Cannot resolve native port configuration for {namespace}")
            source_args = f"-H -m {MINIGRAPH} -p {shlex.quote(port_config)}"
            if init_config:
                source_args += " -j /etc/sonic/init_cfg.json"
        result = duthost.shell(f"sonic-cfggen {namespace_arg} {source_args} --var-json PORT")
        ports = json.loads(result["stdout"] or "{}")
        profiles[namespace] = {
            port: {field: attributes.get(field) for field in ("lanes", "speed", "alias", "admin_status", "fec")}
            for port, attributes in ports.items()
        }
    return profiles


def port_profile_differences(expected, actual):
    differences = {}
    for namespace in sorted(set(expected) | set(actual), key=str):
        before, after = expected.get(namespace, {}), actual.get(namespace, {})
        changed = {
            port: {"expected": before.get(port), "actual": after.get(port)}
            for port in sorted(set(before) | set(after)) if before.get(port) != after.get(port)
        }
        if changed:
            differences[namespace] = changed
    return differences


def get_minigraph_refactor(target, config, namespace):
    ports = config.get("PORT", {})
    aliases = {port: attributes.get("alias", port) for port, attributes in ports.items()}
    asic_names = {name: attributes["asic_port_name"]
                  for port, attributes in ports.items() if attributes.get("asic_port_name")
                  for name in (port, aliases[port])}
    asic_name = config.get("DEVICE_METADATA", {}).get("localhost", {}).get("asic_name") or namespace
    return MinigraphRefactor(target, port_name_to_alias_map=aliases,
                             asic_port_name_maps={asic_name: asic_names} if asic_name else {})


def target_is_operational(duthost, namespace, ports, peers):
    if not ports or not peers:
        logger.warning("Cannot verify target readiness with empty ports or BGP peers")
        return False
    namespace_arg = f"-n {namespace}" if duthost.is_multi_asic else ""
    port_states = {
        port: duthost.shell(
            f'sonic-db-cli {namespace_arg} APPL_DB hget "PORT_TABLE:{port}" oper_status')["stdout"].strip()
        for port in sorted(ports)
    }
    asic = duthost.asic_instance_from_namespace(namespace if duthost.is_multi_asic else None)
    neighbors = asic.bgp_facts()["ansible_facts"]["bgp_neighbors"]
    peer_states = {peer: neighbors.get(peer, {}).get("state") for peer in sorted(peers)}
    ready = all(state == "up" for state in port_states.values()) and all(
        state == "established" for state in peer_states.values())
    if not ready:
        logger.warning("Target readiness in %s: port oper_status=%s, BGP state=%s",
                       namespace, port_states, peer_states)
    return ready


def verify_mirror_acl_bindings(duthost, namespace, full_config, patches):
    """Compare changed MIRROR bindings in their own ASIC, including PortChannels."""
    tables = full_config[namespace].get("ACL_TABLE", {})
    changed = {
        patch["path"].split("/")[3].replace("~1", "/").replace("~0", "~")
        for patch in patches if patch.get("path", "").startswith(f"/{namespace}/ACL_TABLE/")
    }
    expected = {name: tables[name] for name in changed
                if tables.get(name, {}).get("type") in ("MIRROR", "MIRRORV6")}
    if not expected:
        return
    result = duthost.shell(f"sonic-cfggen -n {namespace} -d --var-json ACL_TABLE")
    actual = json.loads(result["stdout"])
    for name, entry in expected.items():
        restored = actual.get(name, {})
        pytest_assert(
            restored.get("type") == entry["type"]
            and sorted(restored.get("ports", [])) == sorted(entry.get("ports", [])),
            f"MIRROR ACL {namespace}/{name} bindings differ: expected {entry}, got {restored}")


def test_addcluster_workflow(duthost):
    # Pin the healthy target before removing it, not from the intentionally without-T1 state.
    original_config = json.loads(duthost.shell(f"sonic-cfggen -n {ASICID} -d --print-data")["stdout"])
    target_ports = {port for port, neighbor in original_config.get("DEVICE_NEIGHBOR", {}).items()
                    if neighbor.get("name") == TARGET_LEAF}
    target_peers = {ip for ip, neighbor in original_config.get("BGP_NEIGHBOR", {}).items()
                    if neighbor.get("name") == TARGET_LEAF}
    if not target_is_operational(duthost, ASICID, target_ports, target_peers):
        pytest.skip("Target ports and BGP peers must be operational before add-cluster testing")

    original_port_profiles = get_port_profiles(duthost)
    profile_changes = port_profile_differences(original_port_profiles, get_port_profiles(duthost, from_minigraph=True))
    if profile_changes:
        pytest.skip(f"Native minigraph port profiles differ from the working configuration: {profile_changes}")

    # Step 1: Backup minigraph
    logger.info(f"Backing up current minigraph from {MINIGRAPH} to {MINIGRAPH_BACKUP}")
    if not duthost.stat(path=MINIGRAPH)["stat"]["exists"]:
        pytest.fail(f"{MINIGRAPH} not found on DUT")
    duthost.shell(f"sudo cp -p {MINIGRAPH} {MINIGRAPH_BACKUP}")

    # Step 1.1: Reload minigraph
    logger.info("Reloading minigraph and starting BGP through config_reload")
    config_reload(duthost, config_source="minigraph", safe_reload=True)

    profile_changes = port_profile_differences(original_port_profiles, get_port_profiles(duthost))
    pytest_assert(not profile_changes, f"Initial minigraph reload changed working port profiles: {profile_changes}")
    pytest_assert(
        wait_until(300, 10, 0, target_is_operational, duthost, ASICID, target_ports, target_peers),
        "Target ports or BGP peers did not recover after the initial minigraph reload")

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
    refactor = get_minigraph_refactor(TARGET_LEAF, original_config, ASICID)
    success, _ = refactor.process_minigraph(local_minigraph, local_minigraph)
    if not success:
        logger.info(f"Skipping test - testbed topology does not match required conditions for {TARGET_LEAF}")
        pytest.skip(f"Testbed topology does not match required conditions for {TARGET_LEAF}")
    duthost.copy(src=local_minigraph, dest=MINIGRAPH)

    # Step 4: Reload minigraph
    logger.info("Reloading minigraph and starting BGP through config_reload")
    config_reload(duthost, config_source="minigraph", safe_reload=True)

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
    patch_file, = generate_config_patch(full_config_path, no_leaf_config_path)

    # Step 7 check corresponding tables in CONFIG_DB, if not, create them by mini patch.
    check_tables = ["BGP_NEIGHBOR", "CABLE_LENGTH", "BUFFER_PG", "PORT_QOS_MAP", "DEVICE_NEIGHBOR_METADATA"]
    logger.info(f"Checking and creating tables: {check_tables}")
    create_table_if_not_exist(duthost, check_tables)

    # Step 8: Apply addcluster.json
    logger.info("Applying addcluster.json patch")
    with open(patch_file) as file:
        json_patch = json.load(file)
    with open(full_config_path) as file:
        full_config = json.load(file)
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
        'PFC_WD': set(),
        'PORTCHANNEL_MEMBER': set(),
        'DEVICE_NEIGHBOR': set()
    }
    for patch_entry in json_patch:
        path = patch_entry.get('path', '')
        if path.startswith(f'/{ASICID}/PORT/'):
            port = path.split('/')[-1]
            ports_to_check.add(port)
        elif path.startswith(f'/{ASICID}/PORTCHANNEL/'):
            portchannel = path.split('/')[-1]
            portchannels_to_check.add(portchannel)
        elif path.startswith(f'/{ASICID}/PORTCHANNEL_MEMBER/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PORTCHANNEL_MEMBER'].add(f"PORTCHANNEL_MEMBER|{entry}")
        elif path.startswith(f'/{ASICID}/BGP_NEIGHBOR/'):
            neighbor = path.split('/')[-1]
            bgp_neighbors_to_check.add(neighbor)
        elif path.startswith(f'/{ASICID}/DEVICE_NEIGHBOR_METADATA/'):
            entry = path.split('/')[-1]
            config_entries_to_check['DEVICE_NEIGHBOR_METADATA'].add(f"DEVICE_NEIGHBOR_METADATA|{entry}")
        elif path.startswith(f'/{ASICID}/DEVICE_NEIGHBOR/'):
            entry = path.split('/')[-1]
            config_entries_to_check['DEVICE_NEIGHBOR'].add(f"DEVICE_NEIGHBOR|{entry}")
        elif path.startswith(f'/{ASICID}/CABLE_LENGTH/AZURE/'):
            entry = path.split('/')[-1]
            config_entries_to_check['CABLE_LENGTH'].add(f"{entry}")
        elif path.startswith(f'/{ASICID}/BUFFER_PG/'):
            entry = '|'.join(path.split('/')[-2:])
            config_entries_to_check['BUFFER_PG'].add(f"{entry}")
        elif path.startswith(f'/{ASICID}/PORT_QOS_MAP/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PORT_QOS_MAP'].add(f"PORT_QOS_MAP|{entry}")
        elif path.startswith(f'/{ASICID}/PFC_WD/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PFC_WD'].add(f"PFC_WD|{entry}")

    try:
        apply_patch_result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if apply_patch_result['rc'] != 0 or "Patch applied successfully" not in apply_patch_result['stdout']:
            pytest.fail(f"Failed to apply patch: {apply_patch_result['stdout']}")
    finally:
        delete_tmpfile(duthost, tmpfile)

    logger.info("Requiring recovery of %d target ports and %d target BGP peers", len(target_ports), len(target_peers))
    pytest_assert(
        wait_until(300, 10, 0, target_is_operational, duthost, ASICID, target_ports, target_peers),
        "Previously operational target ports or BGP peers did not recover after GCU")

    # Step 9: Check port status dynamically
    if not ports_to_check:
        pytest.fail("No ports found in patch to verify")

    for port in ports_to_check:
        logger.info(f"Checking status for port {port}")
        result = duthost.shell(f"show interface status {port}", module_ignore_errors=False)["stdout"]
        pytest_assert("up" in result, f"{port} is not up")

    # Step 9.1: Check the target ASIC's intended MIRROR bindings, not CLI formatting.
    verify_mirror_acl_bindings(duthost, ASICID, full_config, json_patch)

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
        expected_entries = full_config[ASICID].get(table, {})
        for entry in entries:
            if table == 'CABLE_LENGTH':
                redis_cmd = f'sonic-db-cli -n {ASICID} CONFIG_DB hgetall "CABLE_LENGTH|AZURE"'
                redis_output = duthost.shell(redis_cmd, module_ignore_errors=False)['stdout']
                cable_lengths = json.loads(redis_output.replace("'", '"'))

                expected_present = entry in expected_entries.get('AZURE', {})
                pytest_assert((entry in cable_lengths) == expected_present,
                              f"CABLE_LENGTH entry {entry} presence differs from the original configuration. "
                              f"Expected present: {expected_present}. Got: {cable_lengths}")
            else:
                redis_key = f'sonic-db-cli -n {ASICID} CONFIG_DB keys "{entry}"'
                redis_value = duthost.shell(redis_key, module_ignore_errors=False)['stdout'].strip()
                expected_key = entry if entry.partition('|')[2] in expected_entries else ""
                pytest_assert(redis_value == expected_key,
                              f"Key {entry} presence differs from the original configuration. "
                              f"Expected: {expected_key!r}. Got: {redis_value!r}")
                logger.info("Verified %s is %s in CONFIG_DB", entry, "present" if expected_key else "absent")

    # Step 13: capture full running configuration after applying addcluster.json
    logger.info("Capturing applied full running configuration")
    dut_config_path = "/tmp/applied.json"
    applied_config_path = os.path.join(THIS_DIR, "backup", f"{duthost.hostname}-applied.json")
    os.makedirs(os.path.dirname(applied_config_path), exist_ok=True)
    duthost.shell(f"show runningconfiguration all > {dut_config_path}")

    duthost.fetch(src=dut_config_path, dest=applied_config_path, flat=True)
    logger.info(f"Saved applied full configuration backup to {applied_config_path}")
    duthost.shell(f"rm -f {dut_config_path}")

    # Step 14: Compare full configuration before and after applying addcluster.json
    logger.info("Comparing specific tables before and after applying addcluster.json")

    def get_table_data(config, table):
        """Extract table data from config."""
        table_data = config.get(ASICID, {}).get(table, {})
        if table == 'ACL_TABLE':
            # Appended bindings may change order; sorting preserves duplicate detection.
            return {
                name: {**entry, 'ports': sorted(entry['ports'])} if 'ports' in entry else entry
                for name, entry in table_data.items()
            }
        return table_data

    # Get list of tables to compare from the patch
    tables_to_compare = set()
    for patch_entry in json_patch:
        path = patch_entry.get('path', '')
        parts = path.split('/')
        if len(parts) > 2:
            tables_to_compare.add(parts[2])

    # Load configurations
    with open(applied_config_path, 'r') as file:
        applied_config = json.load(file)

    # Compare only modified tables
    for table in tables_to_compare:
        logger.info(f"Comparing table: {table}")
        original_table = get_table_data(full_config, table)
        applied_table = get_table_data(applied_config, table)

        if original_table != applied_table:
            logger.error(f"Table {table} mismatch:")
            logger.error(f"Original: {original_table}")
            logger.error(f"Applied:  {applied_table}")
            pytest.fail(f"Configuration mismatch in table {table}")
        else:
            logger.info(f"Table {table} matches between configurations")
