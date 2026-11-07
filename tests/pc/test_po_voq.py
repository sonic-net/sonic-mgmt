import pytest
import random
import tests.common.helpers.voq_lag as voq_lag
from tests.common.devices.eos import EosHost
from tests.common.helpers.voq_helpers import verify_no_routes_from_nexthop
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import logging
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2', 'lrh', 'urh')
]


def _get_random_asic_with_pc(duthost):
    """Returns a random ASIC with portchannel from given duthost

    Args:
        duthost: A duthost object to probe ASICs

    Returns:
        asic: Random ASIC with PC from the duthost
    """
    asics_with_pc = []
    for asic in duthost.asics:
        config_facts = duthost.config_facts(source='persistent',
                                            asic_index=asic.asic_index)['ansible_facts']
        if 'PORTCHANNEL' in config_facts:
            asics_with_pc.append(asic)

    if asics_with_pc:
        return random.choice(asics_with_pc)
    else:
        pytest.fail("{} has no ASICs with portchannels".format(duthost))


@pytest.fixture(scope='module')
def setup_teardown(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Setup:
    Create a temporary test portchannel, moves members and IP from an existing portchannel
    to the temporary test portchannel

    Teardown:
    Moves members from temporary test portchannel back to the original portchannel,
    deletes temporary test portchannel

    Yields:
        (asic: ASIC that hosts the portchannel,
        portchannel_ip: portchannel ip address,
        portchannel_members: portchannel members)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    candidates = []
    for candidate_asic in duthost.asics:
        candidate_facts = duthost.config_facts(source='persistent',
                                               asic_index=candidate_asic.asic_index)['ansible_facts']
        for name, portchannel_config in candidate_facts.get('PORTCHANNEL', {}).items():
            members = portchannel_config.get('members') or []
            if len(members) > 1:
                candidates.append((candidate_asic, candidate_facts, name, members))
    if not candidates:
        pytest.fail("{} has no PortChannel with at least two members".format(duthost))
    asic, config_facts, portchannel, portchannel_members = random.choice(candidates)

    portchannel_ip = None
    if 'PORTCHANNEL_INTERFACE' in config_facts:
        portchannel_ips = list(config_facts['PORTCHANNEL_INTERFACE'][portchannel].keys())
        for ip in portchannel_ips:
            if '.' in ip:
                portchannel_ip = ip

    for addr in config_facts['BGP_NEIGHBOR']:
        if portchannel_ip.split('/')[0] == config_facts['BGP_NEIGHBOR'][addr]['local_addr']:
            nbr_addr = addr

    # Move members and IP from original lag to newly created temporary lag
    logging.info("Moving LAG members {} and IP {} from LAG {} to temporary LAG {}"
                 .format(portchannel_members, portchannel_ip, portchannel, voq_lag.TMP_PC))
    asic.config_ip_intf(portchannel, portchannel_ip, "remove")
    for portchannel_member in portchannel_members:
        asic.config_portchannel_member(portchannel, portchannel_member, "del")

    verify_no_routes_from_nexthop(duthosts, nbr_addr)

    asic.config_portchannel(voq_lag.TMP_PC, "add")
    asic.config_ip_intf(voq_lag.TMP_PC, portchannel_ip, "add")
    for portchannel_member in portchannel_members:
        asic.config_portchannel_member(voq_lag.TMP_PC, portchannel_member, "add")

    yield asic, portchannel_ip, portchannel_members

    # Move members and IP from new temporary LAG back to original lag, delete old LAG
    logging.info("Moving LAG members {} and IP {} from temporary LAG {} back to LAG {}"
                 .format(portchannel_members, portchannel_ip, portchannel, voq_lag.TMP_PC))
    asic.config_ip_intf(voq_lag.TMP_PC, portchannel_ip, "remove")
    for portchannel_member in portchannel_members:
        asic.config_portchannel_member(voq_lag.TMP_PC, portchannel_member, "del")
    asic.config_portchannel(voq_lag.TMP_PC, "del")

    verify_no_routes_from_nexthop(duthosts, nbr_addr)

    asic.config_ip_intf(portchannel, portchannel_ip, "add")
    for portchannel_member in portchannel_members:
        asic.config_portchannel_member(portchannel, portchannel_member, "add")


@pytest.fixture(scope="module")
def single_member_peer(setup_teardown, duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts, tbinfo):
    """Keep the EOS peer LAG operational with one member, then restore its policy."""
    _, _, members = setup_teardown
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    neighbors = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_neighbors"]
    peer_names = {neighbors[member]["name"] for member in members}
    pytest_assert(len(peer_names) == 1, "LAG members must connect to the same neighbor")
    peer = nbrhosts[peer_names.pop()]["host"]
    if not isinstance(peer, EosHost):
        logger.info("Leaving non-EOS neighbor policy unchanged")
        yield
        return

    peer_lag = peer.get_portchannel_by_member(neighbors[members[0]]["port"])
    pytest_assert(peer_lag, "Could not determine the peer LAG for {}".format(members))
    parent = ["interface {}".format(peer_lag)]
    running_config = peer.eos_command(commands=["show running-config interfaces {}".format(peer_lag)])["stdout"][0]
    original = [line.strip() for line in running_config.splitlines()
                if line.strip().startswith("port-channel min-links ")]
    pytest_assert(len(original) <= 1, "Ambiguous peer min-links configuration: {}".format(original))
    if not original or int(original[0].split()[-1]) == 1:
        yield
        return

    logger.info("Temporarily setting %s on %s to min-links 1; restoring %s afterward",
                peer_lag, peer.hostname, original)
    try:
        peer.eos_config(lines=["port-channel min-links 1"], parents=parent)
        yield
    finally:
        peer.eos_config(lines=original, parents=parent)


def test_voq_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Test to verify when a LAG is added/deleted via CLI, it is synced across all DBs

    All DBs = local app db, chassis app db, local & remote asic db
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    asic = _get_random_asic_with_pc(duthost)
    prev_lag_id_list = voq_lag.get_lag_ids_from_chassis_db(duthosts)
    try:
        # Add LAG and verify LAG creation is synced across all DBs
        logging.info("Add temporary LAG {}".format(voq_lag.TMP_PC))
        asic.config_portchannel(voq_lag.TMP_PC, "add")

        # Verify LAG is created with unique LAG ID in chassis db
        tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
        pytest_assert(tmp_lag_id not in prev_lag_id_list, "Temporary PC LAG ID {} is not unique")

        voq_lag.verify_lag_in_app_db(asic)
        voq_lag.verify_lag_in_chassis_db(duthosts)
        voq_lag.verify_lag_id_in_asic_dbs(duthost.asics, tmp_lag_id)
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_id_in_asic_dbs(remote_duthost.asics, tmp_lag_id)

        # Delete LAG and verify LAG deletion is synced across all DBs
        logging.info("Deleting temporary LAG {}".format(voq_lag.TMP_PC))
        asic.config_portchannel(voq_lag.TMP_PC, "del")

        voq_lag.verify_lag_in_app_db(asic, expected=False)
        voq_lag.verify_lag_in_chassis_db(duthosts, expected=False)
        voq_lag.verify_lag_id_in_asic_dbs(duthost.asics, tmp_lag_id, expected=False)
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_id_in_asic_dbs(remote_duthost.asics, tmp_lag_id, expected=False)
    finally:
        if voq_lag.is_lag_in_app_db(asic):
            logging.info("Deleting temporary LAG {}".format(voq_lag.TMP_PC))
            asic.config_portchannel(voq_lag.TMP_PC, "del")


def test_voq_po_member_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup_teardown):
    """Test to verify when LAG members are added/deleted via CLI, it is synced across all DBs

    All DBs = local app db, chassis app db, local & remote asic db
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    asic, portchannel_ip, portchannel_members = setup_teardown
    tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)

    # Check that members added to LAG in setup is synced across all DBs
    for portchannel_member in portchannel_members:
        voq_lag.verify_lag_member_in_app_db(asic, portchannel_member)
        voq_lag.verify_lag_member_in_chassis_db(duthosts, portchannel_member)
    # For checking LAG member added/deleted in ASIC_DB,
    # we check how many members exist in a LAG since we can't identify individual members
    voq_lag.verify_lag_member_in_asic_db(duthost.asics, tmp_lag_id, expected=len(portchannel_members))
    for remote_duthost in remote_duthosts:
        voq_lag.verify_lag_member_in_asic_db(remote_duthost.asics, tmp_lag_id, expected=len(portchannel_members))

    # Choose a random LAG member to delete, verify deletion is synced across all DBs
    del_pc_member = random.choice(portchannel_members)
    remaining_pc_members = [pc_member for pc_member in portchannel_members if pc_member != del_pc_member]
    try:
        logging.info("Deleting LAG member {} from {}".format(del_pc_member, voq_lag.TMP_PC))
        asic.config_portchannel_member(voq_lag.TMP_PC, del_pc_member, "del")

        # Verify other LAG members are still up
        for remaining_pc_member in remaining_pc_members:
            voq_lag.verify_lag_member_in_app_db(asic, remaining_pc_member)
            voq_lag.verify_lag_member_in_chassis_db(duthosts, remaining_pc_member)

        voq_lag.verify_lag_member_in_app_db(asic, del_pc_member, expected=False)
        voq_lag.verify_lag_member_in_chassis_db(duthosts, del_pc_member, expected=False)
        voq_lag.verify_lag_member_in_asic_db(duthost.asics, tmp_lag_id, expected=len(remaining_pc_members))
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_member_in_asic_db(remote_duthost.asics, tmp_lag_id, expected=len(remaining_pc_members))
    finally:
        logging.info("Adding LAG member {} back to {}".format(del_pc_member, voq_lag.TMP_PC))
        asic.config_portchannel_member(voq_lag.TMP_PC, del_pc_member, "add")


def _lag_members_fully_reenabled(duthost, duthosts, remote_duthosts, asic, tmp_lag_id, pc_members):
    """Retry state mismatches without suppressing interruptions or command failures."""
    try:
        for pc_member in pc_members:
            voq_lag.verify_lag_member_status_in_app_db(asic, pc_member, enabled=True)
            voq_lag.verify_lag_member_status_in_chassis_db(duthosts, pc_member, enabled=True)
        voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=0)
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=0)
    except (AssertionError, pytest.fail.Exception) as error:
        logger.info("LAG members have not converged to enabled: %s", error)
        return False
    return True


def _lag_member_down_state_synced(duthost, duthosts, remote_duthosts, asic, tmp_lag_id,
                                  up_pc_members, down_pc_member):
    """Non-raising check that a single LAG member's disabled state (and the other
    members' enabled state) is synced across app/chassis/asic DB on every ASIC,
    including remote chassis ASICs.

    The chassis-wide propagation of a single-member disable event to remote
    ASIC_DBs is asynchronous; checking it with a single immediate assertion (as
    opposed to the physical-link-state check just above, which already polls) can
    race and produce a false "found N disabled, expected 1" failure. Wrap the
    checks here so they can be retried via wait_until().
    """
    try:
        for up_pc_member in up_pc_members:
            voq_lag.verify_lag_member_status_in_app_db(asic, up_pc_member, enabled=True)
            voq_lag.verify_lag_member_status_in_chassis_db(duthosts, up_pc_member, enabled=True)
        voq_lag.verify_lag_member_status_in_app_db(asic, down_pc_member, enabled=False)
        voq_lag.verify_lag_member_status_in_chassis_db(duthosts, down_pc_member, enabled=False)
        voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=1)
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=1)
    except (AssertionError, pytest.fail.Exception) as error:
        logger.info("LAG member disable state has not converged: %s", error)
        return False
    return True


def test_voq_po_down_via_cli_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup_teardown):
    """Test to verify when a LAG goes down on an ASIC via CLI, it is synced across all DBs

    All DBs = local app db, chassis app db, local & remote asic db
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    asic, portchannel_ip, portchannel_members = setup_teardown
    tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)
    num_portchannels = len(portchannel_members)

    # Make sure LAG is up across all DBs (all PC members are up across all DBs)
    for portchannel_member in portchannel_members:
        voq_lag.verify_lag_member_status_in_app_db(asic, portchannel_member, enabled=True)
        voq_lag.verify_lag_member_status_in_chassis_db(duthosts, portchannel_member, enabled=True)
    # For checking LAG member status in ASIC_DB,
    # we check how many members are disabled in a LAG since we can't identify individual members
    voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=0)
    for remote_duthost in remote_duthosts:
        voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=0)

    try:
        # Bring down LAG, check that LAG down is synced across all DBs (all PC members are down across all DBs)
        logging.info("Disabling {}".format(voq_lag.TMP_PC))
        duthost.shell("config interface {} shutdown {}".format(asic.cli_ns_option, voq_lag.TMP_PC))
        pytest_assert(wait_until(30, 5, 0, lambda: not duthost.check_intf_link_state(voq_lag.TMP_PC)),
                      "{} is not disabled".format(voq_lag.TMP_PC))

        for portchannel_member in portchannel_members:
            voq_lag.verify_lag_member_status_in_app_db(asic, portchannel_member, enabled=False)
            voq_lag.verify_lag_member_status_in_chassis_db(duthosts, portchannel_member, enabled=False)
        voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=num_portchannels)
        for remote_duthost in remote_duthosts:
            voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=num_portchannels)
    finally:
        # Bring LAG back up
        logging.info("Enabling {}".format(voq_lag.TMP_PC))
        duthost.shell("config interface {} startup {}".format(asic.cli_ns_option, voq_lag.TMP_PC))
        pytest_assert(wait_until(30, 5, 0, lambda: duthost.check_intf_link_state(voq_lag.TMP_PC)),
                      "{} is not enabled".format(voq_lag.TMP_PC))

        # Physical link-up does not guarantee the re-enabled LAG-member state has
        # propagated through app/chassis/asic DB yet. Without waiting for that here,
        # the next test in this module (which shares this module-scoped fixture) can
        # start while a member is still shown disabled in a DB, causing a spurious
        # failure on its own precondition check.
        pytest_assert(
            wait_until(180, 20, 0, lambda: _lag_members_fully_reenabled(
                duthost, duthosts, remote_duthosts, asic, tmp_lag_id, portchannel_members)),
            "LAG members did not sync back to enabled across all DBs")


@pytest.mark.parametrize("flap_method", ["local", "remote"])
def test_voq_po_member_down_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                   setup_teardown, single_member_peer, fanouthosts, flap_method):
    """
    Test to verify when a LAG member goes down on an ASIC, it is synced across all DBs

    All DBs = local app db, chassis app db, local & remote asic db
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    remote_duthosts = [dut_host for dut_host in duthosts.frontend_nodes if dut_host != duthost]
    asic, portchannel_ip, portchannel_members = setup_teardown
    tmp_lag_id = voq_lag.get_lag_id_from_chassis_db(duthosts)

    # Make sure LAG is up across all DBs (all PC members are up across all DBs)
    for portchannel_member in portchannel_members:
        voq_lag.verify_lag_member_status_in_app_db(asic, portchannel_member, enabled=True)
        voq_lag.verify_lag_member_status_in_chassis_db(duthosts, portchannel_member, enabled=True)
    # For checking LAG member status in ASIC_DB,
    # we check how many members are disabled in a LAG since we can't identify individual members
    voq_lag.verify_lag_member_status_in_asic_db(duthost.asics, tmp_lag_id, exp_disabled=0)
    for remote_duthost in remote_duthosts:
        voq_lag.verify_lag_member_status_in_asic_db(remote_duthost.asics, tmp_lag_id, exp_disabled=0)

    # Choose a random LAG member to bring down, check that LAG member down is synced across all DBs
    down_pc_member = random.choice(portchannel_members)
    fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, down_pc_member)
    up_pc_members = [pc_member for pc_member in portchannel_members if pc_member != down_pc_member]
    try:
        if flap_method == "local":
            logging.info("Disabling {} via CLI".format(down_pc_member))
            duthost.shell("config interface {} shutdown {}".format(asic.cli_ns_option, down_pc_member))
        else:
            logging.info("Disabling {} via fanout to simulate external flapping".format(down_pc_member))
            logging.info("Disabling {} on {}".format(fanout_port, fanout.hostname))
            fanout.shutdown(fanout_port)

        pytest_assert(wait_until(30, 5, 0, lambda: not duthost.check_intf_link_state(down_pc_member)),
                      "{} is not disabled".format(down_pc_member))

        # Verify other LAG members are still up, and the down member is down, across
        # all DBs on all ASICs (including remote chassis ASICs). Retry: a single
        # member's disable event can take a moment to propagate chassis-wide.
        pytest_assert(
            wait_until(180, 20, 0, lambda: _lag_member_down_state_synced(
                duthost, duthosts, remote_duthosts, asic, tmp_lag_id, up_pc_members, down_pc_member)),
            "{} LAG member disable state did not sync across all DBs".format(down_pc_member))
    finally:
        # Bring LAG member back up
        if flap_method == "local":
            logging.info("Enabling {} via CLI".format(down_pc_member))
            duthost.shell("config interface {} startup {}".format(asic.cli_ns_option, down_pc_member))
        else:
            logging.info("Enabling {} via fanout".format(down_pc_member))
            logging.info("Enabling {} on {}".format(fanout_port, fanout.hostname))
            fanout.no_shutdown(fanout_port)

        pytest_assert(wait_until(30, 5, 0, lambda: duthost.check_intf_link_state(down_pc_member)),
                      "{} is not enabled".format(down_pc_member))

        # Physical link-up does not guarantee the re-enabled LAG-member state has
        # propagated through app/chassis/asic DB yet. Without waiting for that here,
        # the next parametrized case (e.g. flap_method="remote" run right after
        # flap_method="local") can start while a member is still shown disabled in
        # a DB, causing a spurious failure on its own precondition check.
        pytest_assert(
            wait_until(180, 20, 0, lambda: _lag_members_fully_reenabled(
                duthost, duthosts, remote_duthosts, asic, tmp_lag_id, portchannel_members)),
            "LAG members did not sync back to enabled across all DBs")
