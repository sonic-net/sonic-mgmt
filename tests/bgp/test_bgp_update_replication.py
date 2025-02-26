import pytest
import logging

from tests.common.helpers.bgp import BGPNeighbor
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.bgp.test_bgp_update_timer import is_neighbor_sessions_established

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Fixture params
PEER_COUNT = 33
WAIT_TIMEOUT = 120

# General constants
ASN_BASE = 61000
PORT_BASE = 11000


'''
    Helper functions
'''


@pytest.fixture
def setup_bgp_peers(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    tbinfo,
    ptfhost,
    setup_interfaces,
    is_dualtor,
    is_quagga
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    dut_asn = mg_facts["minigraph_bgp_asn"]
    dut_type = mg_facts["minigraph_devices"][duthost.hostname]["type"]
    neigh_type = "LeafRouter" if dut_type in ["ToRRouter", "SpineRouter", "BackEndToRRouter"] else "ToRRouter"

    # Establish 33 peers - 1 route injector, 32 receivers
    connections = setup_interfaces
    bgp_peers: list[BGPNeighbor] = []

    # Validate that the expected number of connections were established
    pytest_assert(
        len(connections) == PEER_COUNT,
        f"Incorrect number of bgp peers established: {len(bgp_peers)} exist, {PEER_COUNT} expected"
    )

    # Validate that all connection namespaces are the same
    connection_ns_set = {connection.get("namespace") for connection in connections}
    pytest_assert(
        len(connection_ns_set) == 1,
        f"Multiple namespaces present: {connection_ns_set}"
    )

    for i, connection in enumerate(connections):
        peer_asn = ASN_BASE + i
        peer_port = PORT_BASE + i
        connection_namespace = connection.get("namespace", DEFAULT_NAMESPACE)

        peer = BGPNeighbor(
            duthost=duthost,
            ptfhost=ptfhost,
            name=f"peer{i}",
            neighbor_ip=connection["neighbor_addr"].split("/")[0],
            neighbor_asn=peer_asn,
            dut_ip=connection["local_addr"].split("/")[0],
            dut_asn=dut_asn,
            port=peer_port,
            neigh_type=neigh_type,
            namespace=connection_namespace,
            is_multihop=is_quagga or is_dualtor,
            is_passive=False
        )

        bgp_peers.append(peer)

    # Start sessions
    for peer in bgp_peers:
        peer.start_session()

    yield bgp_peers

    # TODO: Finish teardown
    # End sessions
    for peer in bgp_peers:
        peer.stop_session()


'''
    Tests
'''


def test_bgp_update_replication(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    setup_bgp_peers,
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bgp_peers: list[BGPNeighbor] = setup_bgp_peers

    # Ensure new sessions are ready
    if not wait_until(
        WAIT_TIMEOUT,
        5,
        20,
        lambda: is_neighbor_sessions_established(duthost, bgp_peers),
    ):
        pytest.fail(f"Could not establish the following bgp sessions: {bgp_peers}")

    # Extract injector and receivers
    route_injector = bgp_peers[0]
    route_receivers = bgp_peers[1:PEER_COUNT]

    logger.info(f"Route injector: '{route_injector}', route receivers: '{route_receivers}'")
