import pytest

from tests.common import reboot
from tests.common.helpers.bgp import BGPNeighbor
from tests.common.dualtor.mux_simulator_control import \
    toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m  # noqa F401
from tests.common.utilities import wait_until, delete_running_config


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.device_type('vs')
]

PEER_COUNT = 1
NEIGHBOR_EXABGP_PORT = 11000


@pytest.fixture(params=["warm", "fast"])
def reboot_type(request):
    return request.param


@pytest.fixture
def slb_neighbor_asn(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """Get the slb neighbor asn based on the deployment id."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    constants_stat = duthost.stat(path="/etc/sonic/constants.yml")
    if constants_stat["stat"]["exists"]:
        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \"constants\
            .deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    else:
        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/deployment_id_asn_map\
            .yml -v \"deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    neighbor_asn = res['stdout'].strip()
    if not neighbor_asn:
        pytest.fail("Failed to retieve asn defined for dynamic neighbors")
    return neighbor_asn


@pytest.fixture
def bgp_slb_neighbor(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup_interfaces, ptfhost, slb_neighbor_asn):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    dut_asn = mg_facts["minigraph_bgp_asn"]

    conn = setup_interfaces[0]
    bgp_neighbor = BGPNeighbor(
        duthost,
        ptfhost,
        "pseudoswitch0",
        conn["neighbor_addr"].split("/")[0],
        slb_neighbor_asn,
        conn["local_addr"].split("/")[0],
        dut_asn,
        NEIGHBOR_EXABGP_PORT,
        "dynamic",
        is_passive=True
    )
    return bgp_neighbor


@pytest.mark.disable_loganalyzer
def test_bgp_slb_neighbor_persistence_across_advanced_reboot(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, bgp_slb_neighbor,
    toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m, reboot_type, localhost     # noqa F811
):

    def verify_bgp_session(duthost, bgp_neighbor):
        """Verify the bgp session to the DUT is established."""
        bgp_facts = duthost.bgp_facts()["ansible_facts"]
        return bgp_neighbor.ip in bgp_facts["bgp_neighbors"] and \
            bgp_facts["bgp_neighbors"][bgp_neighbor.ip]["state"] == "established"

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    neighbor = bgp_slb_neighbor

    try:
        neighbor.start_session()
        if not wait_until(40, 5, 10, verify_bgp_session, duthost, neighbor):
            pytest.fail("dynamic BGP session is not established")
        reboot(duthost, localhost, reboot_type=reboot_type, wait_warmboot_finalizer=True)
        if not wait_until(40, 5, 10, verify_bgp_session, duthost, neighbor):
            pytest.fail("dynamic BGP session is not established after %s" % reboot_type)
    finally:
        neighbor.stop_session()
        delete_slb_json = [{"WARM_RESTART": {}}]
        delete_running_config(delete_slb_json, duthost)
