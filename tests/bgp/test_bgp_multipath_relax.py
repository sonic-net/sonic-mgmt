import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t1')
]

logger = logging.getLogger(__name__)


def get_t2_neigh(tbinfo):
    dut_t2_neigh = []
    for vm in list(tbinfo['topo']['properties']['topology']['VMs'].keys()):
        if 'T2' in vm:
            dut_t2_neigh.append(vm)
    return dut_t2_neigh


def get_t0_neigh(tbinfo, topo_config):
    """
    get all t0 router names which has vips defined
    """
    dut_t0_neigh = []
    for vm in list(tbinfo['topo']['properties']['topology']['VMs'].keys()):
        if 'T0' in vm:
            if 'vips' in topo_config[vm]:
                dut_t0_neigh.append(vm)
    return dut_t0_neigh


def get_vips_prefix(dut_t0_neigh, topo_config):
    vips_prefixes = []

    # find all vips prefixes
    for neigh in dut_t0_neigh:
        prefixes = topo_config[neigh]['vips']['ipv4']['prefixes']
        for prefix in prefixes:
            if prefix not in vips_prefixes:
                vips_prefixes.append(prefix)

    # use the first prefix for testing
    return vips_prefixes[0]


def get_vips_prefix_paths(dut_t0_neigh, vips_prefix, topo_config):
    vips_t0 = []
    vips_asn = []

    for neigh in dut_t0_neigh:
        if vips_prefix in topo_config[neigh]['vips']['ipv4']['prefixes']:
            vips_t0.append(topo_config[neigh]['bgp']['asn'])
            vips_asn.append(topo_config[neigh]['vips']['ipv4']['asn'])
    return vips_t0, vips_asn


def get_bgp_v4_neighbors_from_minigraph(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Find all V4 bgp neighbors from minigraph
    bgp_v4nei = {}
    for item in mg_facts['minigraph_bgp']:
        if ':' in item['addr']:
            continue
        bgp_v4nei[item['name']] = item['addr']
    return bgp_v4nei


def test_bgp_multipath_relax(tbinfo, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Starting test_bgp_multipath_relax on topology {}".format(tbinfo['topo']['name']))
    topo_config = tbinfo['topo']['properties']['configuration']

    bgp_v4nei = get_bgp_v4_neighbors_from_minigraph(duthost, tbinfo)

    logger.info("bgp_v4nei {}".format(bgp_v4nei))

    # get all t0 routers name which has vips defined
    dut_t0_neigh = get_t0_neigh(tbinfo, topo_config)

    # get t2 neighbors
    dut_t2_neigh = get_t2_neigh(tbinfo)

    if not dut_t0_neigh:
        pytest.fail("Didn't find multipath t0's")

    vips_prefix = get_vips_prefix(dut_t0_neigh, topo_config)

    logger.info("vips_prefix = {}, DUT T2 neighbor = {}".format(
        vips_prefix, dut_t2_neigh
    ))

    # find all paths of the prefix for test
    vips_t0, vips_asn = get_vips_prefix_paths(dut_t0_neigh, vips_prefix, topo_config)

    logger.info("vips_t0: {}, vips_asn: {}".format(vips_t0, vips_asn))

    pytest_assert((len(vips_t0) > 1), "Did not find preconfigured multipath for the vips prefix under test")

    # Get the route from the DUT for the prefix
    bgp_route = duthost.get_bgp_route(
        prefix=vips_prefix
    )['ansible_facts']['bgp_route']

    logger.info("Bgp route from DUT for prefix {} is {}".format(vips_prefix, bgp_route))

    # Verify found vips prefix entry in Sonic bgp routes
    pytest_assert(bgp_route[vips_prefix]['found'] is True, "BGP route for {} not found".format(vips_prefix))

    # Verify total multipath match number of t0 with vips that has prefix for test
    pytest_assert(int(bgp_route[vips_prefix]['path_num']) == len(vips_t0), "Path number doesnt match the T0s with VIPS")

    # verify vips asn in each path of installed BGP vips prefix
    for asn in vips_asn:
        for aspath in bgp_route[vips_prefix]['aspath']:
            pytest_assert((str(asn) in aspath))

    # gather one t2 neighbor advertised routes to validate routes advertised to t2 are correct with relaxed multipath
    bgp_route_neiadv = duthost.get_bgp_route(
        neighbor=bgp_v4nei[dut_t2_neigh[0]], direction="adv"
    )['ansible_facts']['bgp_route_neiadv']

    logger.info("Bgp neighbor adv from DUT for neigh {} and prefix {} is {}".
                format(bgp_v4nei[dut_t2_neigh[0]],
                       vips_prefix,
                       bgp_route_neiadv[vips_prefix]))

    # Verify vips prefix in advertised routes to t2 neighbor
    pytest_assert(vips_prefix in bgp_route_neiadv, "{} is not present in bgp neighbor adv".format(vips_prefix))

    # vips prefix path has only 2 hops
    pytest_assert((len(bgp_route_neiadv[vips_prefix]['aspath']) == 2), "vips prefix path doesn't have 2 hops")

    pytest_assert((int(bgp_route_neiadv[vips_prefix]['aspath'][0]) in vips_t0 and
                   int(bgp_route_neiadv[vips_prefix]['aspath'][1]) in vips_asn),
                  "vips_prefix asn doesnt match with bgp route adv")
