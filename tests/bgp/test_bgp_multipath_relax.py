import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)


NEIGHBOR_MAPPING = {
    "T1": {
        "upstream": "T2",
        "downstream": "T0"
    },
    "T2": {
        "upstream": "T3",
        "downstream": "T1"
    }
}


def get_upstream_neigh(tbinfo, topo_config, dut_index):
    topo_type = tbinfo['topo']['type'].upper()

    upstream_duts_neighbor = []

    for vm in tbinfo['topo']['properties']['topology']['VMs'].keys():
        if NEIGHBOR_MAPPING[topo_type]["upstream"] in vm and \
                topo_config[vm]["interfaces"]["Ethernet1"]["dut_index"] == dut_index:
            upstream_duts_neighbor.append(vm)

    return upstream_duts_neighbor


def get_downstream_neigh(tbinfo, topo_config, dut_index):
    """
    get all downstream router names which has vips defined
    """
    topo_type = tbinfo['topo']['type'].upper()
    downstream_duts_neighbor = []

    for vm in tbinfo['topo']['properties']['topology']['VMs'].keys():
        if NEIGHBOR_MAPPING[topo_type]["downstream"] in vm and \
            ("dut_index" not in topo_config[vm]["interfaces"]["Ethernet1"] or
                topo_config[vm]["interfaces"]["Ethernet1"]["dut_index"] == dut_index):
            if "vips" in topo_config[vm]:
                downstream_duts_neighbor.append(vm)

    return downstream_duts_neighbor


def get_vips_prefix(downstream_duts_neighbor, topo_config):
    vips_prefixes = []

    # find all vips prefixes
    for neigh in downstream_duts_neighbor:
        prefixes = topo_config[neigh]['vips']['ipv4']['prefixes']
        for prefix in prefixes:
            if prefix not in vips_prefixes:
                vips_prefixes.append(prefix)

    # use the first prefix for testing
    return vips_prefixes[0]


def get_vips_prefix_paths(downstream_duts_neighbor, vips_prefix, topo_config, dut_index):
    vips_downstream = []
    vips_asn = []

    for neigh in downstream_duts_neighbor:
        if vips_prefix in topo_config[neigh]['vips']['ipv4']['prefixes'] and \
           ("dut_index" not in topo_config[neigh]["interfaces"]["Ethernet1"] or
               topo_config[neigh]["interfaces"]["Ethernet1"]["dut_index"] == dut_index):
            vips_downstream.append(topo_config[neigh]['bgp']['asn'])
            vips_asn.append(topo_config[neigh]['vips']['ipv4']['asn'])
    return vips_downstream, vips_asn


def get_bgp_v4_neighbors_from_minigraph(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Find all V4 bgp neighbors from minigraph
    bgp_v4nei = {}
    for item in mg_facts['minigraph_bgp']:
        if ':' in item['addr']:
            continue
        bgp_v4nei[item['name']] = item['addr']
    return bgp_v4nei


def test_bgp_multipath_relax(tbinfo, duthosts, enum_frontend_dut_hostname):

    logger.info("Starting test_bgp_multipath_relax on topology {}".format(tbinfo['topo']['name']))
    topo_config = tbinfo['topo']['properties']['configuration']
    logger.info("topo config:")
    logger.info(topo_config)

    duthost = duthosts[enum_frontend_dut_hostname]
    dut_index = tbinfo["duts_map"][enum_frontend_dut_hostname]

    bgp_v4nei = get_bgp_v4_neighbors_from_minigraph(duthost, tbinfo)

    logger.info("bgp_v4nei {}".format(bgp_v4nei))

    # get all downstream routers name which has vips defined
    downstream_dut_neighbors = get_downstream_neigh(tbinfo, topo_config, dut_index)

    # get upstream neighbors
    upstream_dut_neighbors = get_upstream_neigh(tbinfo, topo_config, dut_index)

    if not downstream_dut_neighbors:
        pytest.skip("Didn't find multipath downstream neighbor")

    vips_prefix = get_vips_prefix(downstream_dut_neighbors, topo_config)

    logger.info("vips_prefix = {}, upstream dut neighbor = {}".format(
        vips_prefix, upstream_dut_neighbors
    ))

    # find all paths of the prefix for test
    vips_downstream, vips_asn = get_vips_prefix_paths(downstream_dut_neighbors, vips_prefix, topo_config, dut_index)

    logger.info("vips_downstream: {}, vips_asn: {}".format(vips_downstream, vips_asn))

    pytest_assert((len(vips_downstream) > 1), "Did not find preconfigured multipath for the vips prefix under test")

    # Get the route from the DUT for the prefix
    bgp_route = duthost.get_bgp_route(
        prefix=vips_prefix
    )['ansible_facts']['bgp_route']

    logger.info("Bgp route from DUT for prefix {} is {}".format(vips_prefix, bgp_route))

    # Verify found vips prefix entry in Sonic bgp routes
    pytest_assert(bgp_route[vips_prefix]['found'] is True, "BGP route for {} not found".format(vips_prefix))

    # Verify total multipath match number of t0 with vips that has prefix for test
    pytest_assert(int(bgp_route[vips_prefix]['path_num']) == len(vips_downstream),
                  "Path number doesnt match the T0s with VIPS")

    # verify vips asn in each path of installed BGP vips prefix
    for asn in vips_asn:
        for aspath in bgp_route[vips_prefix]['aspath']:
            pytest_assert((str(asn) in aspath))

    # gather one upper neighbor advertised routes to validate routes advertised to lower are
    # correct with relaxed multipath
    bgp_route_neiadv = duthost.get_bgp_route(
        neighbor=bgp_v4nei[upstream_dut_neighbors[0]], direction="adv"
    )['ansible_facts']['bgp_route_neiadv']

    logger.info("Bgp neighbor adv from DUT for neigh {} and prefix {} is {}".
                format(bgp_v4nei[upstream_dut_neighbors[0]],
                       vips_prefix,
                       bgp_route_neiadv[vips_prefix]))

    # Verify vips prefix in advertised routes to t2 neighbor
    pytest_assert(vips_prefix in bgp_route_neiadv, "{} is not present in bgp neighbor adv".format(vips_prefix))

    # vips prefix path has only 2 hops
    pytest_assert((len(bgp_route_neiadv[vips_prefix]['aspath']) == 2), "vips prefix path doesn't have 2 hops")

    pytest_assert((int(bgp_route_neiadv[vips_prefix]['aspath'][0]) in vips_downstream and
                   int(bgp_route_neiadv[vips_prefix]['aspath'][1]) in vips_asn),
                  "vips_prefix asn doesnt match with bgp route adv")
