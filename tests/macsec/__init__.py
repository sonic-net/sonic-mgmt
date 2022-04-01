import pytest
import os
import natsort
import json
import collections
from ipaddress import ip_address, IPv4Address

from macsec_config_helper import enable_macsec_feature
from macsec_config_helper import disable_macsec_feature
from macsec_config_helper import setup_macsec_configuration
from macsec_config_helper import cleanup_macsec_configuration

logger = logging.getLogger(__name__)
with open(os.path.dirname(__file__) + '/profile.json') as f:
    macsec_profiles = json.load(f)


def get_macsec_profile_list():
    return natsort.natsorted(macsec_profiles.keys())


def pytest_addoption(parser):
    parser.addoption("--enable_macsec", action="store_true", default=False,
                     help="Enable macsec on some links of testbed")
    parser.addoption("--macsec_profile", action="store", default="all",
                     type=str, help="profile name list in macsec/profile.json")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "macsec_required: mark test as MACsec required to run")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("enable_macsec"):
        skip_macsec = pytest.mark.skip(reason="macsec test cases")
        for item in items:
            if "macsec_required" in item.keywords:
                item.add_marker(skip_macsec)


def pytest_generate_tests(metafunc):
    if 'macsec_profile' in metafunc.fixturenames:
        if metafunc.config.getoption("enable_macsec"):
            profiles = _generate_macsec_profile(metafunc)
            assert profiles, "Specify valid macsec profile!"
        else:
            profiles = ['']
        metafunc.parametrize('macsec_profile', profiles, scope="session")


def _generate_macsec_profile(metafunc):
    value = metafunc.config.getoption("macsec_profile")
    if value == 'all':
        return get_macsec_profile_list()
    return [x for x in value.split(',') if x in macsec_profiles]


@pytest.fixture(scope="session")
def macsec_feature(request, duthost, macsec_nbrhosts):
    if request.config.getoption("enable_macsec"):
        enable_macsec_feature(duthost, macsec_nbrhosts)
        yield
        disable_macsec_feature(duthost, macsec_nbrhosts)
    else:
        yield
        return


@pytest.fixture(scope="session", autouse=True)
def macsec_setup(request, duthost, ctrl_links, macsec_profile, macsec_feature):
    '''
        setup macsec links
    '''
    if not request.config.getoption("enable_macsec"):
        yield
        return

    profile = macsec_profiles[macsec_profile]
    if request.config.getoption("neighbor_type") == "eos" and duthost.facts["asic_type"] == "vs":
        if profile['send_sci'] == "false":
            # On EOS, portchannel mac is not same as the member port mac (being as SCI),
            # then src mac is not equal to SCI in its sending packet. The receiver of vSONIC
            # will drop it for macsec kernel module does not correctly handle it.
            pytest.skip("macsec on dut vsonic, neighbor eos, send_sci false")

    cleanup_macsec_configuration(duthost, ctrl_links, macsec_profile)
    setup_macsec_configuration(duthost, ctrl_links,
                               macsec_profile, profile['priority'], profile['cipher_suite'],
                               profile['primary_cak'], profile['primary_ckn'], profile['policy'],
                               profile['send_sci'])
    logger.info(
        "Setup MACsec configuration with arguments:\n{}".format(locals()))
    yield
    cleanup_macsec_configuration(duthost, ctrl_links, macsec_profile)


def find_links(duthost, tbinfo, filter):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for interface, neighbor in mg_facts["minigraph_neighbors"].items():
        filter(interface, neighbor, mg_facts, tbinfo)


def find_links_from_nbr(duthost, tbinfo, nbrhosts):
    links = collections.defaultdict(dict)

    def filter(interface, neighbor, mg_facts, tbinfo):
        if neighbor["name"] not in nbrhosts.keys():
            return
        port = mg_facts["minigraph_neighbors"][interface]["port"]
        links[interface] = {
            "name": neighbor["name"],
            "host": nbrhosts[neighbor["name"]]["host"],
            "port": port
        }
    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="session")
def ctrl_links(duthost, tbinfo, nbrhosts):
    assert len(nbrhosts) > 1
    ctrl_nbr_names = natsort.natsorted(nbrhosts.keys())[:2]
    logging.info("Controlled links {}".format(ctrl_nbr_names))
    nbrhosts = {name: nbrhosts[name] for name in ctrl_nbr_names}
    return find_links_from_nbr(duthost, tbinfo, nbrhosts)


@pytest.fixture(scope="session")
def macsec_nbrhosts(ctrl_links):
    return {nbr["name"]: nbr for nbr in ctrl_links.values()}


@pytest.fixture(scope="session")
def unctrl_links(duthost, tbinfo, nbrhosts, ctrl_links):
    unctrl_nbr_names = set(nbrhosts.keys())
    for _, nbr in ctrl_links.items():
        if nbr["name"] in unctrl_nbr_names:
            unctrl_nbr_names.remove(nbr["name"])
    logging.info("Uncontrolled links {}".format(unctrl_nbr_names))
    nbrhosts = {name: nbrhosts[name] for name in unctrl_nbr_names}
    return find_links_from_nbr(duthost, tbinfo, nbrhosts)


@pytest.fixture(scope="session")
def downstream_links(duthost, tbinfo, nbrhosts):
    links = collections.defaultdict(dict)

    def filter(interface, neighbor, mg_facts, tbinfo):
        if tbinfo["topo"]["type"] == "t0" and "Server" in neighbor["name"]:
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "port": port
            }
    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="session")
def upstream_links(duthost, tbinfo, nbrhosts):
    links = collections.defaultdict(dict)

    def filter(interface, neighbor, mg_facts, tbinfo):
        if tbinfo["topo"]["type"] == "t0" and "T1" in neighbor["name"]:
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ip_address(item["addr"]), IPv4Address):
                        local_ipv4_addr = item["addr"]
                        peer_ipv4_addr = item["peer_addr"]
                        break
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "local_ipv4_addr": local_ipv4_addr,
                "peer_ipv4_addr": peer_ipv4_addr,
                "port": port,
                "host": nbrhosts[neighbor["name"]]["host"]
            }
    find_links(duthost, tbinfo, filter)
    return links
