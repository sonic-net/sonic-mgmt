import pytest
import logging
import re
import random
import ipaddress
from multiprocessing.pool import ThreadPool

from tests.common import config_reload

logger = logging.getLogger(__name__)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "macsec_required: mark test as MACsec required to run")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--neighbor_type") == "sonic":
        return
    skip_macsec = pytest.mark.skip(
        reason="Neighbor devices don't support MACsec")
    for item in items:
        if "macsec_required" in item.keywords:
            item.add_marker(skip_macsec)


def global_cmd(duthost, nbrhosts, cmd):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(duthost.command, args=(cmd,))
    for nbr in nbrhosts.values():
        pool.apply_async(nbr["host"].command, args=(cmd, ))
    pool.close()
    pool.join()


def recover_configuration(duthost, nbrhosts):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(config_reload, args=(duthost, "minigraph"))
    for nbr in nbrhosts.values():
        pool.apply_async(config_reload, args=(nbr["host"], "config_db"))
    pool.close()
    pool.join()
    time.sleep(30)


@pytest.fixture(scope="module")
def macsec_environment(duthost, nbrhosts):
    recover_configuration(duthost, nbrhosts)
    logger.info("Prepare MACsec environment")
    yield
    recover_configuration(duthost, nbrhosts)
    logger.info("Cleanup MACsec configuration")


@pytest.fixture(scope="module")
def enable_macsec_feature(duthost, nbrhosts, macsec_environment):
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")
    time.sleep(10)
    logger.info("Enable MACsec feature")


@pytest.fixture(scope="module")
def profile_name():
    return "test"


@pytest.fixture(scope="module")
def default_priority():
    return 64


# TODO: params=["GCM-AES-128", "GCM-AES-256"]
@pytest.fixture(scope="module", params=["GCM-AES-128"])
def cipher_suite(request):
    return request.param


@pytest.fixture(scope="module")
def primary_ckn():
    cak = "6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435"
    return cak


@pytest.fixture(scope="module")
def primary_cak(cipher_suite):
    ckn = "0123456789ABCDEF0123456789ABCDEF"
    if cipher_suite == "GCM-AES-128":
        ckn = ckn * 1
    elif cipher_suite == "GCM-AES-256":
        ckn = ckn * 2
    else:
        raise ValueError("Unknown cipher suite {}".format(cipher_suite))
    return ckn


# TODO @pytest.fixture(scope="module", params=["integrity_only", "security"])
@pytest.fixture(scope="module", params=["security"])
def policy(request):
    return request.param


def find_links(duthost, tbinfo, filter):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for interface, neighbor in mg_facts["minigraph_neighbors"].items():
        filter(interface, neighbor, mg_facts, tbinfo)


@pytest.fixture(scope="module")
def downstream_links(duthost, tbinfo, nbrhosts):
    links = defaultdict(dict)
    def filter(interface, neighbor, mg_facts, tbinfo):
        if tbinfo["topo"]["type"] == "t0" and "Server" in neighbor["name"]:
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "port":"Ethernet{}".format((int(re.search(r"(\d+)",port).group(1)) - 1) * 4)
            }
    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="module")
def upstream_links(duthost, tbinfo, nbrhosts):
    links = defaultdict(dict)
    def filter(interface, neighbor, mg_facts, tbinfo):
        if tbinfo["topo"]["type"] == "t0" and "T1" in neighbor["name"]:
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ipaddress.ip_address(item["addr"]), ipaddress.IPv4Address):
                        ipv4_addr = item["addr"]
                        break
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "ipv4_addr": ipv4_addr,
                "port":"Ethernet{}".format((int(re.search(r"(\d+)",port).group(1)) - 1) * 4)
            }
    find_links(duthost, tbinfo, filter)
    return links


def find_links_from_nbr(duthost, tbinfo, nbrhosts):
    links = defaultdict(dict)

    def filter(interface, neighbor, mg_facts, tbinfo):
        if neighbor["name"] not in nbrhosts.keys():
            return
        port = mg_facts["minigraph_neighbors"][interface]["port"]
        links[interface] = {
            "name": neighbor,
            "host": nbrhosts[neighbor["name"]]["host"],
            "port":"Ethernet{}".format((int(re.search(r"(\d+)",port).group(1)) - 1) * 4)
        }
    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="module")
def ctrl_links(duthost, tbinfo, nbrhosts):
    assert len(nbrhosts) > 1
    ctrl_nbr_names = random.sample(nbrhosts.keys(), len(nbrhosts)/2)
    logging.info("Controlled links {}".format(ctrl_nbr_names))
    nbrhosts = {name: nbrhosts[name] for name in ctrl_nbr_names}
    return find_links_from_nbr(duthost, tbinfo, nbrhosts)


@pytest.fixture(scope="module")
def unctrl_links(duthost, tbinfo, nbrhosts, ctrl_links):
    unctrl_nbr_names = set(nbrhosts.keys()) - set(ctrl_links.keys())
    logging.info("Uncontrolled links {}".format(unctrl_nbr_names))
    nbrhosts = {name: nbrhosts[name] for name in unctrl_nbr_names}
    return find_links_from_nbr(duthost, tbinfo, nbrhosts)

