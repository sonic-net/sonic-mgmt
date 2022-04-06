import pytest
import logging
import ipaddress
import collections

import natsort

from tests.common.utilities import wait_until
from macsec_platform_helper import *

logger = logging.getLogger(__name__)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "macsec_required: mark test as MACsec required to run")


@pytest.fixture(scope="module")
def enable_macsec_feature(duthost, nbrhosts):
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")

    def check_macsec_enabled():
        for nbr in [n["host"] for n in nbrhosts.values()] + [duthost]:
            if isinstance(nbr, EosHost):
                continue
            if len(nbr.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) != 1:
                return False
            if len(nbr.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) != 1:
                return False
        return True
    assert wait_until(180, 5, 5, check_macsec_enabled)
    logger.info("Enable MACsec feature")
    yield
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec disabled")


@pytest.fixture(scope="module")
def profile_name():
    return "test"


@pytest.fixture(scope="module")
def default_priority():
    return 64

@pytest.fixture(scope="module", params=["GCM-AES-128", "GCM-AES-256", "GCM-AES-XPN-128", "GCM-AES-XPN-256"])
def cipher_suite(request):
    if request.config.getoption("--neighbor_type") == "eos" and "XPN" in request.param:
        pytest.skip("{} is not supported on neighbor EOS".format(request.param))
    return request.param


@pytest.fixture(scope="module")
def primary_ckn():
    cak = "6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435"
    return cak


@pytest.fixture(scope="module")
def primary_cak(cipher_suite):
    ckn = "0123456789ABCDEF0123456789ABCDEF"
    if "128" in cipher_suite:
        ckn = ckn * 1
    elif "256" in cipher_suite:
        ckn = ckn * 2
    else:
        raise ValueError("Unknown cipher suite {}".format(cipher_suite))
    return ckn


# Some platform cannot support "integrity_only" mode, skip this option
# @pytest.fixture(scope="module", params=["integrity_only", "security"])
@pytest.fixture(scope="module", params=["security"])
def policy(request):
    return request.param


@pytest.fixture(scope="module", params=["true", "false"])
def send_sci(request):
    if request.param == "false" and request.config.getoption("--neighbor_type") == "eos":
        pytest.skip("EOS with send_sci false does not work due to portchannel mac not matching ether port mac!")
    return request.param


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
def upstream_links(duthost, tbinfo, nbrhosts):
    links = collections.defaultdict(dict)

    def filter(interface, neighbor, mg_facts, tbinfo):
        if tbinfo["topo"]["type"] == "t0" and "T1" in neighbor["name"]:
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ipaddress.ip_address(item["addr"]), ipaddress.IPv4Address):
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


@pytest.fixture(scope="module")
def ctrl_links(duthost, tbinfo, nbrhosts):
    assert len(nbrhosts) > 1
    ctrl_nbr_names = natsort.natsorted(nbrhosts.keys())[:2]
    # ctrl_nbr_names = random.sample(nbrhosts.keys(), len(nbrhosts)//2)
    logging.info("Controlled links {}".format(ctrl_nbr_names))
    nbrhosts = {name: nbrhosts[name] for name in ctrl_nbr_names}
    return find_links_from_nbr(duthost, tbinfo, nbrhosts)


@pytest.fixture(scope="module")
def unctrl_links(duthost, tbinfo, nbrhosts, ctrl_links):
    unctrl_nbr_names = set(nbrhosts.keys())
    for _, nbr in ctrl_links.items():
        if nbr["name"] in unctrl_nbr_names:
            unctrl_nbr_names.remove(nbr["name"])
    logging.info("Uncontrolled links {}".format(unctrl_nbr_names))
    nbrhosts = {name: nbrhosts[name] for name in unctrl_nbr_names}
    return find_links_from_nbr(duthost, tbinfo, nbrhosts)
