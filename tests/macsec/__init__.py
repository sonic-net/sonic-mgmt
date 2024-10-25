import collections
import json
import logging
import os
import sys
from ipaddress import ip_address, IPv4Address

import natsort
import pytest

if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

from .macsec_config_helper import enable_macsec_feature
from .macsec_config_helper import disable_macsec_feature
from .macsec_config_helper import setup_macsec_configuration
from .macsec_config_helper import cleanup_macsec_configuration
# flake8: noqa: F401
from tests.common.plugins.sanity_check import sanity_check

logger = logging.getLogger(__name__)


class MacsecPlugin(object):
    """
    Pytest macsec plugin
    """

    def __init__(self):
        with open(os.path.dirname(__file__) + '/profile.json') as f:
            self.macsec_profiles = json.load(f)
            for k, v in list(self.macsec_profiles.items()):
                self.macsec_profiles[k]["name"] = k
                # Set default value
                if "rekey_period" not in v:
                    self.macsec_profiles[k]["rekey_period"] = 0

    def _generate_macsec_profile(self, metafunc):
        value = metafunc.config.getoption("macsec_profile")
        if value == 'all':
            return natsort.natsorted(list(self.macsec_profiles.keys()))
        return [x for x in value.split(',') if x in self.macsec_profiles]

    def pytest_generate_tests(self, metafunc):
        if 'macsec_profile' in metafunc.fixturenames:
            profiles = self._generate_macsec_profile(metafunc)
            assert profiles, "Specify valid macsec profile!"
            metafunc.parametrize('macsec_profile',
                                 [self.macsec_profiles[x] for x in profiles],
                                 ids=profiles,
                                 scope="module")

    def get_ctrl_nbr_names(self, macsec_duthost, nbrhosts, tbinfo):
        return NotImplementedError()

    def downstream_neighbor(self,tbinfo, neighbor):
        return NotImplementedError()

    def upstream_neighbor(self,tbinfo, neighbor):
        return NotImplementedError()

    @pytest.fixture(scope="module")
    def start_macsec_service(self, macsec_duthost, macsec_nbrhosts):
        def __start_macsec_service():
            enable_macsec_feature(macsec_duthost, macsec_nbrhosts)
        return __start_macsec_service

    @pytest.fixture(scope="module")
    def stop_macsec_service(self, macsec_duthost, macsec_nbrhosts):
        def __stop_macsec_service():
            disable_macsec_feature(macsec_duthost, macsec_nbrhosts)
        return __stop_macsec_service

    @pytest.fixture(scope="module")
    def macsec_feature(self, start_macsec_service, stop_macsec_service):
        start_macsec_service()
        yield
        stop_macsec_service()

    @pytest.fixture(scope="module")
    def startup_macsec(self, request, macsec_duthost, ctrl_links, macsec_profile, tbinfo):
        topo_name = tbinfo['topo']['name']
        def __startup_macsec():
            profile = macsec_profile
            if request.config.getoption("neighbor_type") == "eos":
                if macsec_duthost.facts["asic_type"] == "vs" and profile['send_sci'] == "false":
                    # On EOS, portchannel mac is not same as the member port mac (being as SCI),
                    # then src mac is not equal to SCI in its sending packet. The receiver of vSONIC
                    # will drop it for macsec kernel module does not correctly handle it.
                    pytest.skip(
                        "macsec on dut vsonic, neighbor eos, send_sci false")
            if 't2' not in topo_name:
                cleanup_macsec_configuration(macsec_duthost, ctrl_links, profile['name'])
            setup_macsec_configuration(macsec_duthost, ctrl_links,
                                       profile['name'], profile['priority'], profile['cipher_suite'],
                                       profile['primary_cak'], profile['primary_ckn'], profile['policy'],
                                       profile['send_sci'], profile['rekey_period'])
            logger.info(
                "Setup MACsec configuration with arguments:\n{}".format(locals()))
            macsec_duthost.shell("config save -y")
        return __startup_macsec

    @pytest.fixture(scope="module")
    def shutdown_macsec(self, macsec_duthost, ctrl_links, macsec_profile):
        def __shutdown_macsec():
            profile = macsec_profile
            cleanup_macsec_configuration(macsec_duthost, ctrl_links, profile['name'])
            macsec_duthost.shell("config save -y")
        return __shutdown_macsec

    @pytest.fixture(scope="module", autouse=True)
    def macsec_setup(self, startup_macsec, shutdown_macsec, macsec_feature):
        '''
            setup macsec links
        '''
        startup_macsec()
        yield
        shutdown_macsec()

    @pytest.fixture(scope="module")
    def macsec_nbrhosts(self, ctrl_links):
        return {nbr["name"]: nbr for nbr in list(ctrl_links.values())}

    @pytest.fixture(scope="module")
    def ctrl_links(self, macsec_duthost, tbinfo, nbrhosts):

        if not nbrhosts:
            topo_name = tbinfo['topo']['name']
            pytest.skip("None of neighbors on topology {}".format(topo_name))

        ctrl_nbr_names = self.get_ctrl_nbr_names(macsec_duthost, nbrhosts, tbinfo)
        logger.info("Controlled links {}".format(ctrl_nbr_names))
        nbrhosts = {name: nbrhosts[name] for name in ctrl_nbr_names}
        return self.find_links_from_nbr(macsec_duthost, tbinfo, nbrhosts)

    @pytest.fixture(scope="module")
    def unctrl_links(self, macsec_duthost, tbinfo, nbrhosts, ctrl_links):
        unctrl_nbr_names = set(nbrhosts.keys())
        for _, nbr in ctrl_links.items():
            if nbr["name"] in unctrl_nbr_names:
                unctrl_nbr_names.remove(nbr["name"])

        logger.info("Uncontrolled links {}".format(unctrl_nbr_names))
        nbrhosts = {name: nbrhosts[name] for name in unctrl_nbr_names}
        return self.find_links_from_nbr(macsec_duthost, tbinfo, nbrhosts)

    @pytest.fixture(scope="module")
    def downstream_links(self, macsec_duthost, tbinfo, nbrhosts):
        links = collections.defaultdict(dict)

        def filter(interface, neighbor, mg_facts, tbinfo):
            if self.downstream_neighbor(tbinfo, neighbor):
                port = mg_facts["minigraph_neighbors"][interface]["port"]
                if interface not in mg_facts["minigraph_ptf_indices"]:
                    logger.info("Interface {} not in minigraph_ptf_indices".format(interface))
                    return
                links[interface] = {
                    "name": neighbor["name"],
                    "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                    "port": port
                }
        self.find_links(macsec_duthost, tbinfo, filter)
        return links

    @pytest.fixture(scope="module")
    def upstream_links(self, macsec_duthost, tbinfo, nbrhosts):
        links = collections.defaultdict(dict)

        def filter(interface, neighbor, mg_facts, tbinfo):
            if self.upstream_neighbor(tbinfo, neighbor):
                for item in mg_facts["minigraph_bgp"]:
                    if item["name"] == neighbor["name"]:
                        if isinstance(ip_address(item["addr"]), IPv4Address):
                            # The address of neighbor device
                            local_ipv4_addr = item["addr"]
                            # The address of DUT
                            peer_ipv4_addr = item["peer_addr"]
                            break
                if interface not in mg_facts["minigraph_ptf_indices"]:
                    logger.info("Interface {} not in minigraph_ptf_indices".format(interface))
                    return
                port = mg_facts["minigraph_neighbors"][interface]["port"]
                links[interface] = {
                    "name": neighbor["name"],
                    "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                    "local_ipv4_addr": local_ipv4_addr,
                    "peer_ipv4_addr": peer_ipv4_addr,
                    "port": port,
                    "host": nbrhosts[neighbor["name"]]["host"]
                }
        self.find_links(macsec_duthost, tbinfo, filter)
        return links

    def find_links(self, duthost, tbinfo, filter):

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in mg_facts["minigraph_neighbors"].items():
            filter(interface, neighbor, mg_facts, tbinfo)

    def is_interface_portchannel_member(self, pc, interface):
        for pc_name, elements in list(pc.items()):
            if interface in elements['members']:
                return True
        return False

    def find_links_from_nbr(self, duthost, tbinfo, nbrhosts):
        links = collections.defaultdict(dict)
        def filter(interface, neighbor, mg_facts, tbinfo):
            if neighbor["name"] not in list(nbrhosts.keys()):
                return
            port = mg_facts["minigraph_neighbors"][interface]["port"]

            links[interface] = {
                "name": neighbor["name"],
                "host": nbrhosts[neighbor["name"]]["host"],
                "port": port,
                "dut_name": duthost.hostname
            }
        self.find_links(duthost, tbinfo, filter)
        return links

class MacsecPluginT0(MacsecPlugin):
    """
    Pytest macsec plugin
    """


    def __init__(self):
         super(MacsecPluginT0, self).__init__()

    def get_ctrl_nbr_names(self, macsec_duthost, nbrhosts, tbinfo):
        ctrl_nbr_names = natsort.natsorted(nbrhosts.keys())[:2]
        return ctrl_nbr_names

    def downstream_neighbor(self,tbinfo, neighbor):
        if (tbinfo["topo"]["type"] == "t0" and "Server" in neighbor["name"]):
            return True
        return False

    def upstream_neighbor(self,tbinfo, neighbor):
        if (tbinfo["topo"]["type"] == "t0" and "T1" in neighbor["name"]):
            return True
        return False

class MacsecPluginT2(MacsecPlugin):
    """
    Pytest macsec plugin
    """


    def __init__(self):
         super(MacsecPluginT2, self).__init__()

    def get_ctrl_nbr_names(self, macsec_duthost, nbrhosts, tbinfo):
        mg_facts = macsec_duthost.get_extended_minigraph_facts(tbinfo)
        ctrl_nbr_names = mg_facts['macsec_neighbors']
        return ctrl_nbr_names

    def downstream_neighbor(self,tbinfo, neighbor):
        if ("t2" in tbinfo["topo"]["type"] and "T1" in neighbor["name"]):
            return True
        return False

    def upstream_neighbor(self,tbinfo, neighbor):
        if ("t2" in tbinfo["topo"]["type"] and "T3" in neighbor["name"]):
            return True
        return False
