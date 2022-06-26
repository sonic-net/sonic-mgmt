import pytest
import os
import natsort
import json
import collections
import logging
from ipaddress import ip_address, IPv4Address

from macsec_config_helper import enable_macsec_feature
from macsec_config_helper import disable_macsec_feature
from macsec_config_helper import setup_macsec_configuration
from macsec_config_helper import cleanup_macsec_configuration

logger = logging.getLogger(__name__)


class MacsecPlugin(object):
    """
    Pytest macsec plugin
    """

    def __init__(self):
        with open(os.path.dirname(__file__) + '/profile.json') as f:
            self.macsec_profiles = json.load(f)
            for k, v in self.macsec_profiles.items():
                self.macsec_profiles[k]["name"] = k
                # Set default value
                if "rekey_period" not in v:
                    self.macsec_profiles[k]["rekey_period"] = 0

    def _generate_macsec_profile(self, metafunc):
        value = metafunc.config.getoption("macsec_profile")
        if value == 'all':
            return natsort.natsorted(self.macsec_profiles.keys())
        return [x for x in value.split(',') if x in self.macsec_profiles]

    def pytest_generate_tests(self, metafunc):
        if 'macsec_profile' in metafunc.fixturenames:
            profiles = self._generate_macsec_profile(metafunc)
            assert profiles, "Specify valid macsec profile!"
            metafunc.parametrize('macsec_profile',
                                 [self.macsec_profiles[x] for x in profiles],
                                 ids=profiles,
                                 scope="session")

    @pytest.fixture(scope="session")
    def start_macsec_service(self, duthost, macsec_nbrhosts):
        def __start_macsec_service():
            enable_macsec_feature(duthost, macsec_nbrhosts)
        return __start_macsec_service

    @pytest.fixture(scope="session")
    def stop_macsec_service(self, duthost, macsec_nbrhosts):
        def __stop_macsec_service():
            disable_macsec_feature(duthost, macsec_nbrhosts)
        return __stop_macsec_service

    @pytest.fixture(scope="session")
    def macsec_feature(self, start_macsec_service, stop_macsec_service):
        start_macsec_service()
        yield
        stop_macsec_service()

    @pytest.fixture(scope="session")
    def startup_macsec(self, request, duthost, ctrl_links, macsec_profile):
        def __startup_macsec():
            profile = macsec_profile
            if request.config.getoption("neighbor_type") == "eos":
                if duthost.facts["asic_type"] == "vs" and profile['send_sci'] == "false":
                    # On EOS, portchannel mac is not same as the member port mac (being as SCI),
                    # then src mac is not equal to SCI in its sending packet. The receiver of vSONIC
                    # will drop it for macsec kernel module does not correctly handle it.
                    pytest.skip(
                        "macsec on dut vsonic, neighbor eos, send_sci false")
                if profile['rekey_period'] > 0:
                    pytest.skip(
                        "Rekey period hasn't been supported in EOS platform")

            cleanup_macsec_configuration(duthost, ctrl_links, profile['name'])
            setup_macsec_configuration(duthost, ctrl_links,
                                        profile['name'], profile['priority'], profile['cipher_suite'],
                                        profile['primary_cak'], profile['primary_ckn'], profile['policy'],
                                        profile['send_sci'], profile['rekey_period'])
            logger.info(
                "Setup MACsec configuration with arguments:\n{}".format(locals()))
        return __startup_macsec

    @pytest.fixture(scope="session")
    def shutdown_macsec(self, duthost, ctrl_links, macsec_profile):
        def __shutdown_macsec():
            profile = macsec_profile
            cleanup_macsec_configuration(duthost, ctrl_links, profile['name'])
        return __shutdown_macsec

    @pytest.fixture(scope="session", autouse=True)
    def macsec_setup(self, startup_macsec, shutdown_macsec, macsec_feature):
        '''
            setup macsec links
        '''
        startup_macsec()
        yield
        shutdown_macsec()

    @pytest.fixture(scope="session")
    def macsec_nbrhosts(self, ctrl_links):
        return {nbr["name"]: nbr for nbr in ctrl_links.values()}

    @pytest.fixture(scope="session")
    def ctrl_links(self, duthost, tbinfo, nbrhosts):
        if not nbrhosts:
            topo_name = tbinfo['topo']['name']
            pytest.skip("None of neighbors on topology {}".format(topo_name))
        ctrl_nbr_names = natsort.natsorted(nbrhosts.keys())[:2]
        logger.info("Controlled links {}".format(ctrl_nbr_names))
        nbrhosts = {name: nbrhosts[name] for name in ctrl_nbr_names}
        return self.find_links_from_nbr(duthost, tbinfo, nbrhosts)

    @pytest.fixture(scope="session")
    def unctrl_links(self, duthost, tbinfo, nbrhosts, ctrl_links):
        unctrl_nbr_names = set(nbrhosts.keys())
        for _, nbr in ctrl_links.items():
            if nbr["name"] in unctrl_nbr_names:
                unctrl_nbr_names.remove(nbr["name"])
        logger.info("Uncontrolled links {}".format(unctrl_nbr_names))
        nbrhosts = {name: nbrhosts[name] for name in unctrl_nbr_names}
        return self.find_links_from_nbr(duthost, tbinfo, nbrhosts)

    @pytest.fixture(scope="session")
    def downstream_links(self, duthost, tbinfo, nbrhosts):
        links = collections.defaultdict(dict)

        def filter(interface, neighbor, mg_facts, tbinfo):
            if tbinfo["topo"]["type"] == "t0" and "Server" in neighbor["name"]:
                port = mg_facts["minigraph_neighbors"][interface]["port"]
                links[interface] = {
                    "name": neighbor["name"],
                    "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                    "port": port
                }
        self.find_links(duthost, tbinfo, filter)
        return links

    @pytest.fixture(scope="session")
    def upstream_links(self, duthost, tbinfo, nbrhosts):
        links = collections.defaultdict(dict)

        def filter(interface, neighbor, mg_facts, tbinfo):
            if tbinfo["topo"]["type"] == "t0" and "T1" in neighbor["name"]:
                for item in mg_facts["minigraph_bgp"]:
                    if item["name"] == neighbor["name"]:
                        if isinstance(ip_address(item["addr"]), IPv4Address):
                            # The address of neighbor device
                            local_ipv4_addr = item["addr"]
                            # The address of DUT
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
        self.find_links(duthost, tbinfo, filter)
        return links

    def find_links(self, duthost, tbinfo, filter):
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in mg_facts["minigraph_neighbors"].items():
            filter(interface, neighbor, mg_facts, tbinfo)

    def is_interface_portchannel_member(self, pc, interface):
        for pc_name, elements in pc.items():
            if interface in elements['members']:
                return True
        return False

    def find_links_from_nbr(self, duthost, tbinfo, nbrhosts):
        links = collections.defaultdict(dict)

        def filter(interface, neighbor, mg_facts, tbinfo):
            if neighbor["name"] not in nbrhosts.keys():
                return
            port = mg_facts["minigraph_neighbors"][interface]["port"]

            # Currently in t2 topology macsec is validated on regular interfaces. To remove this once it is validated with PC.
            if tbinfo["topo"]["type"] == "t2" and self.is_interface_portchannel_member(mg_facts['minigraph_portchannels'], interface):
                return
            links[interface] = {
                "name": neighbor["name"],
                "host": nbrhosts[neighbor["name"]]["host"],
                "port": port
            }
        self.find_links(duthost, tbinfo, filter)
        return links
