import json
import logging
import pytest
import ipaddr as ipaddress
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

class PopulateFdb:
    """
        PopulateFdb populates DUT FDB entries

        It accepts MAC to IP ratio (default 100:1) and packet count (default 2000). It generates packets with
        ratio of distinct MAC addresses to distinct IP addresses as provided. The IP addresses starts from VLAN
        address pool.

        Command line sample:
            pytest testbed_setup/test_populate_fdb.py --testbed=<testbed> --inventory=<inventory> --testbed_file=<testbed fiel> \
            --host-pattern={<dut>|all} --module-path=<ansible library path> --mac_to_ip_ratio=100:1 --packet_count=8000

            where:
                mac_to_ip_ratio: Ratio of distinct MAC addresses to distinct IP addresses assigned to VM
                packet_count: Number of packets to be created and sent to DUT
                start_mac: VM start MAC address. Subsequent MAC addresses are increment of 1 on top of start MAC
    """
    PTFRUNNER_QLEN = 1000
    VLAN_CONFIG_FILE = "/tmp/vlan_config.json"

    def __init__(self, request, duthost, ptfhost):
        """
            Class constructor

            Args:
                request: pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        """
        self.macToIpRatio = request.config.getoption("--mac_to_ip_ratio")
        self.startMac = request.config.getoption("--start_mac")
        self.packetCount = request.config.getoption("--packet_count")

        self.duthost = duthost
        self.ptfhost = ptfhost

    def __prepareVlanConfigData(self, tbinfo):
        """
            Prepares Vlan Configuration data

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        """
        mgVlanPorts = []
        mgFacts = self.duthost.get_extended_minigraph_facts(tbinfo)
        for vlan, config in mgFacts["minigraph_vlans"].items():
            for port in config["members"]:
                mgVlanPorts.append({
                    "port": port,
                    "vlan": vlan,
                    "index": mgFacts["minigraph_ptf_indices"][port]
                })
        vlan_interfaces = {}
        for vlan in mgFacts["minigraph_vlan_interfaces"]:
            if ipaddress.IPNetwork(vlan['addr']).version == 4:
                vlan_interfaces[vlan["attachto"]] = vlan

        vlanConfigData = {
            "vlan_ports": mgVlanPorts,
            "vlan_interfaces": vlan_interfaces,
            "dut_mac": self.duthost.facts["router_mac"]
        }

        with open(self.VLAN_CONFIG_FILE, 'w') as file:
            file.write(json.dumps(vlanConfigData, indent=4))

        logger.info("Copying VLan config file to {0}".format(self.ptfhost.hostname))
        self.ptfhost.copy(src=self.VLAN_CONFIG_FILE, dest="/tmp/")

    def run(self, tbinfo):
        """
            Populates DUT FDB entries

            Args:
                None

            Returns:
                None
        """
        self.__prepareVlanConfigData(tbinfo)

        logger.info("Populate DUT FDB entries")
        ptf_runner(
            self.ptfhost,
            "ptftests",
            "populate_fdb.PopulateFdb",
            qlen=self.PTFRUNNER_QLEN,
            platform_dir="ptftests",
            platform="remote",
            params={
                "start_mac": self.startMac,
                "config_data": self.VLAN_CONFIG_FILE,
                "packet_count": self.packetCount,
                "mac_to_ip_ratio": self.macToIpRatio,
            },
            log_file="/tmp/populate_fdb.PopulateFdb.log"
        )

@pytest.fixture
def populate_fdb(request, duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    """
        Populates DUT FDB entries

        Args:
            request: pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    duthost = duthosts[rand_one_dut_hostname]
    populateFdb = PopulateFdb(request, duthost, ptfhost)

    populateFdb.run(tbinfo)
