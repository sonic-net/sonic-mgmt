import json
import logging
import pytest

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t1')
]


class QosSaiBaseMasic:


    def runPtfTest(self, ptfhost, testCase='', testParams={}):
        """
            Runs QoS SAI test case on PTF host

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                testCase (str): SAI tests test case name
                testParams (dict): Map of test params required by testCase

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        pytest_assert(ptfhost.shell(
                      argv = [
                          "ptf",
                          "--test-dir",
                          "saitests",
                          testCase,
                          "--platform-dir",
                          "ptftests",
                          "--platform",
                          "remote",
                          "-t",
                          ";".join(["{}={}".format(k, repr(v)) for k, v in testParams.items()]),
                          "--disable-ipv6",
                          "--disable-vxlan",
                          "--disable-geneve",
                          "--disable-erspan",
                          "--disable-mpls",
                          "--disable-nvgre",
                          "--log-file",
                          "/tmp/{0}.log".format(testCase),
                          "--test-case-timeout",
                          "600"
                      ],
                      chdir = "/root",
                      )["rc"] == 0, "Failed when running test '{0}'".format(testCase))

    def build_port_ips(self, asic_index, ifaces, mg_facts):
        """
        Returns list of port index and IP address for a given ASIC
        """

        dut_port_ips = dict()

        for iface, addr in ifaces.items():
            if iface.startswith("Ethernet"):
                portIndex = mg_facts["minigraph_ptf_indices"][iface]
            elif iface.startswith("PortChannel"):
                portName = mg_facts["minigraph_portchannels"][iface]["members"][0]
                portIndex = mg_facts["minigraph_ptf_indices"][portName]

            dut_port_ips.update({
                portIndex: {
                    "ipv4": addr["peer_ipv4"],
                    "bgp_neighbor": addr["bgp_neighbor"]
                }
            })

        return {asic_index: dut_port_ips}

    def get_backend_ip_ifs(self, duthost, frontend_asic):
        """
        On a frontend ASIC return a dict of interfaces with
        backend ASIC names
        """
        pytest_assert(
            frontend_asic in duthost.get_frontend_asic_ids(),
            "{} is not frontend ASIC ID".format(frontend_asic)
        )

        ip_ifs = duthost.asic_instance(
            frontend_asic
        ).show_ip_interface()["ansible_facts"]["ip_interfaces"]

        # Find backend interface names
        return {intf: ip["bgp_neighbor"].lower() for intf, ip in ip_ifs.items()
                if ip["bgp_neighbor"].lower().startswith("asic")}

    def check_v4route_backend_nhop(self, duthost, frontend_asic, route):
        """
        On frontend ASIC Check if v4 address has at least one backend
        ASIC nexthop

        Returns:
          False if not nexthops with backend ASICs
        """
        cmd = 'vtysh -n {} -c "show ip route {} json"'.format(
            frontend_asic, route
        )
        result = duthost.command(cmd)
        pytest_assert(result["rc"] == 0, cmd)
        route_info = json.loads(result["stdout"])
        nhop = route_info[route_info.keys().pop()][0]

        nhop_ifs = {x.get("interfaceName") for x in nhop["nexthops"]}
        backend_ifs = set(self.get_backend_ip_ifs(
            duthost, frontend_asic).keys()
        )

        return len(nhop_ifs.intersection(backend_ifs))

    def backend_ip_if_admin_state(
        self, duthost, test_asic, frontend_asic, admin_state
    ):
        """
        On a frontend ASIC bring down ports (channels) towards backend ASICs
        other than the ASIC under test, so that traffic always goes via
        backend ASIC under test
        """

        def is_intf_status(asic, intf, oper_state):
            intf_status = duthost.asic_instance(asic).show_interface(
                command="status", include_internal_intfs=True
            )["ansible_facts"]["int_status"]
            if intf_status[intf]["oper_state"] == oper_state:
                return True
            return False

        oper_state = "up" if admin_state == "startup" else "down"
        ip_ifs = self.get_backend_ip_ifs(duthost, frontend_asic)

        for intf, asic in ip_ifs.items():
            if  asic != "asic{}".format(test_asic):
                if admin_state == "startup":
                    duthost.asic_instance(frontend_asic).startup_interface(intf)
                else:
                    duthost.asic_instance(frontend_asic).shutdown_interface(intf)

                # wait for port status to change
                pytest_assert(
                    wait_until(
                        10, 1, 0, is_intf_status, frontend_asic, intf,
                        oper_state
                    ),
                    "Failed to update port status {} {}".format(
                        intf, admin_state
                    )
                )


    def find_asic_traffic_ports(self, duthost, ptfhost, test_params):
        """
        For a given pair of source IP and destination IP, identify
        the path taken by the L3 packet. Path implies the backend ASIC
        and its tx and rx ports. The path is identified by sending
        a burst of packets and finding the difference in interface
        counters before and after the burst.

        Assert is thrown if multiple ports or multiple backend ASICs
        have similar interface counters.
        """
        def find_traffic_ports(asic_id, c1, c2, diff):

            rx_port = None
            tx_port = None

            a1 = c1[asic_id]["ansible_facts"]["int_counter"]
            a2 = c2[asic_id]["ansible_facts"]["int_counter"]

            for port in a2.keys():
                rx_diff = int(a2[port]["RX_OK"]) - int(a1[port]["RX_OK"])

                if rx_diff >= diff:
                    pytest_assert(
                        rx_port is None,
                        "Multiple rx ports with {} rx packets".format(diff)
                    )
                    rx_port = port

                tx_diff = int(a2[port]["TX_OK"]) - int(a1[port]["TX_OK"])
                if tx_diff >= diff:
                    pytest_assert(
                        tx_port is None,
                        "Multiple tx ports with {} tx packets".format(diff)
                    )
                    tx_port = port

            # return rx, tx ports that have a packet count difference of > diff
            return rx_port, tx_port

        test_params["count"] = 100
        duthost.command("sonic-clear counters")
        cnt_before = duthost.show_interface(
            command="counter", asic_index="all", include_internal_intfs=True
        )
        # send a burst of packets from a given src IP to dst IP
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PacketTransmit",
            testParams=test_params
        )
        time.sleep(8)
        cnt_after = duthost.show_interface(
            command="counter", asic_index="all", include_internal_intfs=True
        )

        asic_idx = None
        rx_port = None
        tx_port = None

        # identify the backend ASIC and the rx, tx ports on that ASIC
        # that forwarded the traffic
        for asic in duthost.get_backend_asic_ids():
            rx, tx = find_traffic_ports(
                asic, cnt_before, cnt_after, test_params["count"]
            )
            if rx and tx:
                pytest_assert(
                    rx_port is None and tx_port is None,
                    "Multiple backend ASICs with rx/tx ports"
                )
                rx_port, tx_port, asic_idx  = rx, tx, asic

        pytest_assert(asic_idx is not None, "ASIC, rx and tx ports not found")
        return ({
            "test_src_port_name": rx_port,
            "test_dst_port_name": tx_port,
            "asic_under_test": asic_idx,
            }
        )

    def build_ip_interface(self, duthost, tbinfo):
        """
        builds a list of active IP interfaces and port index
        for each ASIC

        Returns:
        {
            asic_index: {
                portIndex: {
                    "ipv4": peer ipv4,
                    "bgp_neighbor": BGP neighbor
                }
                .
                .
            }
           .
           .
        }
        """ 

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ip_ifaces = duthost.get_active_ip_interfaces(tbinfo, asic_index="all")

        port_ips = dict()
        for idx in range(len(ip_ifaces)):
            port_ips.update(self.build_port_ips(idx, ip_ifaces[idx], mg_facts))

        return port_ips

    def build_test_ports(self, duthost, tbinfo):
        """
        This fixture builds a list of active L3 interface ports on each
        ASIC so that source and destination interfaces can be selected
        from different ASICs. Returns a dict of 'src' and 'dst' interfaces
        along with the ASIC ID

        Only frontend ASCIs connected to T0 devices are reachable end
        to end on multi ASIC platform.
        """
        # find asics with T0 neighbors
        ip_interface = self.build_ip_interface(duthost, tbinfo)
        ports = dict()
        for k, v in ip_interface.items():
            try:
                port_index = next(iter(v))
                port_info = v[port_index]
                if port_info["bgp_neighbor"].lower().endswith("t0"):
                    ports.update({k: v})
            except StopIteration:
                continue

        pytest_assert(
            len(ports) >= 0, "Ports from at least two ASICs required"
        )

        test_ports = dict()
        keys = ports.keys()
        src_asic = keys.pop(0)
        test_ports.update({"src": {src_asic: ports[src_asic]}})
        test_ports.update({"dst": dict()})
        for dst_asic in keys:
            test_ports["dst"].update({dst_asic: ports[dst_asic]})

        return test_ports

    def get_test_ports(self, duthost, tbinfo):
        """
        Fixture to select test ports from a given list of active L3
        interfaces from multiple frontend ASICs. The source and
        destination port will be on different ASICs.

        Fixture also returns the source and desitnation ASCIS IDs
        """
        test_ports = self.build_test_ports(duthost, tbinfo)

        # source port
        src_asic = test_ports["src"].keys().pop(0)
        src_port_ids = test_ports["src"][src_asic].keys()
        src_port_id = src_port_ids.pop(0)
        src_port_ip = test_ports["src"][src_asic][src_port_id]["ipv4"]

        # destination port
        dst_asic = test_ports["dst"].keys().pop(0)
        dst_port_ids = test_ports["dst"][dst_asic].keys()
        dst_port_id = dst_port_ids.pop(0)
        dst_port_ip = test_ports["dst"][dst_asic][dst_port_id]["ipv4"]

        return {
            "dst_port_id": dst_port_id,
            "dst_port_ip": dst_port_ip,
            "dst_asic": dst_asic,
            "src_port_id": src_port_id,
            "src_port_ip": src_port_ip,
            "src_asic": src_asic,
        }


class TestQosSaiMasic(QosSaiBaseMasic):

    def test_qos_masic_dscp_queue_mapping(
        self, duthosts, rand_one_dut_hostname, enum_backend_asic_index,
        ptfhost, dut_test_params, swapSyncd, tbinfo
    ):
        duthost = duthosts[rand_one_dut_hostname]

        # Verify all external and internal BGP sessions are up
        config_facts = duthost.config_facts(
            host=duthost.hostname, source="running"
        )['ansible_facts']
        bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
        bgp_neighbors.update(duthost.get_internal_bgp_peers())

        if not wait_until(
            300, 10, 0, duthost.check_bgp_session_state, bgp_neighbors.keys()
        ):
            pytest.fail("Not all bgp sessions are Up. BGP Sessions: {}".format(
                duthost.get_bgp_neighbors()
            ))

        test_ports = self.get_test_ports(duthost, tbinfo)
        src_asic = test_ports["src_asic"]

        try:
            # Bring down port (channel) towards ASICs other than the ASIC
            # under test, so that traffic always goes via ASIC under test
            self.backend_ip_if_admin_state(
                duthost, enum_backend_asic_index, src_asic, "shutdown"
            )

            test_params = dict()
            test_params.update(dut_test_params["basicParams"])
            test_params.update(test_ports)
            logger.debug(test_params)

            logging.debug(
                "BGP neighbors after backend I/F shut: {}".format(
                    duthost.get_bgp_neighbors()
                )
            )

            # ensure the test destination IP has a path to backend ASIC
            pytest_assert(
                wait_until(
                    300, 1, 0, self.check_v4route_backend_nhop, duthost,
                    test_params["src_asic"], test_params["dst_port_ip"]
                ),
                "Route {} doesn't have backend ASIC nexthop on ASIC {}, {}".format(
                    test_params["dst_port_ip"],
                    test_params["src_asic"],
                    duthost.command('vtysh -n {} -c "show ip route {} json"'.format(
                        test_params["src_asic"], test_params["dst_port_ip"])
                    )["stdout"]
                )
            )

            duthost.asic_instance(
                enum_backend_asic_index
            ).create_ssh_tunnel_sai_rpc()

            # find traffic src/dst ports on the ASIC under test
            test_params.update(
                self.find_asic_traffic_ports(duthost, ptfhost, test_params)
            )

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.DscpMappingPB",
                testParams=test_params
            )

        finally:
            # bring up the backed IFs
            self.backend_ip_if_admin_state(
                duthost, enum_backend_asic_index, src_asic, "startup"
            )

            duthost.asic_instance(
                enum_backend_asic_index
            ).remove_ssh_tunnel_sai_rpc()
