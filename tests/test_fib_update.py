import pytest
import time
import sys
import threading
from ptf_runner import ptf_runner
from netaddr import IPNetwork
from natsort import natsorted


# global variables
SLEEP_TIME = 3

g_vars                          = {}
routes_with_diff_mask           = {
                                    "v4": ["20.0.0.0/8", "20.0.0.0/16", "20.0.0.0/24"],
                                    "v6": ["2020::/32", "2020::/64", "2020::/96"]
                                }
routes_with_full_mask           = {
                                    "v4": ["10.1.1.100/32", "172.16.1.100/32", "192.168.100.100/32"],
                                    "v6": ["2100::100/128", "2200::100/128", "2300::100/128"]
                                }
ip_addr_info                    = {
                                    "v4": ["192.168.96.1/30", "172.16.1.1/16", "10.1.1.1/8"],
                                    "v6": ["2100::1/96", "2200::1/64", "2300::1/32"]
                                }

# fixtures
@pytest.fixture(scope="module")
def host_facts(duthost):
    return duthost.setup()["ansible_facts"]

@pytest.fixture(scope="module")
def mg_facts(duthost, testbed):
    hostname = testbed["dut"]
    return duthost.minigraph_facts(host=hostname)["ansible_facts"]

# helper functions
def get_route_nexthop_info(duthost, ip):
    if IPNetwork(ip).version == 4:
        res = duthost.shell("show ip route {} |grep '*'".format(ip))["stdout"]
    else:
        res = duthost.shell("show ipv6 route {} |grep '*'".format(ip))["stdout"]
    
    out_port_list = []
    nexthop_info = {}
    if res:
        for line in res.split('\n'):
            if "directly connected" in line:
                out_port = line.split(",")[-1].split()[-1]
                nexthop_info[out_port] = "directly connected"
            else:
                out_port = line.split(",")[-1].split()[-1]
                nexthop = line.split(",")[0].split()[-1]
                out_port_list.append(out_port)
                nexthop_info[out_port] = nexthop
    return natsorted(out_port_list), nexthop_info

def clear_arp_table(duthost, ptfhost, port):
    duthost.shell("ip link set arp off dev {0} && ip link set arp on dev {0}".format(port))
    ptfhost.shell("ip -s -s neigh flush all")
    time.sleep(SLEEP_TIME)

def setup_static_route(duthost, ip, nexthop, op="add", ignore_errors=False):
    # op should be add or del
    route_cmd = "no " if op == "del" else ""
    route_cmd += "ip route {} {}".format(ip, nexthop) if IPNetwork(ip).version == 4 else "ipv6 route {} {}".format(ip, nexthop)
    duthost.shell("vtysh -c 'configure terminal' -c '{}'".format(route_cmd), module_ignore_errors=ignore_errors)
    time.sleep(SLEEP_TIME)

def setup_ptf_ip(ptfhost, op, port_if, ip=None, ignore_errors=False):
    # op should be add, del or flush; if op is flush, ip is not necessary
    if op == "flush":
        ptfhost.shell("ip addr {} dev eth{}".format(op, port_if), module_ignore_errors=ignore_errors)
    else:
        ptfhost.shell("ip addr {} {} dev eth{}".format(op, ip, port_if), module_ignore_errors=ignore_errors)
    time.sleep(SLEEP_TIME)

def dut_ping_ip(duthost, ip, port_index=None, expect=True):
    ping_cmd = "ping" if IPNetwork(ip).version == 4 else "ping6"
    if expect:
        duthost.shell("{} {} -c 3 -f -W 2".format(ping_cmd, IPNetwork(ip).ip))
    else:
        duthost.shell("! {} {} -c 3 -f -W 2".format(ping_cmd, IPNetwork(ip).ip))

def setup_sonic_ip(duthost, op, ip, port_name, ignore_errors=False):
    # op should be add or remove
    duthost.shell("config interface ip {} {} {}".format(op, port_name, ip), module_ignore_errors=ignore_errors)
    time.sleep(SLEEP_TIME)

def tcpdump_file(duthost, port, cap_file):
    duthost.shell("tcpdump -G 15 -W 1 -i {} -s 0 -w {}".format(port, cap_file))

@pytest.fixture(scope="module", autouse=True)
def setup_init(mg_facts, duthost, ptfhost):
    # vars
    global g_vars

    g_vars["router_mac"] = duthost.shell("redis-cli -n 4 hget 'DEVICE_METADATA|localhost' mac")["stdout"]
    g_vars["vlan_id"] = mg_facts["minigraph_vlans"].values()[0]["vlanid"]

    # ipv4 and ipv6 address for vlan interface
    g_vars["dut_vlan_ip"] = mg_facts["minigraph_vlan_interfaces"][0]["addr"]
    g_vars["peer_vlan_ip"] = "{}/{}".format(IPNetwork(g_vars["dut_vlan_ip"]).ip+1, mg_facts["minigraph_vlan_interfaces"][0]["prefixlen"])
    g_vars["dut_vlan_ipv6"] = ip_addr_info["v6"][0]
    g_vars["peer_vlan_ipv6"] = "{}/{}".format(IPNetwork(g_vars["dut_vlan_ipv6"]).ip+1, IPNetwork(g_vars["dut_vlan_ipv6"]).prefixlen)

    # Choose the last vlan interface member port for ip forwarding src_port.
    g_vars["src_port_name"] = mg_facts["minigraph_vlans"].values()[0]["members"][-1]
    g_vars["src_port"] = mg_facts["minigraph_port_indices"][g_vars["src_port_name"]]

    # use first vlan member port for traffic test dst port
    g_vars["dut_if"] = mg_facts["minigraph_vlans"].values()[0]["members"][0]
    g_vars["dut_if_peer_index"] = mg_facts["minigraph_port_indices"][g_vars["dut_if"]]

    # get default nexthop info for longest prefix matching test
    g_vars["default_ipv4_out_port_list"], g_vars["default_ipv4_nexthop_info"] = get_route_nexthop_info(duthost, "0.0.0.0/0")
    g_vars["default_ipv4_member_port_list"] = map(lambda port: mg_facts["minigraph_portchannels"][port]["members"][0], g_vars["default_ipv4_out_port_list"])
    g_vars["default_ipv4_ptf_port_list"] = map(lambda port: mg_facts["minigraph_port_indices"][port], g_vars["default_ipv4_member_port_list"])

    g_vars["default_ipv6_out_port_list"], g_vars["default_ipv6_nexthop_info"] = get_route_nexthop_info(duthost, "::/0")
    g_vars["default_ipv6_member_port_list"] = map(lambda port: mg_facts["minigraph_portchannels"][port]["members"][0], g_vars["default_ipv6_out_port_list"])
    g_vars["default_ipv6_ptf_port_list"] = map(lambda port: mg_facts["minigraph_port_indices"][port], g_vars["default_ipv6_member_port_list"])

    # init dut to store pcap files
    duthost.shell("mkdir -p /tmp/fib_update")

    # copy ptftest script and init ptf
    ptfhost.copy(src="ptftests", dest="/root")
    ptfhost.shell("mkdir -p /tmp/fib_update")
    ptfhost.script("scripts/remove_ip.sh")
    ptfhost.script("scripts/change_mac.sh")

class TestCase1_ConnectedRouteAddAndRemove():
    @pytest.fixture(scope="class", autouse=True)
    def setup_tc1(self, duthost, ptfhost):
        # dst ip list for traffic forward
        g_vars["dst_ip_addr_list"] = map(lambda ip_address: str(IPNetwork(ip_address).ip+1), ip_addr_info["v4"])
        g_vars["dst_ipv6_addr_list"] = map(lambda ip_address: str(IPNetwork(ip_address).ip+1), ip_addr_info["v6"])

        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        # --------------------- Testing -----------------------

        yield
        # --------------------- Teardown -----------------------
        for ip in ip_addr_info["v4"]:
            setup_sonic_ip(duthost, "remove", ip, "Vlan{}".format(g_vars["vlan_id"]), ignore_errors=True)
        for ip in ip_addr_info["v6"]:
            setup_sonic_ip(duthost, "remove", ip, "Vlan{}".format(g_vars["vlan_id"]), ignore_errors=True)

        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))

    def test_add_ipv4_connected_route(self, duthost, ptfhost):
        for ip in ip_addr_info["v4"]:
            setup_sonic_ip(duthost, "add", ip, "Vlan{}".format(g_vars["vlan_id"]))
            res = duthost.shell("show ip route {}".format(ip))["stdout"]
            assert "directly connected" in res, "directly connected route {} must in route table".format(ip)

        file_path = "/tmp/fib_update/[{}]_[{}].pcap".format(self.__class__.__name__, sys._getframe().f_code.co_name)
        tcpdump = threading.Thread(target=tcpdump_file, args=(duthost, g_vars["src_port_name"], file_path))
        # start tcpdump
        tcpdump.start()
        time.sleep(SLEEP_TIME)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

        # wait tcpdump stop
        tcpdump.join()

        res = duthost.shell("tcpdump -r {} -en".format(file_path))["stdout"]
        for ip in g_vars["dst_ip_addr_list"]:
            assert ip in res, "dst {} packets should trap to cpu.".format(ip)

    def test_del_ipv4_connected_route(self, duthost, ptfhost):
        for ip in ip_addr_info["v4"]:
            setup_sonic_ip(duthost, "remove", ip, "Vlan{}".format(g_vars["vlan_id"]))
            res = duthost.shell("show ip route {}".format(ip))["stdout"]
            assert ip not in res, "directly connected route {} must del from route table".format(ip)

        duthost.shell("ip link set arp off dev {0} && ip link set arp on dev {0}".format("Vlan{}".format(g_vars["vlan_id"])))

        file_path = "/tmp/fib_update/[{}]_[{}].pcap".format(self.__class__.__name__, sys._getframe().f_code.co_name)
        tcpdump = threading.Thread(target=tcpdump_file, args=(duthost, g_vars["src_port_name"], file_path))
        # start tcpdump
        tcpdump.start()
        time.sleep(SLEEP_TIME)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

        # wait tcpdump stop
        tcpdump.join()

        res = duthost.shell("tcpdump -r {} -en".format(file_path))["stdout"]
        for ip in g_vars["dst_ip_addr_list"]:
            assert ip not in res, "dst {} packets should not trap to cpu.".format(ip)

    def test_add_ipv6_connected_route(self, duthost, ptfhost):
        for ip in ip_addr_info["v6"]:
            setup_sonic_ip(duthost, "add", ip, "Vlan{}".format(g_vars["vlan_id"]))
            res = duthost.shell("show ipv6 route {}".format(ip))["stdout"]
            assert "directly connected" in res, "directly connected route {} must in route table".format(ip)

        file_path = "/tmp/fib_update/[{}]_[{}].pcap".format(self.__class__.__name__, sys._getframe().f_code.co_name)
        tcpdump = threading.Thread(target=tcpdump_file, args=(duthost, g_vars["src_port_name"], file_path))
        # start tcpdump
        tcpdump.start()
        time.sleep(SLEEP_TIME)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

        # wait tcpdump stop
        tcpdump.join()

        res = duthost.shell("tcpdump -r {} -en".format(file_path))["stdout"]
        for ip in g_vars["dst_ipv6_addr_list"]:
            assert ip in res, "dst {} packets should trap to cpu.".format(ip)

    def test_del_ipv6_connected_route(self, duthost, ptfhost):
        for ip in ip_addr_info["v6"]:
            setup_sonic_ip(duthost, "remove", ip, "Vlan{}".format(g_vars["vlan_id"]))
            res = duthost.shell("show ipv6 route {}".format(ip))["stdout"]
            assert ip not in res, "directly connected route {} must del from route table".format(ip)

        duthost.shell("ip link set arp off dev {0} && ip link set arp on dev {0}".format("Vlan{}".format(g_vars["vlan_id"])))

        file_path = "/tmp/fib_update/[{}]_[{}].pcap".format(self.__class__.__name__, sys._getframe().f_code.co_name)
        tcpdump = threading.Thread(target=tcpdump_file, args=(duthost, g_vars["src_port_name"], file_path))
        # start tcpdump
        tcpdump.start()
        time.sleep(SLEEP_TIME)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

        # wait tcpdump stop
        tcpdump.join()

        res = duthost.shell("tcpdump -r {} -en".format(file_path))["stdout"]
        for ip in g_vars["dst_ipv6_addr_list"]:
            assert ip not in res, "dst {} packets should not trap to cpu.".format(ip)

class TestCase2_RouteNexthopStatusUpdate():
    route = routes_with_diff_mask["v4"][0]
    route_v6 = routes_with_diff_mask["v6"][0]

    @pytest.fixture(scope="class", autouse=True)
    def setup_tc2(self, duthost, ptfhost):
        g_vars["dst_ip_addr_list"] = [str(IPNetwork(self.route).ip+1)]
        g_vars["dst_ipv6_addr_list"] = [str(IPNetwork(self.route_v6).ip+1)]

        setup_sonic_ip(duthost, "add", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))

        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        # --------------------- Testing -----------------------

        yield
        # --------------------- Teardown -----------------------
        setup_static_route(duthost, routes_with_diff_mask["v4"][0], IPNetwork(g_vars["peer_vlan_ip"]).ip, op="del", ignore_errors=True)
        setup_static_route(duthost, routes_with_diff_mask["v6"][0], IPNetwork(g_vars["peer_vlan_ipv6"]).ip, op="del", ignore_errors=True)
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"], ignore_errors=True)
        setup_sonic_ip(duthost, "remove", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"], ignore_errors=True)
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))

    def test_traffic_drop_when_ipv4_route_nexthop_not_exist(self, duthost, ptfhost):
        setup_static_route(duthost, self.route, IPNetwork(g_vars["peer_vlan_ip"]).ip)
        res = duthost.shell("show ip route {}".format(self.route))["stdout"]
        assert self.route in res, "static route {} must in route table".format(self.route)

        dut_ping_ip(duthost, g_vars["peer_vlan_ip"], expect=False)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv4_route_nexthop_exist(self, duthost, ptfhost):
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"])
        dut_ping_ip(duthost, g_vars["peer_vlan_ip"])
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_drop_when_ipv6_route_nexthop_not_exist(self, duthost, ptfhost):
        setup_static_route(duthost, self.route_v6, IPNetwork(g_vars["peer_vlan_ipv6"]).ip)
        res = duthost.shell("show ipv6 route {}".format(self.route_v6))["stdout"]
        assert self.route_v6 in res, "static route {} must in route table".format(self.route_v6)

        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"], expect=False)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv6_route_nexthop_exist(self, duthost, ptfhost):
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"])
        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"])
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

class TestCase3_NexthopUpdateMac():
    route = routes_with_diff_mask["v4"][0]
    route_v6 = routes_with_diff_mask["v6"][0]
    tmp_host_mac = "00:00:00:11:22:33"

    @pytest.fixture(scope="class", autouse=True)
    def setup_tc3(self, duthost, ptfhost):
        g_vars["dst_ip_addr_list"] = [str(IPNetwork(self.route).ip+1)]
        g_vars["dst_ipv6_addr_list"] = [str(IPNetwork(self.route_v6).ip+1)]
        g_vars["ptf_origin_mac"] = ptfhost.shell("ip link show eth%s |  grep -o 'link/ether [^ ]*' | awk '{print $2}'" % g_vars["dut_if_peer_index"])["stdout"]

        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))

        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"])
        setup_sonic_ip(duthost, "add", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"])
        # --------------------- Testing -----------------------

        yield
        # --------------------- Teardown -----------------------
        setup_static_route(duthost, self.route, IPNetwork(g_vars["peer_vlan_ip"]).ip, op="del", ignore_errors=True)
        setup_static_route(duthost, self.route_v6, IPNetwork(g_vars["peer_vlan_ipv6"]).ip, op="del", ignore_errors=True)
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"], ignore_errors=True)
        setup_sonic_ip(duthost, "remove", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"], ignore_errors=True)
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        ptfhost.shell("ip link set dev eth{} address {}".format(g_vars["dut_if_peer_index"], g_vars["ptf_origin_mac"]))

    def test_traffic_forward_when_ipv4_route_nexthop_exist(self, duthost, ptfhost):
        dut_ping_ip(duthost, g_vars["peer_vlan_ip"])
        res = duthost.shell("show arp {}".format(IPNetwork(g_vars["peer_vlan_ip"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ip"]).ip) in res and g_vars["ptf_origin_mac"] in res, "arp {} and mac {} should in arp entry".format(IPNetwork(g_vars["peer_vlan_ip"]).ip, g_vars["ptf_origin_mac"])
        
        setup_static_route(duthost, self.route, IPNetwork(g_vars["peer_vlan_ip"]).ip)
        res = duthost.shell("show ip route {}".format(self.route))["stdout"]
        assert self.route in res, "static route {} must in route table".format(self.route)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv4_route_nexthop_mac_change(self, duthost, ptfhost):
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        ptfhost.shell("ip link set dev eth{} address {}".format(g_vars["dut_if_peer_index"], self.tmp_host_mac))

        dut_ping_ip(duthost, g_vars["peer_vlan_ip"])
        res = duthost.shell("show arp {}".format(IPNetwork(g_vars["peer_vlan_ip"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ip"]).ip) in res and self.tmp_host_mac in res, "arp {} and mac {} should in arp entry".format(IPNetwork(g_vars["peer_vlan_ip"]).ip, self.tmp_host_mac)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

        # recover mac
        ptfhost.shell("ip link set dev eth{} address {}".format(g_vars["dut_if_peer_index"], g_vars["ptf_origin_mac"]))
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))

    def test_traffic_forward_when_ipv6_route_nexthop_exist(self, duthost, ptfhost):
        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"])
        res = duthost.shell("show ndp {}".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ipv6"]).ip) in res and g_vars["ptf_origin_mac"] in res, "ndp {} and mac {} should in ndp entry".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip, g_vars["ptf_origin_mac"])
        
        setup_static_route(duthost, self.route_v6, IPNetwork(g_vars["peer_vlan_ipv6"]).ip)
        res = duthost.shell("show ipv6 route {}".format(self.route_v6))["stdout"]
        assert self.route_v6 in res, "static route {} must in route table".format(self.route_v6)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv6_route_nexthop_mac_change(self, duthost, ptfhost):
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        ptfhost.shell("ip link set dev eth{} address {}".format(g_vars["dut_if_peer_index"], self.tmp_host_mac))

        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"])
        res = duthost.shell("show ndp {}".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ipv6"]).ip) in res and self.tmp_host_mac in res, "ndp {} and mac {} should in ndp entry".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip, self.tmp_host_mac)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

class TestCase4_NexthopUpdateEgressPort():
    route = routes_with_diff_mask["v4"][0]
    route_v6 = routes_with_diff_mask["v6"][0]

    @pytest.fixture(scope="class", autouse=True)
    def setup_tc4(self, mg_facts, duthost, ptfhost):
        g_vars["dst_ip_addr_list"] = [str(IPNetwork(self.route).ip+1)]
        g_vars["dst_ipv6_addr_list"] = [str(IPNetwork(self.route_v6).ip+1)]
        # use second vlan member port for changed egress port
        g_vars["dut_if_2"] = mg_facts["minigraph_vlans"].values()[0]["members"][1]
        g_vars["dut_if_2_peer_index"] = mg_facts["minigraph_port_indices"][g_vars["dut_if_2"]]

        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))

        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"])
        setup_sonic_ip(duthost, "add", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"])
        # --------------------- Testing -----------------------

        yield
        # --------------------- Teardown -----------------------
        setup_static_route(duthost, self.route, IPNetwork(g_vars["peer_vlan_ip"]).ip, op="del", ignore_errors=True)
        setup_static_route(duthost, self.route_v6, IPNetwork(g_vars["peer_vlan_ipv6"]).ip, op="del", ignore_errors=True)
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"], ignore_errors=True)
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_2_peer_index"], g_vars["peer_vlan_ip"], ignore_errors=True)
        setup_sonic_ip(duthost, "remove", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"], ignore_errors=True)
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_2_peer_index"], g_vars["peer_vlan_ipv6"], ignore_errors=True)
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))

    def test_traffic_forward_when_ipv4_route_nexthop_exist(self, duthost, ptfhost):
        dut_ping_ip(duthost, g_vars["peer_vlan_ip"])
        res = duthost.shell("show arp {}".format(IPNetwork(g_vars["peer_vlan_ip"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ip"]).ip) in res and g_vars["dut_if"] in res, "arp {} and port {} should in arp entry".format(IPNetwork(g_vars["peer_vlan_ip"]).ip, g_vars["dut_if"])
        
        setup_static_route(duthost, self.route, IPNetwork(g_vars["peer_vlan_ip"]).ip)
        res = duthost.shell("show ip route {}".format(self.route))["stdout"]
        assert self.route in res, "static route {} must in route table".format(self.route)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv4_route_nexthop_egress_port_change(self, duthost, ptfhost):
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"])
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_2_peer_index"], g_vars["peer_vlan_ip"])

        dut_ping_ip(duthost, g_vars["peer_vlan_ip"])
        res = duthost.shell("show arp {}".format(IPNetwork(g_vars["peer_vlan_ip"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ip"]).ip) in res and g_vars["dut_if_2"] in res, "arp {} and port {} should in arp entry".format(IPNetwork(g_vars["peer_vlan_ip"]).ip, g_vars["dut_if_2"])
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_2_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv6_route_nexthop_exist(self, duthost, ptfhost):
        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"])
        res = duthost.shell("show ndp {}".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ipv6"]).ip) in res and g_vars["dut_if"] in res, "ndp {} and port {} should in ndp entry".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip, g_vars["dut_if"])
        
        setup_static_route(duthost, self.route_v6, IPNetwork(g_vars["peer_vlan_ipv6"]).ip)
        res = duthost.shell("show ipv6 route {}".format(self.route_v6))["stdout"]
        assert self.route_v6 in res, "static route {} must in route table".format(self.route_v6)

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_traffic_forward_when_ipv6_route_nexthop_egress_port_change(self, duthost, ptfhost):
        clear_arp_table(duthost, ptfhost, "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"])
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_2_peer_index"], g_vars["peer_vlan_ipv6"])

        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"])
        res = duthost.shell("show ndp {}".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip))["stdout"]
        assert str(IPNetwork(g_vars["peer_vlan_ipv6"]).ip) in res and g_vars["dut_if_2"] in res, "ndp {} and port {} should in ndp entry".format(IPNetwork(g_vars["peer_vlan_ipv6"]).ip, g_vars["dut_if_2"])
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_2_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

class TestCase5_StaticRoutesWithFullMask():
    @pytest.fixture(scope="class", autouse=True)
    def setup_tc5(self, duthost, ptfhost):
        g_vars["dst_ip_addr_list"] = map(lambda ip_address: str(IPNetwork(ip_address).ip), routes_with_full_mask["v4"])
        g_vars["dst_ipv6_addr_list"] = map(lambda ip_address: str(IPNetwork(ip_address).ip), routes_with_full_mask["v6"])

        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"])
        setup_sonic_ip(duthost, "add", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "add", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"])
        # --------------------- Testing -----------------------

        yield
        # --------------------- Teardown -----------------------
        for route in routes_with_full_mask["v4"]:
            setup_static_route(duthost, route, IPNetwork(g_vars["peer_vlan_ip"]).ip, op="del", ignore_errors=True)
        for route in routes_with_full_mask["v6"]:
            setup_static_route(duthost, route, IPNetwork(g_vars["peer_vlan_ipv6"]).ip, op="del", ignore_errors=True)

        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ip"])
        setup_sonic_ip(duthost, "remove", g_vars["dut_vlan_ipv6"], "Vlan{}".format(g_vars["vlan_id"]))
        setup_ptf_ip(ptfhost, "del", g_vars["dut_if_peer_index"], g_vars["peer_vlan_ipv6"])

    def test_add_static_ipv4_route_with_full_mask(self, duthost, ptfhost):
        dut_ping_ip(duthost, g_vars["peer_vlan_ip"])

        for route in routes_with_full_mask["v4"]:
            setup_static_route(duthost, route, IPNetwork(g_vars["peer_vlan_ip"]).ip)
            res = duthost.shell("show ip route {}".format(route))["stdout"]
            assert route in res, "static route {} must in route table".format(route)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_del_static_ipv4_route_with_full_mask(self, duthost, ptfhost):
        for route in routes_with_full_mask["v4"]:
            setup_static_route(duthost, route, IPNetwork(g_vars["peer_vlan_ip"]).ip, op="del")
            res = duthost.shell("show ip route {}".format(route))["stdout"]
            assert route not in res, "static route {} must in route table".format(route)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_add_static_ipv6_route_with_full_mask(self, duthost, ptfhost):
        dut_ping_ip(duthost, g_vars["peer_vlan_ipv6"])

        for route in routes_with_full_mask["v6"]:
            setup_static_route(duthost, route, IPNetwork(g_vars["peer_vlan_ipv6"]).ip)
            res = duthost.shell("show ipv6 route {}".format(route))["stdout"]
            assert route in res, "static route {} must in route table".format(route)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_del_static_ipv6_route_with_full_mask(self, duthost, ptfhost):
        for route in routes_with_full_mask["v6"]:
            setup_static_route(duthost, route, IPNetwork(g_vars["peer_vlan_ipv6"]).ip, op="del")
            res = duthost.shell("show ipv6 route {}".format(route))["stdout"]
            assert route not in res, "static route {} must in route table".format(route)
            
        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": [g_vars["dut_if_peer_index"]],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"],
                        "unexpected_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

class TestCase6_LongestPrefixMatching():
    @pytest.fixture(scope="class", autouse=True)
    def setup_tc6(self, duthost):
        g_vars["dst_ip_addr_list"] = [str(IPNetwork(routes_with_diff_mask["v4"][0]).ip+1)]
        g_vars["dst_ipv6_addr_list"] = [str(IPNetwork(routes_with_diff_mask["v6"][0]).ip+1)]
        # --------------------- Testing -----------------------

        yield
        # --------------------- Teardown -----------------------
        for i in xrange(len(routes_with_diff_mask["v4"])):
            setup_static_route(duthost, routes_with_diff_mask["v4"][i], g_vars["default_ipv4_nexthop_info"][g_vars["default_ipv4_out_port_list"][i]], op="del", ignore_errors=True)
        for i in xrange(len(routes_with_diff_mask["v6"])):
            setup_static_route(duthost, routes_with_diff_mask["v6"][i], g_vars["default_ipv6_nexthop_info"][g_vars["default_ipv6_out_port_list"][i]], op="del", ignore_errors=True)
            
    def test_ipv4_default_route(self, duthost, ptfhost):
        res = duthost.shell("show ip route {}".format(g_vars["dst_ip_addr_list"][0]))["stdout"]
        assert "0.0.0.0/0" in res, "the dst ip {} must in default route".format(g_vars["dst_ip_addr_list"][0])

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": g_vars["default_ipv4_ptf_port_list"],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_add_static_ipv4_route_with_diff_prefix(self, duthost, ptfhost):
        for i in xrange(len(routes_with_diff_mask["v4"])):
            setup_static_route(duthost, routes_with_diff_mask["v4"][i], g_vars["default_ipv4_nexthop_info"][g_vars["default_ipv4_out_port_list"][i]])
            res = duthost.shell("show ip route {}".format(routes_with_diff_mask["v4"][i]))["stdout"]
            assert routes_with_diff_mask["v4"][i] in res, "static route {} must in route table".format(routes_with_diff_mask["v4"][i])

            ptf_runner( ptfhost, \
                        "ptftests",
                        "fib_update_test.FibUpdateTest",
                        platform_dir="ptftests",
                        params={
                            "src_port": g_vars["src_port"],
                            "dst_port_list": [g_vars["default_ipv4_ptf_port_list"][i]],
                            "router_mac": g_vars["router_mac"],
                            "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                                },
                        log_file="/tmp/fib_update/[{}]_[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name, i))

    def test_del_static_ipv4_route_with_diff_prefix(self, duthost, ptfhost):
        route_num = len(routes_with_diff_mask["v4"])
        for i in xrange(route_num):
            setup_static_route(duthost, routes_with_diff_mask["v4"][route_num-1-i], g_vars["default_ipv4_nexthop_info"][g_vars["default_ipv4_out_port_list"][route_num-1-i]], op="del")
            res = duthost.shell("show ip route {}".format(routes_with_diff_mask["v4"][route_num-1-i]))["stdout"]
            assert routes_with_diff_mask["v4"][route_num-1-i] not in res, "static route {} must not in route table".format(routes_with_diff_mask["v4"][route_num-1-i])

            dst_port_list = [g_vars["default_ipv4_ptf_port_list"][route_num-1-i-1]] if i != route_num-1 else g_vars["default_ipv4_ptf_port_list"]
            ptf_runner( ptfhost, \
                        "ptftests",
                        "fib_update_test.FibUpdateTest",
                        platform_dir="ptftests",
                        params={
                            "src_port": g_vars["src_port"],
                            "dst_port_list": dst_port_list,
                            "router_mac": g_vars["router_mac"],
                            "dst_ip_addr_list": g_vars["dst_ip_addr_list"]
                                },
                        log_file="/tmp/fib_update/[{}]_[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name, i))

    def test_ipv6_default_route(self, duthost, ptfhost):
        res = duthost.shell("show ipv6 route {}".format(g_vars["dst_ipv6_addr_list"][0]))["stdout"]
        assert "::/0" in res, "the dst ip {} must in default route".format(g_vars["dst_ipv6_addr_list"][0])

        ptf_runner( ptfhost, \
                    "ptftests",
                    "fib_update_test.FibUpdateTest",
                    platform_dir="ptftests",
                    params={
                        "src_port": g_vars["src_port"],
                        "dst_port_list": g_vars["default_ipv6_ptf_port_list"],
                        "router_mac": g_vars["router_mac"],
                        "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                            },
                    log_file="/tmp/fib_update/[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name))

    def test_static_ipv6_route_with_diff_prefix(self, duthost, ptfhost):
        for i in xrange(len(routes_with_diff_mask["v6"])):
            setup_static_route(duthost, routes_with_diff_mask["v6"][i], g_vars["default_ipv6_nexthop_info"][g_vars["default_ipv6_out_port_list"][i]])
            res = duthost.shell("show ip route {}".format(routes_with_diff_mask["v6"][i]))["stdout"]
            assert routes_with_diff_mask["v6"][i] in res, "static route {} must in route table".format(routes_with_diff_mask["v6"][i])

            ptf_runner( ptfhost, \
                        "ptftests",
                        "fib_update_test.FibUpdateTest",
                        platform_dir="ptftests",
                        params={
                            "src_port": g_vars["src_port"],
                            "dst_port_list": [g_vars["default_ipv6_ptf_port_list"][i]],
                            "router_mac": g_vars["router_mac"],
                            "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                                },
                        log_file="/tmp/fib_update/[{}]_[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name, i))

    def test_del_static_ipv6_route_with_diff_prefix(self, duthost, ptfhost):
        route_num = len(routes_with_diff_mask["v6"])
        for i in xrange(route_num):
            setup_static_route(duthost, routes_with_diff_mask["v6"][route_num-1-i], g_vars["default_ipv6_nexthop_info"][g_vars["default_ipv6_out_port_list"][route_num-1-i]], op="del")
            res = duthost.shell("show ip route {}".format(routes_with_diff_mask["v6"][route_num-1-i]))["stdout"]
            assert routes_with_diff_mask["v6"][route_num-1-i] not in res, "static route {} must not in route table".format(routes_with_diff_mask["v6"][route_num-1-i])

            dst_port_list = [g_vars["default_ipv6_ptf_port_list"][route_num-1-i-1]] if i != route_num-1 else g_vars["default_ipv6_ptf_port_list"]
            ptf_runner( ptfhost, \
                        "ptftests",
                        "fib_update_test.FibUpdateTest",
                        platform_dir="ptftests",
                        params={
                            "src_port": g_vars["src_port"],
                            "dst_port_list": dst_port_list,
                            "router_mac": g_vars["router_mac"],
                            "dst_ip_addr_list": g_vars["dst_ipv6_addr_list"]
                                },
                        log_file="/tmp/fib_update/[{}]_[{}]_[{}].log".format(self.__class__.__name__, sys._getframe().f_code.co_name, i))
