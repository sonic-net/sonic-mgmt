import pytest
import time
import sys
import json
import random
import logging

from natsort import natsorted
from ptf_runner import ptf_runner
import ptf.testutils as testutils
import ptf.mask as mask


SLEEP_TIME = 5
DEFAULT_BALANCING_RANGE = 0.25
BALANCING_TEST_TIMES = 1000
PACKET_SRC_MAC = "00:10:94:00:00:{:x}"
PACKET_DST_MAC = "00:10:94:00:01:{:x}"
PACKET_SRC_IP = "10.0.0.{}"
PACKET_DST_IP = "192.168.0.{}"
PACKET_SRC_IPV6 = "2000::{:x}"
PACKET_DST_IPV6 = "2001::{:x}"

# vars
mac1               = "00:01:00:00:00:01"
mac2               = "00:02:00:00:00:01"
broadcast_mac      = "ff:ff:ff:ff:ff:ff"
multicast_mac      = "01:00:5e:00:00:01"
unkown_unicast_mac = "00:01:02:03:04:05"

g_vars = {}

def wait_until_lags_status_ok(duthost, lag_list, expect_status="up", inteval=5, retry=12):
    '''
    wait lag status
    expect_status should be up or down, default for up
    check inteval 5s by default
    retry 12 by default
    '''
    for _ in range(0, retry):
        for lag_name in lag_list:
            status = duthost.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag_name))["stdout"]
            res = True if status == expect_status else False
            if not res:
                break
        if res:
            break
        time.sleep(inteval)
    return res

def wait_until_lags_member_selected(duthost, lag_list, expect="true", inteval=5, retry=12):
    '''
    wait lag member status
    expect should be true or false, default for true
    check inteval 5s by default
    retry 12 by default
    '''
    for _ in range(0, retry):
        for lag_name in lag_list:
            lag_info = duthost.shell("teamdctl {} config dump".format(lag_name))["stdout"]
            lag_member_ports = json.loads(lag_info)["ports"].keys()
            for port in lag_member_ports:
                status = duthost.shell("teamdctl {} state item get ports.{}.runner.selected".format(lag_name, port))["stdout"]
                res = True if status == expect else False
                if not res:
                    break
            if not res:
                break
        if res:
            break
        time.sleep(inteval)
    return res

def generate_packet(src_mac, dst_mac, pkt_type, hash_key):
    src_mac = PACKET_SRC_MAC.format(random.randint(0, 255)) if hash_key == "src_mac" else src_mac
    dst_mac = PACKET_DST_MAC.format(random.randint(0, 255)) if hash_key == "dst_mac" else dst_mac
    if pkt_type == "ipv4":
        src_ip  = PACKET_SRC_IP.format(random.randint(0, 255 if hash_key == "src_ip" else 0))
        dst_ip  = PACKET_DST_IP.format(random.randint(0, 255 if hash_key == "dst_ip" else 0))
        pkt = testutils.simple_ip_packet( eth_dst=dst_mac,
                                eth_src=src_mac,
                                ip_src=src_ip,
                                ip_dst=dst_ip
                            )
    else:
        src_ip  = PACKET_SRC_IPV6.format(random.randint(0, 65535 if hash_key == "src_ip" else 0))
        dst_ip  = PACKET_DST_IPV6.format(random.randint(0, 65535 if hash_key == "dst_ip" else 0))
        pkt = testutils.simple_tcpv6_packet( eth_dst=dst_mac,
                                eth_src=src_mac,
                                ipv6_src=src_ip,
                                ipv6_dst=dst_ip
                            )
    logging.debug("src_mac: {}".format(src_mac))
    logging.debug("dst_mac: {}".format(dst_mac))
    logging.debug("src_ip: {}".format(src_ip))
    logging.debug("dst_ip: {}".format(dst_ip))

    masked_exp_pkt = mask.Mask(pkt)
    return (pkt, masked_exp_pkt)

def check_within_expected_range(actual, expected):
    """
    @summary: Check if the actual number is within the accepted range of the expected number
    @param actual : acutal number of recieved packets
    @param expected : expected number of recieved packets
    @return (percentage, bool)
    """
    percentage = (actual - expected) / float(expected)
    return (percentage, abs(percentage) <= DEFAULT_BALANCING_RANGE)

def check_balancing(dst_ports, port_hit_cnt):
    """
    @summary: Check if the traffic is balanced across the LAG members
    @param port_hit_cnt : a dict that records the number of packets each port received
    @return bool
    """

    logging.debug("%-10s \t %-10s \t %10s \t %10s \t %10s" % ("type", "port(s)", "exp_cnt", "act_cnt", "diff(%)"))
    result = True

    total_hit_cnt = sum(port_hit_cnt.values())

    for port in dst_ports:
        (p, r) = check_within_expected_range(port_hit_cnt.get(port, 0), float(total_hit_cnt)/len(dst_ports))
        logging.debug("%-10s \t %-10s \t %10d \t %10d \t %10s"
            % ("LAG", str(port), total_hit_cnt/len(dst_ports), port_hit_cnt.get(port, 0), str(round(p, 4)*100) + "%"))
        result &= r

    assert result

def check_traffic(ptfadapter, src_mac, dst_mac, src_port, dst_ports, pkt_type="ipv4", pkt_action="fwd", hash_key=None):
    """
    @summary: check_traffic
    @param ptfadapter: PTF adapter object
    @param src_mac: source mac
    @param dst_mac: destination mac
    @param src_port: source port
    @param dst_ports: destination ports
    @param pkt_action: fwd or drop
    @param pkt_type: ipv4 or ipv6
    @param hash_key: 
        src_mac:    will send packets with src_mac changes
        dst_mac:    will send packets with dst_mac changes
        src_ip:     will send packets with src_ip changes
        dst_ip:     will send packets with dst_ip changes
    @return:
    """

    ptfadapter.dataplane.flush()
    time.sleep(1)

    pkt, masked_exp_pkt = generate_packet(src_mac, dst_mac, pkt_type, hash_key)

    testutils.send(ptfadapter, src_port, pkt)
    logging.debug("Sending packet from port {} to {}".format(src_port, dst_ports))
    logging.debug("packet_action : {}".format(pkt_action))

    if pkt_action == "fwd":
        (matched_index, received) = testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, dst_ports)
        logging.debug("Receive packet at port {}".format(dst_ports[matched_index]))
        assert received
        # check lag load balance
        if hash_key:
            logging.debug("Check PortChannel member balancing...")
            hit_count_map = {}
            for _ in xrange(0, BALANCING_TEST_TIMES):
                pkt, masked_exp_pkt = generate_packet(src_mac, dst_mac, pkt_type, hash_key)
                testutils.send_packet(ptfadapter, src_port, pkt)
                (matched_index, received) = testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, dst_ports)
                matched_port = dst_ports[matched_index]
                hit_count_map[matched_port] = hit_count_map.get(matched_port, 0) + 1
                logging.debug("Receive packet at port {}".format(matched_port))
            check_balancing(dst_ports, hit_count_map)
    else:
        testutils.verify_no_packet_any(ptfadapter, masked_exp_pkt, dst_ports)

# fixtures
@pytest.fixture(scope="module")
def host_facts(duthost):
    return duthost.setup()["ansible_facts"]

@pytest.fixture(scope="module")
def mg_facts(duthost, testbed):
    hostname = testbed["dut"]
    return duthost.minigraph_facts(host=hostname)["ansible_facts"]

@pytest.fixture(scope="module", autouse=True)
def setup_lag(duthost, ptfhost, mg_facts, testbed):
    # only support on t0 topology now
    if "t0" not in testbed["topo"]["name"]:
        logging.warning("Unsupported topology, only support topology t0 now.")
        pytest.skip("Unsupported topology")

    # vars
    global g_vars

    g_vars["vlan_id"] = mg_facts["minigraph_vlans"].values()[0]["vlanid"]
    g_vars["vlan_member_ports"] = mg_facts["minigraph_vlans"].values()[0]["members"]
    g_vars["ptf_ports"] = map(lambda p: mg_facts["minigraph_port_indices"][p], g_vars["vlan_member_ports"])
    # Each two ports which connect to the server constitutes a PortChannnel
    g_vars["lag_num"] = len(g_vars["vlan_member_ports"])/2
    g_vars["lag_info"] = {}
    for lag_id in xrange(1, 1+g_vars["lag_num"]):
        g_vars["lag_info"].update({lag_id: {}})
        g_vars["lag_info"][lag_id].update({"member_ports": g_vars["vlan_member_ports"][2*(lag_id-1):2*lag_id]})
        g_vars["lag_info"][lag_id].update({"ptf_index": map(lambda p: mg_facts["minigraph_port_indices"][p], g_vars["lag_info"][lag_id]["member_ports"])})
    g_vars["l2_lag_list"] = map(lambda lag_id: "PortChannel{}".format(lag_id), natsorted(g_vars["lag_info"].keys()))
    # choose 2 lags for traffic forwarding
    g_vars["test_lag_ids"] = natsorted(random.sample(range(1,g_vars["lag_num"]),2))
    logging.info("traffic lag ids {}".format(g_vars["test_lag_ids"]))
    logging.info("traffic lag member {}".format(map(lambda lag_id: g_vars["lag_info"][lag_id]["member_ports"], g_vars["test_lag_ids"])))

    ptfhost.shell("mkdir -p /tmp/l2_lag")
    ptfhost.script("scripts/remove_ip.sh")
    ptfhost.script("scripts/change_mac.sh")

    # init dut
    duthost.shell("sonic-clear fdb all")
    for port in g_vars["vlan_member_ports"]:
        duthost.shell("config vlan member del {} {}".format(g_vars["vlan_id"], port))
        duthost.shell("ip link set {} nomaster".format(port), module_ignore_errors=True) # workaround for https://github.com/Azure/sonic-swss/pull/1001

    for lag_id in g_vars["lag_info"].keys():
        # start teamd on PTF
        ptf_extra_vars = {
            "lag_id"   : lag_id,
            "members"  : g_vars["lag_info"][lag_id]["ptf_index"]
        }
        ptfhost.host.options["variable_manager"].extra_vars.update(ptf_extra_vars)

        ptfhost.template(src="l2_lag/l2_lag_PortChannel.conf.j2", dest="/tmp/l2_lag/PortChannel{}.conf".format(lag_id))
        ptfhost.copy(src="l2_lag/l2_lag_teamd.sh", dest="/tmp/l2_lag/l2_lag_teamd.sh", mode="0755")
        ptfhost.script("l2_lag/l2_lag_teamd.sh start {} \"{}\"".format(lag_id, " ".join([str(port) for port in g_vars["lag_info"][lag_id]["ptf_index"]])))

        # start teamd on DUT
        duthost.shell("config portchannel add PortChannel{}".format(lag_id))
        for port in g_vars["lag_info"][lag_id]["member_ports"]:
            duthost.shell("config portchannel member add PortChannel{} {}".format(lag_id, port))
        duthost.shell("config vlan member add {} PortChannel{} --untagged".format(g_vars["vlan_id"], lag_id))

    yield

    for lag_id in g_vars["lag_info"].keys():
        # stop teamd on PTF
        ptfhost.script("l2_lag/l2_lag_teamd.sh stop {} \"{}\"".format(lag_id, " ".join([str(port) for port in g_vars["lag_info"][lag_id]["ptf_index"]])))

        # restore configuration on dut
        duthost.shell("config interface shutdown PortChannel{}".format(lag_id))
        duthost.shell("sonic-clear arp")
        duthost.shell("sonic-clear ndp")
        duthost.shell("sonic-clear fdb all")
        duthost.shell("config vlan member del {} PortChannel{}".format(g_vars["vlan_id"], lag_id))
        duthost.shell("ip link set PortChannel{} nomaster".format(lag_id), module_ignore_errors=True) # workaround for https://github.com/Azure/sonic-swss/pull/1001
        duthost.shell("config interface startup PortChannel{}".format(lag_id))

        for port in g_vars["lag_info"][lag_id]["member_ports"]:
            duthost.shell("config portchannel member del PortChannel{} {}".format(lag_id, port))
            duthost.shell("config vlan member add {} {} --untagged".format(g_vars["vlan_id"], port))
        duthost.shell("config portchannel del PortChannel{}".format(lag_id))

    # restore port to admin up
    for port in g_vars["vlan_member_ports"]:
        duthost.shell("config interface startup {}".format(port))

# verify lag status is up before every test case
@pytest.fixture(scope="class", autouse=True)
def check_lag_status(duthost, inteval=5, times=12):
    lag_infos = duthost.shell("redis-cli -n 0 keys '*LAG_TABLE:*'")["stdout"].split("\n")
    lag_list = map(lambda lag_info: lag_info.split("LAG_TABLE:")[-1].strip("\""), lag_infos)
    res = wait_until_lags_status_ok(duthost, lag_list, "up")
    assert res, "All lags shoule be up"

@pytest.fixture(scope="class", autouse=True)
def clear_fwd_info(duthost):
    # clear before every case run
    duthost.shell("sonic-clear arp")
    duthost.shell("sonic-clear ndp")
    duthost.shell("sonic-clear fdb all")

    yield
    # clear after every case finished
    duthost.shell("sonic-clear arp")
    duthost.shell("sonic-clear ndp")
    duthost.shell("sonic-clear fdb all")

class TestCase1_MemberAdminStatus():
    @pytest.fixture(scope="function")
    def shutdown_member(self, request, duthost):
        shutdown_all = request.param.get("all", False) # if not all, shutdown the first member port
        for lag_id in g_vars["lag_info"].keys():
            port_list = g_vars["lag_info"][lag_id]["member_ports"] if shutdown_all else g_vars["lag_info"][lag_id]["member_ports"][:1]
            for port in port_list:
                duthost.shell("config interface shutdown {}".format(port))

        yield

        for lag_id in g_vars["lag_info"].keys():
            port_list = g_vars["lag_info"][lag_id]["member_ports"] if shutdown_all else g_vars["lag_info"][lag_id]["member_ports"][:1]
            for port in port_list:
                duthost.shell("config interface startup {}".format(port))

    def test_traffic_forwarding_when_lag_up(self, ptfadapter):
        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

    @pytest.mark.parametrize("shutdown_member", [{}], indirect=True)
    def test_shutdown_first_lag_member(self, ptfadapter, duthost, ptfhost, shutdown_member):
        # verify member not selected after shutdown
        for lag_id in g_vars["lag_info"].keys():
            member_status = duthost.shell("teamdctl PortChannel{} state item get ports.{}.runner.selected".format(lag_id, g_vars["lag_info"][lag_id]["member_ports"][0]))["stdout"]
            assert member_status == "false", "Member status should not be selected after shutdown"

        # verify lag status is up
        for lag_name in g_vars["l2_lag_list"]:
            lag_status = duthost.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag_name))["stdout"]
            assert lag_status == "up", "{} status should be up after shutdown one of the members".format(lag_name)

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][1], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

    @pytest.mark.parametrize("shutdown_member", [{"all": True}], indirect=True)
    def test_shutdown_all_lag_member(self, ptfadapter, duthost, ptfhost, shutdown_member):
        # shutdown all member and verify member_status
        for lag_id in g_vars["lag_info"].keys():
            for port in g_vars["lag_info"][lag_id]["member_ports"]:
                member_status = duthost.shell("teamdctl PortChannel{} state item get ports.{}.runner.selected".format(lag_id, port))["stdout"]
                assert member_status == "false", "Member {} status should be not selected after shutdown".format(port)

        # verify lag status
        for lag_name in g_vars["l2_lag_list"]:
            lag_status = duthost.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag_name))["stdout"]
            assert lag_status == "down", "{} status should be down after shutdown all members".format(lag_name)

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][1], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]], pkt_action="drop")

    def test_startup_lag_member(self, ptfadapter, duthost, ptfhost):
        # verify lag member status is selected
        res = wait_until_lags_member_selected(duthost, g_vars["l2_lag_list"], "true")
        assert res, "All lags member selected shoule be true"

        # verify lag status is up
        res = wait_until_lags_status_ok(duthost, g_vars["l2_lag_list"], "up")
        assert res, "All lags shoule be up"

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

class TestCase2_LagAdminStatus():
    @pytest.fixture(scope="function")
    def shutdown_lag(self, duthost):
        for lag_name in g_vars["l2_lag_list"]:
            duthost.shell("config interface shutdown {}".format(lag_name))

        yield

        for lag_name in g_vars["l2_lag_list"]:
            duthost.shell("config interface startup {}".format(lag_name))

    @pytest.mark.usefixtures("shutdown_lag")
    def test_shutdown_lag(self, ptfadapter, duthost, ptfhost):
        for lag_name in g_vars["l2_lag_list"]:
            status = duthost.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag_name))["stdout"]
            assert status == "down", "{} status should be down after admin down".format(lag_name)

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]], pkt_action="drop")

    def test_startup_lag(self, ptfadapter, duthost, ptfhost):
        res = wait_until_lags_status_ok(duthost, g_vars["l2_lag_list"], "up")
        assert res, "All lags shoule be up"

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

class TestCase3_MemberRemoveAndAdd():
    @pytest.fixture(scope="function")
    def remove_lag_member(self, request, duthost):
        remove_all = request.param.get("all", False) # if not all, remove the first member port
        for lag_id in g_vars["lag_info"].keys():
            port_list = g_vars["lag_info"][lag_id]["member_ports"] if remove_all else g_vars["lag_info"][lag_id]["member_ports"][:1]
            for port in port_list:
                duthost.shell("config portchannel member del PortChannel{} {}".format(lag_id, port))

        yield

        for lag_id in g_vars["lag_info"].keys():
            port_list = g_vars["lag_info"][lag_id]["member_ports"] if remove_all else g_vars["lag_info"][lag_id]["member_ports"][:1]
            for port in port_list:
                duthost.shell("config portchannel member add PortChannel{} {}".format(lag_id, port))

    @pytest.mark.parametrize("remove_lag_member", [{}], indirect=True)
    def test_remove_first_lag_member(self, ptfadapter, duthost, ptfhost, remove_lag_member):
        # verify first member should remove from the lag
        for lag_id in g_vars["lag_info"].keys():
            res = duthost.shell("teamdctl PortChannel{} state".format(lag_id))["stdout"]
            assert g_vars["lag_info"][lag_id]["member_ports"][0] not in res, "First member port should remove from the lag"

        # verify lag status is up
        for lag_name in g_vars["l2_lag_list"]:
            lag_status = duthost.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag_name))["stdout"]
            assert lag_status == "up", "{} status should be up after remove one of the members".format(lag_name)

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][1], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

    @pytest.mark.parametrize("remove_lag_member", [{"all": True}], indirect=True)
    def test_remove_all_lag_member(self, ptfadapter, duthost, ptfhost, remove_lag_member):
        # all member ports should remove from the lag
        for lag_id in g_vars["lag_info"].keys():
            for port in g_vars["lag_info"][lag_id]["member_ports"]:
                res = duthost.shell("teamdctl PortChannel{} state".format(lag_id))["stdout"]
                assert port not in res, "Member {} should be remove from the lag".format(port)

        # verify lag status
        for lag_name in g_vars["l2_lag_list"]:
            lag_status = duthost.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag_name))["stdout"]
            assert lag_status == "down", "{} status should be down after shutdown all members".format(lag_name)

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][1], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]], pkt_action="drop")

    def test_recover_all_lag_member(self, ptfadapter, duthost, ptfhost):
        # verify lag member status is selected
        res = wait_until_lags_member_selected(duthost, g_vars["l2_lag_list"], "true")
        assert res, "All lags member selected shoule be true"

        # verify lag status is up
        res = wait_until_lags_status_ok(duthost, g_vars["l2_lag_list"], "up")
        assert res, "All lags shoule be up"

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

class TestCase4_LagDelete():
    @pytest.fixture(scope="function")
    def delete_all_lags(self, duthost):
        # delete all l2 lag
        for lag_id in g_vars["lag_info"].keys():
            duthost.shell("config interface shutdown PortChannel{}".format(lag_id))
            duthost.shell("sonic-clear arp")
            duthost.shell("sonic-clear ndp")
            duthost.shell("sonic-clear fdb all")
            duthost.shell("config vlan member del {} PortChannel{}".format(g_vars["vlan_id"], lag_id))
            duthost.shell("ip link set PortChannel{} nomaster".format(lag_id), module_ignore_errors=True) # workaround for https://github.com/Azure/sonic-swss/pull/1001
            duthost.shell("config interface startup PortChannel{}".format(lag_id))

            for port in g_vars["lag_info"][lag_id]["member_ports"]:
                duthost.shell("config portchannel member del PortChannel{} {}".format(lag_id, port))
            duthost.shell("config portchannel del PortChannel{}".format(lag_id))

        yield

        for lag_id in g_vars["lag_info"].keys():
            duthost.shell("config portchannel add PortChannel{}".format(lag_id))
            for port in g_vars["lag_info"][lag_id]["member_ports"]:
                duthost.shell("config portchannel member add PortChannel{} {}".format(lag_id, port))
            duthost.shell("config vlan member add {} PortChannel{} --untagged".format(g_vars["vlan_id"], lag_id))

    @pytest.mark.usefixtures("delete_all_lags")
    def test_delete_all_lags(self, ptfadapter, duthost, ptfhost):
        # all lags should be delete
        res = duthost.shell("show interfaces portchannel")["stdout"]
        for lag_name in g_vars["l2_lag_list"]:
            assert lag_name not in res, "{} should be deleted".format(lag_name)

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]], pkt_action="drop")

    def test_recover_all_lags(self, ptfadapter, duthost, ptfhost):
        # verify lag member status is selected
        res = wait_until_lags_member_selected(duthost, g_vars["l2_lag_list"], "true")
        assert res, "All lags member selected shoule be true"

        # verify lag status is up
        res = wait_until_lags_status_ok(duthost, g_vars["l2_lag_list"], "up")
        assert res, "All lags shoule be up"

        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

class TestCase5_L2LagFDB():
    def test_traffic_forwarding_when_lag_up(self, ptfadapter, duthost, ptfhost):
        check_traffic(ptfadapter, mac1, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"]])

        # verfiy mac learned on l2 lag
        time.sleep(SLEEP_TIME)
        res = duthost.shell("show mac")["stdout"]
        assert mac1 in res, "mac {} should be learned".format(mac1)

    def test_l2_unicast_traffic(self, ptfadapter, duthost, ptfhost):
        check_traffic(ptfadapter, mac2, mac1, g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"])

    def test_l2_unknown_unicast_traffic(self, ptfadapter, duthost, ptfhost):
        check_traffic(ptfadapter, mac2, unkown_unicast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"]])

    def test_l2_multicast_traffic(self, ptfadapter, duthost, ptfhost):
        check_traffic(ptfadapter, mac2, multicast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"]])

    def test_l2_broadcast_traffic(self, ptfadapter, duthost, ptfhost):
        check_traffic(ptfadapter, mac2, broadcast_mac, g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"]])

    def test_flush_fdb(self, ptfadapter, duthost, ptfhost):
        duthost.shell("sonic-clear fdb all")
        res = duthost.shell("show mac")["stdout"]
        assert mac1 not in res, "mac {} should be flushed".format(mac1)

        check_traffic(ptfadapter, mac2, mac1, g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"][0], \
            [port for port in g_vars["ptf_ports"] if port not in g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"]])

class TestCase6_L2LagHashKeys():
    test_vlan = random.randint(2000,3000)

    @pytest.fixture(scope="class", autouse=True)
    def move_lags(self, duthost):
        # move 2 lags to other vlan
        duthost.shell("config vlan add {}".format(self.test_vlan))
        for lag_id in g_vars["test_lag_ids"]:
            duthost.shell("config vlan member del {} PortChannel{}".format(g_vars["vlan_id"], lag_id))
            duthost.shell("config vlan member add {} PortChannel{} --untagged".format(self.test_vlan, lag_id))

        yield

        duthost.shell("sonic-clear fdb all")

        for lag_id in g_vars["test_lag_ids"]:
            duthost.shell("config vlan member del {} PortChannel{}".format(self.test_vlan, lag_id))
            duthost.shell("config vlan member add {} PortChannel{} --untagged".format(g_vars["vlan_id"], lag_id))
        duthost.shell("config vlan del {}".format(self.test_vlan))

    def test_ipv4_traffic_smac_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], hash_key="src_mac")

    def test_ipv4_traffic_dmac_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], hash_key="dst_mac")

    def test_ipv4_traffic_sip_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], hash_key="src_ip")

    def test_ipv4_traffic_dip_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], hash_key="dst_ip")

    def test_ipv6_traffic_smac_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], pkt_type="ipv6", hash_key="src_mac")

    def test_ipv6_traffic_dmac_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], pkt_type="ipv6", hash_key="dst_mac")

    def test_ipv6_traffic_sip_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], pkt_type="ipv6", hash_key="src_ip")

    def test_ipv6_traffic_dip_balance(self, ptfadapter, ptfhost):
        check_traffic(ptfadapter, mac1, mac2, g_vars["lag_info"][g_vars["test_lag_ids"][0]]["ptf_index"][0], \
            g_vars["lag_info"][g_vars["test_lag_ids"][1]]["ptf_index"], pkt_type="ipv6", hash_key="dst_ip")
