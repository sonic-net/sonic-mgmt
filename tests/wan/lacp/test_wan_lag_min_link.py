import time
import pytest
import random
import logging
import ipaddress
import threading

from queue import Queue
from ptf import testutils, mask, packet
from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

pytestmark = [
    pytest.mark.topology('wan-4link'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(scope="module")
def get_target_pcs(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    # generate target pc tuples, be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001")]
    peer_ip_pc_pair = [(pc["addr"], pc["peer_addr"], pc["attachto"])
                       for pc in dut_mg_facts["minigraph_portchannel_interfaces"]
                       if ipaddress.ip_address(pc['peer_addr']).version == 4]

    # generate pc tuples, fill in members,
    # be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001", ["Ethernet48", "Ethernet52"])]
    all_pcs = [(pair[0], pair[1], pair[2], dut_mg_facts["minigraph_portchannels"][pair[2]]["members"])
               for pair in peer_ip_pc_pair]
    pytest_assert(len(all_pcs) > 1, "At least 2 port channels needed")

    # generate output pc tuples, fill in members,
    # be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001", ["Ethernet48", "Ethernet52"])]
    out_pcs = [(pair[0], pair[1], pair[2], dut_mg_facts["minigraph_portchannels"][pair[2]]["members"])
               for pair in all_pcs
               if pair[2] in dut_mg_facts['minigraph_portchannels']
               and len(dut_mg_facts["minigraph_portchannels"][pair[2]]["members"]) >= 2]
    pytest_assert(len(out_pcs) > 0, "One port channel with at least 2 members needed.")

    out_pc = random.sample(out_pcs, k=1)[0]
    selected_pcs = random.sample(all_pcs, k=2)
    in_pc = selected_pcs[0]
    # Make sure the picked in_pc is not the same as the selected out_pc
    if in_pc[2] == out_pc[2]:
        in_pc = selected_pcs[1]

    # use first port of in_pc as input port
    in_ptf_index = dut_mg_facts["minigraph_ptf_indices"][in_pc[3][0]]
    # all ports in out_pc will be output/forward ports
    out_ptf_indices = map(lambda port: dut_mg_facts["minigraph_ptf_indices"][port], out_pc[3])

    return in_pc, out_pc, in_ptf_index, out_ptf_indices


@pytest.fixture(scope='function')
def teardown(duthosts, enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """Recover testbed if case of test_lag_db_status_with_po_update failed"""
    original_lag_facts = {}
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    original_lag_facts[duthost.hostname] = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    yield
    # After test, compare lag_facts to check if port status is unchanged,
    # otherwise recover DUT by reloading minigraph
    try:
        original_data = original_lag_facts[duthost.hostname]
        lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
        for lag_name in original_data['lags'].keys():
            for po_intf, port_info in original_data['lags'][lag_name]['po_stats']['ports'].items():
                if port_info['link']['up'] == lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['link']['up']:
                    logging.info("{} of {} is up, ignore it.".format(po_intf, lag_name))
                    continue
                else:
                    logging.info("{}'s lag_facts is changed, original_data {}\n, lag_facts {}".format(
                                duthost.hostname, original_data, lag_facts))
                    raise Exception("Raise exception for config_reload in next step.")
    except Exception as e:
        # If port was removed from portchannel, it will throw KeyError exception, or catch exception in previous steps,
        # reload DUT to recover it
        logging.info("{}'s lag_facts is changed, comparison failed with exception:{}".format(duthost.hostname, repr(e)))
        config_reload(duthost, safe_reload=True, ignore_loganalyzer=loganalyzer)
    return


class WanLacpTraffic():
    def __init__(self, ptfadapter, testutils, timeout=60):
        self.timeout = timeout
        self.testutils = testutils
        self.ptfadapter = ptfadapter

    def _generateIpPkts(self, src_ip, src_mac, dst_ip, dst_mac):
        pkt = self.testutils.simple_ip_packet(eth_dst=dst_mac,
                                              eth_src=src_mac,
                                              ip_src=src_ip,
                                              ip_dst=dst_ip)

        exp_pkt = pkt.copy()
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')

        return pkt, exp_pkt

    def setTraffic(self, in_ptf_index, out_ptf_indices, src_ip, src_mac, dst_ip, dst_mac):
        self.in_ptf_index = in_ptf_index
        self.out_ptf_indices = out_ptf_indices
        logging.info("in_ptf_index is %s, out_ptf_indices is %s" % (self.in_ptf_index, self.out_ptf_indices))
        self.pkt, self.exp_pkt = self._generateIpPkts(src_ip, src_mac, dst_ip, dst_mac)

    def _dutOperation(self, **kwargs):
        while self.packet_sending_flag.empty() or (not self.packet_sending_flag.get()):
            time.sleep(0.2)
        callback = kwargs.pop('callback', None) if kwargs is not None else None
        if callback is not None:
            callback(**kwargs)
        else:
            time.sleep(1)

    def sendPackets(self, callback=None, **kwargs):
        if callback is not None:
            kwargs["callback"] = callback

        send_count = 0
        stop_sending = False
        # clear queued pkt buffer
        self.ptfadapter.dataplane.flush()
        self.packet_sending_flag = Queue(1)

        t = threading.Thread(target=self._dutOperation, name="dutOperation", kwargs=kwargs)
        t.start()
        t_max = time.time() + self.timeout
        time.sleep(1)
        while not stop_sending:
            # After 100 packets send, awake dutOperation thread, it happens only once.
            if send_count == 100:
                self.packet_sending_flag.put(True)

            self.testutils.send(self.ptfadapter, self.in_ptf_index, self.pkt)
            send_count += 1
            reach_max_time = time.time() > t_max
            stop_sending = reach_max_time or (not t.is_alive())
        t.join(20)
        time.sleep(2)
        match_count = self.testutils.count_matched_packets_all_ports(self.ptfadapter,
                                                                     self.exp_pkt,
                                                                     ports=self.out_ptf_indices,
                                                                     timeout=10)
        logging.info("current: {}, t_max: {}, match_count: {}, send_count: {}".format(
                    time.time(), t_max, match_count, send_count))
        return match_count, send_count


def flap_one_member(**kwargs):
    try:
        pc_members = kwargs.get('pc_members', None)
        duthost = kwargs.get('duthost', None)
        for member in pc_members:
            duthost.shutdown(member)
            time.sleep(2)
            duthost.no_shutdown(member)
            time.sleep(2)
    except Exception as e:
        logging.debug("Exception: {}".format(str(e)))


def lag_facts(duthost):
    return duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts'] if duthost is not None else None


def test_lag_min_link(duthosts,
                      enum_rand_one_per_hwsku_frontend_hostname,
                      ptfadapter,
                      get_target_pcs,
                      teardown):
    # Follow wan_lag_min_link.md test steps
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get in-pc and out-pc
    in_pc, out_pc, in_ptf_index, out_ptf_indices = get_target_pcs
    pc, pc_members = out_pc[2], out_pc[3]

    lacp_traffic = WanLacpTraffic(ptfadapter, testutils, len(pc_members)*20)
    lacp_traffic.setTraffic(in_ptf_index,
                            out_ptf_indices,
                            in_pc[1],
                            ptfadapter.dataplane.get_mac(0, in_ptf_index),
                            out_pc[1],
                            duthost.facts["router_mac"])

    # Step 1: Check PortChannel State
    lag_state = lag_facts(duthost)['lags'][pc]['po_intf_stat']
    pytest_assert(lag_state == "Up", "Expected lag {} state UP found {}.".format(out_pc[2], lag_state))

    int_facts = duthost.interface_facts()['ansible_facts']
    pytest_assert(int_facts['ansible_interface_facts'][out_pc[2]]['link'])

    # Step 2: Flap one member in PortChannel, check traffic and alarm
    # Step 2.1: Keep sending packets, and shutdown/no shutdown different members, observe whether packets lose
    # Step 2.2: Check syslog for port down alarm
    try:
        kwargs = {}
        kwargs["duthost"] = duthost
        kwargs["pc_members"] = pc_members

        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='wan_lacp_flag_member')
        for member in pc_members:
            loganalyzer.expect_regex.append("Port {} oper state set from up to down".format(member))

        with loganalyzer:
            match_count, send_count = lacp_traffic.sendPackets(flap_one_member, **kwargs)
        max_loss_rate = 0.01
        pytest_assert(match_count > send_count * (1 - max_loss_rate),
                      "Packets lost rate > {} during pc members add/removal, send_count: {}, match_count: {}".format(
                      max_loss_rate, send_count, match_count))
    except LogAnalyzerError:
        pytest.fail("Not found Port Oper state down in syslog.")

    # Step 3: Shutdown half of the members, PortChannel should be down and traffic should be failed.
    # Step 3.1 Shutdown half of the members in selected PortChannel.
    # Step 3.2 Check PortChannel Status should be down.
    # Step 3.3 Traffic should be failed.
    selected_pc_members = pc_members[::2]
    duthost.shutdown_multiple(selected_pc_members)
    pytest_assert(wait_until(5, 1, 2, lambda: lag_facts(duthost)['lags'][pc]['po_intf_stat'] == "Down"),
                  "Expected lag {} state Down".format(pc))

    match_count, send_count = lacp_traffic.sendPackets()
    pytest_assert(match_count == 0,
                  "Packets should be dropped as PortChannel {} is Down".format(pc))

    # Step 4: No shutdown previous half members, PortChannel should be up and traffic should be recovered.
    # Step 4.1 No shutdown previous half members.
    # Step 4.2 Check PortChannel Status should be up.
    # Step 4.3 Traffic should be recovered.
    duthost.no_shutdown_multiple(selected_pc_members)
    pytest_assert(wait_until(5, 1, 2, lambda: lag_facts(duthost)['lags'][pc]['po_intf_stat'] == "Up"),
                  "Expected lag {} state Up".format(pc))

    match_count, send_count = lacp_traffic.sendPackets()
    pytest_assert(match_count == send_count,
                  "Packets should not be dropped as PortChannel {} is Up".format(pc))
