import pytest
from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list
import apis.system.logging as slog_obj
import apis.switching.portchannel as portc_obj
import apis.routing.arp as arp_obj
import apis.routing.ip as ip_obj
import apis.system.interface as interface_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac
import apis.common.wait as waitapi
import utilities.common as utils
import apis.system.basic as base_obj
import apis.system.port as papi
from utilities.parallel import exec_all, exec_foreach

data = SpyTestDict()

sth_disable_stream = "stc::config {} -active false"
sth_enable_stream = "stc::config {} -active true"
sth_apply = "stc::apply"


def verify_rif_counters(dut_name, match={}):
    # Arguments
    # Dut_name
    # match : match should contain interface name & Counters names to validate w.r.t that interface
    # example verify_rif_counters(dut,{'Ethernet1':{'RX_OK':100,'TX_OK':100,'RX_ERR':0}})
    cli = 'intfstat -j'
    check = 0
    output = st.show(dut_name, cli)
    if len(match.keys()) >= 1:
        # need to validate 1 or more interface counters
        int_counters_found = {x: 0 for x in match.keys()}
        if len(output) >= 1:
            #
            for i in range(0, len(output) - 1):
                for interface_name in match.keys():
                    if output[i]['iface'] == interface_name:
                        int_counters_found[interface_name] = 1
                        for match_para in match[interface_name].keys():
                            if int(match[interface_name][match_para]) == 0:
                                if int(output[i][match_para]) < 5:
                                    st.log("{} {} packets are expected & {} packets are received"
                                           .format(match_para, match[interface_name][match_para],
                                                   output[i][match_para]))
                                else:
                                    st.warn("{} {} packets are expected & {} packets are received"
                                            .format(match_para, match[interface_name][match_para],
                                                    output[i][match_para]))
                                    check = 1
                            elif int(match[interface_name][match_para]) >= \
                                    int(int(output[i][match_para].replace(',', '')) * 0.95) and \
                                    int(match[interface_name][match_para]) <= \
                                    int(int(output[i][match_para].replace(',', '')) * 1.05):
                                st.log("{} {} packets are expected & {} packets are received"
                                       .format(match_para, match[interface_name][match_para], output[i][match_para]))
                            else:
                                st.warn("{} {} packets are expected & {} packets are received"
                                        .format(match_para, match[interface_name][match_para], output[i][match_para]))
                                check = 1
        else:
            st.warn("intfstat -j not given proper output/template unable to grep output")
            check = 1
        for x in match.keys():
            if int_counters_found[x] == 0:
                st.warn("{} stats are not present in output".format(x))
                check = 1
    if check:
        return False
    else:
        return True


def port_counters(dut_name, match={}):
    check = True
    for interface in match.keys():
        cli = "portstat -i {}".format(interface)
        output = st.show(dut_name, cli)
        for match_param in match[interface]:
            if match[interface][match_param] == 0:
                if int(output[2][match_param].replace(',', '')) > 5:
                    check = False
                    st.warn("expected 0 {} packets where  "
                            "we got {} packets ".format(match_param, output[2][match_param].replace(',', '')))
                else:
                    st.log("{} {} packets are expected & {} packets are received"
                           .format(match_param, match[interface][match_param], output[2][match_param].replace(',', '')))
            else:
                if (int(match[interface][match_param]) * 0.95) <= int(output[2][match_param].replace(',', '')) \
                        and (int(match[interface][match_param]) * 1.05) >= int(output[2][match_param].replace(',', '')):
                    st.log("{} {} packets are expected & {} packets are received"
                           .format(match_param, match[interface][match_param], output[2][match_param].replace(',', '')))
                else:
                    check = False
                    st.warn("{} {} packets are expected & {} packets are received"
                            .format(match_param, match[interface][match_param],
                                    output[2][match_param].replace(',', '')))
    return check


def initialize_variables():
    data.d1t1_ip_addr = "11.1.1.1"
    data.t1d1_adv_ip_addr = "11.1.1.11"
    data.t1d1_adv_ipv6_addr = "11:1:1::11"
    data.t1d1_ip_addr = "11.1.1.2"
    data.t1d1_mac_addr = "00:00:00:00:00:01"
    data.d1t2_ip_addr = "22.1.1.1"
    data.t2d1_adv_ip_addr = "22.1.1.22"
    data.t2d1_adv_ipv6_addr = "22:1:1::22"
    data.t2d1_ip_addr = "22.1.1.2"
    data.t2d1_mac_addr = "00:00:00:00:00:02"
    data.d1t1_ipv6_addr = "11:1:1::1"
    data.t1d1_ipv6_addr = "11:1:1::2"
    data.d1t2_ipv6_addr = "22:1:1::1"
    data.t2d1_ipv6_addr = "22:1:1::2"
    data.d1t1_static_r = "33.1.1.0/24"
    data.t1d1_static_r = "33.1.1.33"
    data.mcast_leave_group_ip = "224.0.0.2"
    data.mcast_query_ip = "224.0.0.1"
    data.mcast_group_ip = "239.0.0.11"
    data.mcast_group_mac = "01:00:5e:00:00:0b"
    data.mcast_report_ip = "237.0.0.11"
    data.mcast_leave_group_mac = "01:00:5e:00:01:02"
    data.mcast_query_mac = "01:00:5e:00:01:01"
    data.t1d1_v6_mac_addr = "00:00:00:00:00:03"
    data.t2d1_v6_mac_addr = "00:00:00:00:00:04"
    data.mcast_SMAC = "01:00:5e:00:01:02"
    data.reserved_DMAC = "01:80:C2:00:00:05"
    data.provider_bridgeg_DMAC = "01:80:C2:00:00:08"
    data.max_mtu_frame_size = 11000
    data.mask = "24"
    data.v6_mask = "64"
    data.vlan_1 = 64
    data.vlan_int_1 = "Vlan{}".format(data.vlan_1)
    data.clear_parallel = False
    data.cli_type = ""
    data.t1_v4_stream_mac = "00:00:00:00:00:05"
    data.t1_v6_stream_mac = "00:00:00:00:00:06"
    data.vlan_list = random_vlan_list(count=2)
    data.vlan_id = str(data.vlan_list[0])
    data.vlan = str(data.vlan_list[1])
    data.kbps = 1000
    data.frame_size = 68
    data.rate_pps = 5000
    data.packets = (data.kbps * 1024) / (data.frame_size * 8)
    data.bum_deviation = int(0.10 * data.packets)
    data.lower_pkt_count = int(data.packets - data.bum_deviation)
    data.higher_pkt_count = int(data.packets + data.bum_deviation)
    data.max_vlan = 4093
    data.pkts_per_burst = 2000
    data.class_e_ip = "240.0.0.1"
    data.non_routable_ip = "0.0.0.0"
    data.non_routable_ipv6 = "::0"
    data.link_local_ip = "169.254.10.125"
    data.portchannel_name1 = "PortChannel0001"
    data.portchannel_name2 = "PortChannel0002"
    data.v4_loopback = "127.0.0.1"
    data.t2_v4_stream_mac = "00:00:00:00:00:50"
    data.dest_mcast_mac = "01:00:5e:00:01:11"
    data.bcast_mac = "ff:ff:ff:ff:ff:ff"


@pytest.fixture(scope="module", autouse=True)
def drop_counters_module_hooks(request):
    global vars, dut1, d1_mac_addr
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    initialize_variables()
    # Min topology verification
    vars = st.ensure_min_topology("D1T1:2")
    # clean up interface coonfigs

    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    portc_obj.clear_portchannel_configuration(st.get_dut_names())

    # Test setup details
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    # Test variables
    d1_mac_addr = str(mac.get_sbin_intf_mac(dut1, "eth0"))
    data.dut_rt_int1_mac = str(base_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1))
    data.dut_rt_int2_mac = str(base_obj.get_ifconfig_ether(vars.D1, vars.D1T1P2))
    data.vlan_data = [{"dut": [dut1], "vlan_id": data.vlan, "tagged": [vars.D1T1P1, vars.D1T1P2]}]
    exec_all(True, [[tg_preconfig], [router_preconfig]], first_on_main=True)
    yield
    exec_all(True, [[tg_preconfig_cleanup], [router_preconfig_cleanup]], first_on_main=True)


def tg_preconfig():
    global h1, h2, tr1, tg, tg_ph_1, tg_ph_2, tg_handler
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]

    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])


def tg_preconfig_cleanup():
    tg.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')


def router_preconfig():
    # ip_obj.config_ip_addr_interface(dut1, data.vlan_int_1, data.d1t2_ip_addr, data.mask)
    pass


def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    portc_obj.clear_portchannel_configuration(st.get_dut_names())


@pytest.fixture(scope="class")
def drop_counters_class_hook_rif(request):
    # T1D1 config
    import sth

    global h1, h2, h3, h4, t1d1_stream_1, t1d1_v6stream_1, sth_disable_stream, sth_enable_stream, sth_apply
    ip_obj.config_ip_addr_interface(dut1, interface_name=vars.D1T1P1, ip_address=data.d1t1_ip_addr, subnet=data.mask,
                                    family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(dut1, interface_name=vars.D1T1P1, ip_address=data.d1t1_ipv6_addr,
                                    subnet=data.v6_mask,
                                    family="ipv6", config='add')
    # tgen config
    h1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
                                gateway=data.d1t1_ip_addr, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    h2 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,
                                ipv6_prefix_length=data.v6_mask, ipv6_gateway=data.d1t1_ipv6_addr,
                                src_mac_addr=data.t1d1_v6_mac_addr, arp_send_req='1')
    # T2D1 config
    ip_obj.config_ip_addr_interface(dut1, interface_name=vars.D1T1P2, ip_address=data.d1t2_ip_addr, subnet=data.mask,
                                    family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(dut1, interface_name=vars.D1T1P2, ip_address=data.d1t2_ipv6_addr,
                                    subnet=data.v6_mask,
                                    family="ipv6", config='add')
    # tgen config
    h3 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t2d1_ip_addr,
                                gateway=data.d1t2_ip_addr, src_mac_addr=data.t2d1_mac_addr, arp_send_req='1')
    h4 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t2d1_ipv6_addr,
                                ipv6_prefix_length=data.v6_mask, ipv6_gateway=data.d1t2_ipv6_addr,
                                src_mac_addr=data.t2d1_v6_mac_addr, arp_send_req='1')
    st.log("Ping check between spirent & UUT")
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_ph_1, dev_handle=h1['handle'], dst_ip=data.d1t1_ip_addr,
                            ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")
        st.report_fail("ping_fail", data.d1t1_ip_addr, 'spirent')

    st.log("Validating ipv4 Traffic between Spirent & UUT..")
    t1d1_stream_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                         pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                         rate_pps=10000, l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                                         mac_dst=data.dut_rt_int1_mac, ip_src_addr=data.t1d1_adv_ip_addr,
                                         ip_dst_addr=data.d1t2_ip_addr, mac_discovery_gw=data.d1t1_ip_addr)
    cli_to_enable_invalipackets_in_spirent = "stc::config {} -AllowInvalidHeaders true".format(
        t1d1_stream_1['stream_id'])
    sth.invoke(cli_to_enable_invalipackets_in_spirent)

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.report_fail("common_setup_fail".format("ipv4"))

    sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
    sth.invoke(sth_apply)

    st.log("Validating ipv6 Traffic between Spirent & UUT..")
    t1d1_v6stream_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                           pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                           rate_pps=10000, l3_protocol='ipv6', mac_src=data.t1_v4_stream_mac,
                                           mac_dst=data.dut_rt_int1_mac, ipv6_src_addr=data.t1d1_adv_ipv6_addr,
                                           ipv6_dst_addr=data.d1t2_ipv6_addr, mac_discovery_gw=data.d1t1_ipv6_addr)
    cli_to_enable_invalipackets_in_spirent = "stc::config {} -AllowInvalidHeaders true".format(
        t1d1_v6stream_1['stream_id'])
    sth.invoke(cli_to_enable_invalipackets_in_spirent)

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

    # enabling IPV4 stream & disabling IPV6 stream

    sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
    sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
    sth.invoke(sth_apply)

    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.warn("IPv6 Packet loss observed")

    yield
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    tg.tg_traffic_control(port_handle=tg_ph_1, stream_handle=t1d1_stream_1['stream_id'], action='reset')
    # clear ip address of RIF interfaces
    pass


@pytest.fixture(scope="function")
def drop_counters_func_hook_rif(request):
    global h1, h2, h3, h4, t1d1_stream_1

    st.log("Validating ipv4 Traffic between Spirent & UUT with correct parameters..")
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

    tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                         pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                         rate_pps=10000, l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                         mac_dst=data.dut_rt_int1_mac, ip_src_addr=data.t1d1_adv_ip_addr,
                         ip_dst_addr=data.d1t2_ip_addr, mac_discovery_gw=data.d1t1_ip_addr,
                         stream_id=t1d1_stream_1['stream_id'])

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.report_fail("common_setup_fail", "ipv4")

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])

    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.warn("IPv6 Packet loss observed")

    yield
    # clear ip address of RIF interfaces
    pass


@pytest.mark.usefixtures('drop_counters_class_hook_rif')
class Test_Drop_Counters_Rif():
    global h1, h2, h3, h4, t1d1_stream_1, t1d1_v6stream_1

    @pytest.mark.same_SMAC_DMAC
    def test_same_smac_dmac(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with same source and destination mac address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.dut_rt_int1_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of equal SMAC & DMAC and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} equal SMAC & DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has same SMAC and DMAC")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "same SMAC & DMAC", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.Mcast_SMAC
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_mcast_smac(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.mcast_SMAC, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of multicast sourceMac address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having Source MAC as Multicast MAC" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has multicastMAC as sourceMac address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has multicastMAC as sourceMac address", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.Reserved_DMAC
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_reserved_dmac(self):
        result = 0
        failure_msg = ""

        # testing Reserved MAC
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.reserved_DMAC,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets as destination MAC is in range of reserved MAC and {}"
                       " packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} reserved DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1

        # testing with Reserved Bridge group MAC
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.provider_bridgeg_DMAC,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats_2 = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count_2 = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets as destination MAC is in range of reserved MAC and {} "
                       "packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} reserved DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has DMAC in range of reserved MAC address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has reservedMAC as DMac address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.Loopback_Filter
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_loopback_filter(self):
        # configure static route
        result = 0
        failure_msg = ""
        ip_obj.create_static_route(dut1, vars.D1T1P1, data.d1t1_static_r)

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t1d1_static_r,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': 0}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        st.log("Unconfiguration : removing static route and changing stream config")

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        ip_obj.delete_static_route(dut1, vars.D1T1P1, data.d1t1_static_r)

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because Loop-back filter and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets " \
                              "having destination route on same incoming " \
                              "interface and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                                dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if Destination route pointing ingress port alone")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "loopback", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.exceed_MTU
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_exceed_mtu(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'],
                             frame_size=data.max_mtu_frame_size)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal MTU")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'],
                             frame_size=data.frame_size)

        check_port_stats = port_counters(dut1, {vars.D1T1P1: {'rx_ok': 0,
                                                              'rx_ovr': data.pkts_per_burst,
                                                              'rx_err': data.pkts_per_burst,
                                                              'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': 0, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_ovr = int(d1t1_interface_counters[0]['rx_ovr'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if dut_rx_value <= 5:
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (dut_rx_drop_value >= int(data.pkts_per_burst * 0.95)) and (
                    dut_rx_err >= int(data.pkts_per_burst * 0.95)) \
                    and (dut_rx_ovr >= int(data.pkts_per_burst * 0.95)):
                st.log("Due to Exceeding MTU size, DUT dropped {} packets and {} packets are errored out and {} "
                       "packets are noted as over sized".format(dut_rx_drop_value, dut_rx_err, dut_rx_ovr))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} Jumbo packets and {} " \
                              "packets are errored out and {} noted as over sized ".format \
                    (dut_rx_drop_value, data.pkts_per_burst, dut_rx_err, dut_rx_ovr)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped Jumbo packets as expected")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "Jumbo", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.Ttl_Expired
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_ttl_expired(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'], ip_ttl=0)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal ttl")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'], ip_ttl=255)

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})
        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} TTL expired packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} TTL expired packets instead of {} packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped all packets with TTL set to 0")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "TTL=0", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.non_routable_packets
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_non_routable_packets(self):

        import sth
        result = 0
        result_v1 = 0
        result_v2 = 0
        result_v3 = 0
        failure_msg = ""

        st.log("disabling IPV4 stream")

        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_apply)

        st.log("adding igmp v1 report header to existing stream")
        # igmp_cli = "stc::create igmp:IGMPV1 -under {}".format(t1d1_stream_1['stream_id'])
        # sth.invoke(igmp_cli)
        t1d1_ip_rif_stream_igmp_v1t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_version='1', igmp_type='2',
                                                            igmp_group_addr=data.mcast_group_ip,
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_report_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v1t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv1 report packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv1 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv1 report packets ")
        else:
            result_v1 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v1t2['stream_id'])
        st.log("disabling IGMP V1 req stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v1t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v1 query")
        t1d1_ip_rif_stream_igmp_v1t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_version='1', igmp_type='1',
                                                            igmp_group_addr="0.0.0.0", mac_src=data.t1_v4_stream_mac,
                                                            mac_dst=data.mcast_query_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_query_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v1t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv1 query packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv1 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv1 query packets")
        else:
            result_v1 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v1t1['stream_id'])
        st.log("disabling IGMP V1 query stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v1t1['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 report")

        t1d1_ip_rif_stream_igmp_v2t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst', igmp_msg_type='report',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_type='16',
                                                            igmp_group_addr=data.mcast_group_ip, igmp_version='2',
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_report_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v2t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(data.pkts_per_burst * 0.95)) \
                    and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 report packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 report packets")
        else:
            result_v2 = 1
        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v2t2['stream_id'])
        st.log("disabling IGMP V2 req stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v2t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 query")
        t1d1_ip_rif_stream_igmp_v2t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='query',
                                                            igmp_version='2', igmp_group_addr="0.0.0.0",
                                                            mac_src=data.t1_v4_stream_mac, igmp_type='11',
                                                            mac_dst=data.mcast_query_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_query_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v2t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 query packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 query packets")
        else:
            result_v2 = 1
        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v2t1['stream_id'])
        st.log("disabling IGMP V2 req stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v2t1['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 leave")
        t1d1_ip_rif_stream_igmp_v2t3 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='report',
                                                            igmp_group_addr=data.mcast_group_ip, igmp_version='2',
                                                            mac_src=data.t1_v4_stream_mac, igmp_type='17',
                                                            mac_dst=data.mcast_leave_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_leave_group_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v2t3['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 leave request packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 leave repquest packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 leave request packets")
        else:
            result_v2 = 1
        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v2t3['stream_id'])
        st.log("disabling IGMP V2 leave stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v2t3['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v3 report")

        t1d1_ip_rif_stream_igmp_v3t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst', igmp_type='22',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='report',
                                                            igmp_version='3',
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_report_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v3t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv3 report packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv3 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv3 report packets")
        else:
            result_v3 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v3t2['stream_id'])

        st.log("disabling IGMP V3 req stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v3t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v3 query")
        t1d1_ip_rif_stream_igmp_v3t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', igmp_type='11',
                                                            transmit_mode='single_burst', igmp_version='3',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='query',
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_query_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_query_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v3t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv3 query packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv3 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped IGMPv3 query packets")
        else:
            result_v3 = 1
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v3t1['stream_id'])

        st.log("disabling IGMP V3 query stream and enabling ipv4 stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v3t1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_apply)

        if result_v1 == 0 and result_v2 == 0 and result_v3 == 0:
            st.log("DUT dropped IGMP packets as expected")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "IGMP", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.IPV4_SIP
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_ipv4_sip(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.mcast_group_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.mcast_group_ip, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        st.log("Unconfiguration : Moving back to different source and destination mac address")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with source address as Mcast IP and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets with source address as Mcast IP and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with source address as Mcast IP")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has source address as Mcast IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.IPV6_SIP
    def test_ipv6_sip(self):
        import sth

        st.log("disabling Ipv4 stream & enabling IPV6 stream")

        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.mcast_SMAC, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.mcast_group_ip, ipv6_dst_addr=data.d1t2_ipv6_addr,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with source address as Mcast IPv6 and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets with source address as Mcast IPv6 and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with source address as Mcast IPv6")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has multicastIPV6 addr as sourceMac ip", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.loopback_dest_ip
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_dest_ip_as_loopback(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with destination as loopback address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.v4_loopback,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])


        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of loopback src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ip as loopback" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with dest ip as loopback address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has destination address as lo IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.loopback_src_ip
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_src_ip_as_loopback(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with destination as loopback address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.v4_loopback, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of loopback src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as loopback" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as loopback address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which has source address as lo IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.dst_ip_as_linklocal
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_dst_ip_as_linklocal(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with destination as linklocal address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.link_local_ip,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of link_local_ip dest ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ip as link_local_ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with dest ip as linklocal address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has dest address as linklocal IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.src_ip_as_linklocal
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_src_ip_as_linklocal(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with source as linklocal address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.link_local_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of link_local_ip src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as link_local_ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as linklocal address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has source address as linklocal IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v4src_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_v4src_ip_not_specified(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with invalid source ip address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.non_routable_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as 0.0.0.0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v4 src ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has doesn't have v4source IP addr",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.classE_src_ip
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_src_ip_as_class_e(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with source as CLASS E address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.class_e_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of class E src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as class e ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as CLASS E address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which has Class E source IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v6dest_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_v6dest_ip_not_specified(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with invalid dest ipv6 address")
        import sth
        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.t1d1_v6_mac_addr, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.t1d1_adv_ipv6_addr, ipv6_dst_addr=data.non_routable_ipv6,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid dest ipv6 address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ipv6 as ::0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v6 dest ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which doesn't had v6 dest address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v6src_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_v6src_ip_not_specified(self):

        result = 0
        failure_msg = ""
        import sth
        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        st.log("Generating packet with invalid source ip address")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.t1d1_v6_mac_addr, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.non_routable_ipv6, ipv6_dst_addr=data.t2d1_adv_ipv6_addr,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as ::0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v6 src ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which doesn't had v6 src address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v4dest_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_v4dest_ip_not_specified(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with invalid dest ip address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.non_routable_ip,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid dest ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ip as 0.0.0.0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v4 dest ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which doesn't had v4 dest address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_bad_version
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_bad_ip_version(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with bad ip version")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', version="1", mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of bad ip version and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having bad ip version" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with bad ip version")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with broken header",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_ihl_too_short
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_bad_ip_ihl_too_short(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with short ip header length ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', ip_hdr_length='1', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of short ip header length and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having short ip header length" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with short ip header length")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with short ihl",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_bad_checksum
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_bad_ip_checksum(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with bad ip checksum ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', ip_checksum="1", mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of bad ip checksum and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having bad ip checksum" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with bad ip checksum")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with bad checksum",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.no_ip_header
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_no_ip_header(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='disable', stream_id=t1d1_stream_1['stream_id'])
        st.log("Generating packet with no ip header ")
        t1d1_no_ip_header = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                 transmit_mode='single_burst',
                                                 pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                 rate_pps=10000,
                                                 l4_protocol='tcp', tcp_src_port=1024, tcp_dst_port=1024,
                                                 mac_src=data.t1_v4_stream_mac,
                                                 mac_dst=data.dut_rt_int1_mac
                                                 )
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_no_ip_header['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_no_ip_header['stream_id'])
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='enable', stream_id=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of no ip header and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having no ip header" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with no ip header")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with out IP header",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.erif_interface_disabled
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_erif_interface_disabled(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with erif disabled ")

        # interface_obj.interface_shutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        # pdb.set_trace()
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        papi.get_interface_counters(dut1, vars.D1T1P2)

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        interface_obj.interface_shutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))
        interface_obj.interface_noshutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with erif disabled which is not expected and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
                result = 1
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT didn't drop packets when  erif disabled")
            st.report_pass("drop_counters_not_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with erif disable",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.unicast_ip_with_mcast_dmac
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_unicast_ip_with_mcast_dmac(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with Unicast IP and MCAST DST MAC ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dest_mcast_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of mcast dmac and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets having unicast ip with mcast dmac" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with unicast ip and mcast dmac")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with unicast IP and Mcast MAC",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.unicast_ip_with_bcast_dmac
    @pytest.mark.usefixtures('drop_counters_func_hook_rif')
    def test_unicast_ip_with_bcast_dmac(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with Unicast IP and BCAST DST MAC ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.bcast_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of mcast dmac and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets having unicast ip with bcast dmac" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with unicast ip and bcast dmac")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with Unicast IP and Bcast MAC",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)


@pytest.fixture(scope="class")
def drop_counters_class_hook_vlan(request):
    global h1, h2, h3, h4, dut1, t1d1_ip_vlan_stream_1, sth_disable_stream, t1d1_ip_vlan_v6stream_1, \
        sth_disable_stream, sth_enable_stream, sth_apply

    vlan_obj.create_vlan_and_add_members(data.vlan_data)
    import sth

    # tgen config
    h1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
                                gateway=data.d1t1_ip_addr, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    h2 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,
                                ipv6_prefix_length=data.v6_mask, ipv6_gateway=data.d1t1_ipv6_addr,
                                src_mac_addr=data.t1d1_v6_mac_addr, arp_send_req='1')

    h3 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t2d1_ip_addr,
                                gateway=data.d1t2_ip_addr, src_mac_addr=data.t2d1_mac_addr, arp_send_req='1')
    h4 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t2d1_ipv6_addr,
                                ipv6_prefix_length=data.v6_mask, ipv6_gateway=data.d1t2_ipv6_addr,
                                src_mac_addr=data.t2d1_v6_mac_addr, arp_send_req='1')

    # stream creation
    t1d1_ip_vlan_stream_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                                 rate_pps=10000,
                                                 pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                 vlan_id=data.vlan,
                                                 l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac,
                                                 l3_protocol='ipv4',
                                                 mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                                                 ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t1_ip_addr)

    t1d1_ip_vlan_v6stream_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                                   pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                   vlan_id=data.vlan,
                                                   rate_pps=10000, l3_protocol='ipv6', mac_src=data.t1_v4_stream_mac,
                                                   mac_dst=data.dut_rt_int1_mac, ipv6_src_addr=data.t1d1_adv_ipv6_addr,
                                                   ipv6_dst_addr=data.d1t2_ipv6_addr,
                                                   mac_discovery_gw=data.d1t1_ipv6_addr)

    cli_to_enable_invalipackets_in_spirent = "stc::config {} -AllowInvalidHeaders true".format(
        t1d1_ip_vlan_v6stream_1['stream_id'])
    sth.invoke(cli_to_enable_invalipackets_in_spirent)

    cli_to_enable_invalipackets_in_spirent = "stc::config {} -AllowInvalidHeaders true".format(
        t1d1_ip_vlan_stream_1['stream_id'])
    sth.invoke(cli_to_enable_invalipackets_in_spirent)
    sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
    sth.invoke(sth_apply)

    yield
    vlan_obj.delete_vlan_member(dut1, vlan=data.vlan, port_list=[vars.D1T1P1, vars.D1T1P2])
    vlan_obj.delete_vlan(dut1, data.vlan)
    tg.tg_traffic_control(port_handle=tg_ph_1, stream_handle=t1d1_ip_vlan_stream_1['stream_id'], action='reset')


@pytest.fixture(scope="function")
def ip_vlan_func_hook(request):
    import sth
    global h1, h2, h3, h4, t1d1_ip_vlan_stream_1, t1d1_ip_vlan_v6stream_1, dut1

    st.log("Validating ipv4 Traffic between Spirent & UUT with proper fields...")

    tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
    tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                         pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                         l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                         mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size, mac_discovery_gw=data.d1t1_ip_addr,
                         ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t1_ip_addr,
                         stream_id=t1d1_ip_vlan_stream_1['stream_id'])
    st.show(dut1, "sonic-clear counters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
    dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")

    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.report_fail("drop_counters_not_incremented", dut_rx_value, "Good", dut_rx_drop_value, data.pkts_per_burst, 0)

    yield
    # clear ip address of RIF interfaces
    pass


@pytest.mark.usefixtures('drop_counters_class_hook_vlan')
class Test_Drop_Counters_Vlan():
    global h1, h2, h3, h4, t1d1_ip_vlan_stream_1, t1d1_eth_vlan_v6stream_1

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.same_SMAC_DMAC
    def test_same_smac_dmac(self):

        result = 0
        failure_msg = ""

        st.log("Generating packet with same source and destination mac address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.dut_rt_int1_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_port_stats:
            st.log('port stats are as expected')
        else:
            st.warn('port stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of equal SMAC & DMAC and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} equal SMAC & DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has same SMAC and DMAC")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "same SMAC and DMAC", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.Different_Vlan_Tag
    def test_Different_Vlan_Tag(self):

        result = 0
        failure_msg = ""

        st.log("Generating packet with different Vlan ID")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan_1,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_port_stats:
            st.log('port stats are as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of equal SMAC & DMAC and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} equal SMAC & DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has same SMAC and DMAC")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "different Vlan tag", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.Mcast_SMAC
    def test_mcast_smac(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.mcast_SMAC, frame_size=data.frame_size, mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_port_stats:
            st.log('port stats are as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of multicast sourceMac address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having " \
                              "Source MAC as Multicat MAC" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has multicastMAC as sourceMac address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with multicastMAC as sourceMac address", dut_rx_drop_value, data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.Reserved_DMAC
    def test_reserved_dmac(self):

        result = 0
        failure_msg = ""

        # testing Reserved MAC

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.reserved_DMAC, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_port_stats:
            st.log('port stats are as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets as destination MAC is in range of reserved MAC and {}"
                       " packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} reserved DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1

        # testing with Reserved Bridge group MAC

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.provider_bridgeg_DMAC, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats_2 = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count_2 = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets as destination MAC is in range of reserved MAC and {} "
                       "packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} reserved DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has DMAC in range of reserved MAC address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with reservedMAC as DMAC address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.Loopback_Filter
    def test_loopback_filter(self):
        # configure static route

        result = 0
        failure_msg = ""
        ip_obj.create_static_route(dut1, "Vlan{}".format(data.vlan), data.d1t1_static_r)

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t1d1_static_r,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': 0}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        st.log("Unconfiguration : removing static route and changing stream config")

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
        ip_obj.delete_static_route(dut1, "Vlan{}".format(data.vlan), data.d1t1_static_r)

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because Loop-back filter and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets having destination route on same incoming " \
                              "interface and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                                dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if Destination route pointing ingress port alone")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "loopback", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.exceed_MTU
    def test_exceed_mtu(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.max_mtu_frame_size,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal MTU")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {vars.D1T1P1: {'rx_ok': 0,
                                                              'rx_ovr': data.pkts_per_burst,
                                                              'rx_err': data.pkts_per_burst,
                                                              'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': 0, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_ovr = int(d1t1_interface_counters[0]['rx_ovr'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal MTU")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if dut_rx_value <= 5:
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (dut_rx_drop_value >= int(data.pkts_per_burst * 0.95)) and (
                    dut_rx_err >= int(data.pkts_per_burst * 0.95)) \
                    and (dut_rx_ovr >= int(data.pkts_per_burst * 0.95)):
                st.log("Due to Exceeding MTU size, DUT dropped {} packets and {} packets are errored out and {} "
                       "packets are noted as over sized".format(dut_rx_drop_value, dut_rx_err, dut_rx_ovr))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} Jumbo packets and {} " \
                              "packets are errored out and {} noted as over sized ".format \
                    (dut_rx_drop_value, data.pkts_per_burst, dut_rx_err, dut_rx_ovr)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped Jumbo packets as expected")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "Jumbo", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.Ttl_Expired
    def test_ttl_expired(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'], ip_ttl=0)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal ttl")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'], ip_ttl=255)

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})
        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} TTL expired packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} TTL expired packets instead of {} packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped all packets with TTL set to 0")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "TTL = 0 ", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.non_routable_packets
    def test_non_routable_packets(self):

        import sth
        result = 0
        result_v1 = 0
        result_v2 = 0
        result_v3 = 0
        failure_msg = ""

        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_apply)

        st.log("adding igmp v1 report header to existing stream")
        t1d1_ip_vlan_stream_igmp_v1t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                             transmit_mode='single_burst',
                                                             rate_pps=10000, pkts_per_burst=data.pkts_per_burst,
                                                             ip_protocol=2,
                                                             vlan_id=data.vlan, l2_encap='ethernet_ii_vlan',
                                                             length_mode='fixed',
                                                             mac_dst=data.mcast_group_mac, l3_protocol='ipv4',
                                                             l4_protocol='igmp',
                                                             igmp_version='1', igmp_type='2',
                                                             mac_src=data.t1_v4_stream_mac,
                                                             ip_src_addr=data.t1d1_adv_ip_addr, frame_size=80,
                                                             ip_dst_addr=data.mcast_report_ip,
                                                             igmp_group_addr=data.mcast_group_ip,
                                                             mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v1t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv1 report packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv1 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv1 report packets ")
        else:
            result_v1 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v1t2['stream_id'])
        st.log('disabling V1 report stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v1t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v1 query")

        t1d1_ip_vlan_stream_igmp_v1t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                             transmit_mode='single_burst',
                                                             rate_pps=10000, pkts_per_burst=data.pkts_per_burst,
                                                             ip_protocol=2,
                                                             vlan_id=data.vlan, l2_encap='ethernet_ii_vlan',
                                                             length_mode='fixed',
                                                             mac_dst=data.mcast_query_mac, l3_protocol='ipv4',
                                                             l4_protocol='igmp',
                                                             igmp_version='1', igmp_type='1',
                                                             mac_src=data.t1_v4_stream_mac, frame_size=80,
                                                             ip_src_addr=data.t1d1_adv_ip_addr,
                                                             ip_dst_addr=data.mcast_query_ip,
                                                             igmp_group_addr='0.0.0.0',
                                                             mac_discovery_gw=data.d1t1_ip_addr)
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v1t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv1 query packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv1 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv1 query packets")
        else:
            result_v1 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v1t1['stream_id'])
        st.log('disabling V1 query stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v1t1['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 report")

        t1d1_ip_vlan_stream_igmp_v2t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                             transmit_mode='single_burst',
                                                             rate_pps=10000, pkts_per_burst=data.pkts_per_burst,
                                                             ip_protocol=2, vlan_id=data.vlan, igmp_msg_type='report',
                                                             l2_encap='ethernet_ii_vlan', length_mode='fixed',
                                                             mac_dst=data.mcast_group_mac, l3_protocol='ipv4',
                                                             l4_protocol='igmp', igmp_version='2', igmp_type='16',
                                                             mac_src=data.t1_v4_stream_mac, frame_size=80,
                                                             ip_src_addr=data.t1d1_adv_ip_addr,
                                                             ip_dst_addr=data.mcast_report_ip,
                                                             igmp_group_addr=data.mcast_group_ip,
                                                             mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v2t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(data.pkts_per_burst * 0.95)) \
                    and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 report packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 report packets")
        else:
            result_v2 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v2t2['stream_id'])
        st.log('disabling V2 report stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v2t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 query")

        t1d1_ip_vlan_stream_igmp_v2t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                             transmit_mode='single_burst', rate_pps=10000,
                                                             pkts_per_burst=data.pkts_per_burst,
                                                             ip_protocol=2, vlan_id=data.vlan, igmp_msg_type='query',
                                                             l2_encap='ethernet_ii_vlan', length_mode='fixed',
                                                             mac_dst=data.mcast_query_mac, l3_protocol='ipv4',
                                                             l4_protocol='igmp', igmp_version='2', igmp_type='11',
                                                             mac_src=data.t1_v4_stream_mac, frame_size=80,
                                                             ip_src_addr=data.t1d1_adv_ip_addr,
                                                             ip_dst_addr=data.mcast_query_ip, igmp_group_addr='0.0.0.0',
                                                             mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v2t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 query packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 query packets")
        else:
            result_v2 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v2t1['stream_id'])
        st.log('disabling V2 query stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v2t1['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 leave")

        t1d1_ip_vlan_stream_igmp_v2t3 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', igmp_msg_type='report',
                                                             transmit_mode='single_burst', rate_pps=10000,
                                                             pkts_per_burst=data.pkts_per_burst, ip_protocol=2,
                                                             vlan_id=data.vlan, l2_encap='ethernet_ii_vlan',
                                                             length_mode='fixed', mac_dst=data.mcast_leave_group_mac,
                                                             l3_protocol='ipv4', l4_protocol='igmp', igmp_version='2',
                                                             igmp_type='17', mac_src=data.t1_v4_stream_mac,
                                                             ip_src_addr=data.t1d1_adv_ip_addr, frame_size=80,
                                                             ip_dst_addr=data.mcast_leave_group_ip,
                                                             igmp_group_addr=data.mcast_group_ip,
                                                             mac_discovery_gw=data.d1t1_ip_addr)
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v2t3['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 leave request packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 leave repquest packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 leave request packets")
        else:
            result_v2 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v2t3['stream_id'])

        st.log('disabling V2 leave stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v2t3['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v3 report")

        t1d1_ip_vlan_stream_igmp_v3t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', ip_protocol=2,
                                                             transmit_mode='single_burst', rate_pps=10000,
                                                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                             vlan_id=data.vlan, igmp_msg_type='report', igmp_type='22',
                                                             l2_encap='ethernet_ii_vlan', mac_dst=data.mcast_group_mac,
                                                             l3_protocol='ipv4', l4_protocol='igmp', igmp_version='3',
                                                             mac_src=data.t1_v4_stream_mac, frame_size=80,
                                                             ip_src_addr=data.t1d1_adv_ip_addr,
                                                             ip_dst_addr=data.mcast_report_ip,
                                                             mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v3t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv3 report packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv3 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv3 report packets")
        else:
            result_v3 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v3t2['stream_id'])

        st.log('disabling V3 report stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v3t2['stream_id']))
        sth.invoke(sth_apply)
        st.log("configuring IGMP v3 query")

        t1d1_ip_vlan_stream_igmp_v3t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=10000,
                                                             transmit_mode='single_burst', igmp_msg_type='query',
                                                             pkts_per_burst=data.pkts_per_burst, ip_protocol=2,
                                                             vlan_id=data.vlan, l2_encap='ethernet_ii_vlan',
                                                             length_mode='fixed', mac_dst=data.mcast_query_mac,
                                                             l3_protocol='ipv4', ip_src_addr=data.t1d1_adv_ip_addr,
                                                             l4_protocol='igmp', igmp_version='3', igmp_type='11',
                                                             mac_src=data.t1_v4_stream_mac, frame_size=80,
                                                             ip_dst_addr=data.mcast_query_ip,
                                                             mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_igmp_v3t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv3 query packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv3 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped IGMPv3 query packets")
        else:
            result_v3 = 1
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_igmp_v3t1['stream_id'])

        st.log('disabling V3 query stream')
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_igmp_v3t1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_apply)

        if result_v1 == 0 and result_v2 == 0 and result_v3 == 0:
            st.log("DUT dropped IGMP packets as expected")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "IGMP", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.IPV4_SIP
    def test_ipv4_sip(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.mcast_group_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.mcast_group_ip, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_ip_vlan_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        st.log("Unconfiguration : Moving back to different source and destination mac address")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with source address as Mcast IP and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets with source address as Mcast IP and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with source address as Mcast IP")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with multicastIP as source IP address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.IPV6_SIP
    def test_ipv6_sip(self):
        import sth

        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.mcast_SMAC, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.mcast_group_ip, ipv6_dst_addr=data.d1t2_ipv6_addr,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_ip_vlan_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_v6stream_1['stream_id'])

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_v6stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_apply)

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with source address as Mcast IPv6 and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets with source address as Mcast IPv6 and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with source address as Mcast IPv6")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with multicastIP as source IP (IPV6)",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.loopback_dest_ip
    def test_dest_ip_as_loopback(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.v4_loopback,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of dst ip as loopback address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dst ip as loopback ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with Destination IP as Loopback address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Destination IP as Loopback IP ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.loopback_src_ip
    def test_src_ip_as_loopback(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.v4_loopback, ip_dst_addr=data.t2d1_adv_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of src ip as loopback address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as loopback ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with Source IP as Loopback address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Source IP as Loopback IP ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.src_ip_as_linklocal
    def test_src_ip_as_linklocal(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.link_local_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        # pdb.set_trace()
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of src ip as linklocal address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as linklocal ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with Source IP as Linklocal address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Source IP as Linklocal IP ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.dst_ip_as_linklocal
    def test_dst_ip_as_linklocal(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.link_local_ip,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of dst ip as linklocal address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dst ip as linklocal ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has Destination IP as Linklocal address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Destination IP as Linklocal IP ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.v4src_ip_not_specified
    def test_v4src_ip_not_specified(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.non_routable_ip, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        # pdb.set_trace()
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of non-routable V4 src ip address 0.0.0.0 and {} packets are "
                       "errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as 0.0.0.0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with non routable V4 src ip 0.0.0.0")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Invalid Source IP 0.0.0.0 ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.v4dest_ip_not_specified
    def test_v4dest_ip_not_specified(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.non_routable_ip,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of non-routable "
                       "V4 dst ip address 0.0.0.0 and {} packets are errored out".format(dut_rx_drop_value, dut_rx_err))          
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dst ip as 0.0.0.0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with non routable V4 dst ip 0.0.0.")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Invalid Destination IP 0.0.0.0 ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.classE_src_ip
    def test_src_ip_as_class_e(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.class_e_ip, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of Class E src ip address and "
                       "{} packets are errored out".format(dut_rx_drop_value, dut_rx_err))           
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets " \
                              "which are having src ip as Class E ip address" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as Class E ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Class E Destination IP address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.v6dest_ip_not_specified
    def test_v6dest_ip_not_specified(self):
        import sth

        result = 0
        failure_msg = ""
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv6',
                             mac_src=data.t1d1_v6_mac_addr, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ipv6_addr, ip_dst_addr=data.non_routable_ipv6,
                             stream_id=t1d1_ip_vlan_v6stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log(
                    "DUT dropped {} packets because of non-routable V6 dst ip address ::0 "
                    "and {} packets are errored out".format(dut_rx_drop_value, dut_rx_err))

            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dst ipv6 as ::0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with non routable V6 dst ip ::0")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Invalid Destination IPv6 address ::0",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.usefixtures('ip_vlan_func_hook')
    @pytest.mark.v6src_ip_not_specified
    def test_v6src_ip_not_specified(self):
        import sth

        result = 0
        failure_msg = ""
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv6',
                             mac_src=data.t1d1_v6_mac_addr, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.non_routable_ipv6, ip_dst_addr=data.d1t2_ipv6_addr,
                             stream_id=t1d1_ip_vlan_v6stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of non-routable V6 src ip address ::0 and"
                       " {} packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ipv6 as ::0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with non routable V6 src ip ::0")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Invalid Source IPv6 address ::0",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_ihl_too_short
    @pytest.mark.usefixtures('ip_vlan_func_hook')
    def test_bad_ip_ihl_too_short(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with short ip header length ")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             ip_hdr_length='1', mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of short ip header length and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets which are having short ip header length" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with short ip header length")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with short IP IHL",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_bad_checksum
    @pytest.mark.usefixtures('ip_vlan_func_hook')
    def test_bad_ip_checksum(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with bad ip checksum ")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             ip_checksum="1", mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of bad ip checksum and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having bad ip checksum" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with bad ip checksum")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with Bad IP Checksum",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.no_ip_header
    @pytest.mark.usefixtures('ip_vlan_func_hook')
    def test_no_ip_header(self):

        result = 0
        failure_msg = ""
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        st.log("Generating packet with no ip header ")
        t1d1_no_ip_header = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                                 rate_pps=10000,
                                                 pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                 vlan_id=data.vlan,
                                                 l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac,
                                                 mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                                                 l4_protocol='tcp', tcp_src_port=1024, tcp_dst_port=1024
                                                 )
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_no_ip_header['stream_id'])
        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_no_ip_header['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_ip_vlan_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of no ip header and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having no ip header" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with no ip header")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets with No IP Header",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.erif_interface_disabled
    @pytest.mark.usefixtures('ip_vlan_func_hook')
    def test_erif_interface_disabled(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with erif disabled ")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dut_rt_int1_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
        papi.get_interface_counters(dut1, vars.D1T1P2)

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        interface_obj.interface_shutdown(dut1, interfaces=data.portchannel_name2, skip_verify=False)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))
        interface_obj.interface_noshutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with erif disabled which is not expected and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
                result = 1
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT didn't drop packets when erif disabled")
            st.report_pass("drop_counters_not_incremented")
        else:
            st.log("DUT dropped packets when erif disabled")
            st.report_fail("drop_counters_incremented")

    @pytest.mark.unicast_ip_with_mcast_dmac
    @pytest.mark.usefixtures('ip_vlan_func_hook')
    def test_unicast_ip_with_mcast_dmac(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with Unicast IP and MCAST DST MAC ")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.dest_mcast_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of mcast dmac and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets " \
                              "which are having unicast ip with mcast dmac" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with unicast ip and mcast dmac")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "Unicast IP packets with MCAST DMAC ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.unicast_ip_with_bcast_dmac
    @pytest.mark.usefixtures('ip_vlan_func_hook')
    def test_unicast_ip_with_bcast_dmac(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with Unicast IP and BCAST DST MAC ")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst', rate_pps=10000,
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', vlan_id=data.vlan,
                             l2_encap='ethernet_ii_vlan', mac_dst=data.bcast_mac, l3_protocol='ipv4',
                             mac_src=data.t1_v4_stream_mac, frame_size=data.frame_size,
                             mac_discovery_gw=data.d1t1_ip_addr,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             stream_id=t1d1_ip_vlan_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        # pdb.set_trace()
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_vlan_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of mcast dmac and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets " \
                              "which are having unicast ip with bcast dmac" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with unicast ip and bcast dmac")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "Unicast IP packets with BCAST DMAC ",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)


@pytest.fixture(scope="class")
def drop_counters_class_hook_portchannel(request):
    # T1D1 config
    import sth

    global h1, h2, h3, h4, t1d1_stream_1, t1d1_v6stream_1, \
        t2d1_stream_1, sth_disable_stream, sth_enable_stream, sth_apply

    portc_obj._config_portchannel(dut1, portchannel_name=data.portchannel_name1, members=vars.D1T1P1, config='add')
    ip_obj.config_ip_addr_interface(dut1, interface_name=data.portchannel_name1, ip_address=data.d1t1_ip_addr,
                                    subnet=data.mask,
                                    family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(dut1, interface_name=data.portchannel_name1, ip_address=data.d1t1_ipv6_addr,
                                    subnet=data.v6_mask,
                                    family="ipv6", config='add')
    # tgen config
    tg.tg_emulation_lacp_config(port_handle=tg_ph_1, mode='enable')
    tg.tg_emulation_lacp_control(port_handle=tg_ph_1, action='start')
    h1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
                                gateway=data.d1t1_ip_addr, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    h2 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,
                                ipv6_prefix_length=data.v6_mask, ipv6_gateway=data.d1t1_ipv6_addr,
                                src_mac_addr=data.t1d1_v6_mac_addr, arp_send_req='1')
    # T2D1 config

    portc_obj._config_portchannel(dut1, portchannel_name=data.portchannel_name2, members=vars.D1T1P2, config='add')
    ip_obj.config_ip_addr_interface(dut1, interface_name=data.portchannel_name2, ip_address=data.d1t2_ip_addr,
                                    subnet=data.mask,
                                    family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(dut1, interface_name=data.portchannel_name2, ip_address=data.d1t2_ipv6_addr,
                                    subnet=data.v6_mask,
                                    family="ipv6", config='add')
    # tgen config
    tg.tg_emulation_lacp_config(port_handle=tg_ph_2, mode='enable')
    tg.tg_emulation_lacp_control(port_handle=tg_ph_2, action='start')
    h3 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t2d1_ip_addr,
                                gateway=data.d1t2_ip_addr, src_mac_addr=data.t2d1_mac_addr, arp_send_req='1')
    h4 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t2d1_ipv6_addr,
                                ipv6_prefix_length=data.v6_mask, ipv6_gateway=data.d1t2_ipv6_addr,
                                src_mac_addr=data.t2d1_v6_mac_addr, arp_send_req='1')
    st.log("Ping check between spirent & UUT")
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_ph_1, dev_handle=h1['handle'], dst_ip=data.d1t1_ip_addr,
                            ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")
        st.report_fail("ping_fail", data.d1t1_ip_addr, 'spirent')

    st.log("Validating ipv4 Traffic between Spirent & UUT..")
    t1d1_stream_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                         pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                         rate_pps=10000, l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                                         mac_dst=data.dut_rt_int1_mac, ip_src_addr=data.t1d1_adv_ip_addr,
                                         ip_dst_addr=data.d1t2_ip_addr, mac_discovery_gw=data.d1t1_ip_addr)
    cli_to_enable_invalipackets_in_spirent = "stc::config {} -AllowInvalidHeaders true".format(
        t1d1_stream_1['stream_id'])
    sth.invoke(cli_to_enable_invalipackets_in_spirent)

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.report_fail("common_setup_fail", "ipv4")

    sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
    sth.invoke(sth_apply)
    st.log("Validating ipv6 Traffic between Spirent & UUT..")
    t1d1_v6stream_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                           pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                           rate_pps=10000, l3_protocol='ipv6', mac_src=data.t1_v4_stream_mac,
                                           mac_dst=data.dut_rt_int1_mac, ipv6_src_addr=data.t1d1_adv_ipv6_addr,
                                           ipv6_dst_addr=data.d1t2_ipv6_addr, mac_discovery_gw=data.d1t1_ipv6_addr)
    cli_to_enable_invalipackets_in_spirent = "stc::config {} -AllowInvalidHeaders true".format(
        t1d1_v6stream_1['stream_id'])
    sth.invoke(cli_to_enable_invalipackets_in_spirent)

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
    sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
    sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
    sth.invoke(sth_apply)

    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.warn("IPv6 Packet loss observed")

    t2d1_stream_1 = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst',
                                         pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                         rate_pps=10000, l3_protocol='ipv4', mac_src=data.t2_v4_stream_mac,
                                         mac_dst=data.dut_rt_int2_mac, ip_src_addr=data.t2d1_adv_ip_addr,
                                         ip_dst_addr=data.d1t1_ip_addr, mac_discovery_gw=data.d1t2_ip_addr)
    tg.tg_traffic_control(action='run', stream_handle=t2d1_stream_1['stream_id'])
    tg.tg_traffic_control(action='stop', stream_handle=t2d1_stream_1['stream_id'])
    papi.get_interface_counters(dut1, vars.D1T1P2)

    yield
    portc_obj.clear_portchannel_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    # clear ip address of RIF interfaces
    pass


@pytest.fixture(scope="function")
def drop_counters_func_hook_portchannel(request):
    global h1, h2, h3, h4, t1d1_stream_1

    st.log("Validating ipv4 Traffic between Spirent & UUT with correct parameters..")
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

    tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                         pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                         rate_pps=10000, l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                         mac_dst=data.dut_rt_int1_mac, ip_src_addr=data.t1d1_adv_ip_addr,
                         ip_dst_addr=data.d1t2_ip_addr, mac_discovery_gw=data.d1t1_ip_addr,
                         stream_id=t1d1_stream_1['stream_id'])

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")

    tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
    d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
    dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))

    check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
    tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
    if int(data.pkts_per_burst * 0.95) <= dut_rx_value:
        st.log("UUT received transmitted packets")
        if check_l3_count:
            st.log("L3 counters are as expected")
        else:
            st.warn("L3 Packet loss was observed")
    else:
        st.log("{} packets received out of {} packets".format(dut_rx_value, data.pkts_per_burst))
        st.report_fail("common_setup_fail", "ipv4")

    st.show(dut1, "sonic-clear counters")
    st.show(dut1, "sonic-clear rifcounters")
    yield
    # clear ip address of RIF interfaces
    pass


@pytest.mark.usefixtures('drop_counters_class_hook_portchannel')
class Test_Drop_Counters_PortChannel():
    global h1, h2, h3, h4, t1d1_stream_1, t1d1_v6stream_1

    @pytest.mark.same_SMAC_DMAC
    def test_same_smac_dmac(self):

        result = 0
        failure_msg = ""
        st.log("Generating packet with same source and destination mac address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.dut_rt_int1_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of equal SMAC & DMAC and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} equal SMAC & DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has same SMAC and DMAC")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "same SMAC & DMAC", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.Mcast_SMAC
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_mcast_smac(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.mcast_SMAC, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of multicast sourceMac address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets " \
                              "which are having Source MAC as Multicat MAC" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has multicastMAC as sourceMac address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has multicastMAC as sourceMac address", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.Reserved_DMAC
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_reserved_dmac(self):
        result = 0
        failure_msg = ""

        # testing Reserved MAC
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.reserved_DMAC,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets as destination MAC is in range of reserved MAC and {}"
                       " packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} reserved DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1

        # teesting with Reserved Bridge group MAC
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.provider_bridgeg_DMAC,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats_2 = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count_2 = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets as destination MAC is in range of reserved MAC and {} "
                       "packets are errored out".format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} reserved DMAC packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if it has DMAC in range of reserved MAC address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has reservedMAC as DMac address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.Loopback_Filter
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_loopback_filter(self):
        # configure static route
        result = 0
        failure_msg = ""
        ip_obj.create_static_route(dut1, vars.D1T1P1, data.d1t1_static_r)

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t1d1_static_r,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        check_port_stats = port_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': 0}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        st.log("Unconfiguration : removing static route and changing stream config")

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        ip_obj.delete_static_route(dut1, vars.D1T1P1, data.d1t1_static_r)

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because Loop-back filter and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets having dest route on same incoming " \
                              "interface and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                                dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets if Destination route pointing ingress port alone")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "loopback", dut_rx_drop_value,
                           data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.exceed_MTU
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_exceed_mtu(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'],
                             frame_size=data.max_mtu_frame_size)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal MTU")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'],
                             frame_size=data.frame_size)

        check_port_stats = port_counters(dut1, {vars.D1T1P1: {'rx_ok': 0,
                                                              'rx_ovr': data.pkts_per_burst,
                                                              'rx_err': data.pkts_per_burst,
                                                              'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': 0, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_ovr = int(d1t1_interface_counters[0]['rx_ovr'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if dut_rx_value <= 5:
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (dut_rx_drop_value >= int(data.pkts_per_burst * 0.95)) and (
                    dut_rx_err >= int(data.pkts_per_burst * 0.95)) \
                    and (dut_rx_ovr >= int(data.pkts_per_burst * 0.95)):
                st.log("Due to Exceeding MTU size, DUT dropped {} packets and {} packets are errored out and {} "
                       "packets are noted as over sized".format(dut_rx_drop_value, dut_rx_err, dut_rx_ovr))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} Jumbo packets and {} " \
                              "packets are errored out and {} noted as " \
                              "over sized ".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err, dut_rx_ovr)
                              
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped Jumbo packets as expected")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "Jumbo", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.Ttl_Expired
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_ttl_expired(self):

        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'], ip_ttl=0)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        st.log("Unconfiguration : Moving back to normal ttl")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'], ip_ttl=255)

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})
        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} TTL expired packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} TTL expired packets instead of {} packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped all packets with TTL set to 0")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "TTL=0", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.non_routable_packets
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_non_routable_packets(self):

        import sth
        result = 0
        result_v1 = 0
        result_v2 = 0
        result_v3 = 0
        failure_msg = ""

        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_apply)
        st.log("adding igmp v1 report header to existing stream")

        # igmp_cli = "stc::create igmp:IGMPV1 -under {}".format(t1d1_stream_1['stream_id'])
        # sth.invoke(igmp_cli)
        t1d1_ip_rif_stream_igmp_v1t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_version='1', igmp_type='2',
                                                            igmp_group_addr=data.mcast_group_ip,
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_report_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v1t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv1 report packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv1 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv1 report packets ")
        else:
            result_v1 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v1t2['stream_id'])
        st.log("disabling V1 request stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v1t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v1 query")
        t1d1_ip_rif_stream_igmp_v1t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_version='1', igmp_type='1',
                                                            igmp_group_addr="0.0.0.0", mac_src=data.t1_v4_stream_mac,
                                                            mac_dst=data.mcast_query_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_query_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v1t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv1 query packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv1 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv1 query packets")
        else:
            result_v1 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v1t1['stream_id'])
        st.log("disabling V1 query stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v1t1['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 report")

        t1d1_ip_rif_stream_igmp_v2t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst', igmp_msg_type='report',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_type='16',
                                                            igmp_group_addr=data.mcast_group_ip, igmp_version='2',
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_report_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v2t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(data.pkts_per_burst * 0.95)) \
                    and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 report packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 report packets")
        else:
            result_v2 = 1
        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v2t2['stream_id'])

        st.log("disabling V2 request stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v2t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 query")
        t1d1_ip_rif_stream_igmp_v2t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='query',
                                                            igmp_version='2', igmp_group_addr="0.0.0.0",
                                                            mac_src=data.t1_v4_stream_mac, igmp_type='11',
                                                            mac_dst=data.mcast_query_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_query_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v2t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 query packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 query packets")
        else:
            result_v2 = 1
        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v2t1['stream_id'])

        st.log("disabling V2 query stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v2t1['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v2 leave")
        t1d1_ip_rif_stream_igmp_v2t3 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='report',
                                                            igmp_group_addr=data.mcast_group_ip, igmp_version='2',
                                                            mac_src=data.t1_v4_stream_mac, igmp_type='17',
                                                            mac_dst=data.mcast_leave_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_leave_group_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v2t3['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv2 leave request packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv2 leave repquest packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv2 leave request packets")
        else:
            result_v2 = 1
        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v2t3['stream_id'])
        st.log("disabling V2 leave req stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v2t3['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v3 report")

        t1d1_ip_rif_stream_igmp_v3t2 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                            transmit_mode='single_burst', igmp_type='22',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='report',
                                                            igmp_version='3',
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_group_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_report_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v3t2['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv3 report packets  and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv3 report packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            result = 1
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
        if result == 0:
            st.log("DUT dropped IGMPv3 report packets")
        else:
            result_v3 = 1

        result = 0
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v3t2['stream_id'])

        st.log("disabling V3 request stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v3t2['stream_id']))
        sth.invoke(sth_apply)

        st.log("configuring IGMP v3 query")
        t1d1_ip_rif_stream_igmp_v3t1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', igmp_type='11',
                                                            transmit_mode='single_burst', igmp_version='3',
                                                            pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                            rate_pps=10000, l3_protocol='ipv4', ip_protocol=2,
                                                            l4_protocol='igmp', igmp_msg_type='query',
                                                            mac_src=data.t1_v4_stream_mac, mac_dst=data.mcast_query_mac,
                                                            ip_src_addr=data.t1d1_adv_ip_addr,
                                                            ip_dst_addr=data.mcast_query_ip,
                                                            mac_discovery_gw=data.d1t1_ip_addr)

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_ip_rif_stream_igmp_v3t1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': data.pkts_per_burst}})
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} IGMPv3 query packets and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} IGMPv3 query packets instead of {}  packets and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped IGMPv3 query packets")
        else:
            result_v3 = 1
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_ip_rif_stream_igmp_v3t1['stream_id'])
        st.log("disabling V3 query stream")
        sth.invoke(sth_disable_stream.format(t1d1_ip_rif_stream_igmp_v3t1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_apply)

        if result_v1 == 0 and result_v2 == 0 and result_v3 == 0:
            st.log("DUT dropped IGMP packets as expected")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "IGMP", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.IPV4_SIP
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_ipv4_sip(self):

        result = 0
        failure_msg = ""

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.mcast_group_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.mcast_group_ip, ip_dst_addr=data.d1t2_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        st.log("Unconfiguration : Moving back to different source and destination mac address")
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with source address as Mcast IP and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets with source address as Mcast IP and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with source address as Mcast IP")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has source address as Mcast IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.IPV6_SIP
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_ipv6_sip(self):
        import sth

        result = 0
        failure_msg = ""
        sth.invoke(sth_enable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_apply)

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.mcast_SMAC, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.mcast_group_ip, ipv6_dst_addr=data.d1t2_ipv6_addr,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface & port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with source address as Mcast IPv6 and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {} packets with source address as Mcast IPv6 and {} " \
                              "packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst, dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with source address as Mcast IPv6")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has multicastIPV6 addr as sourceMac ip", dut_rx_drop_value,
                           data.pkts_per_burst,
                           data.pkts_per_burst)

    @pytest.mark.loopback_dest_ip
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_dest_ip_as_loopback(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with destination as loopback address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.v4_loopback,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of loopback src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ip as loopback" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with dest ip as loopback address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has destination address as lo IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.loopback_src_ip
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_src_ip_as_loopback(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with destination as loopback address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.v4_loopback, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of loopback src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as loopback" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as loopback address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which has source address as lo IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.dst_ip_as_linklocal
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_dst_ip_as_linklocal(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with destination as linklocal address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.link_local_ip,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of link_local_ip dest ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ip as link_local_ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with dest ip as linklocal address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has dest address as linklocal IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.src_ip_as_linklocal
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_src_ip_as_linklocal(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with source as linklocal address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.link_local_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of link_local_ip src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as link_local_ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as linklocal address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has source address as linklocal IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v4src_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_v4src_ip_not_specified(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with invalid source ip address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.non_routable_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as 0.0.0.0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v4 src ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value,
                           "packets which has doesn't have v4source IP addr",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.classE_src_ip
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_src_ip_as_class_e(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with source as CLASS E address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.class_e_ip, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of class E src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as class e ip" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with src ip as CLASS E address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which has Class E source IP",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v6dest_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_v6dest_ip_not_specified(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with invalid dest ipv6 address")
        import sth
        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.t1d1_v6_mac_addr, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.t1d1_adv_ipv6_addr, ipv6_dst_addr=data.non_routable_ipv6,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid dest ipv6 address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ipv6 as ::0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v6 dest ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which doesn't had v6 dest address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v6src_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_v6src_ip_not_specified(self):
        result = 0
        failure_msg = ""
        import sth
        sth.invoke(sth_disable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_enable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)
        st.log("Generating packet with invalid source ip address")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv6', mac_src=data.t1d1_v6_mac_addr, mac_dst=data.dut_rt_int1_mac,
                             ipv6_src_addr=data.non_routable_ipv6, ipv6_dst_addr=data.t2d1_adv_ipv6_addr,
                             mac_discovery_gw=data.d1t1_ipv6_addr, stream_id=t1d1_v6stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_v6stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_v6stream_1['stream_id'])
        sth.invoke(sth_enable_stream.format(t1d1_stream_1['stream_id']))
        sth.invoke(sth_disable_stream.format(t1d1_v6stream_1['stream_id']))
        sth.invoke(sth_apply)

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid src ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having src ip as ::0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v6 src ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which doesn't had v6 src address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.v4dest_ip_not_specified
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_v4dest_ip_not_specified(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with invalid dest ip address")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac, mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.non_routable_ip,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of invalid dest ip address and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having dest ip as 0.0.0.0" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with invalid v4 dest ip address")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets which doesn't had v4 dest address",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_bad_version
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_bad_ip_version(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with bad ip version")
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=data.pkts_per_burst, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', version="1", mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of bad ip version and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having bad ip version" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with bad ip version")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with broken header",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_ihl_too_short
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_bad_ip_ihl_too_short(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with short ip header length ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', ip_hdr_length='1', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of short ip header length and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having short ip header length" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with short ip header length")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with short ihl",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.ip_header_bad_checksum
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_bad_ip_checksum(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with bad ip checksum ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', ip_checksum="1", mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of bad ip checksum and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having bad ip checksum" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with bad ip checksum")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with bad checksum",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.no_ip_header
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_no_ip_header(self):
        result = 0
        failure_msg = ""
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='disable', stream_id=t1d1_stream_1['stream_id'])
        st.log("Generating packet with no ip header ")
        t1d1_no_ip_header = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                 transmit_mode='single_burst',
                                                 pkts_per_burst=data.pkts_per_burst, length_mode='fixed',
                                                 rate_pps=10000,
                                                 l4_protocol='tcp', tcp_src_port=1024, tcp_dst_port=1024,
                                                 mac_src=data.t1_v4_stream_mac,
                                                 mac_dst=data.dut_rt_int1_mac
                                                 )
        st.show(dut1, "sonic-clear counters")
        st.show(dut1, "sonic-clear rifcounters")
        tg.tg_traffic_control(action='run', stream_handle=t1d1_no_ip_header['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_no_ip_header['stream_id'])
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='enable', stream_id=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of no ip header and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets which are having no ip header" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with no ip header")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with out IP header",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.erif_interface_disabled
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_erif_interface_disabled(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with erif disabled ")

        # interface_obj.interface_shutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dut_rt_int1_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])

        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        # pdb.set_trace()
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        papi.get_interface_counters(dut1, vars.D1T1P2)

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        interface_obj.interface_shutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))
        interface_obj.interface_noshutdown(dut1, interfaces=vars.D1T1P2, skip_verify=False)
        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets with erif disabled which is not expected and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
                result = 1
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT didn't drop packets when  erif disabled")
            st.report_pass("drop_counters_not_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with erif disable",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.unicast_ip_with_mcast_dmac
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_unicast_ip_with_mcast_dmac(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with Unicast IP and MCAST DST MAC ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.dest_mcast_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of mcast dmac and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {}packets instead of {}packets having unicast ip with mcast dmac" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with unicast ip and mcast dmac")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with unicast IP and Mcast MAC",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)

    @pytest.mark.unicast_ip_with_bcast_dmac
    @pytest.mark.usefixtures('drop_counters_func_hook_portchannel')
    def test_unicast_ip_with_bcast_dmac(self):
        result = 0
        failure_msg = ""
        st.log("Generating packet with Unicast IP and BCAST DST MAC ")

        tg.tg_traffic_config(port_handle=tg_ph_1, mode='modify', transmit_mode='single_burst',
                             pkts_per_burst=2000, length_mode='fixed', rate_pps=10000,
                             l3_protocol='ipv4', mac_src=data.t1_v4_stream_mac,
                             mac_dst=data.bcast_mac,
                             ip_src_addr=data.t1d1_adv_ip_addr, ip_dst_addr=data.t2d1_adv_ip_addr,
                             mac_discovery_gw=data.d1t1_ip_addr, stream_id=t1d1_stream_1['stream_id'])
        st.show(dut1, "sonic-clear counters")
        papi.clear_rif_interface_counters(dut1)
        tg.tg_traffic_control(action='run', stream_handle=t1d1_stream_1['stream_id'])

        check_port_stats = port_counters(dut1, {
            vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0, 'rx_drp': data.pkts_per_burst}})
        check_l3_count = verify_rif_counters(dut1, {vars.D1T1P1: {'rx_ok': data.pkts_per_burst, 'rx_err': 0}})

        tg.tg_traffic_control(action='stop', stream_handle=t1d1_stream_1['stream_id'])

        if check_l3_count and check_port_stats:
            st.log('Interface and port stats are as expected')
        elif check_l3_count:
            st.warn('portstats are not as expected')
        else:
            st.warn('interface stats are not as expected')

        d1t1_interface_counters = papi.get_interface_counters(dut1, vars.D1T1P1)
        dut_rx_value = int(d1t1_interface_counters[0]['rx_ok'].replace(',', ''))
        dut_rx_drop_value = int(d1t1_interface_counters[0]['rx_drp'].replace(',', ''))
        dut_rx_err = int(d1t1_interface_counters[0]['rx_err'].replace(',', ''))

        if int(data.pkts_per_burst * 1.05) >= dut_rx_value >= int(data.pkts_per_burst * 0.95):
            st.log("DUT received {} packets as expected".format(dut_rx_value))
            if (int(data.pkts_per_burst * 1.05) >= dut_rx_drop_value >= int(
                    data.pkts_per_burst * 0.95)) and dut_rx_err < 5:
                st.log("DUT dropped {} packets because of mcast dmac and {} packets are errored out"
                       .format(dut_rx_drop_value, dut_rx_err))
            else:
                result = 1
                failure_msg = "DUT dropped {} packets instead of {}packets having unicast ip with bcast dmac" \
                              " and {} packets are errored out".format(dut_rx_drop_value, data.pkts_per_burst,
                                                                       dut_rx_err)
                st.warn(failure_msg)
        else:
            failure_msg += "DUT received {} packets instead of {}".format(dut_rx_value, data.pkts_per_burst)
            st.warn(failure_msg)
            result = 1
        if result == 0:
            st.log("DUT dropped packets with unicast ip and bcast dmac")
            st.report_pass("drop_counters_incremented")
        else:
            st.report_fail("drop_counters_not_incremented", dut_rx_value, "packets with Unicast IP and Bcast MAC",
                           dut_rx_drop_value, data.pkts_per_burst, data.pkts_per_burst)
