import multihome.const as const
import vxlan_utils
import apis.switching.portchannel as portchannel_obj

from multihome.const import spytest_data
from spytest import st, tgapi
from multihome.host import get_cli_out
import evpn_mh_utils as evpn_mh_obj
from multihome.status_report import log, report_fail, report_pass, banner
from multihome.dut import wait

PORTCHANNEL_NAME = "PortChannel2"
LAG_POLL_INTERVAL = 20
LAG_POLL_TIMEOUT = 120


def create_a_raw_traffic_stream(stream_info):
    """
    Create a raw traffic stream using the specified stream information.
    :param stream_info: Dictionary containing stream information.
    :return: Dictionary containing stream handle and other information.
    """
    st.log("Creating a raw traffic stream")
    all_port_handles = []
    stream_handle = {}
    vxlan_utils.clear_counters()
    if stream_info.get("src_endpoint") and stream_info.get("dst_endpoint"):
        tg_handle1, port_handle1 = tgapi.get_handle_byname(
            stream_info["src_endpoint"]["port"]
        )
        tg_handle2, port_handle2 = tgapi.get_handle_byname(
            stream_info["dst_endpoint"]["port"]
        )

        all_port_handles.append(port_handle1)
        all_port_handles.append(port_handle2)

        tg_handle1.tg_traffic_control(
            action="clear_stats", port_handle=[port_handle1, port_handle2]
        )
        receive = tg_handle1.tg_traffic_config(
            port_handle=port_handle1,
            port_handle2=port_handle2,
            mode="create",
            transmit_mode=const.spytest_data.transmit_mode,
            pkts_per_burst=const.spytest_data.pkts_per_burst,
            rate_percent=const.spytest_data.rate_percent,
            circuit_endpoint_type=const.spytest_data.circuit_endpoint_type,
            frame_size=const.spytest_data.frame_size,
            mac_src=stream_info["src_endpoint"]["mac"],
            mac_dst=stream_info["dst_endpoint"]["mac"],
        )
        stream_id = receive["stream_id"]
        stream_handle = {
            "tg_handle": tg_handle1,
            "port_handle1": port_handle1,
            "port_handle2": port_handle2,
            "stream_id": stream_id,
            "all_port_handles": all_port_handles,
            "traffic_item_type": "raw",
        }
    return stream_handle


def send_unicast_burst(stream_handle):
    """
    Send a burst of packets using the specified stream handle.
    :param stream_handle: The handle for the stream to be sent.
    :return: Result of the traffic test (bool).
    """
    st.log("Sending unicast burst")
    return vxlan_utils.traffic_test_burst("unicast", stream_handle, timeout=10)


def start_lag_group_protocol(lag_handle, port):
    """
    Start the LAG group protocol on the specified port.
    :param lag_handle: The handle for the LAG group.
    :param port: The port to start the protocol on.
    """
    st.log("Starting LAG group")
    tg_handle = list(lag_handle.values())[0]["tg_handle"]
    tmp_handle = lag_handle[port]["int_handle"]
    device_group = "/" + "/".join(tmp_handle.split("/", 3)[1:3])
    tg_handle.tg_test_control(action="start_protocol", handle=device_group)
    if port == const.lag_name:
        vars = st.get_testbed_vars()
        if not st.poll_wait2(LAG_POLL_INTERVAL, LAG_POLL_TIMEOUT,
                             portchannel_obj.verify_portchannel_state,
                             vars.D2, PORTCHANNEL_NAME, state="up"):
            st.log("PortChannel did not come up after start_protocol")
    else:
        st.wait(10)


def stop_lag_group_protocol(lag_handle, port):
    """
    Stop the LAG group protocol on the specified port.
    :param lag_handle: The handle for the LAG group.
    :param port: The port to stop the protocol on.
    """
    st.log("Stopping LAG group")
    tg_handle = list(lag_handle.values())[0]["tg_handle"]
    tmp_handle = lag_handle[port]["int_handle"]
    tp_group = "/" + "/".join(tmp_handle.split("/", 3)[1:2])  # /topology:2
    tg_handle.tg_test_control(action="stop_protocol", handle=tp_group)
    if port == const.lag_name:
        vars = st.get_testbed_vars()
        if not st.poll_wait2(LAG_POLL_INTERVAL, LAG_POLL_TIMEOUT,
                             portchannel_obj.verify_portchannel_state,
                             vars.D2, PORTCHANNEL_NAME, state="down"):
            st.log("PortChannel did not go down after stop_protocol")
    else:
        st.wait(10)


def create_lag_group_and_start_protocol(lag_handle, port, host_dict, device_group_name):
    """
    Create a LAG group with the specified parameters.
    :param lag_handle: The handle for the LAG group.
    :param port: The port to create the LAG group on.
    :param host_dict: Dictionary containing host information.
    :param device_group_name: The name of the device group.
    """
    st.log("Creating LAG group")

    tg = lag_handle[port]["tg_handle"]
    topology_name = "/" + lag_handle[port]["int_handle"].split("/")[1]  # /topology:2
    tg.tg_test_control(action="stop_protocol", handle=topology_name)
    if port == const.lag_name:
        vars = st.get_testbed_vars()
        if not st.poll_wait2(LAG_POLL_INTERVAL, LAG_POLL_TIMEOUT,
                             portchannel_obj.verify_portchannel_state,
                             vars.D2, PORTCHANNEL_NAME, state="down"):
            st.log("PortChannel did not go down after stop_protocol")
    else:
        st.wait(15)
    _result_ = tg.tg_topology_config(
        topology_handle=topology_name,
        device_group_name=device_group_name,
        device_group_multiplier="1",
        device_group_enabled="1",
    )
    deviceGroup_1_handle = _result_["device_group_handle"]
    _result_ = tg.tg_interface_config(
        protocol_name="Ethernet H1",
        protocol_handle=deviceGroup_1_handle,
        mtu="1500",
        src_mac_addr=host_dict["host_mac"],
    )
    ethernet_1_handle = _result_["ethernet_handle"]
    _result_ = tg.tg_interface_config(
        protocol_name="IPv4",
        protocol_handle=ethernet_1_handle,
        gateway=host_dict["gateway"],
        intf_ip_addr=host_dict["host_ip"],
        netmask="255.255.255.0",
    )
    int_handle = _result_["interface_handle"]
    tg.tg_test_control(action="start_protocol", handle=topology_name)
    if port == const.lag_name:
        if not st.poll_wait2(LAG_POLL_INTERVAL, LAG_POLL_TIMEOUT,
                             portchannel_obj.verify_portchannel_state,
                             vars.D2, PORTCHANNEL_NAME, state="up"):
            st.log("PortChannel did not come up after start_protocol")
    else:
        st.wait(10)
    lag_handle[port].update({"int_handle1": int_handle})


def reset_topology_after_mac_move(lag_handle, port, new_port):
    """
    Reset traffic generator post MAC movement
    :param lag_handle: lag group handle
    :param port: from port
    :param new_port: to port
    """
    tg_handle = list(lag_handle.values())[0]["tg_handle"]
    tmp_handle = lag_handle[port]["int_handle1"]
    stop_lag_group_protocol(lag_handle, port)
    device_group = "/" + "/".join(
        tmp_handle.split("/", 3)[1:3]
    )  # /topology:2/deviceGroup:1
    st.log(
        "Destroying device group {} which was created for mac move".format(device_group)
    )
    tg_handle.tg_topology_config(device_group_handle=device_group, mode="destroy")
    st.wait(10)
    start_lag_group_protocol(lag_handle, new_port)
    st.banner("About to ping gateway after mac move back")
    vxlan_utils.ping_gateway(
        lag_handle,
        new_port,
        spytest_data.d2t1_ip_addr,
        lag_handle[new_port]["int_handle"],
    )
    start_lag_group_protocol(lag_handle, port)


def verify_l3_traffic(stream_list, lag_handle, del_stream=True):
    """
    Start ping test (L3 traffic test)
    :param stream_list: e2e ports of interest
    :param lag_handle: lag group handle
    :param del_stream: delete stream post test
    """
    st.banner("Start to test VxLAN L3  with ping and traffic")

    # Verify Vtep state
    vxlan_utils.verify_vtep_state(
        {
            "LEAF0_VXLAN_IP": const.LEAF0_VXLAN_IP,
            "LEAF1_VXLAN_IP": const.LEAF1_VXLAN_IP,
            "LEAF2_VXLAN_IP": const.LEAF2_VXLAN_IP,
        }
    )

    streams = vxlan_utils.config_traffic_item(
        stream_list, lag_handle, const.interface_map, spytest_data, ping=True
    )
    st.log("Ping passed, sending traffic now")
    vxlan_utils.clear_counters()
    result = vxlan_utils.check_traffic(streams)
    if del_stream:
        vxlan_utils.reset_traffic(streams)
    return result


def verify_bum_traffic(
    lag_handle,
    stream,
    src_port,
    traffic_type,
    dst_port="T1D4P1",
    reset=True,
    ignore_results=False,
):
    flag = False
    vxlan_utils.clear_counters()
    get_cli_out()
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle[src_port],
        lag_handle[dst_port],
        stream,
        "raw",
        spytest_data,
        traffic_type,
    )
    flag = vxlan_utils.send_raw_traffic_stream(lag_handle[src_port], stream_id, reset)
    if not ignore_results:
        if flag:
            st.banner("{} traffic test passed".format(traffic_type))
            flag = True
        else:
            st.banner("{} traffic test failed".format(traffic_type))
            flag = False
    return flag

def create_continous_traffic(
    lag_handle,
    stream,
    src_port,
    traffic_type,
    dst_port="T1D4P1",
):
    transmit_mode = spytest_data.transmit_mode
    rate_percent = spytest_data.rate_percent
    spytest_data.transmit_mode = "continuous"
    spytest_data.rate_percent = 0.01
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle[src_port],
        lag_handle[dst_port],
        stream,
        "raw",
        spytest_data,
        traffic_type,
    )
    spytest_data.transmit_mode = transmit_mode
    spytest_data.rate_percent = rate_percent
    wait(10)

    return stream_id

def continuous_traffic_control(
    stream_list,
    action,
    tg_handle,
    stop_start_protocols=False,
    regenerate_traffic_items=False,
):
    flag = True
    line = '-'*80

    if action == 'start' or action == 'default':
        ###stop/start all protocols###
        if stop_start_protocols:
            tg_handle.tg_test_control("stop_all_protocols")
            wait(15)
            tg_handle.tg_test_control("start_all_protocols")
            wait(15)

        ###Regenerate Traffic###
        if regenerate_traffic_items and action != 'check':
            tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
            tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
            wait(10)

        ###Start Traffic###
        tg_handle.tg_traffic_control(action='run', stream_handle=stream_list)
        wait(30)

    if action == 'start':
        return flag

    ###Stop Traffic###
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)
    st.wait(30)

    if action == 'stop':
        return flag

    traffic_stat = tg_handle.tg_traffic_stats(mode='traffic_item', streams=stream_list)

    min_perc = 92
    max_perc = 108
    row_format = '|{:20}|{:20}|{:20}|{:15}|'
    msg = ""
    for stream_id in traffic_stat['traffic_item'].keys():
        if not stream_id.startswith('TI'): continue

        banner("TRAFFIC ITEM {}".format(stream_id))
        msg += line + "\n"
        msg += row_format.format('Expected Rx', 'Actual Rx', '%', 'Result') + "\n"
        msg += row_format.format('', '',
                                  '({}%-{}%)'.format(str(min_perc),str(max_perc)), '') + "\n"
        msg += line + "\n"
        exp_rx = int(traffic_stat['traffic_item'][stream_id]['tx']['total_pkts'])
        rx = int(traffic_stat['traffic_item'][stream_id]['rx']['total_pkts'])
        perc = rx / float(exp_rx) * 100
        if perc > min_perc and perc < max_perc:
            msg += row_format.format(str(exp_rx), str(rx),
                                     '{:.2f}'.format(perc), 'PASS') + "\n"
            msg += line + "\n"
            msg += "TRAFFIC ITEM {} PASSED".format(stream_id) + "\n"
        else:
            msg += row_format.format(str(exp_rx), str(rx),
                                     '{:.2f}'.format(perc), 'FAIL') + "\n"
            msg += line + "\n"
            msg += "TRAFFIC ITEM {} FAILED".format(stream_id) + "\n"
            flag = False
        log(msg)
    return flag


def verify_df_ndf_traffic(
    nodes,
    lag_handle,
    traffic_setup,
):
    msg = ""
    result = True
    # check es and ndf status
    if not evpn_mh_obj.isDF(nodes["leaf0"], const.ESI1):
        result = False
        msg += "DF status is not set on leaf0 after resetting portchannel\n"

    if evpn_mh_obj.isDF(nodes["leaf1"], const.ESI1):
        result = False
        msg += "DF status is set on leaf1 after resetting portchannel\n"

    # check traffic : send L2 BUM traffic from H3
    cmd_intf = "show interface counters"

    stream = {
        "src_endpoint": {
            "port": "T1D4P1",
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d4t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        },
        "dst_endpoint": {
            "port": "T1D2P1",
            "host_ip": const.spytest_data.t1d2p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d2p1_mac_addr,
        },
    }
    verify_bum_traffic(lag_handle, stream, "T1D4P1", "broadcast", "T1D2P1")

    df_downlink_curr = vxlan_utils.get_counters(
        node=nodes["leaf0"],
        cmd=cmd_intf,
        target_iface=traffic_setup["D2T1P2"],
        r_t_key="tx_ok",
    )
    log("df_downlink_curr is {}".format(df_downlink_curr))

    ndf_downlink_curr = vxlan_utils.get_counters(
        node=nodes["leaf1"],
        cmd=cmd_intf,
        target_iface=traffic_setup["D3T1P1"],
        r_t_key="tx_ok",
    )
    log("ndf_downlink_curr is {}".format(ndf_downlink_curr))

    if not (
        df_downlink_curr >= 0.98 * int(const.spytest_data.pkts_per_burst)
        and df_downlink_curr <= 1.1 * int(const.spytest_data.pkts_per_burst)
        and ndf_downlink_curr <= 0.1 * int(const.spytest_data.pkts_per_burst)
    ):
        result = False
        msg += "BUM traffic is not dropping in NDF\n"

    return result, msg
