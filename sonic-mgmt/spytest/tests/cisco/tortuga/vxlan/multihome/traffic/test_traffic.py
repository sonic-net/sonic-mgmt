import evpn_mh_utils as evpn_mh_obj
import vxlan_utils


from multihome import db
from multihome import const
from multihome.dut import wait
from multihome.host import configure_cmd as host_configure_cmd
from multihome.host import show_cmd as host_show_cmd
from multihome.host import (
    verify_arp,
    verify_port_channel,
    verify_vrf_route_l3vni,
    is_mac_exists,
    is_mac_exists_local,
    verify_ip_route_multihomed_host,
    get_cli_out,
)
from multihome.traffic import *
from multihome.status_report import log, report_fail, report_pass, banner
from multihome.traffic_generator import (
    verify_bum_traffic,
    verify_l3_traffic,
    verify_df_ndf_traffic,
    create_continous_traffic,
    continuous_traffic_control
)
from multihome.vtysh import show_evpn_es
from multihome.vtysh import configure_cmd as vtysh_configure_cmd
import apis.system.interface as intf_obj


def test_local_bias(traffic_setup):
    """
    Test local bias with BUM traffic
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # 1. Send BUM traffic from H1 to H2, check traffic forwarding path with original DF/NDF status
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(
        nodes["leaf0"], nodes["leaf1"], const.ESI1
    )
    if not df_node:
        report_fail(nodes["leaf0"], "Incorrect DF/NDF selection")

    cmd_intf = "show interface counters"
    if df_node == nodes["leaf0"]:
        df_downlink = traffic_setup["D2T1P2"]
        ndf_downlink = traffic_setup["D3T1P1"]
    else:
        df_downlink = traffic_setup["D3T1P1"]
        ndf_downlink = traffic_setup["D2T1P2"]

    # Send BUM traffic
    stream = {
        "src_endpoint": {
            "port": "T1D2P1",
            "host_ip": const.spytest_data.t1d2p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d2p1_mac_addr,
        },
        "dst_endpoint": {
            "port": "T1D4P1",
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d4t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        },
    }
    verify_bum_traffic(lag_handle, stream, "T1D2P1", "unknownunicast")

    df_downlink_curr = vxlan_utils.get_counters(
        node=df_node, cmd=cmd_intf, target_iface=df_downlink, r_t_key="tx_ok"
    )
    log("df_downlink_curr is {}".format(df_downlink_curr))

    ndf_downlink_curr = vxlan_utils.get_counters(
        node=ndf_node, cmd=cmd_intf, target_iface=ndf_downlink, r_t_key="tx_ok"
    )
    log("ndf_downlink_curr is {}".format(ndf_downlink_curr))

    # Parse traffic
    if not (
        df_downlink_curr >= 0.98 * int(const.spytest_data.pkts_per_burst)
        and df_downlink_curr <= 1.1 * int(const.spytest_data.pkts_per_burst)
        and ndf_downlink_curr <= 0.1 * int(const.spytest_data.pkts_per_burst)
    ):
        report_fail(df_node, "Local bias is not effective on {}".format(df_node))
    banner(
        "Local bias testcase passed for unknown unicast traffic before changing DF/NDF roles"
    )
    # 2 Swith DF/NDF, check traffic forwarding path with current DF/NDF status

    # Make leaf0 NDF, leaf1 DF
    vtysh_configure_cmd(
        nodes["leaf0"], "interface PortChannel2\nevpn mh es-df-pref 1\nend\nexit\n"
    )

    vtysh_configure_cmd(
        nodes["leaf1"], "interface PortChannel2\nevpn mh es-df-pref 1000\nend\nexit\n"
    )

    show_evpn_es(nodes["leaf0"], verbose=True)
    show_evpn_es(nodes["leaf1"], verbose=True)

    if evpn_mh_obj.isDF(nodes["leaf0"], const.ESI1):
        report_fail(nodes["leaf0"], "leaf0 is not changed to ndf ")
    if not evpn_mh_obj.isDF(nodes["leaf1"], const.ESI1):
        report_fail(nodes["leaf1"], "leaf1 is not changed to df ")

    # Send BUM traffic from H1
    stream = {
        "src_endpoint": {
            "port": "T1D2P1",
            "host_ip": const.spytest_data.t1d2p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d2p1_mac_addr,
        },
        "dst_endpoint": {
            "port": "T1D4P1",
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d4t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        },
    }
    verify_bum_traffic(lag_handle, stream, "T1D2P1", "unknownunicast")

    df_downlink_curr = vxlan_utils.get_counters(
        node=df_node, cmd=cmd_intf, target_iface=df_downlink, r_t_key="tx_ok"
    )
    log("df_downlink_curr is {}".format(df_downlink_curr))

    ndf_downlink_curr = vxlan_utils.get_counters(
        node=ndf_node, cmd=cmd_intf, target_iface=ndf_downlink, r_t_key="tx_ok"
    )
    log("ndf_downlink_curr is {}".format(ndf_downlink_curr))

    # Restore original DF/NDF status
    vtysh_configure_cmd(
        nodes["leaf0"], "interface PortChannel2\nevpn mh es-df-pref 32767\nend\nexit\n"
    )
    vtysh_configure_cmd(
        nodes["leaf1"], "interface PortChannel2\nevpn mh es-df-pref 32767\nend\nexit\n"
    )

    ##for temporary use
    show_evpn_es(nodes["leaf0"], verbose=True)
    show_evpn_es(nodes["leaf1"], verbose=True)

    # Parse traffic, switching DF/NDF should not have any influence. Local bias should always work.
    if not (
        df_downlink_curr >= 0.98 * int(const.spytest_data.pkts_per_burst)
        and df_downlink_curr <= 1.1 * int(const.spytest_data.pkts_per_burst)
        and ndf_downlink_curr <= 0.1 * int(const.spytest_data.pkts_per_burst)
    ):
        report_fail(ndf_node, "Local bias doesn't work after changing DF/NDF status")

    report_pass("test_case_passed", "test_local_bias")


def test_remote_broadcast_traffic(traffic_setup):
    """
    Broadcast Remote Testing
    Verify broadcast traffic sent from H3 is getting dropped by NDF
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # 1 Verify DF/NDF
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(
        nodes["leaf0"], nodes["leaf1"], const.ESI1
    )
    if not df_node:
        report_fail(nodes["leaf0"], "Incorrect DF/NDF selection")

    # 2 Verify broadcast traffic is drop in NDF

    # 2.1 record initial state
    cmd_intf = "show interface counters"
    if df_node == nodes["leaf0"]:
        df_downlink = traffic_setup["D2T1P2"]
        ndf_downlink = traffic_setup["D3T1P1"]
    else:
        df_downlink = traffic_setup["D3T1P1"]
        ndf_downlink = traffic_setup["D2T1P2"]

    # 2.2 send L2 broadcast traffic from H3
    log("sending broacast traffic from H3")
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
    }  ##in bum traffic, dst_endpoint dest doesn't matter
    verify_bum_traffic(lag_handle, stream, "T1D4P1", "broadcast", "T1D2P1")
    # 2.3 record current state after traffic sent
    df_downlink_curr = vxlan_utils.get_counters(
        node=df_node, cmd=cmd_intf, target_iface=df_downlink, r_t_key="tx_ok"
    )
    log("\ndf_downlink_curr is {}".format(df_downlink_curr))

    ndf_downlink_curr = vxlan_utils.get_counters(
        node=ndf_node, cmd=cmd_intf, target_iface=ndf_downlink, r_t_key="tx_ok"
    )
    log("\nndf_downlink_curr is {}".format(ndf_downlink_curr))

    # 3 analyze result
    if not (
        df_downlink_curr <= 1.1 * int(const.spytest_data.pkts_per_burst)
        and df_downlink_curr >= 0.98 * int(const.spytest_data.pkts_per_burst)
        and ndf_downlink_curr <= 0.1 * int(const.spytest_data.pkts_per_burst)
    ):
        report_fail(ndf_node, "Broadcast traffic not dropped by NDF")

    else:
        report_pass("test_case_passed", "test_remote_broadcast_traffic")


def test_remote_multicast_traffic(traffic_setup):
    """
    Multicast Remote Testing
    Verify multicast traffic sent from H3 is getting dropped by NDF
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # 1 Verify DF/NDF
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(
        nodes["leaf0"], nodes["leaf1"], const.ESI1
    )
    if not df_node:
        report_fail(nodes["leaf0"], "Incorrect DF/NDF selection")

    # 2 Verify multicast traffic is drop in NDF
    # 2.1 record initial state
    cmd_intf = "show interface counters"
    if df_node == nodes["leaf0"]:
        df_downlink = traffic_setup["D2T1P2"]
        ndf_downlink = traffic_setup["D3T1P1"]
    else:
        df_downlink = traffic_setup["D3T1P1"]
        ndf_downlink = traffic_setup["D2T1P2"]

    # 2.2 send L2 multicast traffic from H3
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
    verify_bum_traffic(lag_handle, stream, "T1D4P1", "multicast", "T1D2P1")

    # 2.3 record current state after traffic sent
    df_downlink_curr = vxlan_utils.get_counters(
        node=df_node, cmd=cmd_intf, target_iface=df_downlink, r_t_key="tx_ok"
    )
    log("df_downlink_curr is {}".format(df_downlink_curr))

    ndf_downlink_curr = vxlan_utils.get_counters(
        node=ndf_node, cmd=cmd_intf, target_iface=ndf_downlink, r_t_key="tx_ok"
    )
    log("ndf_downlink_curr is {}".format(ndf_downlink_curr))

    # 3 analyze result
    if not (
        df_downlink_curr >= 0.98 * int(const.spytest_data.pkts_per_burst)
        and df_downlink_curr <= 1.1 * int(const.spytest_data.pkts_per_burst)
        and ndf_downlink_curr <= 0.1 * int(const.spytest_data.pkts_per_burst)
    ):
        report_fail(ndf_node, "Multicast traffic not dropped by NDF")
    else:
        report_pass("test_case_passed", "test_remote_multicast_traffic")


def test_unknown_unicast(traffic_setup):
    """
    Unknown-Unicast Remote Testing
    Verify unknown_unicast traffic sent from H3 is getting dropped by NDF
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # 1 Verify Ethernet Segment is up and peering
    is_peering = evpn_mh_obj.es_peering(
        nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1
    )
    if not is_peering:
        report_fail(nodes["leaf0"], "ES is not peering")

    # 2 Verify DF/NDF
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(
        nodes["leaf0"], nodes["leaf1"], const.ESI1
    )
    if not df_node:
        report_fail(nodes["leaf0"], "Incorrect DF/NDF selection")

    # 3 Verify BUM traffic is ingress replicated towards Leaf0, Leaf1 and drop in NDF

    if df_node == nodes["leaf0"]:
        df_downlink = traffic_setup["D2T1P2"]
        ndf_downlink = traffic_setup["D3T1P1"]
    else:
        df_downlink = traffic_setup["D3T1P1"]
        ndf_downlink = traffic_setup["D2T1P2"]

    # 3.1 send L2 unknown unicast traffic from H3.
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
    verify_bum_traffic(lag_handle, stream, "T1D4P1", "unknownunicast", "T1D2P1")

    # 3.2 record current state after traffic sent
    cmd_vxlan = "show vxlan counters"
    cmd_intf = "show interface counters"

    leaf2_df_vxlan_rx_curr = vxlan_utils.get_counters(
        node=df_node,
        cmd=cmd_vxlan,
        target_iface="EVPN_{}".format(const.LEAF2_VXLAN_IP),
        r_t_key="rx_pkts",
    )
    log("leaf2_df_vxlan_rx_curr is {}".format(leaf2_df_vxlan_rx_curr))

    leaf2_ndf_vxlan_rx_curr = vxlan_utils.get_counters(
        node=ndf_node,
        cmd=cmd_vxlan,
        target_iface="EVPN_{}".format(const.LEAF2_VXLAN_IP),
        r_t_key="rx_pkts",
    )
    log("leaf2_ndf_vxlan_rx_curr is {}".format(leaf2_ndf_vxlan_rx_curr))

    leaf2_df_vxlan_tx_curr = vxlan_utils.get_counters(
        node=nodes["leaf2"],
        cmd=cmd_vxlan,
        target_iface="EVPN_{}".format(const.LEAF0_VXLAN_IP),
        r_t_key="tx_pkts",
    )
    log("leaf2_df_vxlan_tx_curr is {}".format(leaf2_df_vxlan_tx_curr))

    leaf2_ndf_vxlan_tx_curr = vxlan_utils.get_counters(
        node=nodes["leaf2"],
        cmd=cmd_vxlan,
        target_iface="EVPN_{}".format(const.LEAF1_VXLAN_IP),
        r_t_key="tx_pkts",
    )
    log("leaf2_ndf_vxlan_tx_curr is {}".format(leaf2_ndf_vxlan_tx_curr))

    """
    Record current state of interface counters
    """
    df_downlink_curr = vxlan_utils.get_counters(
        node=df_node, cmd=cmd_intf, target_iface=df_downlink, r_t_key="tx_ok"
    )
    log("df_downlink_curr is {}".format(df_downlink_curr))

    ndf_downlink_curr = vxlan_utils.get_counters(
        node=ndf_node, cmd=cmd_intf, target_iface=ndf_downlink, r_t_key="tx_ok"
    )
    log("ndf_downlink_curr is {}".format(ndf_downlink_curr))

    # 4 analyze result
    # Validate traffic is drop in NDF
    if not (
        df_downlink_curr >= 0.98 * int(const.spytest_data.pkts_per_burst)
        and df_downlink_curr <= 1.1 * int(const.spytest_data.pkts_per_burst)
        and ndf_downlink_curr <= 0.1 * int(const.spytest_data.pkts_per_burst)
    ):
        report_fail(ndf_node, "Unknown unicast traffic is not dropped in NDF")
    # Validate Unknown unicast traffic is ingress replicated towards df and ndf
    elif vxlan_utils.tunnel_counters_supported(nodes["leaf2"]) and not (
        leaf2_df_vxlan_rx_curr >= int(const.spytest_data.pkts_per_burst)
        and leaf2_ndf_vxlan_rx_curr >= int(const.spytest_data.pkts_per_burst)
        and leaf2_df_vxlan_tx_curr >= int(const.spytest_data.pkts_per_burst)
        and leaf2_ndf_vxlan_tx_curr >= int(const.spytest_data.pkts_per_burst)
    ):
        report_fail(
            nodes["leaf2"],
            "Unknown unicast traffic is not ingress replicated towards df and ndf",
        )
    else:
        report_pass("test_case_passed", "test_unknown_unicast")


######################################################################
# Test Inter-Subnet Ping
######################################################################
def test_inter_subnet_ping(traffic_setup):
    """
    Test inter-subnet ping
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    try:
        get_cli_out()

        # ping and unicast traffic from H1 to H4
        result = verify_l3_traffic([("T1D2P1", "T1D4P2")], lag_handle)  # H1 -> H4
        if not result:
            report_fail(
                nodes["leaf0"],
                "ping and traffic from single homed host to different subnet host failed with unicast traffic",
            )

        # Check traffic is going over vxlan
        leaf0_evpn_int_counters = vxlan_utils.get_counters(
            nodes["leaf0"],
            cmd="show vxlan counters",
            target_iface="EVPN_{}".format(const.LEAF2_VXLAN_IP),
            r_t_key="tx_pkts",
        )
        log(
            "\nTX counters on leaf0 EVPN connected interface to H1 is {}".format(
                leaf0_evpn_int_counters
            )
        )

        leaf2_evpn_int_counters = vxlan_utils.get_counters(
            nodes["leaf2"],
            cmd="show vxlan counters",
            target_iface="EVPN_{}".format(const.LEAF0_VXLAN_IP),
        )
        log(
            "\nRX counters on leaf2 EVPN connected interface to H4 is {}".format(
                leaf2_evpn_int_counters
            )
        )

        if vxlan_utils.tunnel_counters_supported(nodes["leaf0"]) and not (
            leaf0_evpn_int_counters >= 0.98 * int(const.spytest_data.pkts_per_burst)
            and leaf0_evpn_int_counters <= 1.2 * int(const.spytest_data.pkts_per_burst)
            and leaf2_evpn_int_counters >= 0.98 * int(const.spytest_data.pkts_per_burst)
            and leaf2_evpn_int_counters <= 1.2 * int(const.spytest_data.pkts_per_burst)
        ):
            report_fail(
                nodes["leaf0"],
                "Unicast traffic going from H1 to H4 not taking evpn interface",
            )

        get_cli_out()

        # ping and unicast traffic from H2 to H4
        result = verify_l3_traffic([(const.lag_name, "T1D4P2")], lag_handle)  # H2 -> H4
        if not result:
            report_fail(
                nodes["leaf0"],
                "traffic from multihomed host to different subnet host failed with unicast traffic",
            )

        # Check traffic is going over vxlan
        leaf0_evpn_int_counters = vxlan_utils.get_counters(
            nodes["leaf0"],
            cmd="show vxlan counters",
            target_iface="EVPN_{}".format(const.LEAF2_VXLAN_IP),
            r_t_key="tx_pkts",
        )
        log(
            "\nTX counters on leaf0 EVPN connected interface to H2 is {}".format(
                leaf0_evpn_int_counters
            )
        )

        leaf2_evpn_int_counters = vxlan_utils.get_counters(
            nodes["leaf2"],
            cmd="show vxlan counters",
            target_iface="EVPN_{}".format(const.LEAF0_VXLAN_IP),
        )
        log(
            "\nRX counters on leaf2 EVPN connected interface to H4 is {}".format(
                leaf2_evpn_int_counters
            )
        )

        if vxlan_utils.tunnel_counters_supported(nodes["leaf0"]) and not (
            leaf0_evpn_int_counters >= 0.98 * int(const.spytest_data.pkts_per_burst)
            and leaf0_evpn_int_counters <= 1.2 * int(const.spytest_data.pkts_per_burst)
            and leaf2_evpn_int_counters >= 0.98 * int(const.spytest_data.pkts_per_burst)
            and leaf2_evpn_int_counters <= 1.2 * int(const.spytest_data.pkts_per_burst)
        ):
            report_fail(
                nodes["leaf0"],
                "Unicast traffic going from H2 to H4 not taking evpn interface",
            )

        # Verify RT-5 with subnet are exchanged
        if not verify_vrf_route_l3vni(nodes, const.leaf2_vrf_prefix, "leaf0", "Vrf01"):
            report_fail(
                nodes["leaf0"],
                "Incorrect entry found for {} in show ip route".format(
                    const.leaf2_vrf_prefix
                ),
            )
        if not verify_vrf_route_l3vni(nodes, const.leaf2_vrf_prefix, "leaf1", "Vrf01"):
            report_fail(
                nodes["leaf1"],
                "Incorrect entry found for {} in show ip route".format(
                    const.leaf2_vrf_prefix
                ),
            )
        if not verify_ip_route_multihomed_host(
            nodes, const.leaf2_vrf_prefix, "leaf2", "Vrf01"
        ):
            report_fail(
                nodes["leaf2"],
                "ecmp not installed for {} on {}".format(
                    const.leaf2_vrf_prefix, nodes["leaf2"]
                ),
            )
        if not verify_arp(nodes, const.spytest_data.lag_ip, "leaf0") and verify_arp(
            nodes, const.spytest_data.lag_ip, "leaf1"
        ):
            report_fail(
                "",
                "verify_arp testcase failed for {}".format(const.spytest_data.lag_ip),
            )

        # Verify H2 IP in APP_DB on T1
        db.verify_sonic_app_db_for_pfx(
            nodes,
            const.spytest_data.lag_ip,
            "leaf0",
            "Vlan10:" + const.spytest_data.lag_ip,
        )
        # Verify H2 IP in APP_DB on T2
        db.verify_sonic_app_db_for_pfx(
            nodes,
            const.spytest_data.lag_ip,
            "leaf1",
            "Vlan10:" + const.spytest_data.lag_ip,
        )
        # Verify H2 IP in APP_DB on T3
        db.verify_sonic_app_db_for_pfx(
            nodes,
            const.spytest_data.lag_ip,
            "leaf2",
            "Vrf01:" + const.spytest_data.lag_ip,
        )
        # Verify H4 IP in ASIC_DB on T1
        db.verify_sonic_asic_db_for_pfx(
            nodes, const.spytest_data.t1d4p2_ip_addr, "leaf0", const.LEAF2_VXLAN_IP
        )
        # Verify H4 IP in ASIC_DB on T2
        db.verify_sonic_asic_db_for_pfx(
            nodes, const.spytest_data.t1d4p2_ip_addr, "leaf1", const.LEAF2_VXLAN_IP
        )
        # Verify H2 IP in ASIC_DB on T3
        db.verify_sonic_asic_db_for_pfx(nodes, const.spytest_data.lag_ip, "leaf2")
        # Verify H2 IP in ASIC_DB on T1 and T2
        db.verify_sonic_asic_db_for_neighbor_pfx(
            nodes, const.spytest_data.lag_ip, "leaf0", const.LEAF2_VXLAN_IP
        )
        db.verify_sonic_asic_db_for_neighbor_pfx(
            nodes, const.spytest_data.lag_ip, "leaf1", const.LEAF2_VXLAN_IP
        )
        # Verify H2 MAC is learn locally
        if not is_mac_exists(nodes, "leaf0", const.spytest_data.lag_mac):
            report_fail(
                nodes["leaf0"],
                "verify_mac testcase failed for {} on node leaf0".format(
                    const.spytest_data.lag_mac
                ),
            )
        if not is_mac_exists(nodes, "leaf1", const.spytest_data.lag_mac):
            report_fail(
                nodes["leaf1"],
                "verify_mac testcase failed for {} on node leaf1".format(
                    const.spytest_data.lag_mac
                ),
            )
        # Veify H2 is remotely, not learned locally to leaf2
        if is_mac_exists_local(
            nodes, "leaf2", const.spytest_data.lag_mac
        ) or not is_mac_exists(nodes, "leaf2", const.spytest_data.lag_mac):
            report_fail(
                nodes["leaf2"],
                "verify_mac {} should be remotely present on node leaf2".format(
                    const.spytest_data.lag_mac
                ),
            )
        report_pass("test_case_passed", "test_inter_subnet_ping")

    except Exception as e:
        report_fail("test_case_failed", msg=e)


def test_intra_subnet_ping(traffic_setup):
    """
    Test intra-subnet ping
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    try:
        result = verify_l3_traffic([("T1D2P1", const.lag_name)], lag_handle)  # H1 -> H2
        if not result:
            report_fail(
                "test_case_failed", "test_intra_subnet_ping failed with unicast traffic"
            )

        leaf0_local_int_counters = vxlan_utils.get_counters(
            nodes["leaf0"],
            cmd="show interface counters",
            target_iface=traffic_setup["D2T1P2"],
            r_t_key="tx_ok",
        )
        log(
            "\nTX counters on locally connected interface to H2 is {}".format(
                leaf0_local_int_counters
            )
        )

        leaf1_int_counters = vxlan_utils.get_counters(
            nodes["leaf1"],
            cmd="show interface counters",
            target_iface=traffic_setup["D3T1P1"],
            r_t_key="tx_ok",
        )
        log(
            "\nTX counters on leaf1 connected interface to H2 is {}".format(
                leaf1_int_counters
            )
        )

        if not (
            leaf0_local_int_counters >= 0.98 * int(const.spytest_data.pkts_per_burst)
            and leaf0_local_int_counters <= 1.1 * int(const.spytest_data.pkts_per_burst)
            and (leaf1_int_counters <= 0.1 * int(const.spytest_data.pkts_per_burst))
        ):
            report_fail(
                nodes["leaf1"],
                "Unicast traffic going from H1 to H2 not taking local interface",
            )

        log("\nsending unknownunicast traffic from H2 \n")
        stream = {
            "src_endpoint": {
                "port": const.lag_name,
                "host_ip": const.spytest_data.lag_ip,
                "gateway": const.spytest_data.lag_gateway_ip,
                "mac": const.spytest_data.lag_mac,
            },
            "dst_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d4t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
        }

        wait(15)
        result = verify_bum_traffic(
            lag_handle, stream, const.lag_name, "unknownunicast", "T1D4P1"
        )
        if not result:
            report_fail(
                nodes["leaf1"],
                "test_intra_subnet_ping testcase failed with Unknown Unicast traffic sent from H2",
            )
        intf_cmd = "show interface counters"
        diff_vlan_counters = vxlan_utils.get_counters(
            nodes["leaf2"],
            cmd=intf_cmd,
            target_iface=traffic_setup["D4T1P2"],
            r_t_key="tx_ok",
        )
        log(
            "\nTX counters on interface {} belonging to different vlan is {}".format(
                traffic_setup["D4T1P2"], diff_vlan_counters
            )
        )

        if not (diff_vlan_counters <= 0.1 * int(const.spytest_data.pkts_per_burst)):
            report_fail(nodes["leaf2"], "BUM traffic getting flooded on different vlan")

        log("\nsending BUM traffic from H1 \n")
        stream = {
            "src_endpoint": {
                "port": "T1D2P1",
                "host_ip": const.spytest_data.t1d2p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d2p1_mac_addr,
            },
            "dst_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d4t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
        }
        result = verify_bum_traffic(lag_handle, stream, "T1D2P1", "unknownunicast")
        if not result:
            report_fail(
                "test_case_failed",
                "test_intra_subnet_ping failed with unknown unicast traffic",
            )
        result = verify_bum_traffic(lag_handle, stream, "T1D2P1", "broadcast")
        if not result:
            report_fail(
                "test_case_failed",
                "test_intra_subnet_ping failed with broadcast traffic",
            )
        # arp_leaf0 = verify_arp(nodes,const.spytest_data.lag_ip, 'leaf0')
        # arp_leaf1 = verify_arp(nodes,const.spytest_data.lag_ip, 'leaf1')
        # if not arp_leaf0:
        # if not arp_leaf1:
        # report_fail("test_case_failed", 'verify_arp testcase failed for {}'.format(spytest_data.lag_ip))
        # Verify H2 IP in APP_DB on T1, T2 and T3
        db.verify_sonic_app_db_for_pfx(
            nodes,
            const.spytest_data.lag_ip,
            "leaf0",
            "Vlan10:" + const.spytest_data.lag_ip,
        )
        db.verify_sonic_app_db_for_pfx(
            nodes,
            const.spytest_data.lag_ip,
            "leaf1",
            "Vlan10:" + const.spytest_data.lag_ip,
        )
        db.verify_sonic_app_db_for_pfx(
            nodes,
            const.spytest_data.lag_ip,
            "leaf2",
            "Vrf01:" + const.spytest_data.lag_ip,
        )
        # Verify H2 IP in ASIC_DB on T1 and T2
        db.verify_sonic_asic_db_for_neighbor_pfx(
            nodes, const.spytest_data.lag_ip, "leaf0", const.LEAF2_VXLAN_IP
        )
        db.verify_sonic_asic_db_for_neighbor_pfx(
            nodes, const.spytest_data.lag_ip, "leaf1", const.LEAF2_VXLAN_IP
        )
        # Verify H2 adjacency is learn locally
        db.is_nhg_installed(nodes)
        if not is_mac_exists(nodes, "leaf0", const.spytest_data.lag_mac):
            report_fail(
                nodes["leaf0"],
                "verify_mac testcase failed for {} on node leaf0".format(
                    const.spytest_data.lag_mac
                ),
            )
        if not is_mac_exists(nodes, "leaf1", const.spytest_data.lag_mac):
            report_fail(
                nodes["leaf1"],
                "verify_mac testcase failed for {} on node leaf1".format(
                    const.spytest_data.lag_mac
                ),
            )
        report_pass("test_case_passed", "test_intra_subnet_ping")

    except Exception as e:
        report_fail("", msg=e)


def test_remote_unicast_for_ecmp(traffic_setup):
    """
    Remote unicast for ECMP Testing
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    stream = {
        "src_endpoint": {
            "port": "T1D4P1",
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d4t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        },
        "dst_endpoint": {
            "port": const.lag_name,
            "host_ip": const.spytest_data.lag_ip,
            "gateway": const.spytest_data.lag_gateway_ip,
            "mac": const.spytest_data.lag_mac,
        },
    }
    vxlan_utils.clear_counters()
    get_cli_out()
    stream_id = vxlan_utils.create_udp_traffic_stream(
        lag_handle, const.spytest_data, stream
    )
    result = vxlan_utils.send_udp_traffic(
        lag_handle, const.spytest_data, stream, stream_id
    )

    if not result:
        report_fail(
            nodes["leaf2"], "Unicast traffic in test_remote_unicast_for_ecmp failed"
        )
    intf_cmd = "show interface counters"
    leaf0_counters = vxlan_utils.get_counters(
        nodes["leaf0"],
        cmd=intf_cmd,
        target_iface=traffic_setup["D2T1P2"],
        r_t_key="tx_ok",
    )
    leaf1_counters = vxlan_utils.get_counters(
        nodes["leaf1"],
        cmd=intf_cmd,
        target_iface=traffic_setup["D3T1P1"],
        r_t_key="tx_ok",
    )
    log(
        "\nTX counters on interface {} and {} is {} and {}".format(
            traffic_setup["D2T1P2"],
            traffic_setup["D3T1P1"],
            leaf0_counters,
            leaf1_counters,
        )
    )

    if leaf0_counters <= 0.1 * int(
        const.spytest_data.pkts_per_burst
    ) or leaf1_counters <= 0.1 * int(const.spytest_data.pkts_per_burst):
        banner(
            "Unicast traffic from leaf2 is not getting load balanced between leaf0 and leaf1"
        )
        report_fail(
            nodes["leaf2"],
            "Unicast traffic from leaf2 is not getting load balanced between leaf0 and leaf1",
        )
    host_configure_cmd(
        nodes["leaf0"], "config interface shutdown {}".format(traffic_setup["D2T1P2"])
    )
    vxlan_utils.clear_counters()
    get_cli_out()
    result = vxlan_utils.send_udp_traffic(
        lag_handle, const.spytest_data, stream, stream_id
    )
    vxlan_utils.delete_udp_traffic_stream(lag_handle, stream)
    host_configure_cmd(
        nodes["leaf0"], "config interface start {}".format(traffic_setup["D2T1P2"])
    )
    if not result:
        report_fail(
            nodes["leaf0"],
            "Traffic test failed after shutting down Leaf0 link connected to multihomed host",
        )
    report_pass("test_case_passed", "test_remote_unicast_for_ecmp passed")


def test_portchannel_deconf(traffic_setup):
    """
    Portchannel Deconfig and Config to See DF and NDF is Honored
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # Deconfig
    cmds = [
        "sudo config interface sys-mac remove PortChannel2 00:44:33:22:11:00",
        "sudo config interface evpn-esi del PortChannel2",
        "sudo config vlan member del 10 PortChannel2",
        "sudo config portchannel member del PortChannel2 {}".format(
            traffic_setup["D2T1P2"]
        ),
        "sudo config portchannel del PortChannel2",
    ]
    for cmd in cmds:
        host_configure_cmd(nodes["leaf0"], cmd)

    if not verify_port_channel(nodes, "leaf0"):
        report_fail(nodes["leaf0"], "Portchannel deconfig failed")

    # Restore config
    cmds = [
        "sudo config portchannel add PortChannel2",
        "sudo config interface ipv6 disable use-link-local-only {}".format(
            traffic_setup["D2T1P2"]
        ),
        "sudo config portchannel member add PortChannel2 {}".format(
            traffic_setup["D2T1P2"]
        ),
        "sudo config vlan member add -u 10 PortChannel2",
        "sudo config interface sys-mac add PortChannel2 00:44:33:22:11:00",
        "sudo config interface evpn-esi add PortChannel2 auto-system-mac",
    ]
    for cmd in cmds:
        host_configure_cmd(nodes["leaf0"], cmd)

    wait(20)

    # check portchannel status
    host_show_cmd(nodes["leaf0"], "show interface portchannel")
    host_show_cmd(nodes["leaf1"], "show interface portchannel")

    # check es and ndf status
    if not evpn_mh_obj.isDF(nodes["leaf0"], const.ESI1):
        report_fail(
            nodes["leaf0"], "leaf0 df/ndf status is wrong after resetting portchannel"
        )

    if evpn_mh_obj.isDF(nodes["leaf1"], const.ESI1):
        report_fail(
            nodes["leaf1"], "leaf1 df/ndf status is wrong after resetting portchannel"
        )

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
        report_fail(
            nodes["leaf1"], "BUM traffic is not drop in NDF after resetting portchannel"
        )

    else:
        report_pass("test_case_passed", "test_portchannel_deconf")


def test_portchannel_flap(traffic_setup):
    """
    Portchannel shutdown and startup to See everything is working fine
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]
    test_case_id = "test_portchannel_flap"

    result_str = ""

    # Shutdown portchannel on leaf0
    dut = nodes["leaf0"]
    intf = "PortChannel2"

    intf_obj.interface_shutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "down"):
        log = "Shutdown {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Shutdown portchannel on leaf1
    dut = nodes["leaf1"]
    intf = "PortChannel2"
    intf_obj.interface_shutdown("leaf1", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "down"):
        log = "Shutdown {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Start portchannel on leaf0
    dut = nodes["leaf0"]
    intf = "PortChannel2"
    intf_obj.interface_noshutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "up"):
        log = "Start {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Start portchannel on leaf1
    dut = nodes["leaf1"]
    intf = "PortChannel2"
    intf_obj.interface_noshutdown("leaf1", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "up"):
        log = "Start {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    result, msg = verify_df_ndf_traffic(nodes, lag_handle, traffic_setup)
    if not result:
        banner(msg)
        result_str += "{}\n".format(msg)

    if result_str:
        report_fail(nodes["leaf0"], result_str)
    else:
        report_pass(nodes["leaf0"], test_case_id)


def test_interface_to_spine_flap(traffic_setup):
    """
    Spine facing interface shutdown and startup to See everything is working fine
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]
    test_case_id = "test_interface_to_spine_flap"

    result_str = ""

    # Shutdown interface on leaf0
    dut = nodes["leaf0"]
    intf = traffic_setup["D2D1P1"]

    intf_obj.interface_shutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "down"):
        log = "Shutdown {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Start interface on leaf0
    intf_obj.interface_noshutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "up"):
        log = "Start {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    wait(10)

    result, msg = verify_df_ndf_traffic(nodes, lag_handle, traffic_setup)
    if not result:
        banner(msg)
        result_str += "{}\n".format(msg)

    if result_str:
        report_fail(nodes["leaf0"], result_str)
    else:
        report_pass(nodes["leaf0"], test_case_id)


def test_vlan_member_flap(traffic_setup):
    """
    Vlan member shutdown and startup to See everything is working fine
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]
    intf = traffic_setup["D2T1P1"]
    test_case_id = "test_vlan_member_flap"

    result_str = ""

    # Shutdown vlan member on leaf0
    dut = nodes["leaf0"]

    intf_obj.interface_shutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "down"):
        log = "Shutdown {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Start vlan member on leaf0
    intf_obj.interface_noshutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "up"):
        log = "Start {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    result, msg = verify_df_ndf_traffic(nodes, lag_handle, traffic_setup)
    if not result:
        banner(msg)
        result_str += "{}\n".format(msg)

    if result_str:
        report_fail(nodes["leaf0"], result_str)
    else:
        report_pass(nodes["leaf0"], test_case_id)


def test_portchannel_member_flap(traffic_setup):
    """
    Portchannel member shutdown and startup to See everything is working fine
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]
    test_case_id = "test_portchannel_member_flap"

    result_str = ""

    dut = nodes["leaf0"]
    intf = "PortChannel2"

    tg_handle = lag_handle[const.lag_name]["tg_handle"]
    stream = {
        "src_endpoint": {
            "port": "T1D4P1",
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d4t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        },
        "dst_endpoint": {
            "port": intf,
            "host_ip": const.spytest_data.lag_ip,
            "gateway": const.spytest_data.lag_gateway_ip,
            "mac": const.spytest_data.lag_mac,
        },
    }

    stream_id = create_continous_traffic(
        lag_handle, stream, "T1D4P1", "unknownunicast", const.lag_name
    )

    # Start traffic
    result = continuous_traffic_control([stream_id], "start", tg_handle)
    if not result:
        msg = "Failed to start traffic"
        result_str += "{}\n".format(msg)

    dut = nodes["leaf0"]
    intf = "PortChannel2"
    # Shutdown portchannel on leaf0
    intf_obj.interface_shutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "down"):
        log = "Shutdown {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Start portchannel on leaf0
    intf_obj.interface_noshutdown("leaf0", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "up"):
        log = "Start {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    wait(15)

    # Check traffic
    result = continuous_traffic_control([stream_id], "check", tg_handle)
    if not result:
        msg = "Check traffic Failed"
        result_str += "{}\n".format(msg)

    if result_str:
        report_fail(nodes["leaf0"], result_str)
    else:
        report_pass(nodes["leaf0"], test_case_id)

    # Shutdown portchannel on leaf1
    dut = nodes["leaf1"]
    intf = "PortChannel2"
    intf_obj.interface_shutdown("leaf1", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "down"):
        log = "Shutdown {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)
    # Start portchannel on leaf1
    intf_obj.interface_noshutdown("leaf1", intf)
    if not intf_obj.verify_interface_status(dut, intf, "admin", "up"):
        log = "Start {} {} ports failed".format(dut, intf)
        banner(log)
        result_str += "{}\n".format(log)

    # Check traffic
    result = continuous_traffic_control([stream_id], "check", tg_handle)
    if not result:
        msg = "Check traffic Failed"
        result_str += "{}\n".format(msg)

    if result_str:
        report_fail(nodes["leaf0"], result_str)
    else:
        report_pass(nodes["leaf0"], test_case_id)
