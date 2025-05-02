import evpn_mh_utils
import vxlan_utils


from multihome import const
from multihome import db, host, traffic_generator, vtysh
from multihome.mobility import helpers
from multihome.status_report import report_pass, report_fail, start_banner, log

# Please update the FRR db seq if any MAC move testcases are updated/added.


def test_mac_ip_move_sh(traffic_setup):
    """
    SH mac move test when H1 is moved from L0 to L2 and moved back, H1->H3
    """
    start_banner(
        "SH mac move test when H1 is moved from L0 to L2 and moved back, H1->H3"
    )
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]
    # create raw traffic stream from H5 to H1
    h5_h1_hdl = helpers.create_h5_h1_traffic_stream_handle()
    result = traffic_generator.send_unicast_burst(h5_h1_hdl)
    if not result:
        report_fail(
            nodes["leaf0"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h5", "h1", ""),
        )
    # stop H1 for mac move
    traffic_generator.stop_lag_group_protocol(lag_handle, const.port_name_map["H1"])
    # create same device as stopped device behind different leaf, H1 moved behind leaf2
    host_info_map = {
        "host_ip": const.spytest_data.t1d2p1_ip_addr,
        "host_mac": const.spytest_data.t1d2p1_mac_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
    }
    traffic_generator.create_lag_group_and_start_protocol(
        lag_handle, const.port_name_map["H3"], host_info_map, "moved_deviceGroup_H1"
    )

    # traffic verifications
    h5_moved_h1_handle = traffic_generator.create_a_raw_traffic_stream(
        {
            "src_endpoint": {
                "port": "T1D3P2",
                "host_ip": const.spytest_data.t1d3p2_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d3p2_mac_addr,
            },
            "dst_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d2p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d2p1_mac_addr,
            },
        }
    )
    result = traffic_generator.send_unicast_burst(h5_moved_h1_handle)
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h5", "h1", ""),
        )

    h2_counter = vxlan_utils.get_counters(
        node=nodes["leaf1"],
        cmd="show interface counters",
        target_iface=traffic_setup["D2T1P2"],
        r_t_key="rx_ok",
    )
    if not (h2_counter <= 0.1 * int(const.spytest_data.pkts_per_burst)):
        report_fail(nodes["leaf1"], helpers.ERR_TRAFFIC_FLOOD.format("h5", "h1", "h2"))
    log(helpers.PING_AND_UNICAST_TRAFFIC_SUCCESS.format("h5", "h1"))

    # old traffic stream should fail now

    result = traffic_generator.send_unicast_burst(h5_h1_hdl)
    if result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_UNEXPECTED.format("h5", "h1"),
        )
    log("ping and traffic from H5 to moved H1 failed as expected")

    # Check inter-traffic verifications
    log("send l3 traffic between h1 and h4")
    const.interface_map[const.port_name_map["H3"]] = {
        "host_ip": const.spytest_data.t1d2p1_ip_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
        "mac": const.spytest_data.t1d2p1_mac_addr,
    }
    result = traffic_generator.verify_l3_traffic(
        [("T1D4P1", "T1D4P2")], lag_handle
    )  # H1(H3) -> H4
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
        )
        const.interface_map[const.port_name_map["H3"]] = {
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        }
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h4", "h1", ""
            ),
        )
    # Reset dict
    const.interface_map[const.port_name_map["H3"]] = {
        "host_ip": const.spytest_data.t1d4p1_ip_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
        "mac": const.spytest_data.t1d4p1_mac_addr,
    }

    # FRR verification
    updated_seq_ids = db.update_sequence_ids(["LEAF2"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D4T1P1"],
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr, expected_frr_op
            )
            if not frr:
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
                )
                report_fail(
                    nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE.format(dut, frr)
                )

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_ip_addr
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
                )
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf0",
        const.spytest_data.t1d2p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf0"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d2p1_mac_addr),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf2", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf2", const.spytest_data.t1d2p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
            )
            report_fail(
                nodes["leaf2"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_mac_addr, "leaf2"
                ),
            )
        log(
            "mac {} not found after move to leaf2 in ASIC DB but found in kernel without extern_learn flag.".format(
                const.spytest_data.t1d2p1_mac_addr
            )
        )
    # IP verification
    helpers.verify_sonic_app_db_for_pfx(
        nodes,
        const.spytest_data.t1d2p1_ip_addr,
        "Vrf01",
        "Vrf01",
        "Vlan10",
    )

    # move H1 back behind leaf0
    start_banner("Moving H1 back behind Leaf0")

    traffic_generator.reset_topology_after_mac_move(
        lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
    )
    h5_h1_hdl = helpers.create_h5_h1_traffic_stream_handle()
    result = vxlan_utils.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format(
                "h5", "h1", "behind leaf0"
            ),
        )
    log("ping and traffic from h5 to moved back h1 behind leaf0 passed")

    # FRR
    updated_seq_ids = db.update_sequence_ids(["LEAF0"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D2T1P1"],
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF0_VXLAN_IP,
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF0_VXLAN_IP,
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr, expected_frr_op
            )
            if not frr:
                report_fail(
                    nodes[dut],
                    helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE.format("dut", frr),
                )

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_ip_addr
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf2",
        const.spytest_data.t1d2p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        report_fail(
            nodes["leaf0"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d2p1_mac_addr),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr
        ):
            report_fail(
                nodes["leaf0"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_mac_addr, "leaf0"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.t1d2p1_mac_addr, "leaf0"
            )
        )

    report_pass("test_case_passed", "test_mac_ip_move_sh passed")


def test_mac_ip_move_sh_to_mh(traffic_setup):
    """
    MH mac move test when H1 is moved to H2 and moved back
    """
    start_banner("MH mac move test when H1 is moved to H2 and moved back")
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # create raw traffic stream from H5 to H1
    h5_h1_hdl = helpers.create_h5_h1_traffic_stream_handle()
    result = vxlan_utils.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(
            nodes["leaf0"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h5", "h1", ""),
        )

    # stop H1 for mac move
    traffic_generator.stop_lag_group_protocol(lag_handle, const.port_name_map["H1"])
    # create same device as stopped device behind different leaf, H1 moved behind H2
    host_info_map = {
        "host_ip": const.spytest_data.t1d2p1_ip_addr,
        "host_mac": const.spytest_data.t1d2p1_mac_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
    }
    traffic_generator.create_lag_group_and_start_protocol(
        lag_handle, const.port_name_map["H2"], host_info_map, "moved_deviceGroup_H1"
    )

    if not vxlan_utils.ping_gateway(
        lag_handle,
        const.lag_name,
        const.spytest_data.d2t1_ip_addr,
        lag_handle[const.lag_name]["int_handle1"],
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
        )
        report_fail(nodes["leaf1"], "ping failed after mac move from new h1 to gw")

    # traffic verifications H5->H2
    stream = {
        "src_endpoint": {
            "port": "T1D3P2",
            "host_ip": const.spytest_data.t1d3p2_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d3p2_mac_addr,
        },
        "dst_endpoint": {
            "port": const.lag_name,
            "host_ip": const.spytest_data.t1d2p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d2p1_mac_addr,
        },
    }
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D3P2"],
        lag_handle[const.lag_name],
        stream,
        "raw",
        const.spytest_data,
    )
    result = vxlan_utils.send_raw_traffic_stream(lag_handle["T1D3P2"], stream_id, False)
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h5", "h3"
            ),
        )
    h3_counter = vxlan_utils.get_counters(
        node=nodes["leaf2"],
        cmd="show interface counters",
        target_iface=traffic_setup["D4T1P1"],
        r_t_key="rx_ok",
    )
    if not (h3_counter <= 0.1 * int(const.spytest_data.pkts_per_burst)):
        report_fail(nodes["leaf2"], helpers.ERR_TRAFFIC_FLOOD.format("h5", "h2", "h3"))

    log(helpers.PING_AND_UNICAST_TRAFFIC_SUCCESS.format("h5", "h1"))

    # old traffic stream should fail now
    result = vxlan_utils.traffic_test_burst("unicast", h5_h1_hdl)
    if result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_UNEXPECTED.format("h5", "h1"),
        )
    log("ping and traffic from h5 to moved h1 failed as expected")

    # Check inter-traffic verifications
    log("send l3 traffic between h1 and h4")
    const.interface_map[const.port_name_map["H2"]] = {
        "host_ip": const.spytest_data.t1d2p1_ip_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
        "mac": const.spytest_data.t1d2p1_mac_addr,
    }
    result = traffic_generator.verify_l3_traffic(
        [(const.lag_name, "T1D4P2")], lag_handle
    )  # H1(H2) -> H4
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
        )
        const.interface_map.update(
            {
                const.port_name_map["H2"]: {
                    "host_ip": const.spytest_data.lag_ip,
                    "gateway": const.spytest_data.lag_gateway_ip,
                    "mac": const.spytest_data.lag_mac,
                }
            }
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h4", "h1"
            ),
        )
    # Reset dict
    const.interface_map.update(
        {
            const.port_name_map["H2"]: {
                "host_ip": const.spytest_data.lag_ip,
                "gateway": const.spytest_data.lag_gateway_ip,
                "mac": const.spytest_data.lag_mac,
            }
        }
    )

    # FRR verification
    updated_seq_ids = db.update_sequence_ids(["LEAF0", "LEAF1"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": "PortChannel2",
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": "PortChannel2",
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": "03:00:44:33:22:11:00:00:00:02",
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr, expected_frr_op
            )
            if not frr:
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
                )
                report_fail(
                    nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE.format(dut, frr)
                )

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_ip_addr
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
                )
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr, "static", "0"
    ):
        if not db.verify_mac_in_app_db(
            nodes, "leaf1", const.spytest_data.t1d2p1_mac_addr, "static", "0"
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
            )
            report_fail(
                nodes["leaf1"],
                helpers.ERR_APP_DB_MAC_INCORRECT.format(
                    const.spytest_data.t1d2p1_mac_addr
                ),
            )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf1", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf1", const.spytest_data.t1d2p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
            )
            report_fail(
                nodes["leaf1"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_mac_addr, "leaf0-1"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.t1d2p1_mac_addr, "leaf0-1"
            )
        )

    if not (host.is_mac_exists(nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
            )
            report_fail(
                nodes["leaf0"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_ip_addr, "leaf0-1"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.t1d2p1_mac_addr, "leaf0-1"
            )
        )

    # IP verification
    helpers.verify_sonic_app_db_for_pfx(
        nodes,
        const.spytest_data.t1d2p1_ip_addr,
        "Vlan10",
        "Vlan10",
        "Vrf01",
    )

    # move H1 back behind leaf0
    start_banner("Moving H1 back behind Leaf0")
    traffic_generator.reset_topology_after_mac_move(
        lag_handle, const.port_name_map["H2"], const.port_name_map["H1"]
    )
    h5_h1_hdl = helpers.create_h5_h1_traffic_stream_handle()
    result = vxlan_utils.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format(
                "h5", "h1", "behind leaf0"
            ),
        )
    log("ping and traffic from h5 to moved back h1 behind leaf0 passed")

    # FRR
    updated_seq_ids = db.update_sequence_ids(["LEAF0"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D2T1P1"],
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF0_VXLAN_IP,
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF0_VXLAN_IP,
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr, expected_frr_op
            )
            if not frr:
                report_fail(
                    nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE.format(dut, frr)
                )

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_ip_addr
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf2",
        const.spytest_data.t1d2p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        report_fail(
            nodes["leaf2"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d2p1_mac_addr),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr
        ):
            report_fail(
                nodes["leaf0"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_mac_addr, "back-to-leaf0"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(const.spytest_data.t1d2p1_mac_addr)
        )

    report_pass("test_case_passed", "test_mac_ip_move_sh_to_mh passed")


def test_mac_ip_move_remote_sh_to_mh(traffic_setup):
    """
    SH mac move test when H3  is moved to H2 and moved back
    """
    start_banner("SH mac move test when H3  is moved to H2 and moved back")
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]
    # create raw traffic stream from H5 to H3
    h5_h3_hdl = traffic_generator.create_a_raw_traffic_stream(
        {
            "dst_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
            "src_endpoint": {
                "port": "T1D3P2",
                "host_ip": const.spytest_data.t1d3p2_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d3p2_mac_addr,
            },
        }
    )
    result = vxlan_utils.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(
            nodes["leaf0"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h5", "h3", ""),
        )

    # stop H3 for mac move
    traffic_generator.stop_lag_group_protocol(lag_handle, const.port_name_map["H3"])
    # create same device as stopped device behind different leaf, H3 moved behind H2
    host_info_map = {
        "host_ip": const.spytest_data.t1d4p1_ip_addr,
        "host_mac": const.spytest_data.t1d4p1_mac_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
    }
    traffic_generator.create_lag_group_and_start_protocol(
        lag_handle, const.port_name_map["H2"], host_info_map, "moved_deviceGroup_H3"
    )
    if not vxlan_utils.ping_gateway(
        lag_handle,
        const.lag_name,
        const.spytest_data.d2t1_ip_addr,
        lag_handle[const.lag_name]["int_handle1"],
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
        )
        report_fail(nodes["leaf1"], "ping failed after mac move from new h3 to gw")

    # traffic verifications from H5->H2
    stream = {
        "src_endpoint": {
            "port": "T1D3P2",
            "host_ip": const.spytest_data.t1d3p2_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d3p2_mac_addr,
        },
        "dst_endpoint": {
            "port": const.lag_name,
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        },
    }
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D3P2"],
        lag_handle[const.lag_name],
        stream,
        "raw",
        const.spytest_data,
    )
    result = vxlan_utils.send_raw_traffic_stream(lag_handle["T1D3P2"], stream_id, False)
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
        )
        report_fail(
            nodes["leaf1"], helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format("h5", "h3")
        )

    h1_counter = vxlan_utils.get_counters(
        node=nodes["leaf0"],
        cmd="show interface counters",
        target_iface=traffic_setup["D2T1P1"],
        r_t_key="rx_ok",
    )
    if not (h1_counter <= 0.1 * int(const.spytest_data.pkts_per_burst)):
        report_fail(nodes["leaf0"], helpers.ERR_TRAFFIC_FLOOD("h5", "h2"))
    log(helpers.PING_AND_UNICAST_TRAFFIC_SUCCESS.format("h5", "h3"))
    # old traffic stream should fail now
    result = vxlan_utils.traffic_test_burst("unicast", h5_h3_hdl)
    if result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_UNEXPECTED.format("h5", "h3"),
        )
    log("ping and traffic from h5 to moved h3 failed as expected")

    # FRR verifications
    updated_seq_ids = db.update_sequence_ids(["LEAF0", "LEAF1"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "local",
            "vtep": "PortChannel2",
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "local",
            "vtep": "PortChannel2",
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": "03:00:44:33:22:11:00:00:00:02",
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d4p1_mac_addr, expected_frr_op
            )
            if not frr:
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
                )
                report_fail(
                    nodes["leaf2"],
                    helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE.format(dut, frr),
                )

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.t1d4p1_ip_addr
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.t1d4p1_mac_addr
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
                )
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes, "leaf0", const.spytest_data.t1d4p1_mac_addr, "static", "0"
    ):
        if not db.verify_mac_in_app_db(
            nodes, "leaf1", const.spytest_data.t1d4p1_mac_addr, "static", "0"
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
            )
            report_fail(
                nodes["leaf1"],
                helpers.ERR_APP_DB_MAC_INCORRECT.format(
                    const.spytest_data.t1d4p1_mac_addr
                ),
            )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf1", const.spytest_data.t1d4p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf1", const.spytest_data.t1d4p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
            )
            report_fail(
                nodes["leaf1"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d4p1_mac_addr, "leaf0-1"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.t1d4p1_mac_addr, "leaf0-1"
            )
        )

    if not (host.is_mac_exists(nodes, "leaf0", const.spytest_data.t1d4p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf0", const.spytest_data.t1d4p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
            )
            report_fail(
                nodes["leaf0"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d4p1_mac_addr, "leaf0-1"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.t1d4p1_mac_addr, "leaf0-1"
            )
        )

    if (
        host.is_mac_exists_local(nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr)
    ) or not (host.is_mac_exists(nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr)):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
        )
        report_fail(
            nodes["leaf2"],
            helpers.ERR_MAC_SHOULD_BE_PRESENT.format(
                const.spytest_data.t1d4p1_mac_addr, "leaf2", "leaf0", "leaf1"
            ),
        )

    helpers.verify_sonic_app_db_for_pfx(
        nodes,
        const.spytest_data.t1d4p1_ip_addr,
        "Vlan10",
        "Vlan10",
        "Vrf01",
    )

    # move H3 back behind leaf2
    start_banner("Moving H3 back behind Leaf2")
    traffic_generator.reset_topology_after_mac_move(
        lag_handle, const.port_name_map["H2"], const.port_name_map["H3"]
    )
    result = vxlan_utils.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format(
                "h5", "h3", "behind leaf2"
            ),
        )
    log("ping and traffic from h5 to moved back h3 behind leaf2 passed")

    # FRR verifications
    updated_seq_ids = db.update_sequence_ids(["LEAF2"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D4T1P1"],
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d4p1_mac_addr, expected_frr_op
            )
            if not frr:
                report_fail(nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE)

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.t1d4p1_ip_addr
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.t1d4p1_mac_addr
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf0",
        const.spytest_data.t1d4p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        report_fail(
            nodes["leaf0"],
            helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                const.spytest_data.t1d4p1_mac_addr, "leaf0"
            ),
        )

    if not db.verify_mac_in_app_db(
        nodes,
        "leaf1",
        const.spytest_data.t1d4p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        report_fail(
            nodes["leaf1"],
            helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                const.spytest_data.t1d4p1_mac_addr, "leaf1"
            ),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr
        ):
            report_fail(
                nodes["leaf2"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d4p1_mac_addr, "(back-to-leaf2)"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.t1d4p1_mac_addr, "leaf2"
            )
        )

    report_pass("test_case_passed", "test_mac_ip_move_remote_sh_to_mh")


def test_mac_ip_move_mh_to_remote_sh(traffic_setup):
    """
    MH mac move test when H2 is moved to H3 and moved back
    """
    start_banner("MH mac move test when H2 is moved to H3 and moved back")
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # create raw traffic stream from H5 to H2
    stream = {
        "src_endpoint": {
            "port": "T1D3P2",
            "host_ip": const.spytest_data.t1d3p2_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d3p2_mac_addr,
        },
        "dst_endpoint": {
            "port": const.lag_name,
            "host_ip": const.spytest_data.lag_ip,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.lag_mac,
        },
    }
    old_stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D3P2"],
        lag_handle[const.lag_name],
        stream,
        "raw",
        const.spytest_data,
    )
    result = vxlan_utils.send_raw_traffic_stream(
        lag_handle["T1D3P2"], old_stream_id, False
    )
    if not result:
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h5", "h2", ""),
        )

    # stop H2 for mac move
    start_banner("Moving H2")
    traffic_generator.stop_lag_group_protocol(lag_handle, const.port_name_map["H2"])
    # create same device as stopped device behind different leaf, H2 moved behind leaf0
    host_info_map = {
        "host_ip": const.spytest_data.lag_ip,
        "host_mac": const.spytest_data.lag_mac,
        "gateway": const.spytest_data.d2t1_ip_addr,
    }
    traffic_generator.create_lag_group_and_start_protocol(
        lag_handle, const.port_name_map["H3"], host_info_map, "moved_deviceGroup_H2"
    )
    if not vxlan_utils.ping_gateway(
        lag_handle,
        "T1D4P1",
        const.spytest_data.d2t1_ip_addr,
        lag_handle["T1D4P1"]["int_handle1"],
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h2", "new->gw"
            ),
        )

    start_banner("Traffic tests for the moved H2")
    # verifications
    stream = {
        "src_endpoint": {
            "port": "T1D3P2",
            "host_ip": const.spytest_data.t1d3p2_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d3p2_mac_addr,
        },
        "dst_endpoint": {
            "port": "T1D4P1",
            "host_ip": const.spytest_data.lag_ip,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.lag_mac,
        },
    }
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D3P2"], lag_handle["T1D4P1"], stream, "raw", const.spytest_data
    )
    result = vxlan_utils.send_raw_traffic_stream(lag_handle["T1D3P2"], stream_id, False)
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE("h5", "h2"),
        )

    h1_counter = vxlan_utils.get_counters(
        node=nodes["leaf0"],
        cmd="show interface counters",
        target_iface=traffic_setup["D2T1P1"],
        r_t_key="rx_ok",
    )
    if not (h1_counter <= 0.1 * int(const.spytest_data.pkts_per_burst)):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf0"],
            helpers.ERR_TRAFFIC_FLOOD("h5", "moved-h2", "h1 (behind h3)"),
        )
    log("ping and traffic from h5 to h2 passed after mac move with unicast traffic")

    # old traffic stream should fail now
    result = vxlan_utils.send_raw_traffic_stream(
        lag_handle["T1D3P2"], old_stream_id, False
    )
    if result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf1"],
            "ping and traffic from H5 to moved H2 passed unexpectedly with unicast traffic",
        )
    log("ping and traffic from H5 to moved H2 failed as expected")

    # Check inter-traffic verifications
    log("send l3 traffic between H3 and H4")
    const.interface_map[const.port_name_map["H3"]] = {
        "host_ip": const.spytest_data.lag_ip,
        "gateway": const.spytest_data.lag_gateway_ip,
        "mac": const.spytest_data.lag_mac,
    }
    result = traffic_generator.verify_l3_traffic(
        [("T1D4P1", "T1D4P2")], lag_handle
    )  # H3(H2) -> H4
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        const.interface_map[const.port_name_map["H3"]] = {
            "host_ip": const.spytest_data.t1d4p1_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d4p1_mac_addr,
        }
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h4", "h3"
            ),
        )
    # Reset dict
    const.interface_map[const.port_name_map["H3"]] = {
        "host_ip": const.spytest_data.t1d4p1_ip_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
        "mac": const.spytest_data.t1d4p1_mac_addr,
    }

    # FRR verifications
    updated_seq_ids = db.update_sequence_ids(["LEAF2"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.lag_mac,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.lag_mac,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.lag_mac,
            "type": "local",
            "vtep": "Ethernet1/9",
            "seq": updated_seq_ids[2],
        },
    }

    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.lag_mac, expected_frr_op
            )
            if not frr:
                log("FRR verification failed, reseting topology")
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
                )
                report_fail(nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE)

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.lag_ip
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.lag_mac
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
                )
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes, "leaf1", const.spytest_data.lag_mac, "static", const.EXPECTED_L2VNI
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.lag_mac),
        )
    if not db.verify_mac_in_app_db(
        nodes, "leaf0", const.spytest_data.lag_mac, "static", const.EXPECTED_L2VNI
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf0"],
            helpers.ERR_APP_DB_MAC_INCORRECTformat(const.spytest_data.lag_mac),
        )

    # ASIC DB
    if (host.is_mac_exists_local(nodes, "leaf0", const.spytest_data.lag_mac)) or not (
        host.is_mac_exists(nodes, "leaf0", const.spytest_data.lag_mac)
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf0"],
            helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                const.spytest_data.lag_mac, "leaf0"
            ),
        )
    if (host.is_mac_exists_local(nodes, "leaf1", const.spytest_data.lag_mac)) or not (
        host.is_mac_exists(nodes, "leaf1", const.spytest_data.lag_mac)
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                const.spytest_data.lag_mac, "leaf1"
            ),
        )
    if not (host.is_mac_exists(nodes, "leaf2", const.spytest_data.lag_mac)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf2", const.lag_mac
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
            )
            report_fail(
                nodes["leaf2"],
                "mac {} not found after move to leaf2".format(
                    const.spytest_data.lag_mac
                ),
            )
        log(
            "mac {} not found after move to leaf2 in ASIC DB but found in kernel without extern_learn flag.".format(
                const.spytest_data.lag_mac
            )
        )

    # IP verification
    helpers.verify_sonic_app_db_for_pfx(
        nodes,
        const.spytest_data.lag_ip,
        "Vrf01",
        "Vrf01",
        "Vlan10",
    )

    # move H2 back behind leaf0-leaf1
    start_banner("Moving H2 back behind Leaf0-Leaf1")
    traffic_generator.reset_topology_after_mac_move(
        lag_handle, const.port_name_map["H3"], const.port_name_map["H2"]
    )
    stream = {
        "src_endpoint": {
            "port": "T1D3P2",
            "host_ip": const.spytest_data.t1d3p2_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d3p2_mac_addr,
        },
        "dst_endpoint": {
            "port": const.lag_name,
            "host_ip": const.spytest_data.lag_ip,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.lag_mac,
        },
    }
    old_stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D3P2"],
        lag_handle[const.lag_name],
        stream,
        "raw",
        const.spytest_data,
    )
    result = vxlan_utils.send_raw_traffic_stream(
        lag_handle["T1D3P2"], old_stream_id, False
    )
    if not result:
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h5", "behind h2 (leaf0)"
            ),
        )
    log("ping and traffic from H5 to moved back H2 passed")

    # FRR
    updated_seq_ids = db.update_sequence_ids(["LEAF0", "LEAF1"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.lag_mac,
            "type": "local",
            "vtep": "PortChannel2",
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.lag_mac,
            "type": "remote",
            "vtep": "PortChannel2",
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.lag_mac,
            "type": "remote",
            "vtep": "03:00:44:33:22:11:00:00:00:02",
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.lag_mac, expected_frr_op
            )
            if not frr:
                report_fail(nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE)

    # kernel verification
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            kernel_ip_flag = vxlan_utils.is_ip_neigh_present_in_kernel(
                nodes, dut, const.spytest_data.lag_ip
            )
            kernel_mac_flag = vxlan_utils.is_mac_present_in_kernel(
                nodes, dut, const.spytest_data.lag_mac
            )
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(
                    nodes[dut],
                    helpers.ERR_KERNEL_PROGRAMMING.format(
                        dut, kernel_ip_flag, kernel_mac_flag
                    ),
                )

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes, "leaf2", const.spytest_data.lag_mac, "static", const.EXPECTED_L2VNI
    ):
        report_fail(
            nodes["leaf2"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.lag_mac),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf0", const.spytest_data.lag_mac)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf0", const.spytest_data.lag_mac
        ):
            report_fail(
                nodes["leaf1"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.lag_mac, "leaf0-1"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(
                const.spytest_data.lag_mac, "leaf0-1"
            )
        )

    if not (host.is_mac_exists(nodes, "leaf1", const.spytest_data.lag_mac)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf1", const.spytest_data.lag_mac
        ):
            report_fail(
                nodes["leaf1"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.lag_mac, "leaf0-1"
                ),
            )
        log(helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(const.spytest_data.lag_mac))

    report_pass("test_case_passed", "test_mac_ip_move_mh_to_remote_sh")


def test_sh_mac_ip_move_h1_h5(traffic_setup):
    """
    SH mac move test when H1 -> H5
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    start_banner("SH mac move test when H1 -> H5")
    # create raw traffic stream from H3 to H1
    h3_h1_hdl = traffic_generator.create_a_raw_traffic_stream(
        {
            "dst_endpoint": {
                "port": "T1D2P1",
                "host_ip": const.spytest_data.t1d2p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d2p1_mac_addr,
            },
            "src_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
        }
    )
    result = vxlan_utils.traffic_test_burst("unicast", h3_h1_hdl)
    if not result:
        report_fail(
            nodes["leaf0"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h3", "h1", ""),
        )
    # stop H1 for mac move
    traffic_generator.stop_lag_group_protocol(lag_handle, const.port_name_map["H1"])
    # create same device as stopped device behind different leaf, H1 moved behind leaf1
    host_info_map = {
        "host_ip": const.spytest_data.t1d2p1_ip_addr,
        "host_mac": const.spytest_data.t1d2p1_mac_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
    }
    traffic_generator.create_lag_group_and_start_protocol(
        lag_handle, const.port_name_map["H5"], host_info_map, "moved_deviceGroup_H1"
    )

    # traffic verifications
    h3_moved_h1_handle = traffic_generator.create_a_raw_traffic_stream(
        {
            "src_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
            "dst_endpoint": {
                "port": "T1D3P2",
                "host_ip": const.spytest_data.t1d2p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d2p1_mac_addr,
            },
        }
    )
    result = vxlan_utils.traffic_test_burst("unicast", h3_moved_h1_handle)
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h3", "h1"
            ),
        )

    h2_counter = vxlan_utils.get_counters(
        node=nodes["leaf1"],
        cmd="show interface counters",
        target_iface=traffic_setup["D2T1P2"],
        r_t_key="rx_ok",
    )
    if not (h2_counter <= 0.1 * int(const.spytest_data.pkts_per_burst)):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
        )
        report_fail(nodes["leaf1"], helpers.ERR_TRAFFIC_FLOOD.format("h3", "h1", "h2"))
    log("ping and traffic from h3 to h1 passed after mac move with unicast traffic")

    # old traffic stream should fail now
    result = vxlan_utils.traffic_test_burst("unicast", h3_h1_hdl)
    if result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_UNEXPECTED.format("h3", "h1"),
        )
    log("ping and traffic from H3 to moved H1 failed as expected")

    # Check inter-traffic verifications
    log("send l3 traffic between H1 and H4")
    const.interface_map[const.port_name_map["H5"]] = {
        "host_ip": const.spytest_data.t1d2p1_ip_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
        "mac": const.spytest_data.t1d2p1_mac_addr,
    }
    result = traffic_generator.verify_l3_traffic(
        [("T1D3P2", "T1D4P2")], lag_handle
    )  # H1(H5) -> H4
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
        )
        const.interface_map[const.port_name_map["H5"]] = {
            "host_ip": const.spytest_data.t1d3p2_ip_addr,
            "gateway": const.spytest_data.d2t1_ip_addr,
            "mac": const.spytest_data.t1d3p2_mac_addr,
        }
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h4", "h1"
            ),
        )
    # Reset dict
    const.interface_map[const.port_name_map["H5"]] = {
        "host_ip": const.spytest_data.t1d3p2_ip_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
        "mac": const.spytest_data.t1d3p2_mac_addr,
    }

    # FRR verification
    updated_seq_ids = db.update_sequence_ids(["LEAF1"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF1_VXLAN_IP,
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D3T1P2"],
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF1_VXLAN_IP,
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr, expected_frr_op
            )
            if not frr:
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
                )
                report_fail(nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE)

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf0",
        const.spytest_data.t1d2p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
        )
        report_fail(
            nodes["leaf0"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d2p1_mac_addr),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf1", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf1", const.spytest_data.t1d2p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
            )
            report_fail(
                nodes["leaf1"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_mac_addr, "leaf1"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(const.spytest_data.t1d2p1_mac_addr)
        )

    # move H1 back behind leaf0
    traffic_generator.reset_topology_after_mac_move(
        lag_handle, const.port_name_map["H5"], const.port_name_map["H1"]
    )
    h3_h1_hdl = traffic_generator.create_a_raw_traffic_stream(
        {
            "dst_endpoint": {
                "port": "T1D2P1",
                "host_ip": const.spytest_data.t1d2p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d2p1_mac_addr,
            },
            "src_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
        }
    )
    result = vxlan_utils.traffic_test_burst("unicast", h3_h1_hdl)
    if not result:
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE.format(
                "h3", "h1", "behind-leaf0"
            ),
        )
    log("ping and traffic from h3 to moved back h1 behind leaf0 passed")

    # FRR
    updated_seq_ids = db.update_sequence_ids(["LEAF0"])
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D2T1P1"],
            "seq": updated_seq_ids[0],
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF0_VXLAN_IP,
            "seq": updated_seq_ids[1],
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d2p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF0_VXLAN_IP,
            "seq": updated_seq_ids[2],
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d2p1_mac_addr, expected_frr_op
            )
            if not frr:
                report_fail(nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE)

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf2",
        const.spytest_data.t1d2p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        report_fail(
            nodes["leaf0"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d2p1_mac_addr),
        )

    # ASIC DB
    if not (host.is_mac_exists(nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr)):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr
        ):
            report_fail(
                nodes["leaf0"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d2p1_mac_addr, "leaf0"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(const.spytest_data.t1d2p1_mac_addr)
        )

    report_pass("test_case_passed", "test_sh_mac_ip_move_h1_h5")


def test_sh_mac_ip_move_h3_h4(traffic_setup):
    """
    SH mac move test when H3 -> H4
    """
    start_banner("SH mac move test when H3 -> H4")
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # create raw traffic stream from H5 to H3
    h5_h3_hdl = traffic_generator.create_a_raw_traffic_stream(
        {
            "dst_endpoint": {
                "port": "T1D4P1",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d4t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
            "src_endpoint": {
                "port": "T1D3P2",
                "host_ip": const.spytest_data.t1d3p2_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d3p2_mac_addr,
            },
        }
    )
    result = vxlan_utils.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(
            nodes["leaf0"], helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format("h5", "h3", "")
        )
    # stop H3 for mac move
    traffic_generator.stop_lag_group_protocol(lag_handle, const.port_name_map["H3"])

    # change interface configuration from Vlan20 to Vlan10.
    cmd = "sudo config vlan member del 20 {}".format(traffic_setup["D4T1P2"])
    host.configure_cmd(nodes["leaf2"], cmd)

    cmd = "sudo config vlan member add -u 10 {}".format(traffic_setup["D4T1P2"])
    host.configure_cmd(nodes["leaf2"], cmd)

    # create same device as stopped device behind same leaf2, H3 moved in the same leaf2 of different interface.
    host_info_map = {
        "host_ip": const.spytest_data.t1d4p1_ip_addr,
        "host_mac": const.spytest_data.t1d4p1_mac_addr,
        "gateway": const.spytest_data.d2t1_ip_addr,
    }
    traffic_generator.create_lag_group_and_start_protocol(
        lag_handle, const.port_name_map["H4"], host_info_map, "moved_deviceGroup_H3"
    )

    # traffic verifications
    h5_moved_h3_handle = traffic_generator.create_a_raw_traffic_stream(
        {
            "src_endpoint": {
                "port": "T1D3P2",
                "host_ip": const.spytest_data.t1d3p2_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d3p2_mac_addr,
            },
            "dst_endpoint": {
                "port": "T1D4P2",
                "host_ip": const.spytest_data.t1d4p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d4p1_mac_addr,
            },
        }
    )
    result = vxlan_utils.traffic_test_burst("unicast", h5_moved_h3_handle)
    if not result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H4"], const.port_name_map["H3"]
        )
        cmd = "sudo config vlan member del 10 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        cmd = "sudo config vlan member add -u 20 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        report_fail(
            nodes["leaf1"],
            "ping and traffic from H5 to H1 failed after mac move with unicast traffic",
        )

    h2_counter = vxlan_utils.get_counters(
        node=nodes["leaf1"],
        cmd="show interface counters",
        target_iface=traffic_setup["D2T1P2"],
        r_t_key="rx_ok",
    )
    if not (h2_counter <= 0.1 * int(const.spytest_data.pkts_per_burst)):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H4"], const.port_name_map["H3"]
        )
        cmd = "sudo config vlan member del 10 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        cmd = "sudo config vlan member add -u 20 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        report_fail(nodes["leaf1"], helpers.ERR_TRAFFIC_FLOOD("h5", "h3", "h2"))
    log("ping and traffic from h5 to h3 passed after mac move with unicast traffic")

    # old traffic stream should fail now
    result = vxlan_utils.traffic_test_burst("unicast", h5_h3_hdl)
    if result:
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H4"], const.port_name_map["H3"]
        )
        cmd = "sudo config vlan member del 10 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        cmd = "sudo config vlan member add -u 20 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        report_fail(
            nodes["leaf1"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_UNEXPECTED.format("h5", "h3"),
        )
    log("ping and traffic from h5 to moved h3 failed as expected")

    # FRR verification
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": "0/0",
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": "0/0",
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D4T1P2"],
            "seq": "0/0",
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d4p1_mac_addr, expected_frr_op
            )
            if not frr:
                traffic_generator.reset_topology_after_mac_move(
                    lag_handle, const.port_name_map["H3"], const.port_name_map["H1"]
                )
                cmd = "sudo config vlan member del 10 {}".format(
                    traffic_setup["D4T1P2"]
                )
                host.configure_cmd(nodes["leaf2"], cmd)
                cmd = "sudo config vlan member add -u 20 {}".format(
                    traffic_setup["D4T1P2"]
                )
                host.configure_cmd(nodes["leaf2"], cmd)
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf0",
        const.spytest_data.t1d4p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        traffic_generator.reset_topology_after_mac_move(
            lag_handle, const.port_name_map["H4"], const.port_name_map["H3"]
        )
        cmd = "sudo config vlan member del 10 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        cmd = "sudo config vlan member add -u 20 {}".format(traffic_setup["D4T1P2"])
        host.configure_cmd(nodes["leaf2"], cmd)
        report_fail(
            nodes["leaf2"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d4p1_mac_addr),
        )

    # ASIC DB
    if not host.is_mac_exists(
        nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr, traffic_setup["D4T1P2"]
    ):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr
        ):
            traffic_generator.reset_topology_after_mac_move(
                lag_handle, const.port_name_map["H4"], const.port_name_map["H3"]
            )
            cmd = "sudo config vlan member del 10 {}".format(traffic_setup["D4T1P2"])
            host.configure_cmd(nodes["leaf2"], cmd)
            cmd = "sudo config vlan member add -u 20 {}".format(traffic_setup["D4T1P2"])
            host.configure_cmd(nodes["leaf2"], cmd)
            report_fail(
                nodes["leaf2"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d4p1_mac_addr, "leaf2"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(const.spytest_data.t1d4p1_mac_addr)
        )

    # move H3 back to original interface of H3
    traffic_generator.reset_topology_after_mac_move(
        lag_handle, const.port_name_map["H4"], const.port_name_map["H3"]
    )
    cmd = "sudo config vlan member del 10 {}".format(traffic_setup["D4T1P2"])
    host.configure_cmd(nodes["leaf2"], cmd)
    cmd = "sudo config vlan member add -u 20 {}".format(traffic_setup["D4T1P2"])
    host.configure_cmd(nodes["leaf2"], cmd)
    result = vxlan_utils.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(
            nodes["leaf2"],
            helpers.ERR_PING_AND_UNICAST_TRAFFIC_FAILED.format(
                "h5", "h3", "behind leaf2"
            ),
        )
    log("ping and traffic from h5 to moved back h3 interface is working")

    # FRR verification
    expected_frr_op = {
        "leaf0": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": "0/0",
        },
        "leaf1": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "remote",
            "vtep": const.LEAF2_VXLAN_IP,
            "seq": "0/0",
        },
        "leaf2": {
            "mac_address": const.spytest_data.t1d4p1_mac_addr,
            "type": "local",
            "vtep": traffic_setup["D4T1P1"],
            "seq": "0/0",
        },
    }
    for dut in traffic_setup["dut_names"]:
        if "leaf" in dut:
            frr = vtysh.verify_mac_advertisements(
                nodes, dut, const.spytest_data.t1d4p1_mac_addr, expected_frr_op
            )
            if not frr:
                report_fail(nodes[dut], helpers.ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE)

    # APP DB
    if not db.verify_mac_in_app_db(
        nodes,
        "leaf0",
        const.spytest_data.t1d4p1_mac_addr,
        "static",
        const.EXPECTED_L2VNI,
    ):
        report_fail(
            nodes["leaf2"],
            helpers.ERR_APP_DB_MAC_INCORRECT.format(const.spytest_data.t1d4p1_mac_addr),
        )

    # ASIC DB
    if not host.is_mac_exists(
        nodes,
        "leaf2",
        const.spytest_data.t1d4p1_mac_addr,
        interface=traffic_setup["D4T1P1"],
    ):
        # Since on SIM mac can be learnt directly in kernel. Relaxing the ASIC_DB check.
        if not vxlan_utils.is_mac_no_extern_learn_present_in_kernel(
            nodes, "leaf2", const.spytest_data.t1d4p1_mac_addr
        ):
            report_fail(
                nodes["leaf2"],
                helpers.ERR_MAC_NOT_FOUND_AFTER_MOVE.format(
                    const.spytest_data.t1d4p1_mac_addr, "leaf0"
                ),
            )
        log(
            helpers.LOG_DB_ASIC_MAC_NOT_FOUND.format(const.spytest_data.t1d4p1_mac_addr)
        )

    report_pass("test_case_passed", "test_sh_mac_ip_move_h3_h4")
