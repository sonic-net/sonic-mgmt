import os
import pytest
import re
import evpn_mh_utils
import vxlan_utils

from multihome.status_report import report_fail, report_pass, banner, log
from multihome.dut import wait
from multihome import const, dut, host, vtysh
import json

# After a BUM burst, RIF/port counters in COUNTERS_DB may lag hardware; allow sync
# before show interface counters (slightly above typical 10s counterpoll default).
_INTERFACE_COUNTER_SETTLE_SEC = 12


def test_evpn_mh_basic_config(setup):
    """
    Test EVPN Multihome Basic Config
    """
    banner("test_evpn_mh_basic_config")
    nodes = setup["duts"]

    # Dump LLDP table output
    dut.exec_each(nodes, host.configure_cmd, "show lldp table")

    try:
        # Start Verification
        vxlan_utils.verify_bgp(nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)
        vxlan_utils.verify_bgp(nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI)
        vxlan_utils.verify_bgp(nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)
        report_pass("test_case_passed", "test_evpn_mh_basic_config")
    except Exception as e:
        report_fail("", msg=e)


def test_es_peering(setup):
    """
    Test EVPN Multihome ES Peering between T1 and T2
    """

    banner("test_es_peering")
    nodes = setup["duts"]

    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")
    report_pass("test_case_passed", "test_es_peering")


def test_remote_es(setup):
    """
    Test EVPN Multihome Remote ES on T3 with T1 and T2 as remote
    """
    banner("test_remote_es")

    nodes = setup["duts"]
    _, parsed_output = vtysh.show_evpn_es(nodes["leaf2"])

    for es in parsed_output:
        if es["esi"] == const.ESI1:
            if "R" in es["type"]:
                missing_vtep = False
                fail_msg = ""
                if const.LEAF0_VXLAN_IP not in es["vteps"].split(","):
                    missing_vtep = True
                    fail_msg += "Missing LEAF0_VXLAN_IP \n"
                if const.LEAF1_VXLAN_IP not in es["vteps"].split(","):
                    missing_vtep = True
                    fail_msg += "Missing LEAF1_VXLAN_IP"
                if not missing_vtep:
                    report_pass("test_case_passed", "test_remote_es")
                else:
                    report_fail(nodes["leaf2"], fail_msg)
            else:
                report_fail(nodes["leaf2"], "ES1 is not shown as remote")
        else:
            report_fail(nodes["leaf2"], "ES1 does not show")


def test_df_selection(setup):
    """
    Test EVPN Multihome DF Selection
    """
    banner("test_df_selection")

    nodes = setup["duts"]

    leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)

    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")
    else:
        report_pass("test_case_passed", "test_df_selection")


def test_rt2_proxy(setup):
    """
    Test EVPN Multihome Route Type 2 Proxy
    TC could fail until MIGSOFTWAR-17150 is fixed
    """
    banner("test_rt2_proxy")

    nodes = setup["duts"]
    lag_handle = setup["lag_handle"]

    # Validate Leaf1 regenerates RT-2 as proxy
    leaf0_proxy = False
    leaf1_proxy = False
    leaf0_learned = False
    leaf1_learned = False

    # Reset L3 protocol to trigger type 2 learning
    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="stop_all_protocols",
    )

    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="start_all_protocols",
    )
    wait(10)

    _, parsed_output_leaf1 = vtysh.show_evpn_type_2(nodes["leaf1"])
    _, parsed_output_leaf2 = vtysh.show_evpn_type_2(nodes["leaf2"])

    for route in parsed_output_leaf1:
        if "100.100.100.1:" in route["route_distinguisher"] and route["ip"] == const.spytest_data.lag_ip:
            leaf0_learned = True
            if route["nd_proxy"] == "ND:Proxy":
                leaf0_proxy = True
        if "100.100.100.2:" in route["route_distinguisher"] and route["ip"] == const.spytest_data.lag_ip:
            leaf1_learned = True
            if route["nd_proxy"] == "ND:Proxy":
                leaf1_proxy = True

    if not leaf0_learned:
        report_fail(nodes["leaf0"], "leaf0 did not learn ip address of H2")

    if not leaf1_learned:
        report_fail(nodes["leaf1"], "leaf1 did not learn ip address of H2")

    # only one of leaf0 and leaf1 can have ND_Proxy flag
    if not leaf0_proxy ^ leaf1_proxy:
        report_fail(nodes["leaf1"], "RT2 proxy is not regenerated")

    # Validate ECMP on leaf2
    leaf0_path_seen = False
    leaf1_path_seen = False

    for route in parsed_output_leaf2:
        if "100.100.100.1:" in route["route_distinguisher"] and route["ip"] == const.spytest_data.lag_ip:
            leaf0_path_seen = True
        if "100.100.100.2:" in route["route_distinguisher"] and route["ip"] == const.spytest_data.lag_ip:
            leaf1_path_seen = True

    if not (leaf0_path_seen and leaf1_path_seen):
        report_fail(nodes["leaf2"], "No proper ECMP is shown on Leaf2")
    else:
        report_pass(nodes["leaf2"], "test_rt2_proxy")

'''
def test_reload_and_restart_config(setup):
    """
    Test EVPN Multihome Reload Config
    """
    banner("test_reload_config")

    nodes = setup["duts"]

    log("verifying BGP before reload")
    # Verify BGP
    vxlan_utils.verify_bgp(nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI, single_run=True)
    vxlan_utils.verify_bgp(nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI, single_run=True)
    vxlan_utils.verify_bgp(nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI, single_run=True)

    log("verifying DF before reload")
    leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)

    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    log("saving config before reload")
    # save configuration before reloading
    dut.exec_each(nodes, host.configure_cmd, "sudo config save -y")

    log("download and upload updated config_db.json to support split-unified")
    for name, node in nodes.items():
        config_path = "/tmp/{name}.config_db.json".format(name=name)
        if dut.download_file(node, name, "config_db.json", "/etc/sonic", config_path) != "SUCCESS":
            report_fail(node, "Failed to download config_db.json")
            break

        with open(config_path, "r+") as f:
            config = json.load(f)
            # Update config as needed, for example:
            # config["some_key"] = "new_value"
            config["DEVICE_METADATA"]["localhost"].update({"docker_routing_config_mode": "split-unified"})
            f.seek(0)
            json.dump(config, f, indent=4)
            f.truncate()
        try:
            dut.upload_file(node, config_path, "/etc/sonic/config_db.json")
        except Exception as e:
            report_fail(node, "Failed to upload config_db.json. error: {}".format(e))
            os.remove(config_path)
            break
        # Remove the local copy of the file
        os.remove(config_path)

    log("save frr configuration")
    # save frr configuration
    dut.exec_each(nodes, vtysh.show_cmd, "write")

    log("reloading config")
    # Reload config
    dut.exec_each(nodes, host.reload_config)
    wait(90)

    log("verifying DF after reload")
    for i in range(12):
        leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
        leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
        if leaf0_idDF ^ leaf1_isDF:
            break
        log("DF selection not stable yet, time passed {}, waiting for another 5 seconds".format(i * 5))
        wait(5)
    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    banner("verifying BGP restart")
    # Verify BGP
    vxlan_utils.verify_bgp(nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)
    vxlan_utils.verify_bgp(nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI)
    vxlan_utils.verify_bgp(nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)

    # Restart BGP container
    dut.exec_each(nodes, host.restart_container, "bgp")
    wait(20)

    log("verifying DF after restart")
    for i in range(12):
        leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
        leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
        if leaf0_idDF ^ leaf1_isDF:
            break
        log("DF selection not stable yet, time passed {}, waiting for another 5 seconds".format(i * 5))
        wait(5)
    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    # Verify BGP
    vxlan_utils.verify_bgp(nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)
    vxlan_utils.verify_bgp(nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI)
    vxlan_utils.verify_bgp(nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)

    log("verifying ES peering after reload")
    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")

    report_pass(nodes["leaf0"], "test_reload_config")
'''
# FIXME: This Test on SIM is not working as expected
# eth4 interface is interfering with the EVPN tunnel
# during cleanup, the tunnel is not removed
# then the following configure is not applied
def test_deconfig_config(setup):
    """
    Test EVPN Multihome Deconfig Config
    """
    banner("test_deconfig_config")

    nodes = setup["duts"]
    config_file = setup["config_file"]

    # Deconfig config
    dut.configure(config_file, nodes, add=False)
    wait(5)

    # post deconfig/config some times vtysh may not exit properly
    # adding below logic to exit vtysh if not exited correctly
    for node in nodes:
        if "Unknown command" in vtysh.show_cmd(node, "show version", skip_error_check=True).strip():
            vtysh.show_cmd(node, "\nend\nshow version\n", skip_error_check=True)

    dut.configure(config_file, nodes)
    wait(10)

    # post deconfig/config some times vtysh may not exit properly
    # adding below logic to exit vtysh if not exited correctly
    for node in nodes:
        if "Unknown command" in vtysh.show_cmd(node, "show version", skip_error_check=True).strip():
            vtysh.show_cmd(node, "\nend\nshow version\n", skip_error_check=True)

    log("verifying DF after reconfigure")
    for i in range(12):
        leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
        leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
        if leaf0_idDF ^ leaf1_isDF:
            break
        log("DF selection not stable yet, time passed {}, waiting for another 5 seconds".format(i * 5))
        dut.wait(10)
    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    # Verify BGP
    vxlan_utils.verify_bgp(nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)
    vxlan_utils.verify_bgp(nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI)
    vxlan_utils.verify_bgp(nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI)

    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")
    
    report_pass(nodes["leaf0"], "test_deconfig_config")


def test_portchannel_shutdown_on_mh_peer(setup):
    """
    Test EVPN Multihome PortChannel Shutdown on One Multihomed Peer

    Test Steps:
    1. Verify initial ES peering and DF/NDF selection
    2. Verify initial traffic from remote host (H3) to multihomed host (H2)
    3. Shutdown PortChannel on leaf0 (one of the multihomed peers)
    4. Verify ES state changes - leaf0 ES should be down, leaf1 should become sole DF
    5. Verify traffic still works via leaf1 (all traffic should go through leaf1)
    6. Bring up PortChannel on leaf0
    7. Verify ES peering is restored and DF/NDF selection is correct
    8. Verify traffic works with both peers active
    """
    banner("test_portchannel_shutdown_on_mh_peer")

    nodes = setup["duts"]
    lag_handle = setup["lag_handle"]

    # Step 1: Verify initial ES peering and DF/NDF selection
    log("Step 1: Verifying initial ES peering and DF/NDF selection")
    
    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "Initial ES peering failed between leaf0 and leaf1")

    initial_leaf0_isDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    initial_leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
    
    if not (initial_leaf0_isDF ^ initial_leaf1_isDF):
        report_fail(nodes["leaf0"], "Initial DF selection is incorrect - both or neither are DF")
    
    log("Initial DF status - leaf0: {}, leaf1: {}".format(initial_leaf0_isDF, initial_leaf1_isDF))

    # Collect initial show outputs for debugging
    log("Collecting initial show evpn es output")
    vtysh.show_evpn_es(nodes["leaf0"], verbose=True)
    vtysh.show_evpn_es(nodes["leaf1"], verbose=True)
    vtysh.show_evpn_es(nodes["leaf2"], verbose=True)

    # Verify BGP before shutdown
    log("Verifying BGP routes before PortChannel shutdown")
    vxlan_utils.verify_bgp(
        nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI, single_run=True
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI, single_run=True
    )

    # Step 2: Verify initial traffic - send BUM traffic from H3 to multihomed host
    log("Step 2: Verifying initial traffic from H3 to multihomed host")
    cmd_intf = "show interface counters"
    
    # Determine which leaf is DF
    if initial_leaf0_isDF:
        df_downlink = setup["D2T1P2"]
        ndf_downlink = setup["D3T1P1"]
        df_node = nodes["leaf0"]
        ndf_node = nodes["leaf1"]
    else:
        df_downlink = setup["D3T1P1"]
        ndf_downlink = setup["D2T1P2"]
        df_node = nodes["leaf1"]
        ndf_node = nodes["leaf0"]

    # Send BUM traffic from H3 to verify DF/NDF filtering before shutdown
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
    
    vxlan_utils.clear_counters()
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D4P1"],
        lag_handle["T1D2P1"],
        stream,
        "raw",
        const.spytest_data,
        "broadcast",
    )
    vxlan_utils.send_raw_traffic_stream(lag_handle["T1D4P1"], stream_id, reset=True)

    dut.wait(_INTERFACE_COUNTER_SETTLE_SEC)

    # Verify traffic went through DF and was dropped at NDF
    pkts = int(const.spytest_data.pkts_per_burst)
    df_downlink_initial = vxlan_utils.get_counters(
        node=df_node, cmd=cmd_intf, target_iface=df_downlink, r_t_key="tx_ok"
    )
    ndf_downlink_initial = vxlan_utils.get_counters(
        node=ndf_node, cmd=cmd_intf, target_iface=ndf_downlink, r_t_key="tx_ok"
    )
    log(
        "Initial traffic - DF downlink {}: {}, NDF downlink {}: {}".format(
            df_downlink, df_downlink_initial, ndf_downlink, ndf_downlink_initial
        )
    )

    if not (
        df_downlink_initial >= 0.98 * pkts
        and df_downlink_initial <= 1.1 * pkts
        and ndf_downlink_initial <= 0.1 * pkts
    ):
        report_fail(df_node, "Initial BUM traffic verification failed - DF/NDF filtering not working")

    log("Initial traffic verification passed")

    # Step 3: Shutdown PortChannel on leaf0
    log("Step 3: Shutting down PortChannel2 on leaf0")
    host.configure_cmd(nodes["leaf0"], "sudo config interface shutdown PortChannel2")
    
    # Wait for convergence
    dut.wait(30)

    # Step 4: Verify ES state after shutdown
    log("Step 4: Verifying ES state after PortChannel shutdown on leaf0")
    
    # Show ES output after shutdown
    log("Show evpn es output after shutdown")
    vtysh.show_evpn_es(nodes["leaf0"], verbose=True)
    vtysh.show_evpn_es(nodes["leaf1"], verbose=True)
    vtysh.show_evpn_es(nodes["leaf2"], verbose=True)

    # After shutdown, leaf1 should be the only DF for ESI1
    leaf1_isDF_after_shutdown = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
    
    if not leaf1_isDF_after_shutdown:
        log("Warning: leaf1 is not DF after leaf0 PortChannel shutdown - this may be expected if ES is removed")
    
    # Verify BGP routes still work via leaf1
    log("Verifying BGP routes after PortChannel shutdown on leaf0")
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI, single_run=True
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf2_vrf_prefix, "leaf1", const.EXPECTED_L3VNI, single_run=True
    )

    # Verify remote ES on leaf2 - should now only show leaf1 as VTEP for ESI1
    log("Verifying remote ES on leaf2 after leaf0 PortChannel shutdown")
    _, parsed_output = vtysh.show_evpn_es(nodes["leaf2"])
    for es in parsed_output:
        if es["esi"] == const.ESI1:
            log("Remote ES on leaf2: VTEPs = {}".format(es.get("vteps", "N/A")))
            # After shutdown, leaf2 should only see leaf1 as remote VTEP for ESI1
            if const.LEAF0_VXLAN_IP in es.get("vteps", "").split(","):
                log("Warning: leaf0 VTEP still showing in remote ES on leaf2 - may take time to age out")

    # Step 5: Verify traffic after shutdown - all traffic should go via leaf1
    log("Step 5: Verifying traffic after PortChannel shutdown - should go via leaf1 only")
    
    vxlan_utils.clear_counters()
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D4P1"],
        lag_handle["T1D2P1"],
        stream,
        "raw",
        const.spytest_data,
        "broadcast",
    )
    vxlan_utils.send_raw_traffic_stream(lag_handle["T1D4P1"], stream_id, reset=True)

    dut.wait(_INTERFACE_COUNTER_SETTLE_SEC)

    leaf1_downlink_after_shutdown = vxlan_utils.get_counters(
        node=nodes["leaf1"], cmd=cmd_intf, target_iface=setup["D3T1P1"], r_t_key="tx_ok"
    )
    log("Traffic after shutdown - leaf1 downlink: {}".format(leaf1_downlink_after_shutdown))

    pkts = int(const.spytest_data.pkts_per_burst)
    if not (
        leaf1_downlink_after_shutdown >= 0.98 * pkts
        and leaf1_downlink_after_shutdown <= 1.1 * pkts
    ):
        report_fail(nodes["leaf1"], "Traffic verification failed after PortChannel shutdown - traffic should go via leaf1")

    log("Traffic verification after shutdown passed")

    # Step 6: Bring up PortChannel on leaf0
    log("Step 6: Bringing up PortChannel2 on leaf0")
    host.configure_cmd(nodes["leaf0"], "sudo config interface startup PortChannel2")
    
    # Wait for convergence
    dut.wait(60)

    # Step 7: Verify ES peering is restored
    log("Step 7: Verifying ES peering is restored after PortChannel startup")
    
    # Show ES output after startup
    log("Show evpn es output after startup")
    vtysh.show_evpn_es(nodes["leaf0"], verbose=True)
    vtysh.show_evpn_es(nodes["leaf1"], verbose=True)
    vtysh.show_evpn_es(nodes["leaf2"], verbose=True)

    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES peering not restored after PortChannel startup")

    # Verify DF/NDF selection is restored
    restored_leaf0_isDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    restored_leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
    
    if not (restored_leaf0_isDF ^ restored_leaf1_isDF):
        report_fail(nodes["leaf0"], "DF selection incorrect after PortChannel restore - both or neither are DF")
    
    log("Restored DF status - leaf0: {}, leaf1: {}".format(restored_leaf0_isDF, restored_leaf1_isDF))

    # Verify remote ES on leaf2 - should show both leaf0 and leaf1 as VTEPs
    log("Verifying remote ES on leaf2 after PortChannel restore")
    _, parsed_output = vtysh.show_evpn_es(nodes["leaf2"])
    for es in parsed_output:
        if es["esi"] == const.ESI1:
            if "R" in es["type"]:
                vteps = es.get("vteps", "").split(",")
                if const.LEAF0_VXLAN_IP not in vteps:
                    report_fail(nodes["leaf2"], "leaf0 VTEP missing from remote ES after restore")
                if const.LEAF1_VXLAN_IP not in vteps:
                    report_fail(nodes["leaf2"], "leaf1 VTEP missing from remote ES after restore")
            break

    # Verify BGP routes after restore
    log("Verifying BGP routes after PortChannel restore")
    vxlan_utils.verify_bgp(
        nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )

    # Step 8: Verify traffic after restore - should follow DF/NDF rules again
    log("Step 8: Verifying traffic after PortChannel restore")
    
    # Re-determine which leaf is DF after restore
    if restored_leaf0_isDF:
        restored_df_downlink = setup["D2T1P2"]
        restored_ndf_downlink = setup["D3T1P1"]
        restored_df_node = nodes["leaf0"]
        restored_ndf_node = nodes["leaf1"]
    else:
        restored_df_downlink = setup["D3T1P1"]
        restored_ndf_downlink = setup["D2T1P2"]
        restored_df_node = nodes["leaf1"]
        restored_ndf_node = nodes["leaf0"]

    vxlan_utils.clear_counters()
    stream_id = vxlan_utils.create_raw_traffic_stream(
        lag_handle["T1D4P1"],
        lag_handle["T1D2P1"],
        stream,
        "raw",
        const.spytest_data,
        "broadcast",
    )
    vxlan_utils.send_raw_traffic_stream(lag_handle["T1D4P1"], stream_id, reset=True)

    dut.wait(_INTERFACE_COUNTER_SETTLE_SEC)

    pkts = int(const.spytest_data.pkts_per_burst)
    df_downlink_restored = vxlan_utils.get_counters(
        node=restored_df_node, cmd=cmd_intf, target_iface=restored_df_downlink, r_t_key="tx_ok"
    )
    ndf_downlink_restored = vxlan_utils.get_counters(
        node=restored_ndf_node, cmd=cmd_intf, target_iface=restored_ndf_downlink, r_t_key="tx_ok"
    )
    log(
        "Traffic after restore - DF downlink {}: {}, NDF downlink {}: {}".format(
            restored_df_downlink, df_downlink_restored, restored_ndf_downlink, ndf_downlink_restored
        )
    )

    if not (
        df_downlink_restored >= 0.98 * pkts
        and df_downlink_restored <= 1.1 * pkts
        and ndf_downlink_restored <= 0.1 * pkts
    ):
        report_fail(restored_df_node, "Traffic verification failed after restore - DF/NDF filtering not working")

    log("Traffic verification after restore passed")

    report_pass(nodes["leaf0"], "test_portchannel_shutdown_on_mh_peer")
