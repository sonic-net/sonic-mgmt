import os
import pytest
import re
import evpn_mh_utils
import vxlan_utils

from multihome.status_report import report_fail, report_pass, start_banner, log
from multihome.dut import wait
from multihome import (
    const,
    dut,
    host,
    vtysh
)
import json


def test_evpn_mh_basic_config(setup):
    """
    Test EVPN Multihome Basic Config
    """
    start_banner("test_evpn_mh_basic_config")
    nodes = setup["duts"]

    try:
        # Start Verification
        vxlan_utils.verify_bgp(
            nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
        )
        vxlan_utils.verify_bgp(
            nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI
        )
        vxlan_utils.verify_bgp(
            nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
        )
        report_pass("test_case_passed", "test_evpn_mh_basic_config")
    except Exception as e:
        report_fail("", msg=e)


def test_es_peering(setup):
    """
    Test EVPN Multihome ES Peering between T1 and T2
    """

    start_banner("test_es_peering")
    nodes = setup["duts"]

    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")
    report_pass("test_case_passed", "test_es_peering")


def test_remote_es(setup):
    """
    Test EVPN Multihome Remote ES on T3 with T1 and T2 as remote
    """
    start_banner("test_remote_es")

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
    start_banner("test_df_selection")

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
    start_banner("test_rt2_proxy")

    nodes = setup["duts"]

    _, parsed_output_leaf1 = vtysh.show_evpn_type_2(nodes["leaf1"])
    _, parsed_output_leaf2 = vtysh.show_evpn_type_2(nodes["leaf2"])

    # Validate Leaf1 regenerates RT-2 as proxy
    leaf0_proxy = False
    leaf1_proxy = False
    leaf0_learned = False
    leaf1_learned = False

    for route in parsed_output_leaf1:
        if (
            route["route_distinguisher"] == "100.100.100.1:2"
            and route["ip"] == const.spytest_data.lag_ip
        ):
            leaf0_learned = True
            if route["nd_proxy"] == "ND:Proxy":
                leaf0_proxy = True
        if (
            route["route_distinguisher"] == "100.100.100.2:2"
            and route["ip"] == const.spytest_data.lag_ip
        ):
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
        if (
            route["route_distinguisher"] == "100.100.100.1:2"
            and route["ip"] == const.spytest_data.lag_ip
        ):
            leaf0_path_seen = True
        if (
            route["route_distinguisher"] == "100.100.100.2:2"
            and route["ip"] == const.spytest_data.lag_ip
        ):
            leaf1_path_seen = True

    if not (leaf0_path_seen and leaf1_path_seen):
        report_fail(nodes["leaf2"], "No proper ECMP is shown on Leaf2")
    else:
        report_pass("test_case_passed", "test_rt2_proxy")


@pytest.mark.known_failure("MIGSOFTWAR-24849/MIGSOFTWAR-26359")
def test_reload_config(setup):
    """
    Test EVPN Multihome Reload Config
    """
    start_banner("test_reload_config")

    nodes = setup["duts"]

    log("verifying BGP before reload")
    # Verify BGP
    vxlan_utils.verify_bgp(
        nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI, single_run=True
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI, single_run=True
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI, single_run=True
    )

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

    # wait for 120 seconds for config to take effect and containers to come up
    dut.wait(120)

    log("verifying BGP after reload")
    # Verify BGP
    vxlan_utils.verify_bgp(
        nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )

    log("verifying DF after reload")
    leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)

    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    log("verifying ES peering after reload")
    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")

    report_pass("test_case_passed", "test_reload_config")


@pytest.mark.known_failure("MIGSOFTWAR-24849/MIGSOFTWAR-26359")
def test_bgp_container_restart(setup):
    """
    Test EVPN Multihome BGP Container Restart
    """
    start_banner("test_bgp_container_restart")

    nodes = setup["duts"]

    # Restart BGP container
    dut.exec_each(nodes, host.restart_container, "bgp")

    # wait for 120 seconds for container to come up and replay configuration
    dut.wait(120)

    # Verify BGP
    vxlan_utils.verify_bgp(
        nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )

    leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)
    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")

    report_pass("test_case_passed", "test_bgp_container_restart")


@pytest.mark.known_failure("MIGSOFTWAR-24849/MIGSOFTWAR-26359")
def test_deconfig_config(setup):
    """
    Test EVPN Multihome Deconfig Config
    """
    start_banner("test_deconfig_config")

    nodes = setup["duts"]
    config_file = setup["config_file"]

    
    # Deconfig config
    dut.configure(config_file, nodes, add=False)

    # post deconfig/config some times vtysh may not exit properly
    # adding below logic to exit vtysh if not exited correctly
    for node in nodes:
        if "Unknown command" in vtysh.show_cmd(node, "show version", skip_error_check=True).strip():
            vtysh.show_cmd(node, "\nend\nshow version\n", skip_error_check=True)

    dut.configure(config_file, nodes)

    # post deconfig/config some times vtysh may not exit properly
    # adding below logic to exit vtysh if not exited correctly
    for node in nodes:
        if "Unknown command" in vtysh.show_cmd(node, "show version", skip_error_check=True).strip():
            vtysh.show_cmd(node, "\nend\nshow version\n", skip_error_check=True)

    # wait for 60 seconds for config to take effect
    dut.wait(60)

    # Verify BGP
    vxlan_utils.verify_bgp(
        nodes, const.leaf1_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf0_vrf_prefix, "leaf1", const.EXPECTED_L3VNI
    )
    vxlan_utils.verify_bgp(
        nodes, const.leaf2_vrf_prefix, "leaf0", const.EXPECTED_L3VNI
    )

    leaf0_idDF = evpn_mh_utils.isDF(nodes["leaf0"], const.ESI1)
    leaf1_isDF = evpn_mh_utils.isDF(nodes["leaf1"], const.ESI1)

    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes["leaf0"], "DF is not successly selected for ES1")

    if not evpn_mh_utils.es_peering(nodes["leaf0"], const.LEAF1_VXLAN_IP, const.ESI1):
        report_fail(nodes["leaf0"], "ES is not peering between T1 and T2")
    
    report_pass("test_case_passed", "test_deconfig_config")
