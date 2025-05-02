import evpn_mh_utils
import vxlan_utils

from multihome.status_report import report_fail, report_pass, start_banner
from multihome.vtysh import show_evpn_es, show_evpn_type_2
from multihome import const


def test_evpn_mh_basic_config(setup):
    """
    Test EVPN Multihome Basic Config
    """
    start_banner("Ttest_evpn_mh_basic_config")
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
        report_pass("test_case_passed")
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
    report_pass("test_case_passed")


def test_remote_es(setup):
    """
    Test EVPN Multihome Remote ES on T3 with T1 and T2 as remote
    """
    start_banner("test_remote_es")

    nodes = setup["duts"]
    _, parsed_output = show_evpn_es(nodes["leaf2"])

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
                    report_pass("test_case_passed")
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
        report_pass("test_case_passed")


def test_rt2_proxy(setup):
    """
    Test EVPN Multihome Route Type 2 Proxy
    TC could fail until MIGSOFTWAR-17150 is fixed
    """
    start_banner("test_rt2_proxy")

    nodes = setup["duts"]

    _, parsed_output_leaf1 = show_evpn_type_2(nodes["leaf1"])
    _, parsed_output_leaf2 = show_evpn_type_2(nodes["leaf2"])

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
        report_pass("test_case_passed")
