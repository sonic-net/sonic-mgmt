import pytest
from spytest import st
from evpn_with_rs_and_bg import show_frr, show_host

# test result tolerance values for hw an sim
TOLERANCE_THRESHOLDS = {
    "hw": 0.05,
    "sim": 0.03,
}

bgp_summary_test_data = [
    # BGP sessions between leaf and spine, as well as leaf to RS, are common for both sim and hw
    pytest.param(
        {
            "node": "leaf0",
            "ipv4": {"total_nbr": "8", "state": "established"},
            "ipv6": {"total_nbr": "8", "state": "established"},
            "l2vpn": {"total_nbr": "2", "state": "established"},
        },
        {"expected_result": "ESTABILISHED"},
        id="leaf0 bgp summary",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "ipv4": {"total_nbr": "8", "state": "established"},
            "ipv6": {"total_nbr": "8", "state": "established"},
            "l2vpn": {"total_nbr": "2", "state": "established"},
        },
        {"expected_result": "ESTABILISHED"},
        id="leaf1 bgp summary",
    ),
    # VRF_1000 sim
    pytest.param(
        {
            "node": "leaf0",
            "ipv4": {"total_nbr": "2", "vrfid": "Vrf_1000", "state": "established|NoNeg"},
            "ipv6": {"total_nbr": "1", "vrfid": "Vrf_1000", "state": "established"},
            "dut_type": "sim",
        },
        {"expected_result": "ESTABILISHED"},
        id="leaf0 l3 vrf bgp summary sim",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "ipv4": {"total_nbr": "2", "vrfid": "Vrf_1000", "state": "established|NoNeg"},
            "ipv6": {"total_nbr": "1", "vrfid": "Vrf_1000", "state": "established"},
            "dut_type": "sim",
        },
        {"expected_result": "ESTABILISHED"},
        id="leaf1 l3 vrf bgp summary sim",
    ),
    # VRF_1000 hw
    pytest.param(
        {
            "node": "leaf0",
            "ipv4": {"total_nbr": "116", "vrfid": "Vrf_1000", "state": "established|NoNeg"},  
            "ipv6": {"total_nbr": "50", "vrfid": "Vrf_1000", "state": "established"},
            "dut_type": "hw",
            "topology": "l3",
        },
        {"expected_result": "ESTABILISHED"},
        id="leaf0 l3 vrf bgp summary hw",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "ipv4": {"total_nbr": "100", "vrfid": "Vrf_1000", "state": "established|NoNeg"},
            "ipv6": {"total_nbr": "50", "vrfid": "Vrf_1000", "state": "established"},
            "dut_type": "hw",
            "topology": "l3",
        },
        {"expected_result": "ESTABILISHED"},
        id="leaf1 l3 vrf bgp summary hw",
    ),
]


@pytest.mark.parametrize("bgp_summary, expected_output", bgp_summary_test_data)
def test_bgp_summary(configure_devices, bgp_summary, expected_output):
    """
    Test to check BGP summary on the leaf nodes.
    """
    st.banner(f"running test test_bgp_summary, input:{bgp_summary}")
    topology = "l2" if "l2" in configure_devices.get("ixia_config_file", "") else "l3"
    dut_type = configure_devices.get("dut_type", None)
    # Skip if 'dut_type' is specified in the test data and does not match
    if "dut_type" in bgp_summary and bgp_summary["dut_type"] != dut_type:
        st.log(
            f"Skipping test due to DUT type mismatch, actual: {dut_type}, expected: {bgp_summary['dut_type']}")
        pytest.skip(
            f"Skipping test due to DUT type mismatch: {dut_type}, input: {bgp_summary}"
        )
    # Skip if 'topology' is specified in the test data and does not match
    if "topology" in bgp_summary and bgp_summary["topology"] != topology:
        st.log(
            f"Skipping test due to topology mismatch, actual: {topology}, expected: {bgp_summary['topology']}")
        pytest.skip(
            f"Skipping test due to topology mismatch: {topology}, input: {bgp_summary}"
        )

    nodes = configure_devices["nodes"]
    switch = nodes[bgp_summary.get("node", None)]

    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_bgp_summary {switch}, Switch not found in test input",
        )
        return

    retry = 5
    success = False

    while retry != 0:
        retry -= 1
        if "vrfid" in bgp_summary.get("ipv4", {}):
            output = show_frr.show_bgp_summary(
                switch, skip_tmpl=True, vrf=bgp_summary.get("ipv4", {})["vrfid"], skip_error_check=True
            )
        else:
            output = show_frr.show_bgp_summary(
                switch, skip_tmpl=True, skip_error_check=True
            )
        ipv4 = output.get("ipv4", [])
        ipv6 = output.get("ipv6", [])
        l2vpn = output.get("l2vpn", []) 

        if (
            len(ipv4) == 0
            or len(ipv6) == 0
            or ("vrfid" not in bgp_summary.get("ipv4", {}) and len(l2vpn) == 0) #Vrf_1000 doesn't need to check l2vpn peers
        ):
            st.wait(1)
            continue

        ipv4_peer_count = ipv4[0][0].get("peers")
        ipv6_peer_count = ipv6[0][0].get("peers")
        l2vpn_peer_count = l2vpn[0][0].get("no_peers", "N/A") if len(l2vpn) > 0 else 0

        if (
            ipv4_peer_count != bgp_summary.get("ipv4").get("total_nbr")
            or ipv6_peer_count != bgp_summary.get("ipv6").get("total_nbr")
            or (
                (bgp_summary.get("l2vpn", None) and len(l2vpn[0]) == 0)
                or (
                    bgp_summary.get("l2vpn") is not None
                    and l2vpn_peer_count != bgp_summary.get("l2vpn").get("total_nbr")
                )
            )
        ):
            st.log(
                f"Total neighbors not matching, ipv4: {ipv4_peer_count}, ipv6: {ipv6_peer_count}, l2vpn: {l2vpn_peer_count}"
            )
            st.wait(1)
            continue

        ipv4_up_count = 0
        for _, ip in enumerate(ipv4[0]):
            if (
                not ip.get("state", None).isdigit()
                and ip.get("state", None) not in bgp_summary.get("ipv4").get("state", None)
            ):
                state = (ip.get("state", None),)
                expected_state = (bgp_summary.get("ipv4").get("state", None),)
                st.banner(f"ipv4 state is not good: {state}, expected: {expected_state}")
                st.wait(1)
                continue
            ipv4_up_count += 1
        st.log(
            f"ipv4_up_count: {ipv4_up_count}, expected: {bgp_summary.get('ipv4').get('total_nbr')}"
        )
        success = ipv4_up_count == len(ipv4[0])
        st.banner(f'state: {success}, after ipv4 check')
        if not success:
            continue

        ipv6_up_count = 0
        for _, ip6 in enumerate(ipv6[0]):
            if (
                ip6.get("state", None) != bgp_summary.get("ipv6").get("state", None)
                and not ip6.get("state", None).isdigit()
            ):
                state = ip6.get("state", None)
                expected_state = bgp_summary.get("ipv6").get("state", None)
                st.log(f"ipv6 state is not good: {state}, expected: {expected_state}")
                st.wait(1)
                continue
            ipv6_up_count += 1
        st.banner(
            f"ipv6_up_count: {ipv6_up_count}, expected: {bgp_summary.get('ipv6').get('total_nbr')}"
        )

        success = success and ipv6_up_count == len(ipv6[0])
        st.banner(f'state: {success}, after ipv6 check')
        if not success:
            continue

        l2vpn_up_count = 0
        if l2vpn and len(l2vpn) > 0:
            for _, l2 in enumerate(l2vpn[0]):
                if (
                    l2.get("pfxrcd", None) != bgp_summary.get("l2vpn", {}).get("state", None)
                    and not l2.get("pfxrcd", None).isdigit()
                ):
                    state = l2.get("state", None)
                    expected_state = bgp_summary.get("l2vpn", {}).get("state", None)
                    st.log(f"l2vpn state is not good: {state}, expected: {expected_state}")
                    continue
                l2vpn_up_count += 1
            st.banner(
                f"l2vpn_up_count: {l2vpn_up_count}, expected: {bgp_summary.get('l2vpn').get('total_nbr')}"
             )
            success = l2vpn_up_count == len(l2vpn[0])
            st.banner(f'state: {success}, after l2vpn check')
            if not success:
                continue
  
        st.report_pass(
            "test_case_passed", f"test_bgp_summary {switch}, input:{bgp_summary}"
        )
        break
    if not success:
        st.report_fail(
            "test_case_failed", f"test_bgp_summary {switch}, input:{bgp_summary}"
        )


default_route_advertisement_from_bg_routers_test_data = [
    pytest.param(
        {
            "node": "leaf0",
            "route_type": "ipv6",
        },
        {"network": "::/0", "path_count": 4},
        id="leaf0 default route advertisement from ipv6 neighbor bg routers",
    ),
    pytest.param(
        {
            "node": "leaf0",
            "route_type": "ipv4",
        },
        {"network": "0.0.0.0/0", "path_count": 4},
        id="leaf0 default route advertisement from ipv4 neighbor bg routers",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "route_type": "ipv6",
        },
        {"network": "::/0", "path_count": 4},
        id="leaf1 default route advertisement from ipv6 neighbor bg routers",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "route_type": "ipv4",
        },
        {"network": "0.0.0.0/0", "path_count": 4},
        id="leaf1 default route advertisement from ipv4 neighbor bg routers",
    ),
]


@pytest.mark.parametrize(
    "default_route_advertisement_from_bg_routers, expected_output",
    default_route_advertisement_from_bg_routers_test_data,
)
def test_default_route_advertisement_from_bg_routers(
    configure_devices, default_route_advertisement_from_bg_routers, expected_output
):
    """
    Test to check default route advertisement from bg routers on the leaf nodes.
    """
    st.banner(
        f"running test test_default_route_advertisement_from_bg_routers with input: {default_route_advertisement_from_bg_routers}"
    )
    
    nodes = configure_devices["nodes"]
    switch = nodes[default_route_advertisement_from_bg_routers.get("node", None)]
    route_type = default_route_advertisement_from_bg_routers.get("route_type", None)
    path_count = expected_output.get("path_count", None)
    
    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_default_route_advertisement_from_bg_routers {switch}",
            "Switch not found in test input",
        )
        return

    # Determine VRF(s) based on dut_type and ixia_config_file
    dut_type = configure_devices.get("dut_type", "")
    ixia_config_file = configure_devices.get("ixia_config_file", "")
    
    vrfs_to_check = []
    
    if dut_type == "sim":
        # For sim: check both VRFs
        vrfs_to_check = ["Vrf_92", "Vrf_1000"]
        st.log(f"SIM environment: checking both VRFs {vrfs_to_check}")
    else:
        # For hw: check VRF based on topology
        if "l2" in ixia_config_file:
            vrfs_to_check = ["Vrf_92"]
            st.log(f"HW environment: checking VRF {vrfs_to_check[0]} since loading l2 ixia config file")
        elif "l3" in ixia_config_file:
            vrfs_to_check = ["Vrf_1000"]
            st.log(f"HW environment: checking VRF {vrfs_to_check[0]} since loading l3 ixia config file")

    overall_success = True
    
    for vrf in vrfs_to_check:
        st.log(f"Testing VRF: {vrf}")
        
        retry = 5
        vrf_success = False
        actual_path_count = 0
        
        while retry != 0:
            retry -= 1
            output = []
            
            if route_type == "ipv4":
                output = show_frr.show_ipv4_unicast_routes(
                    switch, vrf=vrf, skip_tmpl=True, skip_error_check=True
                )
            elif route_type == "ipv6":
                output = show_frr.show_ipv6_unicast_routes(
                    switch, vrf=vrf, skip_tmpl=True, skip_error_check=True
                )
            
            if len(output) == 0:
                st.log(f"No routes available for VRF {vrf}")
                st.wait(1)
                continue
         
            actual_path_count = 0
            network = expected_output.get("network")

            for _, route in enumerate(output):
                if network == route.get("network"):
                    actual_path_count += 1

            if path_count == actual_path_count:
                vrf_success = True
                st.log(f"SUCCESS: Default route in VRF {vrf} - Expected: {path_count}, Actual: {actual_path_count}")
                break
            
            st.wait(1)
        
        st.log(f"VRF {vrf} - Expected path count: {path_count}, Actual path count: {actual_path_count}, retry: {retry}")
        
        if not vrf_success:
            st.log(f"FAILED: Default route in VRF {vrf} did not meet expected path count. Expected: {path_count}, Actual: {actual_path_count}")
            overall_success = False
    
    if overall_success:
        st.report_pass(
            "test_case_passed",
            f"test_default_route_advertisement_from_bg_routers {switch}, VRFs: {vrfs_to_check}, input: {default_route_advertisement_from_bg_routers}",
        )
    else:
        st.report_fail(
            "test_case_failed",
            f"test_default_route_advertisement_from_bg_routers {switch}, VRFs: {vrfs_to_check}",
        )


bgp_type_2_routes_test_data = [
    # sim
    pytest.param(
        {
            "node": "leaf0",
            "dut_type": "sim",
        },
        {"expected_result": 304},    
        id="leaf0 bgp type 2 routes sim",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "dut_type": "sim",
        },
        {"expected_result": 448},  
        id="leaf1 bgp type 2 routes sim",
    ),
    # hw
    pytest.param(
        {
            "node": "leaf0",
            "dut_type": "hw",
        },
        {"expected_result": 116477},   
        id="leaf0 bgp type 2 routes hw",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "dut_type": "hw",
        },
        {"expected_result": 116644},
        id="leaf1 bgp type 2 routes hw",
    ),
]


@pytest.mark.parametrize(
    "bgp_type_2_routes, expected_output", bgp_type_2_routes_test_data
)
def test_bgp_type_2_routes(configure_devices, bgp_type_2_routes, expected_output):
    """
    Test to check BGP Type 2 routes on the leaf nodes.
    Only runs for:
      - sim
      - hw if ixia_config_file includes 'l2'
    """
    st.banner(f"running test test_bgp_type_2_routes, input: {bgp_type_2_routes}")
    dut_type = configure_devices.get("dut_type", None)
    ixia_config_file = configure_devices.get("ixia_config_file", "")

    # Skip test unless: DUT types match AND (it's sim OR hw with l2 config)
    is_dut_type_matching = dut_type == bgp_type_2_routes["dut_type"]
    is_sim = dut_type == "sim"
    is_hw_l2 = dut_type == "hw" and "l2" in ixia_config_file
    
    if not (is_dut_type_matching and (is_sim or is_hw_l2)):
        pytest.skip(
            f"Skipping test_bgp_type_2_routes: dut_type={dut_type}, ixia_config_file={ixia_config_file}, input={bgp_type_2_routes}"
        )

    nodes = configure_devices["nodes"]
    switch = nodes[bgp_type_2_routes.get("node", None)]

    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_bgp_type_2_routes {switch}, Switch not found in test input",
        )
        return

    retry = 5
    success = False
    
    expected = expected_output.get("expected_result")
    tolerance = TOLERANCE_THRESHOLDS[dut_type]  
    lower_bound = (1 - tolerance) * expected
    upper_bound = (1 + tolerance) * expected

    while retry != 0:
        retry -= 1
        output = int(st.config(switch, r"vtysh -c 'show bgp l2vpn evpn route type 2' | grep '\[2\]\:\[0\]' | wc -l").split("\n")[0].strip())
        if output == 0:
            st.wait(1)
            continue
        st.banner(f"Actual output: {output}, Expected result: {expected_output.get('expected_result')}")

        if lower_bound <= output <= upper_bound:
            st.report_pass(
                "test_case_passed",
                f"test_bgp_type_2_routes {switch}, input: {bgp_type_2_routes}",
            )
            success = True
            break
        
    if not success:
        st.report_fail(
            "test_case_failed",
            f"test_bgp_type_2_routes {switch}, input {bgp_type_2_routes}",
        )


bgp_type_5_routes_test_data = [
    # sim
    pytest.param(
        {
            "node": "leaf0",
            "dut_type": "sim",
        },
        {"expected_result": 700},   
        id="leaf0 bgp type 5 routes sim",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "dut_type": "sim",
        },
        {"expected_result": 700},   
        id="leaf1 bgp type 5 routes sim",
    ),
    # hw
    pytest.param(
        {
            "node": "leaf0",
            "dut_type": "hw",
        },
        {"expected_result": 713076},  # 714022
        id="leaf0 bgp type 5 routes hw",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "dut_type": "hw",
        },
        {"expected_result": 713076},
        id="leaf1 bgp type 5 routes hw",
    ),
]


@pytest.mark.parametrize(
    "bgp_type_5_routes, expected_output", bgp_type_5_routes_test_data
)
def test_bgp_type_5_routes(configure_devices, bgp_type_5_routes, expected_output):
    """
    Test to check BGP Type 5 routes on the leaf nodes.
    Only runs for:
      - sim
      - hw if loading ixia l3 config file
    """
    st.banner(f"running test test_bgp_type_5_routes, input: {bgp_type_5_routes}")
    dut_type = configure_devices.get("dut_type", None)
    ixia_config_file = configure_devices.get("ixia_config_file", "")

    # Skip test unless: DUT types match AND (it's sim OR hw with l3 config)
    is_dut_type_matching = dut_type == bgp_type_5_routes["dut_type"]
    is_sim = dut_type == "sim"
    is_hw_l3 = dut_type == "hw" and "l3" in ixia_config_file
    
    if not (is_dut_type_matching and (is_sim or is_hw_l3)):
        pytest.skip(
            f"Skipping test_bgp_type_5_routes: dut_type={dut_type}, ixia_config_file={ixia_config_file}, input={bgp_type_5_routes}"
        )

    nodes = configure_devices["nodes"]
    switch = nodes[bgp_type_5_routes.get("node", None)]

    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_bgp_type_5_routes {switch}, Switch not found in test input",
        )
        return

    retry = 5
    success = False
    
    expected = expected_output.get("expected_result")
    tolerance = TOLERANCE_THRESHOLDS[dut_type] 
    lower_bound = (1 - tolerance) * expected
    upper_bound = (1 + tolerance) * expected
    while retry != 0:
        retry -= 1
        output = int(st.config(switch, r"vtysh -c 'show bgp l2vpn evpn route type 5' | grep '\[5\]\:\[0\]' | wc -l").split("\n")[0].strip())
        if output == 0:
            st.wait(1)
            continue
        st.banner(f"Actual output: {output}, Expected result: {expected_output.get('expected_result')}")

        if lower_bound <= output <= upper_bound:
            st.report_pass(
                "test_case_passed",
                f"test_bgp_type_5_routes {switch}, input: {bgp_type_5_routes}",
            )
            success = True
            break

    if not success:
        st.report_fail(
            "test_case_failed",
            f"test_bgp_type_5_routes {switch}, input: {bgp_type_5_routes}",
        )


l3_vrf_routes_test_data = [
    # hw
    pytest.param(
        {
            "node": "leaf0",
            "network_type": "ip",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "hw",
        },
        {"expected_result": 25460},  #25479
        id="leaf0 l3 ip vrf  Vrf_1000 routes",
    ),
    pytest.param(
        {
            "node": "leaf0",
            "network_type": "ipv6",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "hw",
        },
        {"expected_result": 10412},
        id="leaf0 l3 ipv6 vrf  Vrf_1000 routes",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "network_type": "ip",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "hw",
        },
        {"expected_result": 25460},
        id="leaf1 l3 ip vrf  Vrf_1000 routes",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "network_type": "ipv6",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "hw",
        },
        {"expected_result": 10412},
        id="leaf1 l3 ipv6 vrf Vrf_1000 routes",
    ),
    # sim
    pytest.param(
        {
            "node": "leaf0",
            "network_type": "ip",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "sim",
        },
        {"expected_result": 60},
        id="leaf0 l3 ip vrf  Vrf_1000 routes",
    ),
    pytest.param(
        {
            "node": "leaf0",
            "network_type": "ipv6",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "sim",
        },
        {"expected_result": 38},
        id="leaf0 l3 ipv6 vrf  Vrf_1000 routes",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "network_type": "ip",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "sim",
        },
        {"expected_result": 60},
        id="leaf1 l3 ip vrf  Vrf_1000 routes",
    ),
    pytest.param(
        {
            "node": "leaf1",
            "network_type": "ipv6",
            "vrf": "Vrf_1000",
            "count": True,
            "dut_type": "sim",
        },
        {"expected_result": 38},
        id="leaf1 l3 ipv6 vrf Vrf_1000 routes",
    ),
]


@pytest.mark.parametrize("l3_vrf_routes, expected_output", l3_vrf_routes_test_data)
def test_l3_vrf_routes(configure_devices, l3_vrf_routes, expected_output):
    """
    Test to check L3 VRF routes on the leaf nodes.
    Only runs for:
      - sim
      - hw if loading ixia l3 config file'l3'
    """
    st.banner(f"running test test_l3_vrf_routes, input: {l3_vrf_routes}")
    dut_type = configure_devices.get("dut_type", None)
    ixia_config_file = configure_devices.get("ixia_config_file", "")

    # Skip test unless: DUT types match AND (it's sim OR hw with l3 config)
    is_dut_type_matching = dut_type == l3_vrf_routes["dut_type"]
    is_sim = dut_type == "sim"
    is_hw_l3 = dut_type == "hw" and "l3" in ixia_config_file
    
    if not (is_dut_type_matching and (is_sim or is_hw_l3)):
        pytest.skip(
            f"Skipping test_l3_vrf_routes: dut_type={dut_type}, ixia_config_file={ixia_config_file}, input={l3_vrf_routes}"
        )

    nodes = configure_devices["nodes"]
    switch = nodes[l3_vrf_routes.get("node", None)]

    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_l3_vrf_routes {switch}, Switch not found in test input",
        )
        return

    retry = 5
    success = False
    
    expected = expected_output.get("expected_result")
    tolerance = TOLERANCE_THRESHOLDS[dut_type]  
    lower_bound = (1 - tolerance) * expected
    upper_bound = (1 + tolerance) * expected

    while retry != 0:
        retry -= 1
        output = show_frr.show_routes(
            switch,
            network_type=l3_vrf_routes.get("network_type", None),
            vrf=l3_vrf_routes.get("vrf", None),
            count=l3_vrf_routes.get("count", None),
            skip_tmpl=True,
            skip_error_check=True,
        )
        st.log(
            f"Expected result: {expected_output.get('expected_result')}, Actual result: {int(output)}"
        )
        
        if int(output) >= lower_bound and int(output) <= upper_bound:
            st.report_pass(
                "test_case_passed",
                f"test_l3_vrf_routes {switch}, input: {l3_vrf_routes}",
            )
            success = True
            break
        st.wait(1)

    if not success:
        st.report_fail(
            "test_case_failed", f"test_l3_vrf_routes {switch}, input: {l3_vrf_routes}"
        )


vxlan_remote_vtep_test_data = [
    pytest.param(
        {"count": True, "node": "leaf0", "dut_type": "hw"},
        {"expected_result": 152},
        id="leaf0 remote vtep",
    ),
    pytest.param(
        {"count": True, "node": "leaf1", "dut_type": "hw"},
        {"expected_result": 152},
        id="leaf1 remote vtep",
    ),
    pytest.param(
        {"count": True, "node": "leaf0", "dut_type": "sim"},
        {"expected_result": 6},
        id="leaf0 remote vtep",
    ),
    pytest.param(
        {"count": True, "node": "leaf1", "dut_type": "sim"},
        {"expected_result": 6},
        id="leaf0 remote vtep",
    ),
]


@pytest.mark.parametrize(
    "vxlan_remote_vtep, expected_output", vxlan_remote_vtep_test_data
)
def test_vxlan_remote_vtep(configure_devices, vxlan_remote_vtep, expected_output):
    """
    Test to remotevtep count on the leaf nodes.
    """

    st.banner(f"running test test_vxlan_remote_vtep with input: {vxlan_remote_vtep}")
    dut_type = configure_devices.get("dut_type", None)
    if dut_type != vxlan_remote_vtep["dut_type"]:
        pytest.skip(
            f"Skipping test due to DUT type mismatch: {dut_type}, input: {vxlan_remote_vtep}"
        )

    nodes = configure_devices["nodes"]
    switch = nodes[vxlan_remote_vtep.get("node", None)]
    count = vxlan_remote_vtep.get("count", None)
    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_vxlan_remote_vtep {switch}, Switch not found in test input",
        )
        return

    result = show_host.show_remote_vtep(
        switch, count=count, skip_tmpl=True, skip_error_check=True
    ).strip()
    st.log(
        f"Expected result: {expected_output['expected_result']}, Actual result: {int(result)}"
    )
    if int(result) == expected_output["expected_result"]:
        st.report_pass(
            f"test_case_passed",
            f"test_vxlan_remote_vtep {switch}, input: {vxlan_remote_vtep}",
        )
    else:
        st.report_fail(
            "test_case_failed",
            f"test_vxlan_remote_vtep {switch}, input: {vxlan_remote_vtep}",
        )


host_behind_emulated_vtep_mac_learn_test_data = [
    pytest.param(
        {
            "vlan_start": 92,
            "vlan_end": 139,
            "mac_prefix": "a0:",
            "type": "Bridge",
            "count": True,
            "node": "leaf0",
            "dut_type": "hw",
        },
        {"expected_result": 600},
        id="leaf0 emulated vtep mac learn on vlan 92 - 139",
    ),
    pytest.param(
        {
            "vlan_start": 392,
            "vlan_end": 439,
            "mac_prefix": "a0:",
            "type": "Bridge",
            "count": True,
            "node": "leaf1",
            "dut_type": "hw",
        },
        {"expected_result": 600},
        id="leaf1 emulated vtep mac learn on vlan 392 - 439",
    ),
    pytest.param(
        {
            "vlan_start": 92,
            "vlan_end": 99,
            "mac_prefix": "a0:",
            "type": "Bridge",
            "count": True,
            "node": "leaf0",
            "dut_type": "sim",
        },
        {"expected_result": 2},
        id="leaf0 emulated vtep mac learn on vlan 92 - 99",
    ),
    pytest.param(
        {
            "vlan_start": 392,
            "vlan_end": 399,
            "mac_prefix": "a0:",
            "type": "Bridge",
            "count": True,
            "node": "leaf1",
            "dut_type": "sim",
        },
        {"expected_result": 2},
        id="leaf1 emulated vtep mac learn on vlan 392 - 399",
    ),
]


@pytest.mark.parametrize(
    "host_behind_emulated_vtep_mac_learn, expected_output",
    host_behind_emulated_vtep_mac_learn_test_data,
)
def test_host_behind_emulated_vtep_mac_learn(
    configure_devices, host_behind_emulated_vtep_mac_learn, expected_output
):
    """
    Test to check remote MAC address learned on leaf0 and leaf1.
    Only runs for:
      - sim
      - hw if loading l2 ixia config file 
    """
    dut_type = configure_devices.get("dut_type", None)
    ixia_config_file = configure_devices.get("ixia_config_file", "")

    # Skip test unless: DUT types match AND (it's sim OR hw with l2 config)
    is_dut_type_matching = dut_type == host_behind_emulated_vtep_mac_learn["dut_type"]
    is_sim = dut_type == "sim"
    is_hw_l2 = dut_type == "hw" and "l2" in ixia_config_file
    
    if not (is_dut_type_matching and (is_sim or is_hw_l2)):
        pytest.skip(
            f"Skipping test_host_behind_emulated_vtep_mac_learn: dut_type={dut_type}, ixia_config_file={ixia_config_file}, input={host_behind_emulated_vtep_mac_learn}"
        )

    st.banner(
        f"running test test_emulated_vtep_learning with input: {host_behind_emulated_vtep_mac_learn}"
    )

    nodes = configure_devices["nodes"]
    switch = nodes[host_behind_emulated_vtep_mac_learn.get("node", None)]
    mac_prefix = host_behind_emulated_vtep_mac_learn.get("mac_prefix")
    type = host_behind_emulated_vtep_mac_learn.get("type", None)
    count = host_behind_emulated_vtep_mac_learn.get("count", None)

    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_emulated_vtep_learning {switch}, Switch not found in test input",
        )
        return

    for vlan in range(
        host_behind_emulated_vtep_mac_learn["vlan_start"],
        host_behind_emulated_vtep_mac_learn["vlan_end"] + 1,
    ):
        result = show_host.show_bridge_fdb(
            switch,
            mac_prefix=mac_prefix,
            vlan=f'"vlan {vlan}"',
            type=type,
            count=count,
            skip_tmpl=False,
            skip_error_check=True,
        )

        result = result.strip()
        st.log(
            f"Expected result: {expected_output['expected_result']}, Actual result: {int(result)}"
        )
        if int(result) == expected_output["expected_result"]: 
            st.report_pass(
                "test_case_passed",
                f"test_emulated_vtep_learning {switch}, vlan: {vlan}",
            )
        else:
            st.report_fail(
                "test_case_failed",
                f"test_emulated_vtep_learning {switch}, {vlan}",
            )


test_total_mac_learned_test_data = [
    pytest.param(
        {"node": "leaf0", "count": True, "type": "Static", "dut_type": "hw"},
        {"expected_result": 28992},
        id="leaf0 total Static mac learned hw",
    ),
    pytest.param(
        {"node": "leaf0", "count": True, "type": "Dynamic", "dut_type": "hw"},
        {"expected_result": 271}, 
        id="leaf0 total Dynamic mac learned hw",
    ),
    pytest.param(
        {"node": "leaf1", "count": True, "type": "Static", "dut_type": "hw"},
        {"expected_result": 29042},
        id="leaf1 total Static mac learned hw",
    ),
    pytest.param(
        {"node": "leaf1", "count": True, "type": "Dynamic", "dut_type": "hw"},
        {"expected_result": 270},
        id="leaf1 total Dynamic mac learned hw",
    ),
    pytest.param(
        {"node": "leaf0", "count": True, "type": "Static", "dut_type": "sim"},
        {"expected_result": 24},
        id="leaf0 total Static mac learned sim",
    ),
    pytest.param(
        {"node": "leaf0", "count": True, "type": "Dynamic", "dut_type": "sim"},
        {"expected_result": 18},
        id="leaf0 total Dynamic mac learned sim",
    ),
    pytest.param(
        {"node": "leaf1", "count": True, "type": "Static", "dut_type": "sim"},
        {"expected_result": 72},
        id="leaf1 total Static mac learned sim",
    ),
    pytest.param(
        {"node": "leaf1", "count": True, "type": "Dynamic", "dut_type": "sim"},
        {"expected_result": 18},
        id="leaf1 total Dynamic mac learned sim",
    ),
]


@pytest.mark.parametrize(
    "total_mac_learned, expected_output", test_total_mac_learned_test_data
)
def test_total_mac_learned(configure_devices, total_mac_learned, expected_output):
    """
    Test to check total mac learned on the leaf nodes.
    Only runs for:
      - sim
      - hw if loading ixia l2 config file
    """
    dut_type = configure_devices.get("dut_type", None)
    ixia_config_file = configure_devices.get("ixia_config_file", "")

    # Skip test unless: DUT types match AND (it's sim OR hw with l2 config)
    is_dut_type_matching = dut_type == total_mac_learned["dut_type"]
    is_sim = dut_type == "sim"
    is_hw_l2 = dut_type == "hw" and "l2" in ixia_config_file
    
    if not (is_dut_type_matching and (is_sim or is_hw_l2)):
        pytest.skip(
            f"Skipping test_total_mac_learned: dut_type={dut_type}, ixia_config_file={ixia_config_file}, input: {total_mac_learned}"
        )

    st.banner(f"running test test_total_mac_learned input: {total_mac_learned}")
    nodes = configure_devices["nodes"]
    switch = nodes[total_mac_learned.get("node", None)]
    count = total_mac_learned.get("count", None)
    type = total_mac_learned.get("type", None)

    if not switch:
        st.report_fail(
            "test_case_failed",
            f"test_total_mac_learned {switch}, Switch not found in test input",
        )
        return

    result = show_host.show_mac(
        switch, count=count, type=type, skip_tmpl=False, skip_error_check=True
    )

    result = result.strip()
    st.log(
        f"Expected result: {expected_output['expected_result']}, Actual result: {int(result)}"
    )
    
    expected = expected_output.get("expected_result")
    tolerance = TOLERANCE_THRESHOLDS[dut_type]  

    lower_bound = (1 - tolerance) * expected
    upper_bound = (1 + tolerance) * expected

    if int(result) >= lower_bound and int(result) <= upper_bound:
        st.report_pass(
            "test_case_passed",
            f"test_total_mac_learned {switch}, input: {total_mac_learned}",
        )
    else:
        st.report_fail(
            "test_case_failed",
            f"test_total_mac_learned {switch}, input: {total_mac_learned}",
        )
