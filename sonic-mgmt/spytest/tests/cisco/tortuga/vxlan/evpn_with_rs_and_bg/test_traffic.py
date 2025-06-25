import pytest
from spytest import st
from ixnetwork_restpy import SessionAssistant

l2_traffic_items_leaf0_leaf1_test_data = [
    pytest.param(
        {
            "traffic_item": "leaf0 to leaf1 layer2",
            "vlan_start_leaf0": list(range(92, 100)),  # [92...99]
            "vlan_start_leaf1": list(range(392, 400)),  # [392...399]
        },
        id="l2 traffic items between leaf0 and leaf1",
    ),
]


@pytest.mark.parametrize("l2_traffic_item", l2_traffic_items_leaf0_leaf1_test_data)
def test_l2_leaf0_leaf1_traffic(configure_devices, l2_traffic_item):
    """
    Test L2 traffic functionality.
    """
    st.banner("test l2 traffic functionality for all vlans between leaf0 and leaf1")

    if configure_devices["traffic_profile"] != "l2":
        pytest.skip(
            "skipping l2 traffic test as traffic type is not l2. Traffic type: " f"{configure_devices['traffic_type']}"
        )
    session_assistant: SessionAssistant = configure_devices["session_assistant"]
    ixnetwork = session_assistant.Ixnetwork

    traffic_item_name = l2_traffic_item["traffic_item"]
    handle = ixnetwork.Traffic.TrafficItem.find(Name=traffic_item_name)
    handle.Enabled = True
    st.wait(5)
    try:
        handle.BiDirectional = True
        handle.Generate(async_operation=False)
        ixnetwork.Traffic.Apply(async_operation=False)
        handle.StartStatelessTraffic(async_operation=False)
        st.wait(3)
        handle.StopStatelessTraffic(async_operation=False)
        st.wait(3)
    except Exception as e:
        st.log(f"Failed to start traffic: {e}")
        st.report_fail("test_case_failed", "failed to start traffic")

    csv_data = session_assistant.StatViewAssistant("Flow Statistics").AddRowFilter(
        ColumnName="Traffic Item", Comparator="EQUAL", FilterValue=traffic_item_name
    )

    cols = csv_data.ColumnHeaders
    rows = csv_data.Rows

    flow_stats = []
    for raw_data in rows[0].RawData:
        flow_stats.append(dict(zip(cols, raw_data)))
    handle.Enabled = False

    flat_flow_stats = {}
    for flow in flow_stats:
        vlan_value = flow.get("VLAN:VLAN-ID").strip()
        flat_flow_stats[vlan_value] = flow

    st.log(f"flow_stats: {flat_flow_stats}")

    leaf0_vlan_start = l2_traffic_item["vlan_start_leaf0"]
    leaf1_vlan_start = l2_traffic_item["vlan_start_leaf1"]
    merged = list(zip(leaf0_vlan_start, leaf1_vlan_start))  # [(92, 392), (93, 393), ...]
    for val_a, val_b in merged:
        flowA = flat_flow_stats.get(str(val_a))
        flowB = flat_flow_stats.get(str(val_b))
        if flowA is None or flowB is None:
            st.report_fail(
                "test_case_failed",
                f"missing flow stats for vlan combination: ({val_a}, {val_b})",
            )
            continue
        if int(flowA.get("Tx Frames", 0)) != int(flowB.get("Rx Frames", 0)):
            st.log(
                f"tx and rx frames mismatch {flowA.get('Tx Frames', 0)}: {flowB.get('Rx Frames', 0)} for vlan combination: ({val_a}, {val_b})"
            )
            st.report_fail(
                "test_case_failed",
                f"tx and rx frames is not equal for vlan combination: ({val_a}, {val_b})",
            )

    st.report_pass("test_case_passed", f"l2 traffic test passed, for: {l2_traffic_item}")


l2_traffic_items_test_data = [
    pytest.param(
        {
            "traffic_item": "emulated vtep to leaf0 layer2",
            "bidirectional": True,
        },
        id="l2 traffic item between leaf0 and leaf1",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf0 v6",
            "bidirectional": True,
        },
        id="l2 traffic item between external to leaf0 v6",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf1 v6",
            "bidirectional": True,

        },
        id="l2 traffic item between external to leaf1 v6",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf0 v4",
            "bidirectional": True,
        },
        id="l2 traffic item between external to leaf0 v4",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf1 v4",
            "bidirectional": True,
        },
        id="l2 traffic item between external to leaf1 v4",
    ),
    pytest.param(
        {
            "traffic_item": "external to emulated vtep v6",
            "bidirectional": False,
        },
        id="l2 traffic item between external to emulated vtep v6",
    ),
    pytest.param(
        {
            "traffic_item": "external to emulated vtep v4",
            "bidirectional": False,
        },
        id="l2 traffic items between external to emulated vtep v4",
    ),
    pytest.param(
        {
            "traffic_item": "emulated vtep to leaf1 layer2",
            "bidirectional": True,
        },
        id="l2 traffic items between emulated vtep to leaf1 layer2",
    ),
]


@pytest.mark.parametrize("l2_traffic_item", l2_traffic_items_test_data)
def test_traffic_l2(configure_devices, l2_traffic_item):
    """
    Test L2 traffic functionality.
    """
    st.banner(f"test l2 traffic functionality for {l2_traffic_item}")
    if configure_devices["traffic_profile"] != "l2":
        pytest.skip(
            "skipping l2 traffic test as traffic type is not l2. Traffic type: "
            f"{configure_devices['traffic_profile']}"
        )
    session_assistant: SessionAssistant = configure_devices["session_assistant"]
    ixnetwork = session_assistant.Ixnetwork

    # Example of how to start traffic
    traffic_item_name = l2_traffic_item.get("traffic_item")
    handle = ixnetwork.Traffic.TrafficItem.find(Name=traffic_item_name)
    handle.Enabled = True
    st.wait(1)
    try:
        if l2_traffic_item.get("bidirectional", False):
            handle.BiDirectional = True
        handle.Generate(async_operation=False)
        st.wait(2)
        ixnetwork.Traffic.Apply(async_operation=False)
        st.wait(2)
        handle.StartStatelessTraffic(async_operation=False)
        st.wait(3)
        handle.StopStatelessTraffic(async_operation=False)
        st.wait(3)
    except Exception as e:
        st.log(f"Failed to start traffic: {e}")
        st.report_fail("test_case_failed", "failed to start traffic")

    csv_data = session_assistant.StatViewAssistant("Traffic Item Statistics").AddRowFilter(
        ColumnName="Traffic Item", Comparator="EQUAL", FilterValue=traffic_item_name
    )
    cols = csv_data.ColumnHeaders
    rows = csv_data.Rows

    # 1 traffic item at a time. Result will be a single row.
    flow_stats = dict(zip(cols, rows[0].RawData[0]))
    st.log(f"flow_stats: {flow_stats}")

    if l2_traffic_item.get("bidirectional", False):
        handle.Enabled = False

    if int(flow_stats.get("Tx Frames", 0)) != int(flow_stats.get("Rx Frames", 0)):
        st.log(
            f"tx and rx frames mismatch {flow_stats.get('Tx Frames', 0)}: {flow_stats.get('Rx Frames', 0)} for traffic_item: {l2_traffic_item})"
        )
        st.report_fail(
            "test_case_failed",
            f"tx and rx frames is not equal for traffic_item: {l2_traffic_item}",
        )

    st.report_pass("test_case_passed", f"l2 traffic test passed, for: {l2_traffic_item}")


l3_traffic_items_test_data = [
    pytest.param(
        {
            "traffic_item": "leaf0 to leaf1 v6",
            "bidirectional": True,
        },
        id="l3 traffic item between leaf0 and leaf1 v6 layer3",
    ),
    pytest.param(
        {
            "traffic_item": "leaf0 to leaf1 v4",
            "bidirectional": True,
        },
        id="l3 traffic item between leaf0 and leaf1 v4 layer3",
    ),
    pytest.param(
        {
            "traffic_item": "emulated vtep to leaf0 layer3 v6",
            "bidirectional": True,
        },
        id="l3 traffic item between emulated vtep to leaf0 layer3 v6",
    ),
    pytest.param(
        {
            "traffic_item": "emulated vtep to leaf0 layer3 v4",
            "bidirectional": True,
        },
        id="l3 traffic item between emulated vtep to leaf0 layer3 v4",
    ),
    pytest.param(
        {
            "traffic_item": "emulated vtep to leaf1 layer3 v6",
            "bidirectional": True,
        },
        id="l3 traffic item between emulated vtep to leaf1 layer3 v6",
    ),
    pytest.param(
        {
            "traffic_item": "emulated vtep to leaf1 layer3 v4",
            "bidirectional": True,
        },
        id="l3 traffic item between emulated vtep to leaf1 layer3 v4",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf0 vrf RED v6",
            "bidirectional": True,
        },
        id="l3 traffic item between external to leaf0 vrf RED v6",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf0 vrf RED v4",
            "bidirectional": True,
        },
        id="l3 traffic item between external to leaf0 vrf RED v4",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf1 vrf RED v6",
            "bidirectional": True,
        },
        id="l3 traffic item between external to leaf1 vrf RED v6",
    ),
    pytest.param(
        {
            "traffic_item": "external to leaf1 vrf RED v4",
            "bidirectional": True,
        },
        id="l3 traffic item between external to leaf1 vrf RED v4",
    ),
    pytest.param(
        {
            "traffic_item": "external to emulated vtep vrf RED v4",
            "bidirectional": False,
        },
        id="l3 traffic item between external to emulated vtep vrf RED v4",
    ),
    pytest.param(
        {
            "traffic_item": "external to emulated vtep vrf RED v6",
            "bidirectional": False,
        },
        id="l3 traffic item between external to emulated vtep vrf RED v6",
    ),
    pytest.param(
        {
            "traffic_item": "leaf0 vrf GREEN to leaf1 vrf RED inter",
            "bidirectional": True,
        },
        id="l3 traffic item between leaf0 vrf GREEN to leaf1 vrf RED inter",
    ),
    pytest.param(
        {
            "traffic_item": "leaf0 1-48 to leaf1 vrf RED inter",
            "bidirectional": True,
        },
        id="l3 traffic item between leaf0 1-48 to leaf1 vrf RED inter",
    ),
    pytest.param(
        {
            "traffic_item": "leaf0 Vrf GREEN to emulated vtep vrf RED",
            "bidirectional": False,
        },
        id="l3 traffic item between leaf0 Vrf GREEN to emulated vtep vrf RED",
    ),
    pytest.param(
        {
            "traffic_item": "leaf0 vrf GREEN to emulated vtep 1-48",
            "bidirectional": False,
        },
        id="l3 traffic item between leaf0 vrf GREEN to emulated vtep 1-48",
    ),
    pytest.param(
        {
            "traffic_item": "leaf0 1-48 to emulated vtep vrf RED",
            "bidirectional": False,
        },
        id="l3 traffic item between leaf0 1-48 to emulated vtep vrf RED",
    ),
]


@pytest.mark.parametrize("l3_traffic_item", l3_traffic_items_test_data)
def test_traffic_l3(configure_devices, l3_traffic_item):
    """
    Test L3 traffic functionality.
    """
    if configure_devices["traffic_profile"] != "l3":
        pytest.skip(
            "skipping l3 traffic test as traffic type is not l3. Traffic type: "
            f"{configure_devices['traffic_profile']}"
        )
    st.banner(f"test l3 traffic functionality for {l3_traffic_item}")
    session_assistant: SessionAssistant = configure_devices["session_assistant"]
    ixnetwork = session_assistant.Ixnetwork

    # Example of how to start traffic
    traffic_item_name = l3_traffic_item.get("traffic_item")
    handle = ixnetwork.Traffic.TrafficItem.find(Name=traffic_item_name)
    handle.Enabled = True
    st.wait(1)
    try:
        if l3_traffic_item.get("bidirectional", False):
            handle.BiDirectional = True
        handle.Generate(async_operation=False)
        st.log(f"generating traffic item {traffic_item_name} and wait for 2 seconds to generate")
        st.wait(2)
        ixnetwork.Traffic.Apply(async_operation=False)
        st.log(f"applying traffic item {traffic_item_name} and wait for 2 seconds to apply")
        st.wait(2)
        handle.StartStatelessTraffic(async_operation=False)
        st.log(f"starting traffic item {traffic_item_name} for 3 seconds")
        st.wait(3)
        handle.StopStatelessTraffic(async_operation=False)
        st.log(f"stopping traffic item {traffic_item_name} and wait for 3 seconds to for statistics to be updated")
        st.wait(3)
    except Exception as e:
        st.log(f"Failed to start traffic: {e}")
        st.report_fail("test_case_failed", "failed to start traffic")

    csv_data = session_assistant.StatViewAssistant("Traffic Item Statistics").AddRowFilter(
        ColumnName="Traffic Item", Comparator="EQUAL", FilterValue=traffic_item_name
    )
    cols = csv_data.ColumnHeaders
    rows = csv_data.Rows

    # 1 traffic item at a time. Result will be a single row.
    flow_stats = dict(zip(cols, rows[0].RawData[0]))
    st.log(f"flow_stats: {flow_stats}")

    if l3_traffic_item.get("bidirectional", False):
        handle.Enabled = False

    if int(flow_stats.get("Tx Frames", 0)) != int(flow_stats.get("Rx Frames", 0)):
        st.log(
            f"tx and rx frames mismatch {flow_stats.get('Tx Frames', 0)}: {flow_stats.get('Rx Frames', 0)} for traffic_item: {l3_traffic_item})"
        )
        st.report_fail(
            "test_case_failed",
            f"tx and rx frames is not equal for traffic_item: {l3_traffic_item}",
        )

    st.report_pass("test_case_passed", f"l2 traffic test passed, for: {l3_traffic_item}")
