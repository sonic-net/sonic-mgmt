import json
import logging
import os
import threading
import time

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
    VXLAN_UDP_BASE_SRC_PORT,
    VXLAN_UDP_SRC_PORT_MASK,
)
from packets import outbound_pl_packets
from tests.common.devices.duthosts import DutHosts
from tests.common.config_reload import config_reload
from tests.common.dash_utils import apply_swssconfig_file
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import InterruptableThread
from tests.conftest import get_specified_dpus, get_target_hostname, is_parallel_leader
from gnmi_utils import apply_messages
from ha_gnmi import apply_ha_messages, ha_scope_config, ha_set_config
from ha_utils import (
    program_eni_pl_on_dpu,
    set_dash_ha_scope,
    verify_ha_state,
    wait_for_pending_operation_id,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health,
]

TRAFFIC_SEND_INTERVAL = 0.1
MAX_TRAFFIC_LOSS_PCT = 5.0
PL_VERIFY_TIMEOUT = 10


def _requested_dpuhosts(host_nodes, request):
    requested_dpuhosts = get_specified_dpus(request)
    nodes_by_hostname = {node.hostname: node for node in host_nodes}
    missing_dpuhosts = [
        hostname for hostname in requested_dpuhosts if hostname not in nodes_by_hostname
    ]
    pytest_require(
        not missing_dpuhosts,
        f"Requested DPU hosts were not initialized: {missing_dpuhosts}",
    )
    return [nodes_by_hostname[hostname] for hostname in requested_dpuhosts]


def _dpuhost_matches_duthost(dpuhost, duthost):
    return dpuhost.hostname == duthost.hostname or dpuhost.hostname.startswith(
        f"{duthost.hostname}-"
    )


def _repair_index(repair_target):
    return 0 if repair_target == "primary" else 1


def _peer_index(repair_target):
    return 1 - _repair_index(repair_target)


def _repair_title(repair_target):
    return repair_target.capitalize()


def _peer_title(repair_target):
    return "Standby" if repair_target == "primary" else "Primary"


def _replacement_desired_ha_state(repair_target):
    return "active" if repair_target == "primary" else "unspecified"


def _replacement_expected_state(repair_target, ha_owner):
    if repair_target == "primary":
        return "active"
    return "active" if ha_owner == "dpu" else "standby"


def _expected_peer_state_after_repair(repair_target, ha_owner):
    if repair_target == "primary":
        return "active" if ha_owner == "dpu" else "standby"
    return "active"


def _select_replacement_dpuhost(requested_dpuhosts, duthost_to_replace):
    pytest_require(
        len(requested_dpuhosts) in (3, 4),
        "HA repairing tests require exactly 3 or 4 requested DPU hosts",
    )

    if len(requested_dpuhosts) == 3:
        return requested_dpuhosts[2]

    replacement_candidates = requested_dpuhosts[-2:]
    for dpuhost in replacement_candidates:
        if _dpuhost_matches_duthost(dpuhost, duthost_to_replace):
            return dpuhost

    pytest_require(
        False,
        "The last two requested DPU hosts {} do not include a replacement on {}".format(
            [dpuhost.hostname for dpuhost in replacement_candidates],
            duthost_to_replace.hostname,
        ),
    )


@pytest.fixture(scope="session")
def dpuhosts(
    enhance_inventory,
    ansible_adhoc,
    tbinfo,
    request,
    enable_nat_for_dpuhosts,
    duthosts,
):
    """Return all requested DPU hosts in CLI order for the repair test module."""
    del enhance_inventory, enable_nat_for_dpuhosts

    host = DutHosts(
        ansible_adhoc,
        tbinfo,
        request,
        get_specified_dpus(request),
        target_hostname=get_target_hostname(request),
        is_parallel_leader=is_parallel_leader(request),
    )
    requested_dpuhosts = _requested_dpuhosts(host.nodes, request)
    pytest_require(
        len(requested_dpuhosts) in (3, 4),
        "HA repairing tests require exactly 3 or 4 requested DPU hosts",
    )
    pytest_require(
        _dpuhost_matches_duthost(requested_dpuhosts[0], duthosts[0]),
        "The first requested DPU host must belong to {}".format(duthosts[0].hostname),
    )
    pytest_require(
        _dpuhost_matches_duthost(requested_dpuhosts[1], duthosts[1]),
        "The second requested DPU host must belong to {}".format(duthosts[1].hostname),
    )
    return requested_dpuhosts


@pytest.fixture(autouse=True, scope="module")
def require_replacement_dpu(dpuhosts):
    pytest_require(
        len(dpuhosts) in (3, 4),
        "HA repairing tests require the HA pair plus one or two replacement DPU candidates",
    )


@pytest.fixture(params=["primary", "standby"], ids=["primary", "standby"])
def repair_target(request, ha_owner):
    if request.param == "primary" and ha_owner != "dpu":
        pytest.skip("Re-pairing the Active (primary) DPU is only supported for DPU-driven mode")
    return request.param


@pytest.fixture(scope="function")
def selected_dpuhosts(dpuhosts, duthosts, repair_target):
    replacement_dpuhost = _select_replacement_dpuhost(
        dpuhosts,
        duthosts[_repair_index(repair_target)],
    )
    return [dpuhosts[0], dpuhosts[1], replacement_dpuhost]


def _all_recv_ports(dash_pl_config):
    """Combine REMOTE_PTF_RECV_INTF from both DUTs so packets exiting either switch are counted."""
    ports = list(dash_pl_config[0][REMOTE_PTF_RECV_INTF])
    for port in dash_pl_config[1][REMOTE_PTF_RECV_INTF]:
        if port not in ports:
            ports.append(port)
    return ports


def _send_continuous_pl_traffic(ptfadapter, send_config, recv_ports, stop_event, results):
    sent = 0
    received = 0
    send_pkt, exp_pkt = outbound_pl_packets(send_config, "vxlan")
    while not stop_event.is_set():
        try:
            testutils.send(ptfadapter, send_config[LOCAL_PTF_INTF], send_pkt, count=1)
            sent += 1
            try:
                testutils.verify_packet_any_port(
                    ptfadapter,
                    exp_pkt,
                    recv_ports,
                    timeout=1,
                )
                received += 1
            except AssertionError:
                logger.debug("Packet not received")
        except Exception as error:
            logger.debug(f"Traffic sender: {error}")
        time.sleep(TRAFFIC_SEND_INTERVAL)
    results["sent"] = sent
    results["received"] = received


def _verify_baseline_pl_traffic(ptfadapter, send_config, recv_ports):
    send_pkt, exp_pkt = outbound_pl_packets(send_config, "vxlan")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, send_config[LOCAL_PTF_INTF], send_pkt, count=1)
    testutils.verify_packet_any_port(
        ptfadapter,
        exp_pkt,
        recv_ports,
        timeout=PL_VERIFY_TIMEOUT,
    )


def _replacement_context(duthosts, selected_dpuhosts):
    replacement_dpuhost = selected_dpuhosts[2]

    for dut_index, duthost in enumerate(duthosts):
        if _dpuhost_matches_duthost(replacement_dpuhost, duthost):
            return duthost, dut_index, replacement_dpuhost

    raise ValueError(
        "Unable to map replacement DPU '{}' to a DUT in {}".format(
            replacement_dpuhost.hostname,
            [duthost.hostname for duthost in duthosts],
        )
    )


def _replacement_vdpu_id(duthosts, selected_dpuhosts):
    _, replacement_dut_index, replacement_dpuhost = _replacement_context(
        duthosts,
        selected_dpuhosts,
    )
    return f"vdpu{replacement_dut_index}_{replacement_dpuhost.dpu_index}"


def _apply_vxlan_udp_sport_range(dpuhosts):
    vxlan_sport_config = [
        {
            "SWITCH_TABLE:switch": {
                "vxlan_sport": VXLAN_UDP_BASE_SRC_PORT,
                "vxlan_mask": VXLAN_UDP_SRC_PORT_MASK,
            },
            "OP": "SET",
        }
    ]

    logger.info(f"Setting VXLAN source port config: {vxlan_sport_config}")
    config_path = "/tmp/vxlan_sport_config.json"
    for dpuhost in dpuhosts:
        dpuhost.copy(content=json.dumps(vxlan_sport_config, indent=4), dest=config_path, verbose=False)
        apply_swssconfig_file(dpuhost, config_path)
        if 'pensando' in dpuhost.facts['asic_type']:
            logger.warning("Applying Pensando DPU VXLAN sport workaround")
            dpuhost.shell("pdsctl debug update device --vxlan-port 4789 --vxlan-src-ports 5120-5247")


@pytest.fixture(scope="function")
def repair_runtime_state():
    return {"replacement_scope_programmed": False}


def _cleanup_programmed_dpu(localhost, ptfhost, duthost, dpuhost):
    base_config_messages = {
        **pl.APPLIANCE_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
    }
    route_and_mapping_messages = {
        **pl.PE_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG,
    }
    if 'bluefield' in dpuhost.facts['asic_type']:
        route_and_mapping_messages.update({**pl.INBOUND_VNI_ROUTE_RULE_CONFIG})

    meter_rule_messages = {
        **pl.METER_RULE1_V4_CONFIG,
        **pl.METER_RULE2_V4_CONFIG,
    }

    logger.info(
        f"Removing DPU PL programming on {dpuhost.hostname}"
    )

    apply_messages(
        localhost,
        duthost,
        ptfhost,
        pl.ENI_ROUTE_GROUP1_CONFIG,
        dpuhost.dpu_index,
        set_db=False,
        wait_after_apply=1,
    )
    apply_messages(
        localhost,
        duthost,
        ptfhost,
        pl.ENI_CONFIG,
        dpuhost.dpu_index,
        set_db=False,
        wait_after_apply=1,
    )
    apply_messages(
        localhost,
        duthost,
        ptfhost,
        meter_rule_messages,
        dpuhost.dpu_index,
        set_db=False,
        wait_after_apply=1,
    )
    apply_messages(
        localhost,
        duthost,
        ptfhost,
        route_and_mapping_messages,
        dpuhost.dpu_index,
        set_db=False,
        wait_after_apply=1,
    )
    apply_messages(
        localhost,
        duthost,
        ptfhost,
        base_config_messages,
        dpuhost.dpu_index,
        set_db=False,
        wait_after_apply=1,
    )


@pytest.fixture(scope="function")
def set_vxlan_udp_sport_range(selected_dpuhosts, skip_config):
    if skip_config:
        yield
        return

    _apply_vxlan_udp_sport_range(selected_dpuhosts)
    yield


@pytest.fixture(scope="function")
def setup_npu_dpu(add_npu_static_routes, duthosts, selected_dpuhosts, skip_config):
    del add_npu_static_routes
    if skip_config:
        yield
        return

    for dut_index, duthost in enumerate(duthosts):
        dpuhost = selected_dpuhosts[dut_index]
        dpuhost.shell(f'ip route replace {duthost.mgmt_ip}/32 via 169.254.200.254')
        interfaces = dpuhost.shell("show ip int")["stdout"]
        dpu_commands = []
        if "Loopback0" not in interfaces:
            dpu_commands.append("config loopback add Loopback0")
            dpu_commands.append(f"config int ip add Loopback0 {pl.APPLIANCE_VIP}/32")
            dpuhost.shell_cmds(cmds=dpu_commands)

    yield


def _activate_replacement_dpu(
    localhost,
    replacement_duthost,
    ptfhost,
    scope_key,
    owner,
    repair_target,
):
    fields = {
        "version": "1",
        "disabled": False,
        "desired_ha_state": _replacement_desired_ha_state(repair_target),
        "owner": owner,
    }
    vdpu_id_part, ha_set_id_part = scope_key.split(":", 1)
    activation_messages = ha_scope_config(
        vdpu_id=vdpu_id_part,
        ha_set_id=ha_set_id_part,
        **fields,
    )
    apply_ha_messages(
        localhost=localhost,
        duthost=replacement_duthost,
        ptfhost=ptfhost,
        messages=activation_messages,
    )

    pending_id = wait_for_pending_operation_id(
        replacement_duthost,
        scope_key,
        "activate_role",
        timeout=60,
    )
    if pending_id:
        logger.info(
            f"Replacement {repair_target} DPU {scope_key} pending id {pending_id}; approving activation"
        )
        approval_messages = ha_scope_config(
            vdpu_id=vdpu_id_part,
            ha_set_id=ha_set_id_part,
            approved_pending_operation_ids=[pending_id],
            **fields,
        )
        apply_ha_messages(
            localhost=localhost,
            duthost=replacement_duthost,
            ptfhost=ptfhost,
            messages=approval_messages,
        )
    else:
        logger.info(
            f"Replacement {repair_target} DPU {scope_key} has no activate_role pending id; "
            "continuing with direct state verification"
        )

    return verify_ha_state(
        replacement_duthost,
        scope_key,
        _replacement_expected_state(repair_target, owner),
        timeout=120,
        interval=5,
    )


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    skip_config,
    repair_runtime_state,
    selected_dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json_func_scope,
    ha_owner,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu,
):
    """
    Apply base DASH pipeline config on duthosts[0]/selected_dpuhosts[0] (primary)
    and duthosts[1]/selected_dpuhosts[1] (standby). selected_dpuhosts[2] is the
    scenario-selected replacement DPU and is left unconfigured until the test body
    needs it.
    """
    del setup_ha_config, setup_dash_ha_from_json_func_scope, setup_gnmi_server
    del set_vxlan_udp_sport_range, setup_npu_dpu

    if skip_config:
        return

    for dut_index in range(2):
        duthost = duthosts[dut_index]
        dpuhost = selected_dpuhosts[dut_index]
        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG,
        }
        logger.info(
            f"configure on {duthost.hostname} dpu {dpuhost.dpu_index} {base_config_messages}"
        )
        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_CONFIG,
        }
        if 'bluefield' in dpuhost.facts['asic_type']:
            route_and_mapping_messages.update({**pl.INBOUND_VNI_ROUTE_RULE_CONFIG})

        logger.info(route_and_mapping_messages)
        apply_messages(
            localhost,
            duthost,
            ptfhost,
            route_and_mapping_messages,
            dpuhost.dpu_index,
        )

        meter_rule_messages = {
            **pl.METER_RULE1_V4_CONFIG,
            **pl.METER_RULE2_V4_CONFIG,
        }
        logger.info(meter_rule_messages)
        apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)

        logger.info(pl.ENI_CONFIG)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index)

        logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    replacement_duthost, _, replacement_dpuhost = _replacement_context(duthosts, selected_dpuhosts)
    ha_set_id = "haset0_0"
    replacement_scope_key = f"{_replacement_vdpu_id(duthosts, selected_dpuhosts)}:{ha_set_id}"

    try:
        cleanup_targets = [
            (duthosts[0], selected_dpuhosts[0]),
            (duthosts[1], selected_dpuhosts[1]),
            (replacement_duthost, replacement_dpuhost),
        ]
        for duthost, dpuhost in cleanup_targets:
            _cleanup_programmed_dpu(
                localhost,
                ptfhost,
                duthost,
                dpuhost,
            )
        if repair_runtime_state["replacement_scope_programmed"]:
            logger.info(
                f"Setting replacement HA scope '{replacement_scope_key}' to dead on {replacement_duthost.hostname}"
            )
            set_dash_ha_scope(
                localhost,
                replacement_duthost,
                ptfhost,
                replacement_scope_key,
                "dead",
                ha_owner,
                disabled=True,
            )

        logger.info("Removing all DASH_HA_SCOPE_CONFIG_TABLE entries on both switches")
        scope_targets = [
            (duthosts[0], f"vdpu0_{selected_dpuhosts[0].dpu_index}"),
            (duthosts[1], f"vdpu1_{selected_dpuhosts[1].dpu_index}"),
        ]
        if repair_runtime_state["replacement_scope_programmed"]:
            replacement_vdpu_id, _ = replacement_scope_key.split(":", 1)
            scope_targets.append((replacement_duthost, replacement_vdpu_id))
        for duthost, vdpu_id in scope_targets:
            scope_messages = ha_scope_config(
                vdpu_id=vdpu_id,
                ha_set_id=ha_set_id,
                version="1",
                disabled=True,
                desired_ha_state="unspecified",
                owner=ha_owner,
            )
            apply_ha_messages(
                localhost=localhost,
                duthost=duthost,
                ptfhost=ptfhost,
                messages=scope_messages,
                set_db=False,
            )

        logger.info("Removing all DASH_HA_SET_CONFIG_TABLE entries on both switches")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.join(current_dir, "..", "common", "ha")
        ha_set_file = os.path.join(base_dir, "dash_ha_set_config_table.json")
        with open(ha_set_file) as ha_set_handle:
            ha_set_data = json.load(ha_set_handle)["DASH_HA_SET_CONFIG_TABLE"]
        for duthost in duthosts:
            for key, fields in ha_set_data.items():
                ha_set_messages = ha_set_config(ha_set_id=key, **fields)
                apply_ha_messages(
                    localhost=localhost,
                    duthost=duthost,
                    ptfhost=ptfhost,
                    messages=ha_set_messages,
                    set_db=False,
                )
    finally:
        for dpuhost in selected_dpuhosts:
            logger.info(f"config reload on {dpuhost.hostname}")
            config_reload(dpuhost, safe_reload=True, yang_validate=False)


def _update_ha_set_with_replacement_dpu(
    localhost,
    duthosts,
    ptfhost,
    ha_owner,
    old_vdpu_id,
    new_vdpu_id,
    old_duthost,
    peer_duthost,
    replacement_duthost,
    repair_target,
    ha_set_id="haset0_0",
):
    """Replace the old DPU's HA programming with the replacement DPU.

    The peer switch (hosting the surviving DPU) keeps its existing scope and
    only receives an updated DASH_HA_SET_CONFIG_TABLE. The old DPU's switch
    has its old scope and old set deleted first, then the new set and new
    scope (for the replacement DPU) are written.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, "..", "common", "ha")
    ha_set_file = os.path.join(base_dir, "dash_ha_set_config_table.json")

    with open(ha_set_file) as ha_set_handle:
        ha_set_data = json.load(ha_set_handle)["DASH_HA_SET_CONFIG_TABLE"]

    ha_set_entry = ha_set_data.get(ha_set_id, {})
    vdpu_ids = ha_set_entry.get("vdpu_ids", [])
    updated_vdpu_ids = [new_vdpu_id if vdpu_id == old_vdpu_id else vdpu_id for vdpu_id in vdpu_ids]
    ha_set_entry["vdpu_ids"] = updated_vdpu_ids

    if repair_target == "primary":
        if ha_set_entry.get("preferred_vdpu_id") == old_vdpu_id:
            ha_set_entry["preferred_vdpu_id"] = new_vdpu_id
    elif ha_set_entry.get("preferred_vdpu_id") == old_vdpu_id:
        surviving_vdpu_ids = [vdpu_id for vdpu_id in updated_vdpu_ids if vdpu_id != new_vdpu_id]
        if surviving_vdpu_ids:
            ha_set_entry["preferred_vdpu_id"] = surviving_vdpu_ids[0]

    ha_set_data[ha_set_id] = ha_set_entry

    old_scope_key = f"{old_vdpu_id}:{ha_set_id}"
    logger.info(
        f"Removing old DASH_HA_SCOPE_CONFIG_TABLE '{old_scope_key}' on "
        f"{old_duthost.hostname}"
    )
    old_scope_messages = ha_scope_config(
        vdpu_id=old_vdpu_id,
        ha_set_id=ha_set_id,
        version="1",
        disabled=True,
        desired_ha_state="unspecified",
        owner=ha_owner,
    )
    apply_ha_messages(
        localhost=localhost,
        duthost=old_duthost,
        ptfhost=ptfhost,
        messages=old_scope_messages,
        set_db=False,
    )

    logger.info(
        f"Removing old DASH_HA_SET_CONFIG_TABLE entries on {old_duthost.hostname}"
    )
    for key, fields in ha_set_data.items():
        ha_set_messages = ha_set_config(ha_set_id=key, **fields)
        apply_ha_messages(
            localhost=localhost,
            duthost=old_duthost,
            ptfhost=ptfhost,
            messages=ha_set_messages,
            set_db=False,
        )

    logger.info(
        f"Updating DASH_HA_SET_CONFIG_TABLE on peer {peer_duthost.hostname} "
        f"with vdpu_ids={updated_vdpu_ids}"
    )
    for key, fields in ha_set_data.items():
        ha_set_messages = ha_set_config(ha_set_id=key, **fields)
        apply_ha_messages(
            localhost=localhost,
            duthost=peer_duthost,
            ptfhost=ptfhost,
            messages=ha_set_messages,
        )

    if replacement_duthost is not peer_duthost:
        logger.info(
            f"Creating DASH_HA_SET_CONFIG_TABLE on replacement {replacement_duthost.hostname} "
            f"with vdpu_ids={updated_vdpu_ids}"
        )
        for key, fields in ha_set_data.items():
            ha_set_messages = ha_set_config(ha_set_id=key, **fields)
            apply_ha_messages(
                localhost=localhost,
                duthost=replacement_duthost,
                ptfhost=ptfhost,
                messages=ha_set_messages,
            )

    new_scope_key = f"{new_vdpu_id}:{ha_set_id}"
    new_scope_fields = {
        "version": "1",
        "disabled": True,
        "desired_ha_state": "unspecified",
        "owner": ha_owner,
    }
    logger.info(
        f"Programming new DPU scope '{new_scope_key}' with disabled state on {replacement_duthost.hostname}"
    )
    vdpu_id_part, ha_set_id_part = new_scope_key.split(":", 1)
    new_scope_messages = ha_scope_config(
        vdpu_id=vdpu_id_part,
        ha_set_id=ha_set_id_part,
        **new_scope_fields,
    )
    apply_ha_messages(
        localhost=localhost,
        duthost=replacement_duthost,
        ptfhost=ptfhost,
        messages=new_scope_messages,
    )


def test_ha_repairing_dpu(
    localhost,
    duthosts,
    dpuhosts,
    repair_runtime_state,
    selected_dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    ptfadapter,
    dash_pl_config,
    repair_target,
):
    """
    Test replacement of either the primary or the standby DPU in a live HA set.

    Each parametrized case starts from a fresh HA setup and re-applies the DPU-side
    configuration that is cleared by the per-case config_reload cleanup.
    """
    del activate_dash_ha_from_json, dpuhosts

    ha_set_id = "haset0_0"
    repair_index = _repair_index(repair_target)
    peer_index = _peer_index(repair_target)
    repair_title = _repair_title(repair_target)
    peer_title = _peer_title(repair_target)

    replacement_duthost, _, replacement_dpuhost = _replacement_context(
        duthosts,
        selected_dpuhosts,
    )

    repair_vdpu_key = (
        f"vdpu{repair_index}_{selected_dpuhosts[repair_index].dpu_index}:{ha_set_id}"
    )
    peer_vdpu_key = f"vdpu{peer_index}_{selected_dpuhosts[peer_index].dpu_index}:{ha_set_id}"
    new_vdpu_id = _replacement_vdpu_id(duthosts, selected_dpuhosts)
    new_vdpu_key = f"{new_vdpu_id}:{ha_set_id}"
    expected_replacement_state = _replacement_expected_state(repair_target, ha_owner)
    expected_peer_state = _expected_peer_state_after_repair(repair_target, ha_owner)

    pl_config = dash_pl_config[0]
    recv_ports = _all_recv_ports(dash_pl_config)
    _verify_baseline_pl_traffic(ptfadapter, pl_config, recv_ports)
    logger.info("Baseline PL traffic verified")

    stop_event = threading.Event()
    traffic_results = {}
    traffic_thread = InterruptableThread(
        target=_send_continuous_pl_traffic,
        args=(ptfadapter, pl_config, recv_ports, stop_event, traffic_results),
    )
    traffic_thread.start()
    time.sleep(2)

    try:
        logger.info(f"Step 1: Triggering planned shutdown on {repair_target} DPU")
        set_dash_ha_scope(
            localhost,
            duthosts[repair_index],
            ptfhost,
            repair_vdpu_key,
            "dead",
            ha_owner,
            disabled=True,
        )

        pytest_assert(
            verify_ha_state(duthosts[repair_index], repair_vdpu_key, "dead"),
            f"{repair_title} DPU did not reach dead state after planned shutdown",
        )
        pytest_assert(
            verify_ha_state(duthosts[peer_index], peer_vdpu_key, "standalone"),
            f"{peer_title} HA state is not standalone",
        )

        logger.info(
            f"{repair_title} DPU is in dead state, {peer_title} DPU is in standalone state"
        )

        logger.info(
            f"Step 2: Updating HA set to replace '{repair_vdpu_key}' with '{new_vdpu_id}' "
            "on all switches and DPUs"
        )
        old_vdpu_id = f"vdpu{repair_index}_{selected_dpuhosts[repair_index].dpu_index}"
        _update_ha_set_with_replacement_dpu(
            localhost=localhost,
            duthosts=duthosts,
            ptfhost=ptfhost,
            ha_owner=ha_owner,
            old_vdpu_id=old_vdpu_id,
            new_vdpu_id=new_vdpu_id,
            old_duthost=duthosts[repair_index],
            peer_duthost=duthosts[peer_index],
            replacement_duthost=replacement_duthost,
            repair_target=repair_target,
            ha_set_id=ha_set_id,
        )
        repair_runtime_state["replacement_scope_programmed"] = True
        logger.info(
            f"Replacement {repair_target} DPU scope programmed with disabled admin state; "
            "HA role activation is verified in the next step"
        )

        logger.info(
            f"HA: Step 3: Programming ENIs on the replacement DPU: {replacement_dpuhost.hostname}"
        )
        program_eni_pl_on_dpu(localhost, ptfhost, replacement_duthost, replacement_dpuhost)

        logger.info(f"Step 4: Activating the new {repair_target} DPU")
        pytest_assert(
            _activate_replacement_dpu(
                localhost,
                replacement_duthost,
                ptfhost,
                new_vdpu_key,
                ha_owner,
                repair_target,
            ),
            f"Failed to activate HA on replacement {repair_target} DPU ({new_vdpu_key})",
        )
        logger.info(
            f"Replacement {repair_target} DPU reached {expected_replacement_state} state"
        )

        logger.info("Step 5: Verifying final HA states")
        pytest_assert(
            verify_ha_state(
                replacement_duthost,
                new_vdpu_key,
                expected_replacement_state,
            ),
            f"Replacement {repair_target} DPU HA state is not {expected_replacement_state}",
        )
        pytest_assert(
            verify_ha_state(duthosts[peer_index], peer_vdpu_key, expected_peer_state),
            f"{peer_title} DPU HA state is not {expected_peer_state} after {repair_target} replacement",
        )

        logger.info(
            f"{repair_title} DPU replacement test completed successfully: replacement DPU "
            f"'{new_vdpu_key}' is {expected_replacement_state}, surviving peer DPU "
            f"'{peer_vdpu_key}' is {expected_peer_state}"
        )
    finally:
        stop_event.set()
        traffic_thread.join(timeout=30)
        if traffic_thread.is_alive():
            logger.warning("Traffic thread still running after 30 seconds; waiting 5 more seconds")
            traffic_thread.join(timeout=5)
        pytest_assert(
            not traffic_thread.is_alive(),
            "Continuous PL traffic thread did not stop cleanly",
        )
        ptfadapter.dataplane.flush()

    sent = traffic_results.get("sent", 0)
    received = traffic_results.get("received", 0)
    loss_pct = 100 * (sent - received) / max(sent, 1)
    logger.info(
        f"Traffic: sent={sent} received={received} loss={sent - received} ({loss_pct:.1f}%)"
    )
    assert loss_pct <= MAX_TRAFFIC_LOSS_PCT, (
        f"Traffic loss {loss_pct:.1f}% exceeds threshold "
        f"{MAX_TRAFFIC_LOSS_PCT}%  (sent={sent} received={received})"
    )
