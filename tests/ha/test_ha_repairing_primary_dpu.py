import logging
import json
import os
import time
import threading

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF
from packets import outbound_pl_packets
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.utilities import InterruptableThread
from gnmi_utils import apply_messages
from ha_gnmi import apply_ha_messages, ha_scope_config, ha_set_config
from ha_utils import (
    activate_primary_dash_ha,
    program_eni_pl_on_dpu,
    verify_ha_state,
    set_dead_dash_ha_scope,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

TRAFFIC_SEND_INTERVAL = 0.1
MAX_TRAFFIC_LOSS_PCT = 5.0
PL_VERIFY_TIMEOUT = 10


def _all_recv_ports(dash_pl_config):
    """Combine REMOTE_PTF_RECV_INTF from both DUTs so packets exiting
    either switch are counted."""
    ports = list(dash_pl_config[0][REMOTE_PTF_RECV_INTF])
    for p in dash_pl_config[1][REMOTE_PTF_RECV_INTF]:
        if p not in ports:
            ports.append(p)
    return ports


def _send_continuous_pl_traffic(ptfadapter, send_config, recv_ports,
                                stop_event, results):
    sent = 0
    received = 0
    send_pkt, exp_pkt = outbound_pl_packets(send_config, "vxlan")
    while not stop_event.is_set():
        try:
            testutils.send(
                ptfadapter, send_config[LOCAL_PTF_INTF], send_pkt, count=1
            )
            sent += 1
            try:
                testutils.verify_packet_any_port(
                    ptfadapter, exp_pkt, recv_ports, timeout=1,
                )
                received += 1
            except AssertionError:
                logger.debug("Packet not received")
                pass
        except Exception as e:
            logger.debug(f"Traffic sender: {e}")
        time.sleep(TRAFFIC_SEND_INTERVAL)
    results["sent"] = sent
    results["received"] = received


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    skip_config,
    dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json,
    ha_owner,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    """
    Apply base DASH pipeline config on duthosts[0]/dpuhosts[0] (primary) and
    duthosts[1]/dpuhosts[1] (standby).  duthosts[2]/dpuhosts[2] is the
    replacement DPU and is left unconfigured until the test body needs it.
    """
    if skip_config:
        return

    for i in range(2):
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]
        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG
        }
        logger.info(
            f"configure on {duthost.hostname} dpu {dpuhost.dpu_index} "
            f"{base_config_messages}"
        )
        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_CONFIG
        }
        if 'bluefield' in dpuhost.facts['asic_type']:
            route_and_mapping_messages.update({**pl.INBOUND_VNI_ROUTE_RULE_CONFIG})

        logger.info(route_and_mapping_messages)
        apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

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

    # Teardown: config-reload on all three DPUs to ensure a clean state
    for dpuhost in dpuhosts:
        logger.info(f"config reload on {dpuhost.hostname}")
        config_reload(dpuhost, safe_reload=True, yang_validate=False)


def _update_ha_set_with_replacement_dpu(
    localhost,
    duthosts,
    ptfhost,
    ha_owner,
    old_vdpu_id,
    new_vdpu_id,
    replacement_duthost,
    ha_set_id="haset0_0",
):
    """
    Update DASH_HA_SET_CONFIG_TABLE on all switches so that *old_vdpu_id* is
    replaced by *new_vdpu_id*.  The new DPU's HA scope is also programmed with
    ``disabled=True`` / ``desired_ha_state="unspecified"`` so it enters the HA
    set in Dead state as required by the workflow.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, "..", "common", "ha")
    ha_set_file = os.path.join(base_dir, "dash_ha_set_config_table.json")

    with open(ha_set_file) as f:
        ha_set_data = json.load(f)["DASH_HA_SET_CONFIG_TABLE"]

    ha_set_entry = ha_set_data.get(ha_set_id, {})

    # Replace the old vdpu_id with the new one in the member list
    vdpu_ids = ha_set_entry.get("vdpu_ids", [])
    updated_vdpu_ids = [new_vdpu_id if v == old_vdpu_id else v for v in vdpu_ids]
    ha_set_entry["vdpu_ids"] = updated_vdpu_ids

    # Keep preferred_vdpu_id pointing to the surviving (standby) DPU
    if ha_set_entry.get("preferred_vdpu_id") == old_vdpu_id:
        surviving = [v for v in updated_vdpu_ids if v != new_vdpu_id]
        if surviving:
            ha_set_entry["preferred_vdpu_id"] = surviving[0]

    ha_set_data[ha_set_id] = ha_set_entry

    logger.info(
        f"Updating HA set '{ha_set_id}' on all switches: "
        f"vdpu_ids={updated_vdpu_ids}"
    )

    for duthost in duthosts:
        if len(duthosts) > 2 and duthost == duthosts[0]:
            # Skip programming the old primary DPU's switch if it's different from the replacement's switch
            continue
        for key, fields in ha_set_data.items():
            ha_set_messages = ha_set_config(ha_set_id=key, **fields)
            apply_ha_messages(
                localhost=localhost,
                duthost=duthost,
                ptfhost=ptfhost,
                messages=ha_set_messages,
            )

    # Program the new DPU's HA scope as disabled on the switch that hosts it (duthosts[2])
    new_scope_key = f"{new_vdpu_id}:{ha_set_id}"
    new_scope_fields = {
        "version": "1",
        "disabled": True,
        "desired_ha_state": "unspecified",
        "owner": ha_owner,
    }
    logger.info(
        f"Programming new DPU scope '{new_scope_key}' with disabled state "
        f"on {replacement_duthost.hostname}"
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


def test_ha_repairing_primary_dpu(
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    ptfadapter,
    dash_pl_config,
):
    """
    Test replacement of the primary DPU in a live HA set.

    Workflow:
      1. Trigger planned shutdown on the primary DPU (dpuhosts[0]) that is
         being removed from the HA set.
      2. Update the HA set on all switches so that the old primary vDPU is
         replaced by the new vDPU (dpuhosts[2]).  This causes:
           - Old HA set tables/objects to be deleted.
           - A new HA set to be created.
           - The new DPU starts in Dead state.
      3. Program all ENIs on the new (replacement) DPU.
      4. SDN controller enables HA admin state (``disabled=False``) on the new
         DPU to start the HA set creation workflow.
      5. Verify that the replacement DPU reaches the active state and the
         surviving standby DPU reaches the standby state.
    """
    ha_set_id = "haset0_0"

    # When duthosts has only 2 elements the replacement DPU lives on
    # duthosts[1] (a different DPU slot on the same switch as the standby).
    replacement_duthost = duthosts[2] if len(duthosts) > 2 else duthosts[1]

    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:{ha_set_id}"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:{ha_set_id}"
    new_vdpu_id = f"vdpu0_{dpuhosts[2].dpu_index}"
    new_vdpu_key = f"{new_vdpu_id}:{ha_set_id}"

    # ---------------------------------------------------------------------------------------
    # Baseline traffic check before starting the continuous traffic thread
    # If verification fails here, the test will be aborted before making any HA state changes
    # ---------------------------------------------------------------------
    pl_config = dash_pl_config[0]
    recv_ports = _all_recv_ports(dash_pl_config)
    send_pkt, exp_pkt = outbound_pl_packets(pl_config, "vxlan")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pl_config[LOCAL_PTF_INTF], send_pkt, count=1)
    testutils.verify_packet_any_port(
        ptfadapter, exp_pkt, recv_ports, timeout=PL_VERIFY_TIMEOUT,
    )
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
        # ------------------------------------------------------------------
        # Step 1: Planned shutdown — remove primary DPU from the HA set
        # ------------------------------------------------------------------
        logger.info("Step 1: Triggering planned shutdown on primary DPU")
        set_dead_dash_ha_scope(localhost, duthosts[0], ptfhost, primary_vdpu_key)

        pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "dead"),
                      "Primary DPU did not reach dead state after planned shutdown")
        pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "standalone"),
                      "Standby HA state is not standalone")

        logger.info("Primary DPU in dead state, Standby DPU in standalone state")

        # ------------------------------------------------------------------
        # Step 2: Update HA set on all switches — replace old primary with new DPU
        # ------------------------------------------------------------------
        logger.info(
            f"Step 2: Updating HA set to replace '{primary_vdpu_key}' with "
            f"'{new_vdpu_id}' on all switches and DPUs"
        )
        old_vdpu_id = f"vdpu0_{dpuhosts[0].dpu_index}"
        _update_ha_set_with_replacement_dpu(
            localhost=localhost,
            duthosts=duthosts,
            ptfhost=ptfhost,
            ha_owner=ha_owner,
            old_vdpu_id=old_vdpu_id,
            new_vdpu_id=new_vdpu_id,
            replacement_duthost=replacement_duthost,
            ha_set_id=ha_set_id,
        )

        # Verify the new primary DPU is in dead state (as expected right after joining)
        pytest_assert(
            verify_ha_state(replacement_duthost, new_vdpu_key, "dead"),
            "New primary DPU did not reach dead state after joining the HA set"
        )
        logger.info("New primary DPU is in dead state as expected after HA set update")

        # ------------------------------------------------------------------
        # Step 3: Program all ENIs on the new (replacement) DPU
        # ------------------------------------------------------------------
        replacement_dpuhost = dpuhosts[2]
        logger.info(f"HA: Step 3: Programming ENIs on the replacement DPU: {replacement_dpuhost.hostname}")
        program_eni_pl_on_dpu(localhost, ptfhost, replacement_duthost, replacement_dpuhost)

        # ------------------------------------------------------------------
        # Step 4: SDN controller enables HA admin state on the new DPU
        # ------------------------------------------------------------------
        logger.info("Step 4: Activating the new primary DPU")
        pytest_assert(
            activate_primary_dash_ha(
                localhost, replacement_duthost, ptfhost, new_vdpu_key, "activate_role",
                owner=ha_owner
            ),
            f"Failed to activate HA on replacement primary DPU ({new_vdpu_key})"
        )
        logger.info("Replacement primary DPU reached active state")

        # ------------------------------------------------------------------
        # Step 5: Verify final HA states
        # ------------------------------------------------------------------
        logger.info("Step 5: Verifying final HA states")
        pytest_assert(
            verify_ha_state(replacement_duthost, new_vdpu_key, "active"),
            "Replacement primary DPU HA state is not active"
        )
        pytest_assert(
            verify_ha_state(duthosts[1], standby_vdpu_key, "standby"),
            "Standby DPU HA state is not standby after primary replacement"
        )

        logger.info(
            "Primary DPU replacement test completed successfully: "
            f"replacement primary DPU '{new_vdpu_key}' is active, "
            f"standby DPU '{standby_vdpu_key}' is standby"
        )
    finally:
        stop_event.set()
        traffic_thread.join(timeout=30)

    sent = traffic_results.get("sent", 0)
    received = traffic_results.get("received", 0)
    loss_pct = 100 * (sent - received) / max(sent, 1)
    logger.info(
        f"Traffic: sent={sent} received={received} "
        f"loss={sent - received} ({loss_pct:.1f}%)"
    )
    assert loss_pct <= MAX_TRAFFIC_LOSS_PCT, (
        f"Traffic loss {loss_pct:.1f}% exceeds threshold "
        f"{MAX_TRAFFIC_LOSS_PCT}%  (sent={sent} received={received})"
    )
