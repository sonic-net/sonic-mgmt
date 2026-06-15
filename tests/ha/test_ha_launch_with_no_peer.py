import os
import json
import pytest
import logging
import ptf.testutils as testutils
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
)
from conftest import (
    activate_scope_per_dut,
    deactivate_dash_ha_from_json_util,
    ha_scope_per_dut,
    remove_setup_dash_ha_from_json_util,
    wait_for_dpu_neighbor_resolution,
)
from packets import outbound_pl_packets
from ha_utils import verify_ha_state, wait_for_pending_operation_id, ha_scope_config, ha_set_config, apply_ha_messages
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha"),
    pytest.mark.skip_check_dut_health,
]

logger = logging.getLogger(__name__)

"""
The assumption for the test is that duthosts has primary and secondary in this order
"""


def setup_dash_ha(duthost, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner, role_index):
    dpuhost = dpuhosts[role_index]
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, "..", "common", "ha")
    ha_set_file = os.path.join(base_dir, "dash_ha_set_config_table.json")

    template_key = f"vdpu{role_index}_0:haset0_0"
    actual_key = f"vdpu{role_index}_{dpuhost.dpu_index}:haset0_0"

    _, scope_fields = next(
        (name, data) for name, data in ha_scope_per_dut
        if name == template_key
    )
    scope_fields = dict(scope_fields)
    scope_fields['owner'] = ha_owner

    # TODO: remove once neighbor flakiness is fixed.
    '''
    ip_part = 200 + role_index
    ip_last = dpuhost.dpu_index + 1
    logger.info(f"Sending ping to DPU{dpuhost.dpu_index} for {duthost.hostname}")
    ping_result = duthost.shell(f"ping -c 3 20.0.{ip_part}.{ip_last}", module_ignore_errors=True)["stdout"]
    logger.info(f"{duthost.hostname} ping_result [{ping_result}]")
    '''

    wait_for_dpu_neighbor_resolution(
        duthost=duthost,
        role_index=role_index,
        dpu_index=dpuhost.dpu_index,
    )

    with open(ha_set_file) as f:
        ha_set_data = json.load(f)["DASH_HA_SET_CONFIG_TABLE"]

    ha_set_entry = ha_set_data.get("haset0_0", {})
    ha_set_entry["vdpu_ids"] = [f"vdpu0_{dpuhosts[0].dpu_index}", f"vdpu1_{dpuhosts[1].dpu_index}"]
    ha_set_entry["preferred_vdpu_id"] = f"vdpu0_{dpuhosts[0].dpu_index}"
    ha_set_data["haset0_0"] = ha_set_entry

    # Step 1: Program HA SET on this DUT
    for key, set_fields in ha_set_data.items():
        ha_set_messages = ha_set_config(ha_set_id=key, **set_fields)
        apply_ha_messages(
            localhost=localhost,
            duthost=duthost,
            ptfhost=ptfhost,
            messages=ha_set_messages,
        )

    # Step 2: Program HA SCOPE for this DUT
    vdpu_id, ha_set_id = actual_key.split(":", 1)
    ha_scope_messages = ha_scope_config(
        vdpu_id=vdpu_id,
        ha_set_id=ha_set_id,
        **scope_fields,
    )
    apply_ha_messages(
        localhost=localhost,
        duthost=duthost,
        ptfhost=ptfhost,
        messages=ha_scope_messages,
    )
    logger.info(f"HA: Setup completed for {duthost.hostname}")


def activate_dash_ha(duthost, dpuhost, localhost, ptfhost, setup_gnmi_server,
                     ha_owner, role_index, approval_needed=True):
    template_key = f"vdpu{role_index}_0:haset0_0"
    actual_key = f"vdpu{role_index}_{dpuhost.dpu_index}:haset0_0"

    _, fields = next(
        (name, data) for name, data in activate_scope_per_dut
        if name == template_key
    )
    fields = dict(fields)
    fields['owner'] = ha_owner

    vdpu_id, ha_set_id = actual_key.split(":", 1)
    ha_scope_messages = ha_scope_config(
        vdpu_id=vdpu_id,
        ha_set_id=ha_set_id,
        **fields,
    )
    apply_ha_messages(
        localhost=localhost,
        duthost=duthost,
        ptfhost=ptfhost,
        messages=ha_scope_messages,
    )

    if approval_needed:
        pending_id = wait_for_pending_operation_id(
            duthost,
            scope_key=actual_key,
            expected_op_type="activate_role",
            timeout=300,
            interval=2
        )
        assert pending_id, (
            f"Timed out waiting for active pending_operation_id "
            f"for {duthost.hostname} scope {actual_key}"
        )

        logger.info(f"HA: {duthost.hostname} found pending id {pending_id}")
        ha_scope_messages = ha_scope_config(
            vdpu_id=vdpu_id,
            ha_set_id=ha_set_id,
            approved_pending_operation_ids=[pending_id],
            **fields,
        )
        apply_ha_messages(
            localhost=localhost,
            duthost=duthost,
            ptfhost=ptfhost,
            messages=ha_scope_messages,
        )
    logger.info(f"HA: Activate completed for {duthost.hostname}")


def verify_primary_standalone_traffic(ptfadapter, dash_pl_config):
    primary_config = dash_pl_config[0]
    send_pkt, exp_pkt = outbound_pl_packets(primary_config, "vxlan")

    logger.info("HA: verify PL traffic sent to primary NPU while primary is standalone")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, primary_config[LOCAL_PTF_INTF], send_pkt, count=1)
    testutils.verify_packet_any_port(
        ptfadapter,
        exp_pkt,
        primary_config[REMOTE_PTF_RECV_INTF],
    )


def test_ha_launch_with_no_peer(request, duthosts, dpuhosts, localhost, ptfhost, setup_ha_config,
                                ha_owner, setup_gnmi_server, primary_vdpu_key, standby_vdpu_key,
                                setup_dash_pl_pipeline, ptfadapter, dash_pl_config):

    logger.info("HA: activate only primary")
    try:
        setup_dash_ha(duthosts[0], dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner, role_index=0)
        activate_dash_ha(duthosts[0], dpuhosts[0], localhost, ptfhost, setup_gnmi_server, ha_owner, role_index=0,
                         approval_needed=(ha_owner == "dpu"))

        pytest_assert(verify_ha_state(duthosts[0], scope_key=primary_vdpu_key, expected_state="standalone",
                                      timeout=150),
                      "HA: Primary state is not standalone")
        verify_primary_standalone_traffic(ptfadapter, dash_pl_config)

        logger.info("HA: activate standby with standalone primary")
        setup_dash_ha(duthosts[1], dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner, role_index=1)
        activate_dash_ha(duthosts[1], dpuhosts[1], localhost, ptfhost, setup_gnmi_server, ha_owner, role_index=1)
        if ha_owner == "dpu":
            pytest_assert(verify_ha_state(duthosts[1], scope_key=standby_vdpu_key, expected_state="active"),
                          "HA: Standby state is not active")
            pytest_assert(verify_ha_state(duthosts[0], scope_key=primary_vdpu_key, expected_state="active"),
                          "HA: Primary state is not active")
        else:
            pytest_assert(verify_ha_state(duthosts[1], scope_key=standby_vdpu_key, expected_state="standby"),
                          "HA: Standby state is not standby")
            pytest_assert(verify_ha_state(duthosts[0], scope_key=primary_vdpu_key, expected_state="active"),
                          "HA: Primary state is not active")
    finally:
        deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
