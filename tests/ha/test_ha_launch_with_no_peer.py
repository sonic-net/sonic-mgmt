import pytest
import logging
from tests.ha.conftest import setup_gnmi_server
from conftest import activate_scope_per_dut
from ha_utils import verify_ha_state, wait_for_pending_operation_id, ha_scope_config, apply_ha_messages
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha")
]

logger = logging.getLogger(__name__)

"""
The assumption for the test is that duthosts has primary and secondary in this order
"""


def activate_dash_ha_primary(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    activate_scope_per_dut_modified = []
    for index, (name, data) in enumerate(activate_scope_per_dut):
        if name == "vdpu0_0:haset0_0":
            name = primary_vdpu_key
        if name == "vdpu1_0:haset0_0":
            name = standby_vdpu_key
        activate_scope_per_dut_modified.append((name, data))

    for index, (name, data) in enumerate(activate_scope_per_dut_modified):
        activate_scope_per_dut_modified[index][1]['owner'] = ha_owner

    for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut_modified):
        vdpu_id, ha_set_id = key.split(":", 1)
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

    for idx, (duthost, (key, fields)) in enumerate(zip(duthosts, activate_scope_per_dut_modified)):
        if duthost != duthosts[0]:
            continue
        pending_id = wait_for_pending_operation_id(
            duthost,
            scope_key=key,
            expected_op_type="activate_role",
            timeout=300,
            interval=2
        )
        assert pending_id, (
            f"Timed out waiting for active pending_operation_id "
            f"for {duthost.hostname} scope {key}"
        )

        logger.info(f"HA: {duthost.hostname} found pending id {pending_id}")
        vdpu_id, ha_set_id = key.split(":", 1)
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


def activate_dash_ha_standby(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    activate_scope_per_dut_modified = []
    for index, (name, data) in enumerate(activate_scope_per_dut):
        if name == "vdpu0_0:haset0_0":
            name = primary_vdpu_key
        if name == "vdpu1_0:haset0_0":
            name = standby_vdpu_key
        activate_scope_per_dut_modified.append((name, data))

    for index, (name, data) in enumerate(activate_scope_per_dut_modified):
        activate_scope_per_dut_modified[index][1]['owner'] = ha_owner

    for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut_modified):
        vdpu_id, ha_set_id = key.split(":", 1)
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

    for idx, (duthost, (key, fields)) in enumerate(zip(duthosts, activate_scope_per_dut_modified)):
        if duthost != duthosts[1]:
            continue
        pending_id = wait_for_pending_operation_id(
            duthost,
            scope_key=key,
            expected_op_type="activate_role",
            timeout=300,
            interval=2
        )
        assert pending_id, (
            f"Timed out waiting for active pending_operation_id "
            f"for {duthost.hostname} scope {key}"
        )

        logger.info(f"HA: {duthost.hostname} found pending id {pending_id}")
        vdpu_id, ha_set_id = key.split(":", 1)
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


def test_ha_launch_with_no_peer(request, duthosts, localhost, dpuhosts, ptfhost, setup_ha_config,
                                setup_dash_ha_from_json, ha_owner):

    logger.info("HA: activate only primary")
    activate_dash_ha_primary(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)

    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    pytest_assert(verify_ha_state(duthosts[0], scope_key=primary_vdpu_key, expected_state="standalone"),
                  "Primary HA state is not standalone")

    logger.info("HA: activate standby without primary")
    activate_dash_ha_standby(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"
    pytest_assert(verify_ha_state(duthosts[1], scope_key=standby_vdpu_key, expected_state="standalone"),
                  "Standby HA state is not standalone")
