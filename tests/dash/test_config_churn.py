# flake8: noqa: E231
import logging
import time

import configs.privatelink_config as pl
import pytest
from dash_api.eni_pb2 import EniMode, State
from dash_api.route_type_pb2 import RoutingType
from gnmi_utils import apply_messages

from tests.common import config_reload
from tests.common.dash_utils import apply_dash_configs
from tests.common.helpers.assertions import pytest_assert
from tests.dash.sairedis_utils import (get_sairedis_line_count,
                                       parse_sairedis_changes)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("smartswitch"), pytest.mark.skip_check_dut_health]


@pytest.fixture(autouse=True)
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    set_vxlan_udp_sport_range,
    # manually invoke setup_npu_dpu to ensure routes are added before DASH configs are programmed
    setup_npu_dpu,  # noqa: F811
):
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]

    # inbound routing not implemented in Pensando SAI yet, so skip route rule programming
    route_rule_configs = []
    if "pensando" not in dpuhost.facts["asic_type"]:
        route_rule_configs = [
            pl.VM_VNI_ROUTE_RULE_CONFIG,
            pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
        ]

    # ``apply_dash_configs`` buckets entries by DASH table name and applies
    # them in dependency order (see ``DashPhase`` in ``tests/common/dash_utils.py``):
    # GROUP_1 (APPLIANCE) -> GROUP_2 (ROUTING_TYPE/METER_POLICY/OUTBOUND_PORT_MAP/VNET) ->
    # GROUP_3 (METER_RULE) -> GROUP_4 (TUNNEL/OUTBOUND_PORT_MAP_RANGE/ENI/ROUTE_GROUP) ->
    # GROUP_5 (ROUTE_RULE/ROUTE/VNET_MAPPING) -> GROUP_6 (ENI_ROUTE).
    apply_dash_configs(
        localhost, duthost, ptfhost, dpuhost.dpu_index,
        pl.APPLIANCE_FNIC_CONFIG,
        pl.ROUTING_TYPE_PL_CONFIG,
        pl.ROUTING_TYPE_VNET_CONFIG,
        pl.VNET_CONFIG,
        pl.ROUTE_GROUP1_CONFIG,
        pl.METER_POLICY_V4_CONFIG,
        pl.PE_VNET_MAPPING_CONFIG,
        pl.PE_SUBNET_ROUTE_CONFIG,
        pl.VM_VNET_MAPPING_CONFIG,
        pl.VM_SUBNET_ROUTE_CONFIG,
        *route_rule_configs,
        pl.ENI_FNIC_CONFIG,
        pl.ENI_ROUTE_GROUP1_CONFIG,
    )

    yield

    # Route rule removal is broken so config reload to cleanup for now
    # https://github.com/sonic-net/sonic-buildimage/issues/23590
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


def test_route_bind_churn(localhost, duthost, ptfhost, dpuhosts, dpu_index):
    """
    Tests ENI route group binding churn
    1. Creates new route group with a route
    2. Binds ENI to new route group
    3. Deletes old route and route group
    """
    dpuhost = dpuhosts[dpu_index]

    start_line = get_sairedis_line_count(dpuhost)

    route_group2_config = {
        f"DASH_ROUTE_GROUP_TABLE:{pl.ROUTE_GROUP2}": {"guid": pl.ROUTE_GROUP2_GUID, "version": "rg_version"}
    }
    apply_messages(localhost, duthost, ptfhost, pl.VNET2_CONFIG, dpuhost.dpu_index)
    apply_messages(localhost, duthost, ptfhost, route_group2_config, dpuhost.dpu_index)

    pe_subnet_route_group2_config = {
        f"DASH_ROUTE_TABLE:{pl.ROUTE_GROUP2}:{pl.PE_CA_SUBNET}": {
            "routing_type": RoutingType.ROUTING_TYPE_VNET,
            "vnet": pl.VNET1,
            "metering_class_or": "2048",
            "metering_class_and": "4095",
        }
    }
    apply_messages(localhost, duthost, ptfhost, pe_subnet_route_group2_config, dpuhost.dpu_index)

    time.sleep(2)

    eni_route_group2_config = {f"DASH_ENI_ROUTE_TABLE:{pl.ENI_ID}": {"group_id": pl.ROUTE_GROUP2}}
    apply_messages(localhost, duthost, ptfhost, eni_route_group2_config, dpuhost.dpu_index)

    time.sleep(2)

    route_messages = {**pl.PE_SUBNET_ROUTE_CONFIG, **pl.VM_SUBNET_ROUTE_CONFIG}
    apply_messages(localhost, duthost, ptfhost, route_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    time.sleep(2)

    all_changes = parse_sairedis_changes(dpuhost, start_line)

    route_creates = [c for c in all_changes.created if c.object_type == "SAI_OBJECT_TYPE_OUTBOUND_ROUTING_ENTRY"]
    route_deletes = [c for c in all_changes.removed if c.object_type == "SAI_OBJECT_TYPE_OUTBOUND_ROUTING_ENTRY"]
    route_group_creates = [c for c in all_changes.created if c.object_type == "SAI_OBJECT_TYPE_OUTBOUND_ROUTING_GROUP"]
    route_group_deletes = [c for c in all_changes.removed if c.object_type == "SAI_OBJECT_TYPE_OUTBOUND_ROUTING_GROUP"]
    eni_changes = [c for c in all_changes.edited if c.object_type == "SAI_OBJECT_TYPE_ENI"]

    pytest_assert(
        len(route_creates) == 1,
        f"Expected exactly 1 route create for new route in ROUTE_GROUP2 but got {len(route_creates)}",
    )
    pytest_assert(
        len(route_deletes) == 2,
        f"Expected exactly 2 route deletes for old routes in ROUTE_GROUP1 but got {len(route_deletes)}",
    )
    pytest_assert(
        len(route_group_creates) == 1,
        f"Expected exactly 1 route group create for ROUTE_GROUP2 but got {len(route_group_creates)}",
    )
    pytest_assert(
        len(route_group_deletes) == 1,
        f"Expected exactly 1 route group delete for ROUTE_GROUP1 but got {len(route_group_deletes)}",
    )
    pytest_assert(
        len(eni_changes) == 1, f"Expected exactly 1 ENI edit for new route in ROUTE_GROUP2 but got {len(eni_changes)}"
    )


def test_vnet_map_churn(localhost, duthost, ptfhost, dpuhosts, dpu_index):
    """
    Test VNET mapping churn by:
    1. Remove existing VNET mapping
    2. Apply a different VNET mapping for the same destination IP with a different underlay IP
    """
    dpuhost = dpuhosts[dpu_index]

    # Record starting point for sairedis tracking
    start_line = get_sairedis_line_count(dpuhost)

    apply_messages(localhost, duthost, ptfhost, pl.PE_VNET_MAPPING_CONFIG, dpuhost.dpu_index, False)

    time.sleep(2)

    new_underlay_ip = "102.2.3.4"
    pe_vnet_mapping_config_v2 = {
        f"DASH_VNET_MAPPING_TABLE:{pl.VNET1}:{pl.PE_CA}": {
            "routing_type": RoutingType.ROUTING_TYPE_PRIVATELINK,
            "underlay_ip": new_underlay_ip,
            "overlay_sip_prefix": f"{pl.PL_OVERLAY_SIP}/{pl.PL_OVERLAY_SIP_MASK}",
            "overlay_dip_prefix": f"{pl.PL_OVERLAY_DIP}/{pl.PL_OVERLAY_DIP_MASK}",
            "metering_class_or": "1586",
        }
    }
    apply_messages(localhost, duthost, ptfhost, pe_vnet_mapping_config_v2, dpuhost.dpu_index)

    time.sleep(2)

    all_changes = parse_sairedis_changes(dpuhost, start_line)

    ca_to_pa_creates = [c for c in all_changes.created if c.object_type == "SAI_OBJECT_TYPE_OUTBOUND_CA_TO_PA_ENTRY"]
    ca_to_pa_removes = [c for c in all_changes.removed if c.object_type == "SAI_OBJECT_TYPE_OUTBOUND_CA_TO_PA_ENTRY"]

    pytest_assert(
        len(ca_to_pa_creates) == 1, f"Expected exactly 1 OUTBOUND_CA_TO_PA_ENTRY create, got {len(ca_to_pa_creates)}"
    )
    pytest_assert(
        len(ca_to_pa_removes) == 1, f"Expected exactly 1 OUTBOUND_CA_TO_PA_ENTRY remove, got {len(ca_to_pa_removes)}"
    )


def test_eni_churn(localhost, duthost, ptfhost, dpuhosts, dpu_index):
    """
    Test ENI churn by:
    1. Remove the ENI configuration programmed during test setup
    2. Program a new ENI with the same ID but a different underlay_ip value
    """
    dpuhost = dpuhosts[dpu_index]

    start_line = get_sairedis_line_count(dpuhost)

    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)

    if "pensando" not in dpuhost.facts["asic_type"]:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
        }
        logger.info(route_rule_messages)
        apply_messages(localhost, duthost, ptfhost, route_rule_messages, dpuhost.dpu_index, False)

    apply_messages(localhost, duthost, ptfhost, pl.ENI_FNIC_CONFIG, dpuhost.dpu_index, False)

    time.sleep(2)

    new_underlay_ip = "26.2.2.2"  # Different underlay IP from VM1_PA (25.1.1.1)
    eni_fnic_config_v2 = {
        f"DASH_ENI_TABLE:{pl.ENI_ID}": {
            "vnet": pl.VNET1,
            "underlay_ip": new_underlay_ip,
            "mac_address": pl.ENI_MAC,
            "eni_id": pl.ENI_ID2,
            "admin_state": State.STATE_ENABLED,
            "pl_underlay_sip": pl.APPLIANCE_VIP,
            "pl_sip_encoding": f"{pl.PL_ENCODING_IP}/{pl.PL_ENCODING_MASK}",
            "eni_mode": EniMode.MODE_FNIC,
            "trusted_vnis": [pl.VNET1_VNI],
        }
    }
    apply_messages(localhost, duthost, ptfhost, eni_fnic_config_v2, dpuhost.dpu_index)

    time.sleep(2)

    all_changes = parse_sairedis_changes(dpuhost, start_line)

    eni_creates = [c for c in all_changes.created if c.object_type == "SAI_OBJECT_TYPE_ENI"]
    eni_removes = [c for c in all_changes.removed if c.object_type == "SAI_OBJECT_TYPE_ENI"]

    pytest_assert(len(eni_creates) == 1, f"Expected exactly 1 ENI create, got {len(eni_creates)}")
    pytest_assert(len(eni_removes) == 1, f"Expected exactly 1 ENI remove, got {len(eni_removes)}")


def test_vnet_churn(localhost, duthost, ptfhost, dpuhosts, dpu_index):
    """
    Test VNET churn by:
    1. Remove dependencies on the VNET (ENI route group binding, ENI, routes, mappings)
    2. Remove the VNET configuration programmed during test setup
    3. Program a new VNET with the same ID but a different VNI value
    4. Restore the ENI and route group binding
    """
    dpuhost = dpuhosts[dpu_index]

    # Record starting point for sairedis tracking
    start_line = get_sairedis_line_count(dpuhost)

    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)

    if "pensando" not in dpuhost.facts["asic_type"]:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
        }
        logger.info(route_rule_messages)
        apply_messages(localhost, duthost, ptfhost, route_rule_messages, dpuhost.dpu_index, False)

    apply_messages(localhost, duthost, ptfhost, pl.ENI_FNIC_CONFIG, dpuhost.dpu_index, False)
    route_and_mapping_messages = {
        **pl.PE_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_VNET_MAPPING_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG,
    }
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.METER_POLICY_V4_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.VNET_CONFIG, dpuhost.dpu_index, False)

    time.sleep(2)

    new_vni = "3001"
    vnet_config_v2 = {f"DASH_VNET_TABLE:{pl.VNET1}": {"vni": new_vni, "guid": pl.VNET1_GUID}}
    eni_fnic_config_v2 = dict(pl.ENI_FNIC_CONFIG)  # deep copy to avoid modifying the original
    eni_key = list(eni_fnic_config_v2.keys())[0]
    # Update pl_sip_encoding to reflect the new VNI of 3001
    eni_fnic_config_v2[eni_key]["pl_sip_encoding"] = f"::b90b:64:ff71:0:0/{pl.PL_ENCODING_MASK}"

    apply_messages(localhost, duthost, ptfhost, vnet_config_v2, dpuhost.dpu_index)
    apply_messages(localhost, duthost, ptfhost, pl.ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)
    apply_messages(localhost, duthost, ptfhost, pl.METER_POLICY_V4_CONFIG, dpuhost.dpu_index)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)
    apply_messages(localhost, duthost, ptfhost, eni_fnic_config_v2, dpuhost.dpu_index)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    time.sleep(2)

    all_changes = parse_sairedis_changes(dpuhost, start_line)

    vnet_creates = [c for c in all_changes.created if c.object_type == "SAI_OBJECT_TYPE_VNET"]
    vnet_removes = [c for c in all_changes.removed if c.object_type == "SAI_OBJECT_TYPE_VNET"]
    eni_creates = [c for c in all_changes.created if c.object_type == "SAI_OBJECT_TYPE_ENI"]
    eni_removes = [c for c in all_changes.removed if c.object_type == "SAI_OBJECT_TYPE_ENI"]
    eni_changes = [c for c in all_changes.edited if c.object_type == "SAI_OBJECT_TYPE_ENI"]

    pytest_assert(len(vnet_creates) == 1, f"Expected exactly 1 VNET create, got {len(vnet_creates)}")
    pytest_assert(len(vnet_removes) == 1, f"Expected exactly 1 VNET remove, got {len(vnet_removes)}")
    pytest_assert(len(eni_creates) == 1, f"Expected exactly 1 ENI create, got {len(eni_creates)}")
    pytest_assert(len(eni_removes) == 1, f"Expected exactly 1 ENI remove, got {len(eni_removes)}")
    pytest_assert(len(eni_changes) == 2, f"Expected exactly 2 ENI edits, got {len(eni_changes)}")
