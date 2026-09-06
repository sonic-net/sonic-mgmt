"""Advanced DOM TC1: validate DOM state across interface shutdown/startup."""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    DOM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.topology import resolve_remote_peer
from tests.transceiver.dom.dom_helpers import (
    active_lanes_from_group_mask,
    build_dom_sensor_plan,
    build_dom_deviation_checks,
    dom_field_available,
    dom_field_in_operational_range,
    dom_rx_power_flag_candidates,
    dom_tx_los_hostlane_candidates,
    format_dom_port_failure,
    max_system_wait,
    parse_required_number,
    parse_required_positive_int,
    ports_for_primary,
    read_dom_interface_state_tables,
    validate_appl_port_down_time,
    validate_dom_baseline_flags,
    validate_dom_deviation_checks,
    validate_dom_flag_lifecycle,
    validate_dom_plan_fields,
    validate_sensor_below_threshold,
    validate_sensor_freshness_after,
    validate_sensor_operational_fields,
    wait_for_dom_sensor_update,
)

logger = logging.getLogger(__name__)

HOST_LANE_MASK_KEY = "host_lane_mask"
SHUTDOWN_TX_BIAS_ATTR = "shutdown_tx_bias_threshold"
SHUTDOWN_TX_POWER_ATTR = "shutdown_tx_power_threshold"
SHUTDOWN_RX_POWER_ATTR = "shutdown_rx_power_threshold"
MAX_UPDATE_TIME_ATTR = "max_update_time_sec"
LOCAL_DEVIATION_ATTRS = (
    "voltage_deviation_range",
    "laser_temperature_deviation_range",
    "txLANE_NUMbias_deviation_range",
    "txLANE_NUMpower_deviation_range",
)
REMOTE_DEVIATION_ATTRS = ("rxLANE_NUMpower_deviation_range",)
LOCAL_SHUTDOWN_OPERATIONAL_FIELDS = ("temperature", "voltage")
DOM_UPDATE_MARGIN_SEC = 30


def _validate_local_shutdown(context, baseline_tables, shutdown_tables, shutdown_time):
    """Return failures for local DOM shutdown state."""
    local_port = context["local_port"]
    sensor_data = shutdown_tables["sensor"].get(local_port)
    plan = context["local_plan"]
    failures = []

    failures.extend(
        validate_sensor_freshness_after(
            context["duthost"],
            local_port,
            sensor_data,
            plan.get("max_age_min"),
            shutdown_time,
            "local shutdown",
        )
    )
    if not isinstance(sensor_data, dict) or not sensor_data:
        return failures

    for lane in plan["active_media_lanes"]:
        failures.extend(
            validate_sensor_below_threshold(
                local_port,
                sensor_data,
                "tx{}bias".format(lane),
                context["shutdown_tx_bias_threshold"],
                "local shutdown",
            )
        )
        failures.extend(
            validate_sensor_below_threshold(
                local_port,
                sensor_data,
                "tx{}power".format(lane),
                context["shutdown_tx_power_threshold"],
                "local shutdown",
            )
        )

    op_failures, _checked = validate_sensor_operational_fields(
        local_port,
        sensor_data,
        plan.get("expected_fields", {}),
        lambda field: field in LOCAL_SHUTDOWN_OPERATIONAL_FIELDS,
        "local shutdown",
    )
    failures.extend(op_failures)

    for lane in context["active_host_lanes"]:
        failures.extend(
            validate_dom_flag_lifecycle(
                local_port,
                dom_tx_los_hostlane_candidates(lane),
                baseline_tables,
                shutdown_tables,
                "status",
                True,
                "set",
                shutdown_time,
                require_clear_time_unchanged=True,
            )
        )

    baseline_appl = baseline_tables["appl_port"]
    shutdown_appl = shutdown_tables["appl_port"]
    for port in context["toggle_ports"]:
        failures.extend(
            validate_appl_port_down_time(
                port,
                baseline_appl.get(port),
                shutdown_appl.get(port),
                shutdown_time,
            )
        )

    return failures


def _validate_remote_shutdown(context, baseline_tables, shutdown_tables, shutdown_time):
    """Return failures for remote DOM link-down state."""
    remote_port = context["remote"].primary_port
    sensor_data = shutdown_tables["sensor"].get(remote_port)
    plan = context["remote_plan"]
    failures = []

    failures.extend(
        validate_sensor_freshness_after(
            context["remote"].host,
            remote_port,
            sensor_data,
            plan.get("max_age_min"),
            shutdown_time,
            "remote shutdown",
        )
    )
    if not isinstance(sensor_data, dict) or not sensor_data:
        return failures

    for lane in plan["active_media_lanes"]:
        failures.extend(
            validate_sensor_below_threshold(
                remote_port,
                sensor_data,
                "rx{}power".format(lane),
                context["shutdown_rx_power_threshold"],
                "remote shutdown",
            )
        )
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(
                validate_dom_flag_lifecycle(
                    remote_port,
                    dom_rx_power_flag_candidates(lane, suffix),
                    baseline_tables,
                    shutdown_tables,
                    "dom",
                    True,
                    "set",
                    shutdown_time,
                )
            )

    return failures


def _validate_local_startup(context, baseline_tables, startup_tables, startup_time):
    """Return failures for local DOM recovery after startup."""
    local_port = context["local_port"]
    sensor_data = startup_tables["sensor"].get(local_port)
    plan = context["local_plan"]
    failures = []

    field_failures, _checked_fields, _checked_ports = validate_dom_plan_fields(
        context["duthost"],
        [local_port],
        startup_tables["sensor"],
        {local_port: plan},
        dom_field_in_operational_range,
    )
    failures.extend(field_failures)
    failures.extend(
        validate_sensor_freshness_after(
            context["duthost"],
            local_port,
            sensor_data,
            plan.get("max_age_min"),
            startup_time,
            "local startup",
        )
    )

    for lane in context["active_host_lanes"]:
        failures.extend(
            validate_dom_flag_lifecycle(
                local_port,
                dom_tx_los_hostlane_candidates(lane),
                baseline_tables,
                startup_tables,
                "status",
                False,
                "clear",
                startup_time,
            )
        )

    deviation_failures, checked_count = validate_dom_deviation_checks(
        local_port,
        baseline_tables["sensor"].get(local_port, {}),
        sensor_data or {},
        context["local_deviation_checks"],
        "local startup",
    )
    failures.extend(deviation_failures)
    if checked_count:
        logger.info("DOM interface-state local deviation checks passed for %s: %d field(s)",
                    local_port, checked_count)
    return failures


def _validate_remote_startup(context, baseline_tables, startup_tables, startup_time):
    """Return failures for remote DOM recovery after startup."""
    remote_port = context["remote"].primary_port
    sensor_data = startup_tables["sensor"].get(remote_port)
    plan = context["remote_plan"]
    failures = []

    failures.extend(
        validate_sensor_freshness_after(
            context["remote"].host,
            remote_port,
            sensor_data,
            plan.get("max_age_min"),
            startup_time,
            "remote startup",
        )
    )
    if isinstance(sensor_data, dict) and sensor_data:
        op_failures, checked = validate_sensor_operational_fields(
            remote_port,
            sensor_data,
            plan.get("expected_fields", {}),
            lambda field: field.startswith("rx") and field.endswith("power"),
            "remote startup",
        )
        failures.extend(op_failures)
        if not checked:
            failures.append("remote startup no configured RX power operational field was checked")

    for lane in plan["active_media_lanes"]:
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(
                validate_dom_flag_lifecycle(
                    remote_port,
                    dom_rx_power_flag_candidates(lane, suffix),
                    baseline_tables,
                    startup_tables,
                    "dom",
                    False,
                    "clear",
                    startup_time,
                )
            )

    deviation_failures, checked_count = validate_dom_deviation_checks(
        remote_port,
        baseline_tables["sensor"].get(remote_port, {}),
        sensor_data or {},
        context["remote_deviation_checks"],
        "remote startup",
    )
    failures.extend(deviation_failures)
    if checked_count:
        logger.info("DOM interface-state remote deviation checks passed for %s: %d field(s)",
                    remote_port, checked_count)
    return failures


def _validate_baseline(context, local_tables, remote_tables):
    """Return failures for pre-disruption local and remote baseline state."""
    local_port = context["local_port"]
    remote_port = context["remote"].primary_port
    failures = []

    local_failures, _checked_fields, _checked_ports = validate_dom_plan_fields(
        context["duthost"],
        [local_port],
        local_tables["sensor"],
        {local_port: context["local_plan"]},
        dom_field_available,
        include_freshness_only=True,
    )
    failures.extend(local_failures)

    remote_failures, _checked_fields, _checked_ports = validate_dom_plan_fields(
        context["remote"].host,
        [remote_port],
        remote_tables["sensor"],
        {remote_port: context["remote_plan"]},
        dom_field_available,
        include_freshness_only=True,
    )
    failures.extend(remote_failures)
    local_flag_failures = validate_dom_baseline_flags(
        local_port,
        local_tables,
        context["active_host_lanes"],
        [],
    )
    if local_flag_failures:
        failures.append(
            format_dom_port_failure(
                local_port,
                context["active_host_lanes"],
                {},
                local_flag_failures,
                field_label="baseline local flag(s)",
            )
        )

    remote_flag_failures = validate_dom_baseline_flags(
        remote_port,
        remote_tables,
        [],
        context["remote_plan"]["active_media_lanes"],
    )
    if remote_flag_failures:
        failures.append(
            format_dom_port_failure(
                remote_port,
                context["remote_plan"]["active_media_lanes"],
                {},
                remote_flag_failures,
                field_label="baseline remote flag(s)",
            )
        )
    return failures


def _operation_context(duthost, duthosts, conn_graph_facts, local_port,
                       port_attributes_dict, lport_to_first_subport_mapping):
    """Return ``(context, errors)`` for one local primary port under test."""
    errors = []
    remote, error = resolve_remote_peer(
        duthost,
        duthosts,
        conn_graph_facts,
        local_port,
        lport_to_first_subport_mapping,
    )
    if error:
        return None, [error]

    if remote.primary_port not in port_attributes_dict:
        return None, [
            "{} peer port {} is not present in port_attributes_dict".format(local_port, remote.primary_port)
        ]

    toggle_ports = ports_for_primary(local_port, port_attributes_dict, lport_to_first_subport_mapping)
    if remote.host == duthost and remote.primary_port in toggle_ports:
        return None, [
            "{} remote peer {} overlaps local shutdown group {}".format(
                local_port,
                remote.primary_port,
                toggle_ports,
            )
        ]

    local_plan = build_dom_sensor_plan(
        port_attributes_dict,
        [local_port],
        lport_to_first_subport_mapping,
    )[local_port]
    remote_plan = build_dom_sensor_plan(
        port_attributes_dict,
        [remote.primary_port],
        lport_to_first_subport_mapping,
    )[remote.primary_port]
    active_host_lanes, host_lane_errors = active_lanes_from_group_mask(
        local_port,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        HOST_LANE_MASK_KEY,
    )
    errors.extend(host_lane_errors)
    if not active_host_lanes:
        errors.append("{} no active host lanes resolved".format(local_port))

    local_dom_attrs = port_attributes_dict[local_port].get(DOM_ATTRIBUTES_KEY, {})
    remote_dom_attrs = port_attributes_dict[remote.primary_port].get(DOM_ATTRIBUTES_KEY, {})
    local_deviation_checks, deviation_errors = build_dom_deviation_checks(
        local_dom_attrs,
        local_plan["active_media_lanes"],
        LOCAL_DEVIATION_ATTRS,
    )
    errors.extend(deviation_errors)
    remote_deviation_checks, deviation_errors = build_dom_deviation_checks(
        remote_dom_attrs,
        remote_plan["active_media_lanes"],
        REMOTE_DEVIATION_ATTRS,
    )
    errors.extend(deviation_errors)

    parsed_attrs = {}
    for attr_name in (SHUTDOWN_TX_BIAS_ATTR, SHUTDOWN_TX_POWER_ATTR):
        parsed_attrs[attr_name], error = parse_required_number(local_dom_attrs, attr_name)
        if error:
            errors.append("{} {}".format(local_port, error))
    parsed_attrs[SHUTDOWN_RX_POWER_ATTR], error = parse_required_number(remote_dom_attrs, SHUTDOWN_RX_POWER_ATTR)
    if error:
        errors.append("{} {}".format(remote.primary_port, error))

    local_update_time, error = parse_required_positive_int(
        local_dom_attrs,
        MAX_UPDATE_TIME_ATTR,
        minimum=1,
    )
    if error:
        errors.append("{} {}".format(local_port, error))
    remote_update_time, error = parse_required_positive_int(
        remote_dom_attrs,
        MAX_UPDATE_TIME_ATTR,
        minimum=1,
    )
    if error:
        errors.append("{} {}".format(remote.primary_port, error))

    shutdown_wait, wait_errors = max_system_wait(
        port_attributes_dict,
        toggle_ports,
        "port_shutdown_wait_sec",
    )
    errors.extend(wait_errors)
    startup_wait, wait_errors = max_system_wait(
        port_attributes_dict,
        toggle_ports,
        "port_startup_wait_sec",
    )
    errors.extend(wait_errors)

    if errors:
        return None, errors

    shutdown_wait = scenario_ops.scale_bulk_wait(shutdown_wait, len(toggle_ports))
    startup_wait = scenario_ops.scale_bulk_wait(startup_wait, len(toggle_ports))
    dom_update_wait = max(local_update_time, remote_update_time) + DOM_UPDATE_MARGIN_SEC

    return {
        "duthost": duthost,
        "local_port": local_port,
        "remote": remote,
        "toggle_ports": toggle_ports,
        "local_plan": local_plan,
        "remote_plan": remote_plan,
        "active_host_lanes": active_host_lanes,
        "shutdown_tx_bias_threshold": parsed_attrs[SHUTDOWN_TX_BIAS_ATTR],
        "shutdown_tx_power_threshold": parsed_attrs[SHUTDOWN_TX_POWER_ATTR],
        "shutdown_rx_power_threshold": parsed_attrs[SHUTDOWN_RX_POWER_ATTR],
        "local_deviation_checks": local_deviation_checks,
        "remote_deviation_checks": remote_deviation_checks,
        "shutdown_wait": shutdown_wait,
        "startup_wait": startup_wait,
        "dom_update_wait": dom_update_wait,
    }, []


def _exercise_port(context, baseline_local_tables, baseline_remote_tables):
    """Run shutdown/startup for one port context and return aggregate failures."""
    local_port = context["local_port"]
    remote_port = context["remote"].primary_port
    failures = []
    touched_ports = list(context["toggle_ports"])

    logger.info(
        "DOM Advanced TC1: %s -> peer %s:%s, toggling %s "
        "(shutdown_wait=%ss startup_wait=%ss dom_update_wait=%ss)",
        local_port,
        context["remote"].device,
        context["remote"].port,
        touched_ports,
        context["shutdown_wait"],
        context["startup_wait"],
        context["dom_update_wait"],
    )

    try:
        shutdown_time = context["duthost"].get_now_time(utc_timezone=True)
        failures.extend(
            scenario_ops.perform_ports_shutdown(
                context["duthost"],
                touched_ports,
                context["shutdown_wait"],
            )
        )
        local_sensor, update_failures = wait_for_dom_sensor_update(
            context["duthost"],
            [local_port],
            shutdown_time,
            context["dom_update_wait"],
            "local shutdown",
        )
        failures.extend(update_failures)
        remote_sensor, update_failures = wait_for_dom_sensor_update(
            context["remote"].host,
            [remote_port],
            shutdown_time,
            context["dom_update_wait"],
            "remote shutdown",
        )
        failures.extend(update_failures)
        shutdown_local_tables, read_failures = read_dom_interface_state_tables(
            context["duthost"],
            [local_port] + touched_ports,
            include_appl_port=True,
        )
        failures.extend(read_failures)
        shutdown_remote_tables, read_failures = read_dom_interface_state_tables(
            context["remote"].host,
            [remote_port],
            include_appl_port=False,
        )
        failures.extend(read_failures)
        shutdown_local_tables["sensor"].update(local_sensor)
        shutdown_remote_tables["sensor"].update(remote_sensor)

        failures.extend(
            _validate_local_shutdown(
                context,
                baseline_local_tables,
                shutdown_local_tables,
                shutdown_time,
            )
        )
        failures.extend(
            _validate_remote_shutdown(
                context,
                baseline_remote_tables,
                shutdown_remote_tables,
                shutdown_time,
            )
        )

        startup_time = context["duthost"].get_now_time(utc_timezone=True)
        failures.extend(
            scenario_ops.perform_ports_startup(
                context["duthost"],
                touched_ports,
                context["startup_wait"],
            )
        )
        local_sensor, update_failures = wait_for_dom_sensor_update(
            context["duthost"],
            [local_port],
            startup_time,
            context["dom_update_wait"],
            "local startup",
        )
        failures.extend(update_failures)
        remote_sensor, update_failures = wait_for_dom_sensor_update(
            context["remote"].host,
            [remote_port],
            startup_time,
            context["dom_update_wait"],
            "remote startup",
        )
        failures.extend(update_failures)
        startup_local_tables, read_failures = read_dom_interface_state_tables(
            context["duthost"],
            [local_port],
            include_appl_port=False,
        )
        failures.extend(read_failures)
        startup_remote_tables, read_failures = read_dom_interface_state_tables(
            context["remote"].host,
            [remote_port],
            include_appl_port=False,
        )
        failures.extend(read_failures)
        startup_local_tables["sensor"].update(local_sensor)
        startup_remote_tables["sensor"].update(remote_sensor)

        failures.extend(
            _validate_local_startup(
                context,
                baseline_local_tables,
                startup_local_tables,
                startup_time,
            )
        )
        failures.extend(
            _validate_remote_startup(
                context,
                baseline_remote_tables,
                startup_remote_tables,
                startup_time,
            )
        )
    finally:
        restore_failures = scenario_ops.perform_ports_startup(
            context["duthost"],
            touched_ports,
            context["startup_wait"],
        )
        failures.extend("teardown: {}".format(failure) for failure in restore_failures)

    return failures


def test_dom_data_during_interface_state_changes(
    duthost,
    duthosts,
    conn_graph_facts,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify local and remote DOM state transitions across shut/no-shut."""
    all_failures = []
    checked_port_count = 0

    for local_port in dom_primary_ports:
        context, config_errors = _operation_context(
            duthost,
            duthosts,
            conn_graph_facts,
            local_port,
            port_attributes_dict,
            lport_to_first_subport_mapping,
        )
        if config_errors:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    [],
                    {},
                    config_errors,
                    field_label="advanced interface-state configuration item(s)",
                    include_lanes=False,
                )
            )
            continue

        baseline_local_tables, read_failures = read_dom_interface_state_tables(
            duthost,
            [local_port] + context["toggle_ports"],
            include_appl_port=True,
        )
        baseline_remote_tables, remote_read_failures = read_dom_interface_state_tables(
            context["remote"].host,
            [context["remote"].primary_port],
            include_appl_port=False,
        )
        read_failures.extend(remote_read_failures)
        if read_failures:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    context["local_plan"]["active_media_lanes"],
                    context["local_plan"]["expected_fields"],
                    read_failures,
                    field_label="baseline read item(s)",
                )
            )
            continue

        baseline_failures = _validate_baseline(context, baseline_local_tables, baseline_remote_tables)
        if baseline_failures:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    context["local_plan"]["active_media_lanes"],
                    context["local_plan"]["expected_fields"],
                    baseline_failures,
                    field_label="baseline validation item(s)",
                )
            )
            continue

        port_failures = _exercise_port(context, baseline_local_tables, baseline_remote_tables)
        if port_failures:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    context["local_plan"]["active_media_lanes"],
                    context["local_plan"]["expected_fields"],
                    port_failures,
                    field_label="advanced interface-state check(s)",
                )
            )
            continue

        checked_port_count += 1

    if all_failures:
        pytest.fail("DOM interface-state validation failures:\n" + "\n".join(all_failures))

    if not checked_port_count:
        pytest.skip("No DOM interface-state checks executed")

    logger.info("DOM interface-state validation passed for %d primary port(s)", checked_port_count)
