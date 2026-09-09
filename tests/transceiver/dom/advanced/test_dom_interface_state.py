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


def _operation_context(
    duthost,
    duthosts,
    conn_graph_facts,
    local_port,
    port_attributes_by_dut,
    lport_to_first_subport_mapping_by_dut,
):
    """Return ``(context, errors)`` for one local primary port under test."""
    errors = []
    local_port_attributes = port_attributes_by_dut.get(duthost.hostname)
    local_port_mapping = lport_to_first_subport_mapping_by_dut.get(duthost.hostname)
    if local_port_attributes is None or local_port_mapping is None:
        return None, ["{} has no transceiver attribute/mapping context".format(duthost.hostname)]

    remote, error = resolve_remote_peer(
        duthost,
        duthosts,
        conn_graph_facts,
        local_port,
        lport_to_first_subport_mapping_by_dut,
    )
    if error:
        return None, [error]

    remote_port_attributes = port_attributes_by_dut.get(remote.device)
    remote_port_mapping = lport_to_first_subport_mapping_by_dut.get(remote.device)
    if remote_port_attributes is None or remote_port_mapping is None:
        return None, ["{} peer DUT {} has no transceiver attribute/mapping context".format(
            local_port,
            remote.device,
        )]
    if remote.primary_port not in remote_port_attributes:
        return None, [
            "{} peer port {}:{} is not present in that DUT's port_attributes_dict".format(
                local_port,
                remote.device,
                remote.primary_port,
            )
        ]

    toggle_ports = ports_for_primary(local_port, local_port_attributes, local_port_mapping)
    if remote.device == duthost.hostname and remote.primary_port in toggle_ports:
        return None, [
            "{} remote peer {} overlaps local shutdown group {}".format(
                local_port,
                remote.primary_port,
                toggle_ports,
            )
        ]

    local_plan = build_dom_sensor_plan(
        local_port_attributes,
        [local_port],
        local_port_mapping,
    )[local_port]
    remote_plan = build_dom_sensor_plan(
        remote_port_attributes,
        [remote.primary_port],
        remote_port_mapping,
    )[remote.primary_port]
    active_host_lanes, host_lane_errors = active_lanes_from_group_mask(
        local_port,
        local_port_attributes,
        local_port_mapping,
        HOST_LANE_MASK_KEY,
    )
    errors.extend(host_lane_errors)
    if not active_host_lanes:
        errors.append("{} no active host lanes resolved".format(local_port))

    local_dom_attrs = local_port_attributes[local_port].get(DOM_ATTRIBUTES_KEY, {})
    remote_dom_attrs = remote_port_attributes[remote.primary_port].get(DOM_ATTRIBUTES_KEY, {})
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
        local_port_attributes,
        toggle_ports,
        "port_shutdown_wait_sec",
    )
    errors.extend(wait_errors)
    startup_wait, wait_errors = max_system_wait(
        local_port_attributes,
        toggle_ports,
        "port_startup_wait_sec",
    )
    errors.extend(wait_errors)

    if errors:
        return None, errors

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


def _contexts_conflict(left, right):
    """Return whether two contexts cannot be exercised in the same batch."""
    if set(left["toggle_ports"]).intersection(right["toggle_ports"]):
        return True

    for observer, toggled in ((left, right), (right, left)):
        remote = observer["remote"]
        if (
            remote.host.hostname == toggled["duthost"].hostname
            and remote.primary_port in toggled["toggle_ports"]
        ):
            return True
    return False


def _build_context_batches(contexts):
    """Greedily group contexts while keeping peer endpoints out of each batch."""
    batches = []
    for context in contexts:
        for batch in batches:
            if not any(_contexts_conflict(context, existing) for existing in batch):
                batch.append(context)
                break
        else:
            batches.append([context])
    return batches


def _add_host_ports(grouped, host, ports):
    entry = grouped.setdefault(host.hostname, {"host": host, "ports": []})
    for port in ports:
        if port not in entry["ports"]:
            entry["ports"].append(port)


def _batch_ports_by_host(contexts, include_toggle_ports):
    """Return unique local/remote ports grouped by the host that owns them."""
    grouped = {}
    for context in contexts:
        local_ports = context["toggle_ports"] if include_toggle_ports else [context["local_port"]]
        _add_host_ports(grouped, context["duthost"], local_ports)
        _add_host_ports(grouped, context["remote"].host, [context["remote"].primary_port])
    return grouped


def _read_batch_tables(contexts, include_local_appl_port):
    """Read one aggregate Advanced TC1 snapshot per participating host."""
    local_hostname = contexts[0]["duthost"].hostname
    tables_by_host = {}
    failures = []
    for hostname, entry in _batch_ports_by_host(contexts, include_toggle_ports=True).items():
        tables, read_failures = read_dom_interface_state_tables(
            entry["host"],
            entry["ports"],
            include_appl_port=include_local_appl_port and hostname == local_hostname,
        )
        tables_by_host[hostname] = tables
        failures.extend("{}: {}".format(hostname, failure) for failure in read_failures)
    return tables_by_host, failures


def _wait_for_batch_sensor_updates(contexts, operation_time, timeout_sec, label):
    """Wait once per host for all local and remote primary-port DOM updates."""
    sensor_by_host = {}
    failures = []
    for hostname, entry in _batch_ports_by_host(contexts, include_toggle_ports=False).items():
        sensor_by_port, update_failures = wait_for_dom_sensor_update(
            entry["host"],
            entry["ports"],
            operation_time,
            timeout_sec,
            "{} {}".format(hostname, label),
        )
        sensor_by_host[hostname] = sensor_by_port
        failures.extend(update_failures)
    return sensor_by_host, failures


def _merge_batch_sensor_updates(tables_by_host, sensor_by_host):
    for hostname, sensor_by_port in sensor_by_host.items():
        tables_by_host[hostname]["sensor"].update(sensor_by_port)


def _exercise_batch(contexts, baseline_tables_by_host):
    """Exercise one non-conflicting context batch and aggregate its failures."""
    duthost = contexts[0]["duthost"]
    touched_ports = []
    for context in contexts:
        for port in context["toggle_ports"]:
            if port not in touched_ports:
                touched_ports.append(port)

    shutdown_wait = scenario_ops.scale_bulk_wait(
        max(context["shutdown_wait"] for context in contexts),
        len(touched_ports),
    )
    startup_wait = scenario_ops.scale_bulk_wait(
        max(context["startup_wait"] for context in contexts),
        len(touched_ports),
    )
    dom_update_wait = max(context["dom_update_wait"] for context in contexts)
    failures_by_port = {context["local_port"]: [] for context in contexts}
    batch_failures = []

    logger.info(
        "DOM Advanced TC1 batch: local ports=%s, toggling=%s "
        "(shutdown_wait=%ss startup_wait=%ss dom_update_wait=%ss)",
        [context["local_port"] for context in contexts],
        touched_ports,
        shutdown_wait,
        startup_wait,
        dom_update_wait,
    )

    try:
        shutdown_time = duthost.get_now_time(utc_timezone=True)
        batch_failures.extend(
            scenario_ops.perform_ports_shutdown(duthost, touched_ports, shutdown_wait)
        )
        shutdown_sensor_by_host, update_failures = _wait_for_batch_sensor_updates(
            contexts,
            shutdown_time,
            dom_update_wait,
            "shutdown",
        )
        batch_failures.extend(update_failures)
        shutdown_tables_by_host, read_failures = _read_batch_tables(
            contexts,
            include_local_appl_port=True,
        )
        batch_failures.extend(read_failures)
        _merge_batch_sensor_updates(shutdown_tables_by_host, shutdown_sensor_by_host)

        for context in contexts:
            local_port = context["local_port"]
            failures_by_port[local_port].extend(
                _validate_local_shutdown(
                    context,
                    baseline_tables_by_host[duthost.hostname],
                    shutdown_tables_by_host[duthost.hostname],
                    shutdown_time,
                )
            )
            failures_by_port[local_port].extend(
                _validate_remote_shutdown(
                    context,
                    baseline_tables_by_host[context["remote"].device],
                    shutdown_tables_by_host[context["remote"].device],
                    shutdown_time,
                )
            )

        startup_time = duthost.get_now_time(utc_timezone=True)
        batch_failures.extend(
            scenario_ops.perform_ports_startup(duthost, touched_ports, startup_wait)
        )
        startup_sensor_by_host, update_failures = _wait_for_batch_sensor_updates(
            contexts,
            startup_time,
            dom_update_wait,
            "startup",
        )
        batch_failures.extend(update_failures)
        startup_tables_by_host, read_failures = _read_batch_tables(
            contexts,
            include_local_appl_port=False,
        )
        batch_failures.extend(read_failures)
        _merge_batch_sensor_updates(startup_tables_by_host, startup_sensor_by_host)

        for context in contexts:
            local_port = context["local_port"]
            failures_by_port[local_port].extend(
                _validate_local_startup(
                    context,
                    baseline_tables_by_host[duthost.hostname],
                    startup_tables_by_host[duthost.hostname],
                    startup_time,
                )
            )
            failures_by_port[local_port].extend(
                _validate_remote_startup(
                    context,
                    baseline_tables_by_host[context["remote"].device],
                    startup_tables_by_host[context["remote"].device],
                    startup_time,
                )
            )
    finally:
        restore_failures = scenario_ops.perform_ports_startup(duthost, touched_ports, startup_wait)
        batch_failures.extend("teardown: {}".format(failure) for failure in restore_failures)

    return failures_by_port, batch_failures


def _format_batch_failure(batch_index, contexts, failures):
    return "batch {} [local ports {}]:\n  {}".format(
        batch_index,
        [context["local_port"] for context in contexts],
        "\n  ".join(failures),
    )


def test_dom_data_during_interface_state_changes(
    duthost,
    duthosts,
    conn_graph_facts,
    dom_primary_ports,
    port_attributes_by_dut,
    lport_to_first_subport_mapping_by_dut,
):
    """Verify local and remote DOM state transitions across shut/no-shut."""
    all_failures = []
    checked_port_count = 0

    contexts = []
    for local_port in dom_primary_ports:
        context, config_errors = _operation_context(
            duthost,
            duthosts,
            conn_graph_facts,
            local_port,
            port_attributes_by_dut,
            lport_to_first_subport_mapping_by_dut,
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
        contexts.append(context)

    for batch_index, batch in enumerate(_build_context_batches(contexts), start=1):
        baseline_tables_by_host, read_failures = _read_batch_tables(
            batch,
            include_local_appl_port=True,
        )
        if read_failures:
            all_failures.append(_format_batch_failure(batch_index, batch, read_failures))
            continue

        ready_contexts = []
        for context in batch:
            local_port = context["local_port"]
            baseline_failures = _validate_baseline(
                context,
                baseline_tables_by_host[duthost.hostname],
                baseline_tables_by_host[context["remote"].device],
            )
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
            ready_contexts.append(context)

        if not ready_contexts:
            continue

        failures_by_port, batch_failures = _exercise_batch(
            ready_contexts,
            baseline_tables_by_host,
        )
        if batch_failures:
            all_failures.append(_format_batch_failure(batch_index, ready_contexts, batch_failures))

        for context in ready_contexts:
            local_port = context["local_port"]
            port_failures = failures_by_port[local_port]
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
            if not batch_failures:
                checked_port_count += 1

    if all_failures:
        pytest.fail("DOM interface-state validation failures:\n" + "\n".join(all_failures))

    if not checked_port_count:
        pytest.skip("No DOM interface-state checks executed")

    logger.info("DOM interface-state validation passed for %d primary port(s)", checked_port_count)
