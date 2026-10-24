"""VDM field planning, STATE_DB reads, and read-only validation."""

import logging
import math
import re
from collections import namedtuple

from tests.transceiver.attribute_parser.attribute_keys import VDM_ATTRIBUTES_KEY
from tests.transceiver.common.attribute_helpers import (
    LANE_NUM_PLACEHOLDER, MEDIA_LANE_MASK_KEY, OPERATIONAL_SUFFIX, THRESHOLD_SUFFIX,
    parse_min_max_range, resolve_breakout_lanes,
)
from tests.transceiver.common.db_helpers import (
    check_entry_freshness,
    parse_numeric,
    read_state_db_table_for_ports,
)

STATE_DB_REAL_VALUE_TABLE = "TRANSCEIVER_VDM_REAL_VALUE"
VDM_THRESHOLD_TABLES = (
    ("lowalarm", "TRANSCEIVER_VDM_LALARM_THRESHOLD"),
    ("lowwarning", "TRANSCEIVER_VDM_LWARN_THRESHOLD"),
    ("highwarning", "TRANSCEIVER_VDM_HWARN_THRESHOLD"),
    ("highalarm", "TRANSCEIVER_VDM_HALARM_THRESHOLD"),
)

logger = logging.getLogger(__name__)

HOST_LANE_MASK_KEY = "host_lane_mask"
VDM_BANK_0_MAX_LANE = 8

VdmMappedField = namedtuple("VdmMappedField", ("source_attr", "attr_value", "lane_domain"))
VdmLaneDomains = namedtuple("VdmLaneDomains", ("media", "host", "data_path", "errors"))

MEDIA_QUANTITIES = {
    "laser_temperature_media",
    "esnr_media_input",
    "pam4_level_transition_media_input",
}
HOST_QUANTITIES = {
    "esnr_host_input",
    "pam4_level_transition_host_input",
}

DATA_PATH_QUANTITIES = {
    "biasxi", "biasxq", "biasxp", "biasyi", "biasyq", "biasyp",
    "cdshort", "cdlong", "dgd", "sopmd", "soproc", "pdl", "osnr", "esnr",
    "cfo", "txcurrpower", "rxtotpower", "rxsigpower",
}
for _metric in ("prefec_ber", "errored_frames"):
    for _kind in ("curr", "avg", "min", "max"):
        DATA_PATH_QUANTITIES.add("{}_{}_media_input".format(_metric, _kind))
        DATA_PATH_QUANTITIES.add("{}_{}_host_input".format(_metric, _kind))


def _map_vdm_attributes_to_fields(vdm_attrs, suffix, lane_domains):
    """Map one attribute family, preserving explicit-lane overrides."""
    expected_fields = {}
    errors = []
    for attr_name, attr_value in sorted(vdm_attrs.items()):
        if not attr_name.endswith(suffix):
            continue
        quantity = attr_name[:-len(suffix)]
        if quantity.endswith(LANE_NUM_PLACEHOLDER):
            quantity = quantity[:-len(LANE_NUM_PLACEHOLDER)]
            explicit_lane = None
        else:
            match = re.fullmatch(r"(.+?)(\d+)", quantity)
            if not match:
                errors.append("{} has no lane suffix".format(attr_name))
                continue
            quantity, explicit_lane = match.group(1), int(match.group(2))
        if quantity in MEDIA_QUANTITIES:
            domain = "media"
        elif quantity in HOST_QUANTITIES:
            domain = "host"
        elif quantity in DATA_PATH_QUANTITIES:
            domain = "data_path"
        else:
            errors.append("unknown VDM attribute {}".format(attr_name))
            continue
        lanes = getattr(lane_domains, domain)
        if explicit_lane is not None and explicit_lane not in lanes:
            errors.append("{} targets inactive lane {}".format(attr_name, explicit_lane))
            continue
        if explicit_lane is not None:
            lanes = [explicit_lane]
        for lane in lanes:
            field = "{}{}".format(quantity, lane)
            if explicit_lane is not None or field not in expected_fields:
                expected_fields[field] = VdmMappedField(attr_name, attr_value, domain)
    return expected_fields, errors


def resolve_vdm_lane_domains(
    primary_port,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Return media/host lanes and first-host-lane data-path anchors."""
    media = resolve_breakout_lanes(
        primary_port, port_attributes_dict,
        lport_to_first_subport_mapping, MEDIA_LANE_MASK_KEY,
    )
    host = resolve_breakout_lanes(
        primary_port, port_attributes_dict,
        lport_to_first_subport_mapping, HOST_LANE_MASK_KEY,
    )
    data_path_anchors = {min(lanes) for lanes in host.lanes_by_port.values() if lanes}
    errors = list(media.errors) + list(host.errors)

    for domain, lanes in (
        ("media", media.active_lanes),
        ("host", host.active_lanes),
        ("data_path", data_path_anchors),
    ):
        unsupported_lanes = sorted(lane for lane in lanes
                                   if lane > VDM_BANK_0_MAX_LANE)
        if unsupported_lanes:
            errors.append(
                "{} {} lane(s) {} exceed the current VDM Bank-0 "
                "limit {}".format(primary_port, domain, unsupported_lanes,
                                  VDM_BANK_0_MAX_LANE)
            )

    return VdmLaneDomains(
        media=media.active_lanes, host=host.active_lanes,
        data_path=sorted(data_path_anchors), errors=errors,
    )


def build_vdm_field_plan(
    port_attributes_dict, primary_ports, lport_to_first_subport_mapping,
):
    """Build reusable expected REAL_VALUE fields for each primary port."""
    plan_by_port = {}

    for port in primary_ports:
        lane_domains = resolve_vdm_lane_domains(
            port, port_attributes_dict, lport_to_first_subport_mapping,
        )
        errors = list(lane_domains.errors)
        vdm_attrs = port_attributes_dict[port][VDM_ATTRIBUTES_KEY]
        expected_fields, mapping_errors = _map_vdm_attributes_to_fields(
            vdm_attrs, OPERATIONAL_SUFFIX, lane_domains,
        )
        errors.extend(mapping_errors)

        if not expected_fields:
            errors.append("{} has no authored VDM fields".format(port))

        max_age_min = parse_numeric(vdm_attrs.get("data_max_age_min"))
        if "data_max_age_min" not in vdm_attrs:
            errors.append("{} missing data_max_age_min in {}".format(port, VDM_ATTRIBUTES_KEY))
        elif max_age_min is None or not math.isfinite(max_age_min) or max_age_min <= 0:
            errors.append(
                "{} has invalid data_max_age_min {}; expected a finite positive number".format(
                    port, vdm_attrs.get("data_max_age_min"),
                )
            )

        plan_by_port[port] = {
            "expected_fields": expected_fields,
            "lane_domains": lane_domains,
            "errors": errors,
            "max_age_min": max_age_min,
        }

    return plan_by_port


def read_vdm_real_values(duthost, ports):
    """Return current VDM REAL_VALUE rows for the requested ports."""
    return read_state_db_table_for_ports(duthost, ports, STATE_DB_REAL_VALUE_TABLE)


def validate_vdm_availability(
    duthost, primary_ports, non_primary_ports, rows, plan_by_port, now_utc=None,
):
    """Validate TC1 freshness, fields, and primary-only publication."""
    failures = []
    checked_fields = 0

    for port in primary_ports:
        plan = plan_by_port[port]
        expected_fields = plan["expected_fields"]
        port_failures = list(plan["errors"])
        row = rows.get(port)
        if row is not None:
            if not row:
                port_failures.append("REAL_VALUE row is missing")
            else:
                if plan["max_age_min"] is not None:
                    if now_utc is None:
                        now_utc = duthost.get_now_time(utc_timezone=True)
                    freshness = check_entry_freshness(
                        row, plan["max_age_min"], now_utc, table_name=STATE_DB_REAL_VALUE_TABLE,
                    )
                    port_failures.extend(freshness["failures"])
                for field, mapped_field in expected_fields.items():
                    value = parse_numeric(row.get(field))
                    if value is None or not math.isfinite(value):
                        port_failures.append(
                            "{} from {} is missing or non-numeric (raw={})".format(
                                field, mapped_field.source_attr, row.get(field),
                            )
                        )
                    else:
                        checked_fields += 1
        if port_failures:
            failures.append("{}:\n  {}".format(port, "\n  ".join(port_failures)))

    for port in non_primary_ports:
        if rows.get(port):
            failures.append(
                "{}: non-primary subport unexpectedly publishes {}".format(
                    port, STATE_DB_REAL_VALUE_TABLE,
                )
            )
    return failures, checked_fields


def validate_vdm_operational_ranges(duthost, primary_ports, rows, plan_by_port, now_utc=None):
    """Validate availability, freshness, and inclusive authored ranges."""
    failures, _ = validate_vdm_availability(
        duthost, primary_ports, [], rows, plan_by_port, now_utc=now_utc,
    )
    checked_fields = 0
    for port in primary_ports:
        row = rows.get(port)
        if row is None:
            failures.append("{}: could not read {} (namespace read failed)".format(
                port, STATE_DB_REAL_VALUE_TABLE,
            ))
        for field, mapped in plan_by_port[port]["expected_fields"].items():
            context = "{}: {} from {} ({} domain)".format(
                port, field, mapped.source_attr, mapped.lane_domain,
            )
            low, high, range_error = parse_min_max_range(mapped, attribute_key=VDM_ATTRIBUTES_KEY)
            if range_error:
                failures.append("{}: {}".format(context, range_error))
                continue
            value = parse_numeric(row.get(field)) if row else None
            if value is None or not math.isfinite(value):
                continue
            checked_fields += 1
            if not low <= value <= high:
                failures.append("{} actual={} (raw={!r}) outside expected [{}, {}]".format(
                    context, value, row[field], low, high,
                ))
    return failures, checked_fields


def build_vdm_threshold_plan(port_attributes_dict, primary_ports, field_plan):
    """Attach optional equality expectations to operational-range fields."""
    plans = {}
    for port in primary_ports:
        plan = field_plan[port]
        threshold_fields, errors = _map_vdm_attributes_to_fields(
            port_attributes_dict[port][VDM_ATTRIBUTES_KEY],
            THRESHOLD_SUFFIX, plan["lane_domains"],
        )
        plans[port] = {
            "expected_fields": plan["expected_fields"],
            "threshold_fields": {
                field: mapped for field, mapped in threshold_fields.items()
                if field in plan["expected_fields"]
            },
            "errors": list(plan["errors"]) + errors,
        }
    return plans


def read_vdm_thresholds(duthost, ports):
    """Dump each threshold table once per namespace."""
    ports = list(ports)
    rows_by_severity = {}
    errors = []
    for severity, table in VDM_THRESHOLD_TABLES:
        rows_by_severity[severity], table_errors = read_state_db_table_for_ports(duthost, ports, table)
        errors.extend(table_errors)
    return rows_by_severity, errors


def _parse_vdm_threshold_range(mapped):
    """Require finite configured values for every threshold severity."""
    values = mapped.attr_value
    if not isinstance(values, dict):
        return {}, ["{} must define a severity dict (raw={!r})".format(mapped.source_attr, values)]
    thresholds = {}
    errors = []
    known_severities = {severity for severity, _ in VDM_THRESHOLD_TABLES}
    for severity in sorted(set(values) - known_severities):
        errors.append("{} has unknown severity {}".format(mapped.source_attr, severity))
    for severity, _ in VDM_THRESHOLD_TABLES:
        raw_value = values.get(severity)
        value = parse_numeric(raw_value)
        if value is None or not math.isfinite(value):
            errors.append("{} has missing/non-finite numeric value {}={!r}".format(
                mapped.source_attr, severity, raw_value,
            ))
        else:
            thresholds[severity] = value
    return ({}, errors) if errors else (thresholds, [])


def validate_vdm_thresholds(primary_ports, rows_by_severity, plan_by_port):
    """Require all keys, order numeric severities, and compare authored values exactly."""
    failures = []
    checked_fields = 0
    equality_checks = 0
    for port in primary_ports:
        plan = plan_by_port[port]
        port_failures = list(plan["errors"])
        for severity, table in VDM_THRESHOLD_TABLES:
            row = rows_by_severity[severity].get(port)
            if row is None:
                port_failures.append("{} ({}): namespace read failed".format(table, severity))
            elif not row:
                port_failures.append("{} ({}): port row is missing".format(table, severity))
        for field, mapped in plan["expected_fields"].items():
            numeric = {}
            represented = 0
            for severity, table in VDM_THRESHOLD_TABLES:
                row = rows_by_severity[severity].get(port)
                if not row:
                    continue
                raw_value = row.get(field)
                context = "{} ({}) {} from {} (raw={!r})".format(
                    table, severity, field, mapped.source_attr, raw_value,
                )
                if field not in row:
                    port_failures.append("{}: field is missing".format(context))
                elif isinstance(raw_value, str) and raw_value.strip().upper() == "N/A":
                    represented += 1
                else:
                    value = parse_numeric(raw_value)
                    if value is None or not math.isfinite(value):
                        port_failures.append("{}: expected finite numeric value or N/A".format(context))
                    else:
                        numeric[severity] = value
                        represented += 1
            if represented == len(VDM_THRESHOLD_TABLES):
                checked_fields += 1
                if len(numeric) < 2:
                    logger.warning(
                        "%s %s from %s: reduced threshold hierarchy coverage (%d numeric severities)",
                        port, field, mapped.source_attr, len(numeric),
                    )
            ordered = [(severity, numeric[severity]) for severity, _ in VDM_THRESHOLD_TABLES if severity in numeric]
            for (low_name, low), (high_name, high) in zip(ordered, ordered[1:]):
                if low >= high:
                    port_failures.append(
                        "{} from {}: invalid hierarchy {}={} >= {}={} (tables {}, {})".format(
                            field, mapped.source_attr, low_name, low, high_name, high,
                            dict(VDM_THRESHOLD_TABLES)[low_name], dict(VDM_THRESHOLD_TABLES)[high_name],
                        )
                    )
            equality = plan["threshold_fields"].get(field)
            if equality is None:
                continue
            expected_values, config_errors = _parse_vdm_threshold_range(equality)
            port_failures.extend("{}: {}".format(field, error) for error in config_errors)
            for severity, expected in expected_values.items():
                row = rows_by_severity[severity].get(port)
                raw_value = row.get(field) if row else None
                context = "{} ({}) {} from {} (raw={!r}, expected={})".format(
                    dict(VDM_THRESHOLD_TABLES)[severity], severity, field,
                    equality.source_attr, raw_value, expected,
                )
                if severity not in numeric:
                    port_failures.append("{}: authored threshold requires a finite numeric live value".format(context))
                else:
                    equality_checks += 1
                    if numeric[severity] != expected:
                        port_failures.append("{}: threshold equality mismatch (tolerance=0)".format(context))
        failures.extend("{}: {}".format(port, error) for error in port_failures)
    return failures, checked_fields, equality_checks
