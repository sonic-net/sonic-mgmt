"""VDM availability field planning, STATE_DB reads, and validation."""

import math
from collections import defaultdict, namedtuple

from tests.transceiver.attribute_parser.attribute_keys import VDM_ATTRIBUTES_KEY
from tests.transceiver.common.db_helpers import (
    check_entry_freshness,
    get_state_db_table,
    parse_numeric,
    resolve_port_namespace,
)
from tests.transceiver.dom.dom_helpers import resolve_breakout_lanes

STATE_DB_REAL_VALUE_TABLE = "TRANSCEIVER_VDM_REAL_VALUE"

OPERATIONAL_SUFFIX = "_operational_range"

MEDIA_LANE_MASK_KEY = "media_lane_mask"
HOST_LANE_MASK_KEY = "host_lane_mask"
VDM_BANK_0_MAX_LANE = 8

VdmMappedField = namedtuple("VdmMappedField", ("source_attr", "attr_value"))

MEDIA_QUANTITIES = {
    "laser_temperature_media",
    "esnr_media_input",
    "pam4_level_transition_media_input",
}
HOST_QUANTITIES = {
    "esnr_host_input",
    "pam4_level_transition_host_input",
}
for _metric in ("prefec_ber", "errored_frames"):
    for _kind in ("curr", "avg", "min", "max"):
        MEDIA_QUANTITIES.add("{}_{}_media_input".format(_metric, _kind))
        HOST_QUANTITIES.add("{}_{}_host_input".format(_metric, _kind))

DATA_PATH_QUANTITIES = {
    "biasxi", "biasxq", "biasxp", "biasyi", "biasyq", "biasyp",
    "cdshort", "cdlong", "dgd", "sopmd", "soproc", "pdl", "osnr", "esnr",
    "cfo", "txcurrpower", "rxtotpower", "rxsigpower",
}


def resolve_vdm_lane_domains(
    primary_port,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Return module media/host lanes and first-lane data-path anchors."""
    media = resolve_breakout_lanes(
        primary_port, port_attributes_dict,
        lport_to_first_subport_mapping, MEDIA_LANE_MASK_KEY,
    )
    host = resolve_breakout_lanes(
        primary_port, port_attributes_dict,
        lport_to_first_subport_mapping, HOST_LANE_MASK_KEY,
    )
    data_path_anchors = {
        min(lanes) for lanes in media.lanes_by_port.values() if lanes
    }
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

    return {
        "media": media.active_lanes,
        "host": host.active_lanes,
        "data_path": sorted(data_path_anchors),
        "errors": errors,
    }


def build_vdm_field_plan(
    port_attributes_dict, primary_ports, lport_to_first_subport_mapping,
):
    """Build reusable expected REAL_VALUE fields for each primary port."""
    plan_by_port = {}

    for port in primary_ports:
        lane_domains = resolve_vdm_lane_domains(
            port, port_attributes_dict, lport_to_first_subport_mapping,
        )
        errors = list(lane_domains["errors"])
        expected_fields = {}
        vdm_attrs = port_attributes_dict[port][VDM_ATTRIBUTES_KEY]

        for attr_name, attr_value in sorted(vdm_attrs.items()):
            if not attr_name.endswith(OPERATIONAL_SUFFIX):
                continue
            quantity = attr_name[:-len(OPERATIONAL_SUFFIX)]
            if not quantity.endswith("LANE_NUM"):
                errors.append("{} has no LANE_NUM placeholder".format(attr_name))
                continue
            quantity = quantity[:-len("LANE_NUM")]
            if quantity in MEDIA_QUANTITIES:
                lanes = lane_domains["media"]
            elif quantity in HOST_QUANTITIES:
                lanes = lane_domains["host"]
            elif quantity in DATA_PATH_QUANTITIES:
                lanes = lane_domains["data_path"]
            else:
                errors.append("unknown VDM attribute {}".format(attr_name))
                continue
            for lane in lanes:
                field = "{}{}".format(quantity, lane)
                expected_fields[field] = VdmMappedField(attr_name, attr_value)

        if not expected_fields:
            errors.append("{} has no authored VDM fields".format(port))

        max_age_min = parse_numeric(vdm_attrs.get("data_max_age_min"))
        if max_age_min is None or not math.isfinite(max_age_min) or max_age_min <= 0:
            errors.append(
                "{} has invalid data_max_age_min {}; expected a finite positive number".format(
                    port, vdm_attrs.get("data_max_age_min")
                )
            )

        plan_by_port[port] = {
            "expected_fields": expected_fields,
            "lane_domains": lane_domains,
            "errors": errors,
            "max_age_min": max_age_min,
        }

    return plan_by_port


def _read_vdm_table_data(duthost, ports, table_name):
    """Return rows and errors from one VDM STATE_DB table."""
    ports = list(ports)
    table_data_by_port = {port: {} for port in ports}
    errors = []
    ports_by_namespace = defaultdict(list)

    for port in ports:
        ports_by_namespace[resolve_port_namespace(duthost, port)].append(port)

    for namespace, namespace_ports in ports_by_namespace.items():
        table_data, error = get_state_db_table(duthost, table_name, namespace=namespace)
        if error:
            errors.append(
                "{} namespace {} ({} port(s)): {}".format(
                    table_name, namespace or "default", len(namespace_ports), error,
                )
            )
            for port in namespace_ports:
                table_data_by_port[port] = None
            continue

        for port in namespace_ports:
            table_data_by_port[port] = table_data.get(port, {}) or {}

    return table_data_by_port, errors


def read_vdm_real_values(duthost, ports):
    """Return current VDM REAL_VALUE rows for the requested ports."""
    return _read_vdm_table_data(duthost, ports, STATE_DB_REAL_VALUE_TABLE)


def validate_vdm_availability(
    duthost, primary_ports, non_primary_ports, rows, plan_by_port,
):
    """Validate TC1 freshness, fields, and primary-only publication."""
    failures = []
    checked_fields = 0
    now_utc = duthost.get_now_time(utc_timezone=True)

    for port in primary_ports:
        plan = plan_by_port[port]
        expected_fields = plan["expected_fields"]
        port_failures = list(plan["errors"])
        row = rows.get(port)
        if row is not None:
            if not row:
                port_failures.append("REAL_VALUE row is missing")
            else:
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
