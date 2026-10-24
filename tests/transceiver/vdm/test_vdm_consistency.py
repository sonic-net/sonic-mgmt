"""VDM data consistency checks across polling cycles."""

import logging
import math
import re
import time
from collections import defaultdict

import pytest

from tests.transceiver.attribute_parser.attribute_keys import VDM_ATTRIBUTES_KEY
from tests.transceiver.common.attribute_helpers import parse_positive_int
from tests.transceiver.common.db_helpers import STATE_DB_UPDATE_TIME_FIELD, parse_numeric, parse_update_time
from tests.transceiver.vdm.vdm_helpers import (
    build_vdm_field_plan,
    read_vdm_real_values,
    validate_vdm_operational_ranges,
)

logger = logging.getLogger(__name__)

UPDATE_ADVANCE_MARGIN_SEC = 5
_STATISTIC_FIELD = re.compile(r"^(prefec_ber|errored_frames)_(min|avg|max|curr)_(media_input|host_input)(\d+)$")


def _build_vdm_consistency_plan(port_attributes_dict, primary_ports, field_plan):
    """Resolve timing and complete authored statistic families per primary."""
    plans = {}
    for port in primary_ports:
        attrs = port_attributes_dict[port][VDM_ATTRIBUTES_KEY]
        errors = list(field_plan[port]["errors"])
        count, count_error = parse_positive_int(
            "consistency_check_poll_count", attrs.get("consistency_check_poll_count"),
            minimum=2, attribute_key=VDM_ATTRIBUTES_KEY,
        )
        if count_error:
            errors.append(count_error)
        interval, interval_error = parse_positive_int(
            "max_update_time_sec", attrs.get("max_update_time_sec"),
            minimum=1, attribute_key=VDM_ATTRIBUTES_KEY,
        )
        if interval_error:
            errors.append(interval_error)
        families = defaultdict(dict)
        for field in field_plan[port]["expected_fields"]:
            match = _STATISTIC_FIELD.fullmatch(field)
            if match:
                metric, kind, side, lane = match.groups()
                families["{}_{}{}".format(metric, side, lane)][kind] = field
        complete_families = {}
        for family, fields in sorted(families.items()):
            if all(kind in fields for kind in ("min", "avg", "max")):
                complete_families[family] = fields
            elif set(fields) != {"curr"}:
                logger.warning(
                    "%s %s: reduced statistic coherence coverage; authored kinds=%s",
                    port, family, sorted(fields),
                )
        plans[port] = {
            "poll_count": count,
            "interval_sec": interval,
            "statistic_families": complete_families,
            "errors": errors,
        }
    return plans


def _collect_vdm_samples(duthost, primary_ports, consistency_plan):
    """Read a shared schedule; each primary consumes only its configured prefix."""
    sample_count = max(consistency_plan[port]["poll_count"] for port in primary_ports)
    interval_sec = max(consistency_plan[port]["interval_sec"] for port in primary_ports)
    samples_by_port = {port: [] for port in primary_ports}
    read_failures = []
    for index in range(sample_count):
        sample_ports = [port for port in primary_ports if index < consistency_plan[port]["poll_count"]]
        rows, errors = read_vdm_real_values(duthost, sample_ports)
        now_utc = duthost.get_now_time(utc_timezone=True)
        read_failures.extend("sample {}: {}".format(index + 1, error) for error in errors)
        for port in sample_ports:
            samples_by_port[port].append({"row": rows.get(port), "now_utc": now_utc})
        logger.info(
            "Collected VDM consistency sample %d/%d for %d primary port(s)",
            index + 1, sample_count, len(sample_ports),
        )
        if index + 1 < sample_count:
            time.sleep(interval_sec + UPDATE_ADVANCE_MARGIN_SEC)
    return samples_by_port, read_failures


def _validate_statistic_coherence(port, row, families):
    failures = []
    checked_families = 0
    for family, fields in families.items():
        values = {kind: parse_numeric(row.get(field)) for kind, field in fields.items()}
        # Availability/range validation reports missing and non-finite values.
        if any(values[kind] is None or not math.isfinite(values[kind]) for kind in ("min", "avg", "max")):
            continue
        checked_families += 1
        logger.info("%s %s statistic tuple: %s", port, family, values)
        if not values["min"] <= values["avg"] <= values["max"]:
            failures.append("{}: {} has incoherent statistic tuple {} (expected min <= avg <= max)".format(
                port, family, values,
            ))
    return failures, checked_families


def _validate_vdm_samples(duthost, primary_ports, samples_by_port, field_plan, consistency_plan):
    """Validate every sample at its observation time, including timestamp advancement."""
    failures = []
    checked_samples = 0
    checked_families = 0
    for port in primary_ports:
        plan = consistency_plan[port]
        port_samples = samples_by_port[port][:plan["poll_count"]]
        if len(port_samples) != plan["poll_count"]:
            failures.append("{}: expected {} samples, collected {}".format(
                port, plan["poll_count"], len(port_samples),
            ))
        previous_time = None
        previous_raw = None
        for index, sample in enumerate(port_samples, 1):
            row = sample["row"]
            sample_failures, _ = validate_vdm_operational_ranges(
                duthost, [port], {port: row}, field_plan, now_utc=sample["now_utc"],
            )
            raw_time = row.get(STATE_DB_UPDATE_TIME_FIELD) if row else None
            current_time = parse_update_time(raw_time)
            if previous_time is not None and current_time is not None and current_time <= previous_time:
                sample_failures.append("{}: {} did not advance (prev={!r}, curr={!r})".format(
                    port, STATE_DB_UPDATE_TIME_FIELD, previous_raw, raw_time,
                ))
            previous_time, previous_raw = current_time, raw_time
            if row:
                statistic_failures, count = _validate_statistic_coherence(
                    port, row, plan["statistic_families"],
                )
                sample_failures.extend(statistic_failures)
                checked_families += count
            failures.extend("sample {}: {}".format(index, failure) for failure in sample_failures)
            checked_samples += 1
    return failures, checked_samples, checked_families


def test_vdm_data_consistency(
    duthost, vdm_primary_ports, port_attributes_dict, lport_to_first_subport_mapping,
):
    """Verify fresh in-range publications, advancing timestamps, and statistic tuples."""
    field_plan = build_vdm_field_plan(
        port_attributes_dict, vdm_primary_ports, lport_to_first_subport_mapping,
    )
    consistency_plan = _build_vdm_consistency_plan(
        port_attributes_dict, vdm_primary_ports, field_plan,
    )
    config_failures = [
        "{}: {}".format(port, error)
        for port in vdm_primary_ports for error in consistency_plan[port]["errors"]
    ]
    if config_failures:
        pytest.fail("VDM consistency configuration failures:\n" + "\n".join(config_failures))

    samples_by_port, read_failures = _collect_vdm_samples(duthost, vdm_primary_ports, consistency_plan)
    sample_failures, checked_samples, checked_families = _validate_vdm_samples(
        duthost, vdm_primary_ports, samples_by_port, field_plan, consistency_plan,
    )
    failures = read_failures + sample_failures
    if failures:
        pytest.fail("VDM data consistency failures:\n" + "\n".join(failures))
    if not checked_families:
        logger.warning("VDM statistic coherence is not covered: no complete min/avg/max family authored")
    logger.info(
        "VDM data consistency passed: %d port-sample(s), %d statistic tuple(s) across %d primary port(s)",
        checked_samples, checked_families, len(vdm_primary_ports),
    )
