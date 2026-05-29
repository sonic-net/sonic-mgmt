"""Attribute-driven DOM field mapping helpers."""

import re

from tests.transceiver.dom.utils.dom_constants import (
    CONSISTENCY_VARIATION_THRESHOLD_ATTRS,
    LANE_NUM_PLACEHOLDER,
    OPERATIONAL_SUFFIX,
    THRESHOLD_FIELD_SUFFIXES,
    THRESHOLD_PREFIX_OVERRIDES,
    THRESHOLD_SUFFIX,
    THRESHOLD_TO_OPERATIONAL_ATTR_CANDIDATES,
)
from tests.transceiver.dom.utils.dom_state_db_reader import parse_numeric


_PORT_SUFFIX_PATTERN = re.compile(r"^(.*?)(\d+)$")


def port_sort_key(port_name):
    """Return a natural sort key for SONiC interface names.

    Args:
        port_name: Interface name such as ``Ethernet0``.

    Returns:
        tuple: Sort key that orders matching interface prefixes by numeric suffix.
    """
    text = str(port_name)
    match = _PORT_SUFFIX_PATTERN.match(text)
    if not match:
        return (text, -1, text)
    return (match.group(1), int(match.group(2)), text)


def get_lane_count(base_attrs):
    """Return the configured media lane count, falling back to host lanes.

    Args:
        base_attrs: Base transceiver attributes for one port.

    Returns:
        int: Positive media or host lane count when configured, otherwise ``0``.
    """
    media_lane_count = base_attrs.get("media_lane_count")
    if isinstance(media_lane_count, int) and media_lane_count > 0:
        return media_lane_count

    host_lane_count = base_attrs.get("host_lane_count")
    if isinstance(host_lane_count, int) and host_lane_count > 0:
        return host_lane_count

    return 0


def expand_operational_fields(attr_name, lane_count):
    """Expand a DOM operational attribute into expected STATE_DB sensor fields.

    Args:
        attr_name: DOM attribute name ending in ``_operational_range``.
        lane_count: Number of lanes used to expand lane placeholders.

    Returns:
        list: Expected ``TRANSCEIVER_DOM_SENSOR`` field names for the attribute.
    """
    base_name = attr_name[: -len(OPERATIONAL_SUFFIX)]
    if LANE_NUM_PLACEHOLDER not in base_name:
        return [base_name]

    if lane_count <= 0:
        return []

    return [base_name.replace(LANE_NUM_PLACEHOLDER, str(lane)) for lane in range(1, lane_count + 1)]


def build_operational_field_range_map(dom_attrs, lane_count):
    """Build a sensor field to operational range map from resolved DOM attributes.

    Args:
        dom_attrs: Resolved ``DOM_ATTRIBUTES`` for one port.
        lane_count: Number of lanes used to expand lane-scoped attributes.

    Returns:
        dict: Mapping from sensor field name to source attribute, min, and max metadata.
    """
    field_map = {}
    for attr_name, attr_value in dom_attrs.items():
        if not attr_name.endswith(OPERATIONAL_SUFFIX) or not isinstance(attr_value, dict):
            continue
        for field in expand_operational_fields(attr_name, lane_count):
            field_map[field] = {
                "attr_name": attr_name,
                "min": attr_value.get("min"),
                "max": attr_value.get("max"),
            }
    return field_map


def build_threshold_field_map(attr_name):
    """Build logical threshold keys to STATE_DB threshold field names.

    Args:
        attr_name: DOM attribute name ending in ``_threshold_range``.

    Returns:
        dict: Mapping from logical threshold suffix to STATE_DB threshold field name.
    """
    base_name = attr_name[: -len(THRESHOLD_SUFFIX)]
    prefix = THRESHOLD_PREFIX_OVERRIDES.get(base_name, base_name.replace("_", ""))
    return {suffix: "{}{}".format(prefix, suffix) for suffix in THRESHOLD_FIELD_SUFFIXES}


def threshold_field_map(attr_name):
    """Return threshold STATE_DB field mappings for threshold attributes only.

    Args:
        attr_name: Candidate DOM attribute name.

    Returns:
        dict: Threshold field map for threshold attributes, or an empty dict otherwise.
    """
    if not attr_name.endswith(THRESHOLD_SUFFIX):
        return {}
    return build_threshold_field_map(attr_name)


def operational_attr_candidates(base_name):
    """Return operational range attribute names related to a threshold base name.

    Args:
        base_name: Threshold attribute base name without ``_threshold_range``.

    Returns:
        tuple: Candidate operational range attribute names for the threshold base.
    """
    default = ("{}_operational_range".format(base_name),)
    return THRESHOLD_TO_OPERATIONAL_ATTR_CANDIDATES.get(base_name, default)


def parse_consistency_variation_thresholds(dom_attrs):
    """Parse optional consistency variation thresholds from resolved DOM attributes.

    Args:
        dom_attrs: Resolved ``DOM_ATTRIBUTES`` for one port.

    Returns:
        dict: Parsed threshold values plus separate ``errors`` and optional ``missing`` attrs.
    """
    thresholds = {}
    errors = []
    missing = []
    for attr_name in CONSISTENCY_VARIATION_THRESHOLD_ATTRS:
        raw_value = dom_attrs.get(attr_name)
        if raw_value is None:
            missing.append(attr_name)
            continue

        numeric = parse_numeric(raw_value)
        if numeric is None:
            errors.append("{} is non-numeric in DOM_ATTRIBUTES (raw={!r})".format(attr_name, raw_value))
            continue

        if numeric < 0:
            errors.append("{} must be >= 0, got {}".format(attr_name, numeric))
            continue

        thresholds[attr_name] = float(numeric)

    return {
        "thresholds": thresholds,
        "errors": errors,
        "missing": missing,
    }
