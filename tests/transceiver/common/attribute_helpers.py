"""Shared attribute validation, conventions, and breakout lane resolution."""

import logging
import math
from collections import namedtuple

from tests.transceiver.attribute_parser.attribute_keys import BASE_ATTRIBUTES_KEY, DOM_ATTRIBUTES_KEY
from tests.transceiver.common.db_helpers import parse_numeric

logger = logging.getLogger(__name__)

OPERATIONAL_SUFFIX = "_operational_range"
THRESHOLD_SUFFIX = "_threshold_range"
LANE_NUM_PLACEHOLDER = "LANE_NUM"
MEDIA_LANE_MASK_KEY = "media_lane_mask"

BreakoutLaneSelection = namedtuple("BreakoutLaneSelection", ("lanes_by_port", "active_lanes", "errors"))


def parse_min_max_range(mapped_field, attribute_key=DOM_ATTRIBUTES_KEY):
    """Return ``(min_value, max_value, error)`` for an authored min/max range."""
    attr_name = mapped_field.source_attr
    attr_value = mapped_field.attr_value

    if not isinstance(attr_value, dict):
        return None, None, "{} must be a dict with min/max in {}".format(attr_name, attribute_key)

    min_value = parse_numeric(attr_value.get("min"))
    max_value = parse_numeric(attr_value.get("max"))
    if min_value is None or max_value is None:
        return None, None, "{} missing numeric min/max in {}".format(attr_name, attribute_key)
    if not math.isfinite(min_value) or not math.isfinite(max_value):
        return None, None, "{} has non-finite min/max in {}".format(attr_name, attribute_key)
    if min_value > max_value:
        return None, None, "{} has invalid range [{}, {}]".format(
            attr_name,
            attr_value.get("min"),
            attr_value.get("max"),
        )

    return min_value, max_value, None


def parse_positive_int(attr_name, raw_value, minimum, attribute_key=DOM_ATTRIBUTES_KEY):
    """Return ``(value, error)`` for an integer attribute at or above its minimum."""
    if raw_value is None:
        return None, "{} missing in {}".format(attr_name, attribute_key)

    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or int(value) != value or value < minimum:
        return None, "{} must be an integer >= {} in {} (got {!r})".format(
            attr_name, minimum, attribute_key, raw_value,
        )
    return int(value), None


def resolve_breakout_lanes(
    primary_port,
    port_attributes_dict,
    lport_to_first_subport_mapping,
    mask_key,
):
    """Return per-subport and unioned lanes for one breakout mask.

    The module-wide active lane set is the union of ``mask_key`` across every
    logical subport in the breakout group. Each set mask bit is an absolute,
    1-indexed lane. ``lanes_by_port`` preserves each subport's lanes for callers
    that need data-path anchors.
    """
    mapping = lport_to_first_subport_mapping or {}
    group = [sub for sub, first in mapping.items() if first == primary_port] or [primary_port]

    lanes_by_port = {}
    active_lanes = set()
    mask_union = 0
    errors = []
    for subport in group:
        base_attrs = port_attributes_dict.get(subport, {}).get(BASE_ATTRIBUTES_KEY, {})
        raw_mask = base_attrs.get(mask_key)
        if raw_mask is None:
            errors.append(
                "{} missing {} in {}".format(
                    subport,
                    mask_key,
                    BASE_ATTRIBUTES_KEY,
                )
            )
            continue
        try:
            mask = int(str(raw_mask), 16)
        except (TypeError, ValueError):
            errors.append(
                "{} has unparsable {} {!r} in {}".format(
                    subport,
                    mask_key,
                    raw_mask,
                    BASE_ATTRIBUTES_KEY,
                )
            )
            continue

        lanes = [bit + 1 for bit in range(mask.bit_length()) if mask & (1 << bit)]
        lanes_by_port[subport] = lanes
        active_lanes.update(lanes)
        mask_union |= mask

    logger.debug(
        "%s active lanes %s (breakout group %s, %s union %#x)",
        primary_port, sorted(active_lanes), sorted(group), mask_key, mask_union,
    )
    return BreakoutLaneSelection(
        lanes_by_port=lanes_by_port,
        active_lanes=sorted(active_lanes),
        errors=errors,
    )
