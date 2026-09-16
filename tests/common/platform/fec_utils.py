"""Shared FEC attribute defaults and resolution helpers."""

import logging

from tests.common.port_attributes.attribute_keys import FEC_ATTRIBUTES_KEY


logger = logging.getLogger(__name__)


# Legacy values used when the optional FEC category or one of its keys is absent.
DEFAULT_FEC_ATTRIBUTES = {
    "supported_speeds": ["50G", "100G", "200G", "400G", "800G", "1600G"],
    "fec_mode_restore_timeout_sec": 30,
    "clear_counters_wait_sec": 60,
    "fec_histogram_stale_error_wait_sec": 600,
    "critical_histogram_bins": [7, 8, 9, 10, 11, 12, 13, 14, 15],
}


def _port_fec_attributes(port_attrs, port_name):
    if not port_attrs:
        return {}
    return port_attrs.get(port_name, {}).get(FEC_ATTRIBUTES_KEY, {})


def get_fec_attribute(port_attrs, port_name, attr_name):
    """Return one resolved per-port value, falling back to the legacy default."""
    fec_attributes = _port_fec_attributes(port_attrs, port_name)
    if attr_name in fec_attributes:
        return fec_attributes[attr_name]
    return DEFAULT_FEC_ATTRIBUTES.get(attr_name)


def get_capability(port_attrs, port_name, capability_name):
    """Return explicit ``True``/``False``, or ``None`` when the key is omitted."""
    return _port_fec_attributes(port_attrs, port_name).get(capability_name)


def resolve_capability(port_attrs, port_name, capability_name, legacy_supported):
    """Apply a consumer's legacy predicate only when a capability is omitted."""
    explicit = get_capability(port_attrs, port_name, capability_name)
    return legacy_supported if explicit is None else explicit


def get_max_wait_for_ports(port_attrs, port_names, attr_name):
    """Return the maximum resolved wait for one DUT-wide operation."""
    if attr_name not in DEFAULT_FEC_ATTRIBUTES:
        raise KeyError(f"No legacy default is defined for '{attr_name}'")
    return max(
        (
            get_fec_attribute(port_attrs, port_name, attr_name)
            for port_name in port_names
        ),
        default=0,
    )


def filter_interfaces_by_speed(candidate_interfaces, port_attrs):
    """Filter ``{port: live_speed}`` using each port's own resolved speed list."""
    eligible = []
    for port_name, live_speed in candidate_interfaces.items():
        supported_speeds = get_fec_attribute(
            port_attrs,
            port_name,
            "supported_speeds",
        )
        if live_speed in supported_speeds:
            eligible.append(port_name)
        else:
            logger.info(
                "Excluding %s: live speed %s is not in its supported FEC speeds %s",
                port_name,
                live_speed,
                supported_speeds,
            )
    return eligible
