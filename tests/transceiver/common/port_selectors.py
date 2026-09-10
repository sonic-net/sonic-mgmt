"""Shared port selectors for transceiver attribute-driven tests."""

import logging
from collections import namedtuple

from natsort import natsorted

from tests.common.platform.interface_utils import (
    get_physical_to_logical_port_mapping,
    is_first_subport,
)


logger = logging.getLogger(__name__)
PortSelection = namedtuple("PortSelection", ("primary_ports", "non_primary_ports"))


def has_attribute_category(port_attrs, attribute_key):
    """Return True when ``port_attrs`` carries a non-empty attribute category."""
    category_attrs = port_attrs.get(attribute_key, {})
    return isinstance(category_attrs, dict) and bool(category_attrs)


def select_attribute_ports(
    port_attributes_dict,
    attribute_key,
    lport_to_first_subport_mapping=None,
    explicit_ports=None,
    predicate=None,
    include_non_primary=False,
):
    """Select deterministic ports carrying ``attribute_key``.

    ``explicit_ports`` narrows the candidate set for suites with a configured
    port list.  ``predicate`` is an optional callable ``(port, attrs) -> bool``
    for category-specific filters.  Empty-case verdicts stay with the caller so
    suites can choose skip vs. fail semantics independently.  When no first
    subport mapping is supplied, all selected ports are treated as primary ports
    and ``include_non_primary`` has no effect.
    """
    explicit_port_set = None
    if explicit_ports is not None:
        explicit_port_set = (
            {explicit_ports}
            if isinstance(explicit_ports, str)
            else set(explicit_ports)
        )

    primary_ports = []
    non_primary_ports = []

    for port, attrs in port_attributes_dict.items():
        if explicit_port_set is not None and port not in explicit_port_set:
            continue
        if not has_attribute_category(attrs, attribute_key):
            continue
        if predicate is not None and not predicate(port, attrs):
            continue

        if lport_to_first_subport_mapping is None:
            primary_ports.append(port)
            continue

        first_subport = lport_to_first_subport_mapping.get(port)
        if first_subport is None:
            logger.debug(
                "%s carries %s attributes but is absent from the first-subport mapping",
                port,
                attribute_key,
            )
            continue
        if is_first_subport(port, lport_to_first_subport_mapping):
            primary_ports.append(port)
        elif include_non_primary:
            non_primary_ports.append(port)

    return PortSelection(
        primary_ports=natsorted(primary_ports),
        non_primary_ports=natsorted(non_primary_ports),
    )


def resolve_ports_under_test(lport_to_pport, port_attributes_dict, attribute_key):
    """Resolve a suite's configured ``ports_under_test`` to logical ports.

    Returns:
        set | None: the logical ports the configured physical indices map to,
        or ``None`` when ``ports_under_test`` is absent/empty.
    """
    if not port_attributes_dict:
        return None
    attrs = next(iter(port_attributes_dict.values())).get(attribute_key, {})
    ports_under_test = attrs.get("ports_under_test")
    if not ports_under_test:
        return None
    pport_to_lport_mapping = get_physical_to_logical_port_mapping(lport_to_pport)
    resolved_ports = set()
    for pindex in ports_under_test:
        resolved_ports.update(pport_to_lport_mapping.get(pindex, []))
    return resolved_ports
