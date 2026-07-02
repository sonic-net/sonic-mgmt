"""Pure helpers for Port Config value derivation (speed, lanes, subport groups).

I/O-free logic kept separate from the test files and the DB reader so it can be
unit-tested in isolation.  Covers the three derivations the Port Config tests
need beyond a plain field compare:

* speed Mbps(str) -> Gbps(int)
* "owns the first host lane" decision for the DOM-polling first-subport gate
* grouping logical ports by physical index for the subport-field check
"""
import logging

from tests.transceiver.port_config.utils.port_config_constants import (
    MBPS_PER_GBPS,
    PORT_FIELD_SPEED,
)

logger = logging.getLogger(__name__)


def config_db_speed_to_gbps(port_config):
    """Convert the CONFIG_DB ``speed`` field (Mbps string) to Gbps as an int.

    Returns ``(gbps, None)`` on success or ``(None, err)`` when the field is
    absent or not a positive integer Mbps value, so the caller can aggregate the
    error per the suite-wide per-port failure pattern.
    """
    raw = port_config.get(PORT_FIELD_SPEED)
    if raw is None:
        return None, "no '{}' field in CONFIG_DB PORT entry".format(PORT_FIELD_SPEED)
    try:
        mbps = int(str(raw).strip())
    except (TypeError, ValueError):
        return None, "'{}' is non-integer in CONFIG_DB: {!r}".format(PORT_FIELD_SPEED, raw)
    if mbps <= 0:
        return None, "'{}' must be positive Mbps, got {}".format(PORT_FIELD_SPEED, mbps)
    return mbps // MBPS_PER_GBPS, None


def parse_host_lane_mask(mask):
    """Parse a host-lane-mask attribute (hex string like ``"0xF"`` or int) to int.

    Returns ``None`` for a missing/unparseable value so the caller treats it as
    "cannot decide" rather than crashing.
    """
    if isinstance(mask, bool):
        return None
    if isinstance(mask, int):
        return mask
    if isinstance(mask, str):
        text = mask.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 0)
        except ValueError:
            return None
    return None


def owns_first_host_lane(host_lane_mask):
    """True iff the host-lane bitmask includes the first host lane (bit 0).

    The first subport of a breakout group is the one that owns the lowest host
    lane; a non-breakout port owns all its lanes (mask includes bit 0 too), so
    it also returns True and is therefore validated by the DOM-polling check.
    Returns ``False`` for an unparseable mask (skip defensively).
    """
    parsed = parse_host_lane_mask(host_lane_mask)
    if parsed is None:
        return False
    return (parsed & 0x1) != 0


def group_ports_by_physical_index(ports, physical_index_by_port):
    """Group logical ports by their physical port index.

    Args:
        ports: iterable of logical port names to group.
        physical_index_by_port: ``{logical_port: physical_index}`` mapping.

    Returns:
        ``({physical_index: [logical_port, ...]}, unknown_ports)`` where
        ``unknown_ports`` lists ports that have no resolvable physical index
        (``None`` in the mapping) so the caller can flag them rather than
        silently dropping them.
    """
    groups = {}
    unknown_ports = []
    for port in ports:
        pindex = physical_index_by_port.get(port)
        if pindex is None:
            unknown_ports.append(port)
            continue
        groups.setdefault(pindex, []).append(port)
    return groups, unknown_ports
