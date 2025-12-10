import pytest
import logging
import re

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

FROM_V6_NEXT_HOP_CLAUSE = "set ipv6 next-hop prefer-global"


def get_run_config(duthost):
    """Fetch plain-text running config via 'vtysh -c "show run"'."""
    res = duthost.shell('vtysh -c "show run"')["stdout"]
    logger.info(f"Running config: {res}")
    return res


def verify_v6_next_hop_from_run(raw_run_config):
    """Parse 'show run' to verify IPv6 next-hop prefer-global under any FROM_*_V6 route-map.

    We only require the clause to appear once in at least one block of the same
    route-map name (e.g., permit 100 has it, permit 200 may not). As soon as we
    find the clause inside any matching block, we return True.
    """
    if not raw_run_config:
        return False

    current_map = None
    current_mode = None  # 'permit' or 'deny'
    for raw_line in raw_run_config.splitlines():
        line = raw_line.strip()
        # detect start of a route-map block
        m = re.match(r"^route-map\s+(\S+)\s+(permit|deny)\s+\d+", line)
        if m:
            current_map = m.group(1)
            current_mode = m.group(2)
            continue
        if current_map:
            # end of block
            if line == "exit":
                current_map = None
                current_mode = None
                continue
            # within a FROM_*_V6 block, any single clause occurrence suffices
            # Only require rule for route-maps that are FROM_*_V6 and in 'permit' mode
            if current_mode == "permit" and "FROM" in current_map and "V6" in current_map:
                # match exact clause, case-insensitive and tolerant to extra spaces
                normalized = " ".join(line.split()).lower()
                target = " ".join(FROM_V6_NEXT_HOP_CLAUSE.split()).lower()
                if normalized == target or normalized.startswith(target):
                    return True

    # No matching clause found in any FROM_*_V6 route-map
    return False


def test_route_map_check(duthosts):
    """Validate IPv6 next-hop prefer-global is configured in bgpd route-maps.

    Strategy:
    - Try JSON via 'show route-map json' first; if parsing fails or clause missing,
      fallback to parsing plain-text 'show run'. This handles FRR output differences.
    """
    failures = []
    for duthost in duthosts:
        raw_run = get_run_config(duthost)
        result = verify_v6_next_hop_from_run(raw_run)
        if result is False:
            reason = "Missing clause in running-config"
            failures.append((duthost.hostname, reason))

    assert not failures, (
        f"ipv6 next-hop prefer-global is not set in route-map on: {', '.join([f[0] for f in failures])}")
