import pytest
import logging
import re

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
    pytest.mark.device_type('vs')
]

FROM_V6_NEXT_HOP_CLAUSE = "set ipv6 next-hop prefer-global"


def get_run_configs(duthost):
    """Fetch FRR running config per ASIC namespace.

    Returns list of (asic_label, config_text). `asic_label` is the ASIC id as
    string, or 'global' for single-ASIC/default namespace.
    """
    results = []

    if duthost.is_multi_asic:
        asic_len = len(duthost.asics)
        for asic_id in range(asic_len):
            logger.info(f"Fetching 'show run' from {duthost.hostname} asic {asic_id}")
            out = duthost.command(f'vtysh -n {asic_id} -c "show run"').get("stdout", "")
            results.append((str(asic_id), out))
    else:
        logger.info(f"Fetching 'show run' from {duthost.hostname} default namespace")
        out = duthost.command('vtysh -c "show run"').get("stdout", "")
        results.append(("default namespace", out))

    return results


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
        output = get_run_configs(duthost)
        logger.info(f"Get route-map configs from {duthost.hostname}: {output}")
        for asic, raw_run in output:
            logger.info(f"Verifying route-map config on {duthost.hostname} asic {asic}")
            result = verify_v6_next_hop_from_run(raw_run)
            if result is False:
                failures.append((duthost.hostname, asic if asic else None))

    assert not failures, (
        f"ipv6 next-hop prefer-global is not set in route-map on: {failures}")
