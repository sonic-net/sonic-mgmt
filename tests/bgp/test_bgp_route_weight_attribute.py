import pytest
import logging
import json
import re
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def parse_bgp_summary(text_output):
    neighbors = []
    in_table = False

    for line in text_output.splitlines():
        if re.match(r"^Neighbor\s+V\s+AS\s+", line):
            in_table = True
            continue
        if not in_table or line.strip() == "":
            continue
        cols = re.split(r'\s+', line.strip())
        if len(cols) < 10:
            continue
        neighbor_ip = cols[0]
        state_or_pfx = cols[9]
        try:
            pfxRcd = int(state_or_pfx)
            state = "Established"
        except ValueError:
            state = state_or_pfx
            try:
                pfxRcd = int(cols[10]) if len(cols) > 10 else 0
            except (IndexError, ValueError):
                pfxRcd = 0
        neighbors.append({
            "neighbor": neighbor_ip,
            "state": state,
            "pfxRcd": pfxRcd,
        })
    return neighbors


@pytest.mark.bgp_ft
@pytest.mark.community
def test_bgp_route_weight_attribute(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    topo = tbinfo["topo"]["type"]
    if topo not in ["t0", "t1", "dualtor", "any"]:
        pytest.skip(f"Unsupported topology: {topo}")

    logger.info("Fetching current BGP summary")
    summary = duthost.shell("vtysh -c 'show ip bgp summary'")["stdout"]
    neighbors = parse_bgp_summary(summary)

    # Run this BEFORE assigning test_nbr
    raw = duthost.shell("vtysh -c 'show bgp ipv4 unicast 0.0.0.0/0 json'")["stdout"]
    default_route_data = json.loads(raw)
    advertising_peers = {p["peer"]["peerId"] for p in default_route_data.get("paths", [])}

    valid_nbrs = [
        n for n in neighbors
        if n["neighbor"].startswith("10.0.0.")
        and n["state"] == "Established"
        and n["pfxRcd"] > 0
        and n["neighbor"] in advertising_peers
    ]

    if not valid_nbrs:
        pytest.skip("No suitable IPv4 BGP neighbors found")

    test_nbr = valid_nbrs[0]["neighbor"]
    logger.info(f"Testing neighbor: {test_nbr}")

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    local_asn = mg_facts.get("minigraph_bgp_asn")
    if not local_asn:
        pytest.skip("Local BGP ASN not found in minigraph")

    expected_weight = 200
    try:
        logger.info(f"Applying weight={expected_weight} to {test_nbr}")
        duthost.shell(
            f'vtysh -c "configure terminal" '
            f'-c "router bgp {local_asn}" '
            f'-c "address-family ipv4 unicast" '
            f'-c "neighbor {test_nbr} weight {expected_weight}" '
            f'-c "end"'
        )

        logger.debug("Sleeping 10 seconds to allow session reset...")
        time.sleep(10)

        def session_established():
            output = duthost.shell("vtysh -c 'show ip bgp summary'")["stdout"]
            for line in output.splitlines():
                if test_nbr in line:
                    logger.debug(f"BGP summary line: {line}")
                    match = re.search(
                        rf"{re.escape(test_nbr)}\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:]+?\s+(\S+)", line)
                    if match:
                        state_or_pfx = match.group(1)
                        try:
                            return int(state_or_pfx) > 0
                        except ValueError:
                            return state_or_pfx == "Established"
            return False

        logger.info("Waiting for BGP session to re-establish...")
        pytest_assert(wait_until(180, 5, 0, session_established),
                      f"BGP did not reach Established with {test_nbr} after applying weight")

        logger.info("Verifying route weight in default route (0.0.0.0/0)")
        raw = duthost.shell("vtysh -c 'show bgp ipv4 unicast 0.0.0.0/0 json'")["stdout"]
        data = json.loads(raw)
        for path in data.get("paths", []):
            if path.get("peer", {}).get("peerId") == test_nbr:
                pytest_assert(path.get("weight") == expected_weight,
                              f"Weight mismatch: expected {expected_weight},"
                              f"got {path.get('weight')}")
                logger.info("Weight correctly applied and used for best path")
                break
        else:
            pytest.fail(f"Route via neighbor {test_nbr} not found in paths")

    finally:
        logger.info(f"Removing weight configuration for {test_nbr}")
        duthost.shell(
            f'vtysh -c "configure terminal" '
            f'-c "router bgp {local_asn}" '
            f'-c "address-family ipv4 unicast" '
            f'-c "no neighbor {test_nbr} weight" '
            f'-c "end"',
            module_ignore_errors=True
        )
        logger.info("Cleanup completed")
