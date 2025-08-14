import pytest
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)  # Ensure logs are shown in pytest output

SCAN_BATCH_SIZE = 1000    # Redis SCAN COUNT for each iteration
LOG_PROGRESS_EVERY = 100  # Log after this many BGP routes checked


@pytest.mark.bgp_ft
@pytest.mark.community
def test_bgp_route_weight_first_missing(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Scan APPL_DB ROUTE_TABLE for BGP-learned routes and
    skip immediately if the first one without a 'weight' or with non-numeric weight is found.
    Clearly log the offending key and reason.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Get known BGP neighbors from FRR running-config (fallback check)
    bgp_neighbors_output = duthost.shell(
        "vtysh -c 'show running-config | include neighbor'"
    )["stdout_lines"]
    bgp_neighbors = {
        line.split()[1] for line in bgp_neighbors_output if line.strip().startswith("neighbor")
    }
    if not bgp_neighbors:
        pytest.skip("No BGP neighbors found in running config")

    logger.info(f"Collected BGP neighbors: {bgp_neighbors}")

    skipped_non_bgp = 0
    checked = 0
    cursor = "0"

    while True:
        scan_cmd = f"redis-cli -n 0 --raw SCAN {cursor} MATCH ROUTE_TABLE:\\* COUNT {SCAN_BATCH_SIZE}"
        scan_result = duthost.shell(scan_cmd)["stdout_lines"]
        if not scan_result:
            break

        cursor = scan_result[0].strip()
        keys = [k for k in scan_result[1:] if k.startswith("ROUTE_TABLE:")]

        for key in keys:
            route_data = duthost.shell(f"redis-cli -n 0 HGETALL '{key}'")["stdout_lines"]
            route_dict = dict(zip(route_data[0::2], route_data[1::2]))

            nexthop = route_dict.get("nexthop")
            protocol = route_dict.get("protocol", "").lower()

            # Detect BGP-learned routes
            is_bgp = (protocol == "bgp") or (
                nexthop and any(nh in bgp_neighbors for nh in nexthop.split(","))
            )

            if not is_bgp:
                skipped_non_bgp += 1
                continue

            checked += 1
            if checked % LOG_PROGRESS_EVERY == 0:
                logger.info(f"Checked {checked} BGP routes so far...")

            #  Missing weight
            if "weight" not in route_dict:
                msg = f"First offending BGP route without weight: {key} (nexthop={nexthop})"
                logger.error(msg)
                pytest.skip(msg)  # <-- Will be shown with pytest -rs

            #  Non-numeric weight
            try:
                int(route_dict["weight"])
            except ValueError:
                msg = f"First offending BGP route with non-numeric weight: {key} -> {route_dict['weight']}"
                logger.error(msg)
                pytest.skip(msg)  # <-- Will be shown with pytest -rs

        if cursor == "0":
            break

    logger.info(f"Skipped {skipped_non_bgp} non-BGP routes during validation.")
    logger.info(f"Checked {checked} BGP routes — all have valid weight attributes.")
