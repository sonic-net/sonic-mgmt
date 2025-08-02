import pytest
import logging
import json

logger = logging.getLogger(__name__)


SRV6_LOC_BLOCK = "fcbb:bbbb"
IXIA_PORTS_PER_TG = 8
MAX_SID_NUM = 128


def get_max_number_of_parallel_links_and_neighbors(duthost):
    """Get the maximum number of parallel links and neighbors for SRv6 configuration"""
    lldp_table = duthost.command("show lldp table")['stdout_lines'][3:]
    lldp_table = lldp_table[:-2]  # remove the trailing 2 lines
    counters = dict()
    for line in lldp_table:
        neigh = line.split(maxsplit=2)[1]
        counters[neigh] = counters.get(neigh, 0) + 1

    return max(counters.values())


@pytest.fixture(scope="session")
def config_setup(duthosts, tbinfo):
    logger.info("Setting up SRv6 configuration")

    # Setup SRV6 configuration for each DUT and keep track of host SIDs
    device_sids = {}  # Bookkeeping dict for host SIDs
    for index, duthost in enumerate(duthosts):
        max_parallel_links = get_max_number_of_parallel_links_and_neighbors(duthost)
        logger.info(f"Max parallel links for {duthost.hostname}: {max_parallel_links}")
        if max_parallel_links > MAX_SID_NUM:
            pytest.skip(f"Max parallel links {max_parallel_links} exceeds the limit of {MAX_SID_NUM} for {duthost.hostname}")

        # Initialize the dictionary that contains SRv6 configuration
        config = {
            "SRV6_MY_LOCATORS": {},
            "SRV6_MY_SIDS": {},
            "FLEX_COUNTER_TABLE": {
                "SRV6": {
                    "FLEX_COUNTER_STATUS": "enable"
                }
            }
        }

        # Initialize the host SID list
        device_sids[duthost.hostname] = []
        # configure a number of SRv6 SIDs based on max_parallel_links
        for i in range(1, max_parallel_links + 1):
            sid = (index << 8) + i
            config['SRV6_MY_LOCATORS'][f"loc{i}"] = {
                "prefix": f"{SRV6_LOC_BLOCK}:{sid:x}::",
                "func_len": 0
            }
            config['SRV6_MY_SIDS'][f"loc{i}|{SRV6_LOC_BLOCK}:{sid:x}::/48"] = {
                "action": "uN",
                "decap_dscp_mode": "pipe"
            }
            device_sids[duthost.hostname].append(sid)

        # Apply the configuration to the DUT
        tmpfile = duthost.shell('mktemp')['stdout']
        duthost.copy(content=json.dumps(config, indent=4), dest=tmpfile)
        duthost.shell(f'sonic-cfggen -j {tmpfile} -w')

    #Ixia Traffic Generators
    tgs = tbinfo['tgs']
    # Generate SIDs for Ixia Traffic Generators
    for index, tg in enumerate(tgs):
        # Initialize the host SID list
        device_sids[tg] = []
        for i in range(1, IXIA_PORTS_PER_TG + 1):
            device_sids[tg].append(((len(duthosts) + index) << 8) + i)

    # Setup static routes for SRv6 forwarding
    for duthost in duthosts:
        ipv6_interfaces = duthost.show_and_parse('show ipv6 int')
        neighbor2intf = dict()
        # First, create a mapping of neighbors to interfaces and their IPv6 addresses
        for intf in ipv6_interfaces:
            if 'bgp neighbor' in intf and intf['bgp neighbor'] != 'N/A':
                neighbor2intf.setdefault(intf['bgp neighbor'], []).append((intf['interface'], intf['neighbor ip']))

        # Then, create static routes for each neighbor and their corresponding SIDs (1 route per SID)
        config = {
            "STATIC_ROUTE": {}
        }
        for neigh in neighbor2intf.keys():
            if neigh not in device_sids:
                logger.warning(f"Neighbor {neigh} is not a DUT or TG, skipping...")
                continue  # Skip if the neighbor is not a DUT or TG

            for i, sid in enumerate(device_sids[neigh]):
                if i >= len(neighbor2intf[neigh]):
                    logger.warning(f"Not enough interfaces for neighbor {neigh} on {duthost.hostname}, \
                                   {len(device_sids[neigh])} > {len(neighbor2intf[neigh])}, \
                                   skipping the rest of SIDs")
                    continue

                intf, ipv6_addr = neighbor2intf[neigh][i]
                config["STATIC_ROUTE"][f"default|{SRV6_LOC_BLOCK}:{sid:x}::/48"] = {
                    "nexthop": ipv6_addr,
                    "ifname": intf,
                    "advertise": "false",
                }
        # Apply the static route configuration
        tmpfile = duthost.shell('mktemp')['stdout']
        duthost.copy(content=json.dumps(config, indent=4), dest=tmpfile)
        duthost.shell(f'sonic-cfggen -j {tmpfile} -w')

    yield

    logger.info("Tearing down SRv6 configuration by config reload")
    for duthost in duthosts:
        duthost.command("config reload -y")
