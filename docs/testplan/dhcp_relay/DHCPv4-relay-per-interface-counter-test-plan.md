# DHCPv4 Relay Per-Interface Counter Test Plan

## Overview

The purpose is to test whether the DHCPv4 relay per-interface counter in dhcpmon works well. Feature HLD: [\[doc\]\[dhcp_relay\] Add hld for DHCPv4 relay per-interface counter](https://github.com/sonic-net/SONiC/pull/1861)

## Scope

The test is targeting a running SONiC system with dhcp_relay enabled.

### Topologies

Supported topologies: T0, DualToR, M0

## Test Case

### Enhance

#### test_dhcp_relay.py

Current test_dhcp_relay would send and verify packets relayed, there is already verification for dhcpmon syslog counter (Only count Vlan and 5 types of packets). We would make below changes to this test case:

- Verify DB counter

    1. Clear DB counter before sending and verifying packets
    2. Read counter from COUNTERS_DB to check whether it count as expected

- Verify more DHCP type packets

    1. In dhcp_relay_test.py, send more types of DHCP packets
    2. Verify counter in COUNTERS_DB

- Verify DHCP packets sent to standby interfaces

    1. In dhcp_relay_test.py, send DHCP reply packets to standby interfaces of DualToR
    2. Verify packets relaying status and COUNTERS_DB. Expected result is that ingress packets would be counted and relayed

- Verify DHCP packets with bad IP / UDP checksum

    1. In dhcp_relay_test.py, send DHCP packets with incorect IP / UDP checksum
    2. Verify packets relaying status and COUNTERS_DB. Expected result is that ingress packets wouldn't be counted and relayed

- Verify DHCP packets with length exceeds limit

    1. In dhcp_relay_test.py, send DHCP packets with length exceeds limit
    2. Verify packets relaying status and COUNTERS_DB, expected result is that ingress packets wouldn't be counted and relayed

### New Added

#### test_dhcp_counter_stress.py

1. Clear DB counter before sending packets

2. Keep sending DHCP packets with fixed packets rate for 2mins. In the mean time, capture and count packets in DUT

3. After sending, compare the counter in DB and the packets count captured in DUT

NOTICE: dhcpmon in low performance devices maybe have some acceptable packets drop during counting with high packets rate. Considering in real scenario there wouldn't be high DHCP packets rates for a long time. Hence for now there would be a default packets rates for all platforms. We will enhance it with adding more packets rates for different platform in the future
