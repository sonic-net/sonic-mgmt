# Chassis/Multi-ASIC Generic Config Updater (GCU) Test Plan

## Overview

##  Generic Config Updater (GCU) Test Coverage for Multi-ASIC Support
The existing community test coverage for the Generic Config Updater (GCU) has been enhanced to support running in multi-ASIC platforms and t2 topology.

### Key Changes
1. Multi-ASIC Adaptation:
Test cases have been adapted to use a fixture that returns a random ASIC namespace for verification.

2. Namespace Customization:
For multi-ASIC DUT hosts, JSON patch paths are customized to include the namespace prefix. For changes in global paths, the /localhost prefix was added to the path.

3. Single-ASIC Compatibility:
For single-ASIC DUT hosts, no changes were made to the paths, ensuring compatibility with the existing test setup.

### Test Case Updates

- test_ipv6.py --> test_ip_bgp.py
Previously, this test case verified paths only for IPv6 BGP neighbors. It has been expanded to run repeatedly for both IPv4 and IPv6 BGP neighbor types. As a result, the test suite file has been renamed to test_ip_bgp.py to reflect its broader scope.

### Test PRs

Above changes were added via Test PRs:
- [Generalizing GCU test suite to verify both ip types (IPV4, IPV6) for BGP Neighbors](https://github.com/sonic-net/sonic-mgmt/pull/13650)
- [GCU adding Multi-ASIC support in existing test code base](https://github.com/sonic-net/sonic-mgmt/pull/14070)

## Testbed

The test will run on T2 testbeds.

## Setup Configuration

TBD

## Testing Plan

### Test Case # 1 - Add Cluster With Basic QoS

#### Test Objective

To verify updates in config paths:
    /asic/BGP_NEIGHBOR
    /asic/DEVICE_NEIGHBOR
    /asic/DEVICE_NEIGHBOR_METADATA
    /asic/PORTCHANNEL_MEMBER
    /asic/PORTCHANNEL_INTERFACE
    /asic/INTERFACE
    /asic/PORT
    /localhost/BGP_NEIGHBOR
    /localhost/DEVICE_NEIGHBOR_METADATA
    /localhost/INTERFACE
    /localhost/PORTCHANNEL_INTERFACE
    /localhost/PORTCHANNEL_MEMBER

#### Test Requirements:

At least two frontend DUT hosts are required to perform traffic. Modifications via apply-patch are applied on the downstream frontend DUT host. The scenario verifies data traffic from upstream to downstream and downstream to downstream.

#### Testing Steps

- Select a random ASIC from the downstream host.
- Select a random BGP neighbor fro-m that namespace and announce a static route for a DST_IP that is advertised only via this neighbor.
- Verify the route table in the downstream DUT host to ensure that the static route is visible.

Remove Peers from Downstream Namespace:
- Remove all BGP neighbors for the selected ASIC namespace via apply-patch.
- Verify the route table. All routes for BGP neighbors should be gone. Additionally, all kernel and directly connected routes toward the neighbor IPs should be removed.
- Shutdown local interfaces for the selected ASIC namespace via apply-patch.
- Verify that the admin status of local interfaces in the selected ASIC namespace is down/down.
- Perform data traffic tests toward a randomly selected neighbor. Traffic should fail.
- Perform data traffic tests toward the static route from the randomly selected neighbor. Traffic should fail.

Re-add Peers and Re-enable Interfaces:
- Change cable lengths.
- Re-add peers in the downstream namespace. -
- Re-enable interfaces.
- Verify that the peers are re-added, BGP sessions are established, and the route table is updated.
- Verify the buffer profile created for the new cable length in CONFIG_DB, APPL_DB, and ASIC_DB.
- Perform data traffic tests toward a randomly selected neighbor. Traffic should pass.
- Perform data traffic tests toward the static route from the randomly selected neighbor. Traffic should pass.

Send PFC Frame Pause/Continue:
- Send a PFC pause frame.
- Perform data traffic tests toward the static route. Traffic should not pass.
- Send a PFC continue frame.
- Perform data traffic tests toward the static route. Traffic should pass.

### Test Case # 2 - Update CABLE Length

#### Test Objective
To verify updates in config path "CABLE_LENGTH".

#### Testing Steps

- Select a random ASIC namespace and shut down the interfaces.
- Update cable length via apply-patch. Identify the current cable length and add the previous or next supported length value for this frontend card.
- Bring the interfaces back up via apply-patch.
- Verify that the interfaces are up.
- Verify in CONFIG_DB and APPL_DB that the new cable length is applied.
- Verify that updated pg lossless profile was created in CONFIG_DB and APPL_DB and that it was assigned to active interfaces.


### Test Case # 3 - Load QoS

#### Test Objective
To verify qos updates in multi-asic t2 platform. To verify updates in tables "BUFFER_PG", "BUFFER_QUEUE", "PORT_QOS_MAP", and "QUEUE".

#### Testing Steps

- Select a random ASIC namespace and shut down the interfaces.
- Remove QoS config via apply-patch remove operation for tables "BUFFER_PG", "BUFFER_QUEUE", "PORT_QOS_MAP", and "QUEUE".
- Verify that configuration is cleared in CONFIG_DB, APPL_DB and ASIC_DB.
- Add back QoS config via apply-patch add operation in tables "BUFFER_PG", "BUFFER_QUEUE", "PORT_QOS_MAP", and "QUEUE".
- Verify that configuration is populated to CONFIG_DB, APPL_DB and ASIC_DB.
- Bring the interfaces back up via apply-patch.
- Verify that the interfaces are up.
