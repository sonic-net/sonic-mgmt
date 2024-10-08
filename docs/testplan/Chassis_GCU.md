# Chassis/Multi-ASIC Generic Config Updater (GCU) Test Plan

## Overview

TBD

##  Generic Config Updater (GCU) Test Coverage for Multi-ASIC Support
The existing community test coverage for the Generic Config Updater (GCU) has been enhanced to support running in multi-ASIC platforms.

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

TBD

#### Test Requirements:

At least 2 DUT hosts (one upstream, one downstream)

#### Testing Steps

- Select a random ASIC from the downstream host.
- Select a random BGP neighbor fro-m that namespace and announce a static route for a DST_IP that is advertised only via this neighbor.
- Verify the route table in the downstream DUT host to ensure that the static route is visible.

Remove Peers from Downstream Namespace:
- [S] Remove all BGP neighbors for the selected ASIC namespace via apply-patch.
- [V] Verify the route table. All routes for BGP neighbors should be gone. Additionally, all kernel and directly connected routes toward the neighbor IPs should be removed.
- [S] Shutdown local interfaces for the selected ASIC namespace via apply-patch.
- [V] Verify that the admin status of local interfaces in the selected ASIC namespace is down/down.
- [SV] Perform data traffic tests toward a randomly selected neighbor. Traffic should fail.
- [SV] Perform data traffic tests toward the static route from the randomly selected neighbor. Traffic should fail.

Re-add Peers and Re-enable Interfaces:
- [S] Change cable lengths.
- [S] Re-add peers in the downstream namespace. -
- [S] Re-enable interfaces.
- [V] Verify that the peers are re-added, BGP sessions are established, and the route table is updated.
- [V] Verify the buffer profile created for the new cable length in CONFIG_DB, APPL_DB, and ASIC_DB.
- [SV] Perform data traffic tests toward a randomly selected neighbor. Traffic should pass.
- [SV] Perform data traffic tests toward the static route from the randomly selected neighbor. Traffic should pass.

Send PFC Frame Pause/Continue:
- [S] Send a PFC pause frame.
- [SV] Perform data traffic tests toward the static route. Traffic should not pass.
- [S] Send a PFC continue frame.
- [SV] Perform data traffic tests toward the static route. Traffic should pass.

### Test Case # 2 - Update Buffer Queue

#### Test Objective
TBD

#### Testing Steps

- Select a random ASIC namespace and shut down the interfaces.
- Create new egress lossy and lossless profiles under BUFFER_PROFILE via apply-patch.
- Assign the new profiles to queues (path /BUFFER_QUEUE) of the shutdown interfaces via apply-patch.
- Bring the interfaces back up via apply-patch.
- Verify that the interfaces are up.
- Verify in CONFIG_DB and APPL_DB that the new profile names are configured.


### Test Case # 3 - Update WRED Profiles

#### Test Objective
TBD

#### Testing Steps

- Select a random ASIC namespace and shut down the interfaces.
- Remove WRED profile from queues (path /QUEUE) of the shutdown interfaces via apply-patch.
- Bring the interfaces back up via apply-patch.
- Verify that the interfaces are up.
- Verify in CONFIG_DB that the profile name is removed.
- Add WRED profile to queues (path /QUEUE) of the shutdown interfaces via apply-patch.
- Verify in CONFIG_DB that the profile name is successfully configured.


## Notes:
[S]: Setup
[V]: Verification
[SV]: Setup & Verification
