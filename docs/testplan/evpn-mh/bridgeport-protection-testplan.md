# EVPN-MH Bridge-Port Protection Test Plan

## Revision

| Revision | Date | Author | Description |
|---|---|---|---|
| 0.1 | 2026-11-04 | TBD | Initial software-protection test plan based on the Bridge-Port Protection HLD and EVPN-MH topology. |

## Abbreviations

| Term | Definition |
|---|---|
| BPP | Bridge-Port Protection |
| dT0 | Distributed top-of-rack / leaf switch in this EVPN-MH topology |
| ESI | Ethernet Segment Identifier |
| EVPN-MH | Ethernet VPN multihoming |
| FDB | Forwarding database |
| FPM | Forwarding Plane Manager |
| GRT | Global routing table |
| LACP | Link Aggregation Control Protocol |
| L3VNI | Layer-3 VXLAN Network Identifier |
| NHG | Next-hop group |
| PTF | Packet Test Framework |
| RMAC | Remote router MAC |
| SAI | Switch Abstraction Interface |
| VTEP | VXLAN Tunnel Endpoint |

## Overview

This plan specifies system tests for software protection of a protected bridge port in an EVPN Layer-3 multihoming deployment. The tests shall verify the binding to the backup NHG, software selection of the protection path after a qualified protected-bridge-port failure, and recovery under the configured revertive policy.

## Scope

### In scope

- Software protection mode and its per-port policy.
- Qualified operational-down events on the protected bridge port, caused by PortChannel shutdown, physical-member shutdown, or LACP timeout.
- Traffic selection between the primary path and the protection path.
- Revertive and non-revertive recovery, `admin_mode` overrides, and recovery races.
- Backup NHG membership changes; MAC, neighbor, and FDB lifecycle; and protection removal.
- IPv4/IPv6 host reachability over the routed protection path, including VXLAN encapsulation, peer-side decapsulation, and delivery to the host.

### Out of scope

- Hardware protection mode, which shall be qualified in Phase 2.
- Warm-restart replay and reconciliation coverage. The SWSS container restart in Test Case 11 tests ordinary service reconstruction, not warm-restart behavior.
- YANG schema rejection of unsupported enum values and negative timer values; these checks belong in the `sonic-bridge-port-protection.yang` model unit tests.
- Full zebra restart or BGP container restart while SWSS remains running shall be out of scope because FRR does not yet guarantee persistence of protection member and group IDs across these restarts.

## Testbed

The testbed setup shall be as described in the [sonic-mgmt EVPN-MH test-plan PR #26752](https://github.com/sonic-net/sonic-mgmt/pull/26752).

## Test Configuration

Configure the FRR Ethernet Segment on each dT0's server-facing PortChannel:

```text
interface PortChannel1001
 evpn mh es-id 00:00:00:00:00:00:00:00:00:01
 evpn mh bridge-port-protection
```

Set valid per-port policy values with the CLI from [sonic-utilities PR #5003](https://github.com/sonic-net/sonic-utilities/pull/5003). The test image shall include that CLI change.
The first command shall create the `CONFIG_DB BRIDGE_PORT_PROTECTION|PortChannel1001` policy row if it is absent; subsequent commands shall update that row. No pre-existing policy row is required.

```text
config portchannel protection PortChannel1001 protection_mode SOFTWARE
config portchannel protection PortChannel1001 admin_mode AUTO
config portchannel protection PortChannel1001 revertive true
config portchannel protection PortChannel1001 wait_to_restore_time_ms 0
```

## Traffic Setup and Measurement

1. Use the IPv4/IPv6 addresses assigned to the physical host's LACP bond by the testbed setup. Verify the host neighbor resolves through the GRT.
2. Connect PTF to the T2/upstream traffic path. Define a runtime traffic fixture parameterized by `transport` (TCP or UDP) and `address_family` (IPv4 or IPv6). Each fixture invocation shall generate sequenced traffic to the physical host bond IP with a distinct 5-tuple.
3. PTF shall transmit fixture traffic and capture packets on the PTF ports mapped to the relevant testbed links. Unless a test case specifies otherwise, it shall run only the UDP/IPv4 fixture instance. Each case shall identify its PTF capture ports and expected path.
4. For each failure and recovery, record fault time, last packet before the path transition, first sustained delivery on the new path, packet loss, and convergence time.

The expected path is the primary path while the protected bridge port is up, the protection path through the backup NHG while the protected bridge port is down, and the primary path after revertive recovery. Server-to-T2 traffic is not the protection stimulus because the physical host can transmit on its surviving bond member.

## Common Verification

- Run `show bridge-port-protection` and `show bridge-port-protection PortChannel1001 --verbose`.
- Read policy and protection state with `sonic-db-cli CONFIG_DB HGETALL "BRIDGE_PORT_PROTECTION|PortChannel1001"` and `sonic-db-cli STATE_DB HGETALL "BRIDGE_PORT_PROTECTION_STATE|PortChannel1001"`.
- Run `vtysh -c 'show bgp l2vpn evpn route type ead'` on each dT0 and record the remote VTEPs advertising the protected ESI. Read `EVPN_ES_BACKUP_NHG_TABLE:PortChannel1001` in APPL_DB and copy its `nexthop_group` value; read `L2_NEXTHOP_GROUP_TABLE:<NHG_ID>` and each member row referenced by its `nexthop_group` field. Compare the member `remote_vtep` set with the EAD peer VTEP set for that ESI, excluding peers whose same-ES PortChannel is down. Confirm the binding key is the FRR-configured protected PortChannel for that ESI and check each member's `type`, `vni`, and `router_mac` against the testbed inventory.
- Read the host neighbor with `sonic-db-cli APPL_DB HGETALL "NEIGH_TABLE:<VLAN>:<HOST_IP>"`; verify its `neigh` field equals the host MAC recorded by the testbed. Read the FDB entry with `sonic-db-cli STATE_DB HGETALL "FDB_TABLE|<VLAN>:<HOST_MAC>"`; verify the entry is present and `port=PortChannel1001` while the local PortChannel is up. Substitute the testbed's VLAN, IP, and MAC values for the placeholders.
- Run `show interfaces portchannel`; inspect physical-member and LACP/team state. For LACP timeout, record PDU stop, member removal, PortChannel-down, and protection activation times.
- Run `show arp` and `show ndp`; inspect FDB and ASIC/SAI state for the tested host and protected bridge port.
- Capture the protected packet path and verify the peer VTEP, VRF-selected L3VNI, peer RMAC/inner DMAC, and end-host delivery. Correlate sequence numbers to calculate loss and convergence.

## Test Cases

Each test case shall run independently. **Common Per-Test Setup** shall run before the case steps, and **Common Per-Test Teardown** shall run after validation, including when a case fails. No test case shall depend on state created by a previous case. The EVPN-MH underlay, VLAN/VRF/L3VNI mappings, host addressing, and physical wiring are pre-provisioned testbed infrastructure; these procedures reset BPP policy, link state, and test traffic.

### Common Per-Test Setup

1. On the physical host, restore every NIC to the configured 802.3ad bond and verify all members are up. On each dT0, run `config interface startup <server-member-interface>` for each server-facing member used by PortChannel1001 or a peer PortChannel, then run `config interface startup PortChannel1001` and the equivalent startup command for each peer PortChannel used in the case.
2. On each dT0, remove previous BPP enablement with `vtysh -c 'configure terminal' -c 'interface PortChannel1001' -c 'no evpn mh bridge-port-protection'` and delete the previous policy with `config portchannel protection PortChannel1001 delete`.
3. On each dT0, configure the protected Ethernet Segment and enable BPP with `vtysh -c 'configure terminal' -c 'interface PortChannel1001' -c 'evpn mh es-id 00:00:00:00:00:00:00:00:00:01' -c 'evpn mh bridge-port-protection'`.
4. On each dT0, set the baseline policy using the commands in Test Configuration.
5. Run `show interfaces portchannel` and `show bridge-port-protection PortChannel1001 --verbose`. Read `CONFIG_DB BRIDGE_PORT_PROTECTION|PortChannel1001` with `sonic-db-cli CONFIG_DB HGETALL "BRIDGE_PORT_PROTECTION|PortChannel1001"` and read `STATE_DB BRIDGE_PORT_PROTECTION_STATE|PortChannel1001` with `sonic-db-cli STATE_DB HGETALL "BRIDGE_PORT_PROTECTION_STATE|PortChannel1001"`.
6. Run the binding/NHG checks from Common Verification. Check neighbor/FDB state after the case starts traffic.

**Setup validation:**
- The CONFIG_DB row shall contain `protection_mode=SOFTWARE`, `admin_mode=AUTO`, `revertive=true`, and `wait_to_restore_time_ms=0`.
- The protected PortChannel shall be up, and STATE_DB shall report `protection_state=PRIMARY` and `admin_mode=AUTO` before test traffic starts.

### Common Per-Test Teardown

1. Stop all traffic streams and packet captures started by the case. Restore any host-side LACP test control to transmit PDUs.
2. On the physical host, restore every NIC to the configured 802.3ad bond. On each dT0, run `config interface startup <server-member-interface>` for each server-facing member changed by the case, then run `config interface startup PortChannel1001` and the equivalent startup command for every peer PortChannel changed by the case. For each host bond whose transmit-hash policy was changed, restore its saved policy with `sudo ip link set dev <host-bond> type bond xmit_hash_policy <saved-policy>` and verify it with `cat /sys/class/net/<host-bond>/bonding/xmit_hash_policy`, including when the case fails.
3. On each dT0, set `admin_mode=AUTO`, `revertive=true`, and `wait_to_restore_time_ms=0` using the commands in Test Configuration.
4. On each dT0, disable BPP with `vtysh -c 'configure terminal' -c 'interface PortChannel1001' -c 'no evpn mh bridge-port-protection'` and remove its policy with `config portchannel protection PortChannel1001 delete`.
5. Verify the CONFIG_DB policy and APPL_DB binding are absent, all changed PortChannels are up, and the pre-provisioned EVPN-MH routes remain established.

### Configuration and Baseline

#### Test Case 1: Configure software protection

**Objective:** Verify valid per-port policy updates and software-mode state reporting.

**Test steps:**
1. Read the baseline policy with `sonic-db-cli CONFIG_DB HGETALL "BRIDGE_PORT_PROTECTION|PortChannel1001"` and run `show bridge-port-protection PortChannel1001 --verbose`.
2. Update the policy with `config portchannel protection PortChannel1001 revertive false` and `config portchannel protection PortChannel1001 wait_to_restore_time_ms 5000`.
3. Read the policy with `sonic-db-cli CONFIG_DB HGETALL "BRIDGE_PORT_PROTECTION|PortChannel1001"`.
4. Reset the policy with `config portchannel protection PortChannel1001 revertive true` and `config portchannel protection PortChannel1001 wait_to_restore_time_ms 0`; read the row again.
5. Run the binding/NHG checks from Common Verification.

**Validation:**
- The initial policy shall match the baseline in Common Per-Test Setup and the protected bridge port shall report `protection_state=PRIMARY` and `admin_mode=AUTO`.
- After the recovery fields are set, CONFIG_DB shall report `revertive=false` and `wait_to_restore_time_ms=5000`; after reset, it shall report `revertive=true` and `wait_to_restore_time_ms=0`.
- Omitted-field defaults shall be verified in Test Case 9.
- Software protection shall be reported, and the protected bridge port shall return to `protection_state=PRIMARY` and `admin_mode=AUTO`.
- The binding and protection NHG member set shall match the ESI peer set checked by Common Verification.

#### Test Case 2: Baseline forwarding

**Objective:** Verify local primary forwarding and backup readiness.

**Test steps:**
1. Start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4` to the physical host IP to generate traffic for the host entry.
2. Run `show interfaces portchannel` and `show bridge-port-protection PortChannel1001 --verbose`.
3. Run Common Verification.
4. Capture the local server-facing link and the protection path while the UDP/IPv4 stream runs.

**Validation:**
- The UDP/IPv4 stream shall be delivered over the primary path.
- No protection-path VXLAN packet shall carry that stream.
- PortChannel1001 shall be up, `protection_state` shall be PRIMARY, and `admin_mode` shall be AUTO.

#### Test Case 3: Administrative overrides

**Objective:** Verify PRIMARY, PROTECTION, and AUTO override behavior.

**Test steps:**
1. Start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4`; keep it running continuously through steps 2-4.
2. Run `config portchannel protection PortChannel1001 admin_mode PRIMARY`; run `show bridge-port-protection PortChannel1001 --verbose` and capture the flow path.
3. Run `config portchannel protection PortChannel1001 admin_mode PROTECTION`; run the verbose show command and capture the flow path.
4. Run `config portchannel protection PortChannel1001 admin_mode AUTO`; run the verbose show command and capture the flow path.

**Validation:**
- With `admin_mode=PRIMARY`, `protection_state` shall be PRIMARY and forwarding shall use the protected bridge port.
- With `admin_mode=PROTECTION`, forwarding shall use the backup NHG and `protection_state` shall be PROTECTION.
- With `admin_mode=AUTO`, software protection shall select the path based on the protected bridge-port state.

### Failure Detection and Forwarding

#### Test Case 4: Protected PortChannel down

**Objective:** Verify software protection for one physical host when its protected PortChannel is administratively shut down, using each transport/address-family combination.

**Test steps:**
1. Run the following steps sequentially for TCP/IPv4, UDP/IPv4, TCP/IPv6, and UDP/IPv6. Start only one PTF runtime traffic fixture instance at a time.
2. Start the fixture instance for the current transport/address-family pair and capture it on the dT0 under test.
3. Run `config interface shutdown PortChannel1001` on that dT0 to administratively shut down the protected PortChannel.
4. Poll `show interfaces portchannel` and `show bridge-port-protection PortChannel1001 --verbose`; record the state transition times.
5. Capture the protection-path VXLAN packets to an eligible peer and packets leaving the peer toward the physical host.
6. Run `config interface startup PortChannel1001`; poll the state and capture the current fixture instance through recovery.
7. Stop the current fixture instance before starting the next combination.

**Validation:**
- The protected bridge port shall transition operationally down; software shall set `admin_mode=PROTECTION` and `protection_state=PROTECTION`.
- For each fixture combination, the protection NHG shall carry that stream to the physical host through a peer VTEP.
- The physical host's IPv4/IPv6 neighbor entries and FDB entry shall remain present.
- Packet loss and convergence time shall be recorded.

#### Test Case 5: Single PortChannel member down

**Objective:** Verify software protection and routed IPv4/IPv6 packet forwarding when the sole physical member fails while the PortChannel remains administratively enabled.

**Test steps:**
1. Run the following steps sequentially for UDP/IPv4 and UDP/IPv6. Start one PTF runtime traffic fixture instance at a time.
2. Start the current fixture instance and capture it on the sole physical member mapped to PortChannel1001.
3. Run `config interface shutdown <server-member-interface>` on the dT0 under test; leave PortChannel1001 administratively enabled.
4. Poll `show interfaces status`, `show interfaces portchannel`, and `show bridge-port-protection PortChannel1001 --verbose`; record transition times.
5. Use PTF to capture protection-path VXLAN packets on the T2-facing uplink port or ports selected by ECMP toward the peer VTEP; capture packets on the peer dT0's server-facing link.
6. From the captures, record the outer source and destination VTEPs, packet-VRF-selected L3VNI, peer RMAC/inner DMAC, and sequence numbers received on the peer server-facing link.
7. Run `config interface startup <server-member-interface>` and capture the returned primary path.
8. Stop the current fixture instance before starting the next address-family variant.

**Validation:**
- The physical member shall transition down and PortChannel1001 shall become operationally down while remaining administratively enabled.
- Software shall set `admin_mode=PROTECTION` and `protection_state=PROTECTION`; the protection NHG shall carry each UDP stream to the physical host through a peer VTEP.
- Protection-path packets shall use an eligible peer VTEP as the outer destination, the packet VRF shall select the L3VNI, and the peer RMAC shall be the inner destination MAC.
- The physical host shall receive each UDP/IPv4 and UDP/IPv6 stream through the protection path.
- Restoring the physical member shall bring PortChannel1001 up and return each stream to the primary path.
- Member failure detection shall be recorded separately from protection convergence and recovery.

#### Test Case 6: LACP timeout

**Objective:** Verify protection after LACP timeout while carrier remains up.

**Test steps:**
1. Start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4`, and record the configured LACP fast timer.
2. Stop LACP PDUs and block data on the tested physical host NIC member using the host-side LACP test control.
3. Poll LACP member and PortChannel state and record transition times.
4. Read the protection state and capture protection-path VXLAN packets.
5. Restore LACP PDUs and data; poll the protection state and capture the UDP/IPv4 stream through recovery.

**Validation:**
- PortChannel1001 shall remain operationally up until the configured LACP timeout expires; it shall then transition down and software shall set `admin_mode=PROTECTION` and `protection_state=PROTECTION`.
- LACP detection loss shall be measured separately from protection convergence loss.

### NHG, Recovery, and Lifecycle

#### Test Case 7: Protection NHG member loss with `protection_state=PRIMARY`


**Test steps:**
1. Keep the local PortChannel1001 up and run downstream traffic through the dT0 under test.
2. On one peer dT0, run `config interface shutdown <peer-server-member-interface>` for the physical member of the PortChannel attached to the same ESI.
3. Run `vtysh -c 'show bgp l2vpn evpn route type ead'` and read the protection NHG membership on the dT0 under test.
4. Capture the test flow; then run `config interface startup <peer-server-member-interface>` and read the NHG membership again.

**Validation:**
- The protection NHG shall not contain the peer whose PortChannel is down.
- `protection_state` shall remain PRIMARY, `admin_mode` shall remain AUTO, and traffic shall continue on the primary path through the protected bridge port.
- Restoring the peer PortChannel shall restore its protection NHG membership.

#### Test Case 8: Protection NHG member loss with `protection_state=PROTECTION`

**Objective:** Verify forwarding through remaining protection NHG members and behavior when the protection NHG has no members.

**Test steps:**
1. Start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4` toward the physical host through the dT0 under test. Verify primary-path delivery and keep the fixture transmitting continuously through local failure, peer failure, and peer restoration. Record transmitted sequence numbers throughout, including while the NHG has no members.
2. Run `config interface shutdown <server-member-interface>` on the dT0 under test, leaving PortChannel1001 administratively enabled, and capture the flow on the peer dT0 and physical host-facing link.
3. Run `config interface shutdown <peer-server-member-interface>` on the peer dT0 for the PortChannel attached to the same ESI.
4. Read the protection NHG and capture the flow on the peer and physical host-facing links.
5. Restore the peer member with `config interface startup <peer-server-member-interface>` and capture the protection NHG and flow again.

**Validation:**
- With at least one protection NHG member, `protection_state=PROTECTION` shall forward traffic to the physical host through an eligible peer VTEP.
- When the protected bridge port is down and the protection NHG has no members, traffic shall be dropped without a loop or stale NHG member.
- Restoring a peer PortChannel shall restore protection NHG membership and protection forwarding.

#### Test Case 9: Revertive recovery and wait-to-restore


**Test steps:**
1. Remove the baseline policy with `config portchannel protection PortChannel1001 delete` and verify `sonic-db-cli CONFIG_DB EXISTS "BRIDGE_PORT_PROTECTION|PortChannel1001"` returns `0`. Create a sparse policy row with `sonic-db-cli CONFIG_DB HSET "BRIDGE_PORT_PROTECTION|PortChannel1001" protection_mode SOFTWARE`. Read it with `sonic-db-cli CONFIG_DB HGETALL "BRIDGE_PORT_PROTECTION|PortChannel1001"` and verify that it contains only `protection_mode=SOFTWARE`; `HEXISTS` for each of `admin_mode`, `revertive`, and `wait_to_restore_time_ms` shall return `0`. Do not use the policy-setting CLI for this step: it materializes defaults instead of leaving the fields absent. Wait for the protected port to report `protection_state=PRIMARY` and `admin_mode=AUTO` before proceeding.
2. Start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4`; run `config interface shutdown <server-member-interface>` and poll `show interfaces portchannel` and `show bridge-port-protection PortChannel1001 --verbose` until the protected PortChannel is operationally down and `protection_state=PROTECTION`. Begin collecting timestamped DUT event evidence before running `config interface startup <server-member-interface>`. Wait for LACP to bring the PortChannel operationally up and record the qualified operational-up event consumed by PortsOrch as `t_up`. Repeatedly run `show bridge-port-protection PortChannel1001 --verbose` until `protection_state=PRIMARY`, and use the timestamped event evidence to record that transition as `t_primary`. Measure recovery as `t_primary - t_up` while capturing traffic; record the startup-to-operational-up LACP recovery separately, not as part of the wait-to-restore interval.
3. Stop the UDP/IPv4 stream. Set `revertive=true` with `config portchannel protection PortChannel1001 revertive true` and `wait_to_restore_time_ms=5000` with `config portchannel protection PortChannel1001 wait_to_restore_time_ms 5000`; read the row with `sonic-db-cli CONFIG_DB HGETALL "BRIDGE_PORT_PROTECTION|PortChannel1001"`.
4. Start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4`; run `config interface shutdown <server-member-interface>` and poll until the protected PortChannel is operationally down and `protection_state=PROTECTION`. Begin collecting timestamped DUT event evidence before running `config interface startup <server-member-interface>`. Wait for LACP to bring the PortChannel operationally up and record this variant's qualified operational-up event as `t_up`, as in step 2. Poll at intervals shorter than 5000 ms and capture the stream to verify `protection_state` remains PROTECTION until `t_up + 5000 ms`, then continue through expiry until it returns to PRIMARY. Record that transition as `t_primary` from timestamped DUT event evidence and measure `t_primary - t_up`; record startup-to-operational-up LACP recovery separately.

**Validation:**
- With recovery fields omitted, the effective defaults shall be `revertive=true` and `wait_to_restore_time_ms=0`; `protection_state` shall return to PRIMARY without a configured wait-to-restore delay.
- With wait-to-restore set to 5000 ms, `protection_state` shall remain PROTECTION until `t_up + 5000 ms`; the PRIMARY transition shall not occur before that deadline.
- Software shall set `admin_mode=PRIMARY`, then return `admin_mode=AUTO`; captures shall show traffic returning to the primary path.
- Both variants shall measure recovery from their qualified operational-up event, using a common DUT time base for `t_up` and `t_primary`. Startup command completion and LACP negotiation shall not define the timer start. If the event timing cannot be established, timer validation shall not be reported as passing.
- Packet loss and recovery timing shall be recorded.

#### Test Case 10: Non-revertive recovery and repeated failure

**Objective:** Verify non-revertive behavior and that a new member failure supersedes pending revertive recovery.

**Test steps:**
1. Set `revertive=false` with `config portchannel protection PortChannel1001 revertive false`; start the PTF runtime traffic fixture with `transport=UDP` and `address_family=IPv4`, run `config interface shutdown <server-member-interface>`, and wait until the protected PortChannel is operationally down and `protection_state=PROTECTION`. Run `config interface startup <server-member-interface>`, wait until it is operationally up, and verify `protection_state` remains PROTECTION while capturing the stream.
2. Stop the streams; run Common Per-Test Teardown, then Common Per-Test Setup.
3. Set `revertive=true` and `wait_to_restore_time_ms=5000` with the CLI commands in Test Case 9; start the UDP/IPv4 runtime fixture, run `config interface shutdown <server-member-interface>`, and wait until the protected PortChannel is operationally down and `protection_state=PROTECTION`. Run `config interface startup <server-member-interface>`, wait for LACP to bring the PortChannel operationally up, and record the qualified operational-up event consumed by PortsOrch as `t_up`. Confirm `protection_state` remains PROTECTION during the wait-to-restore interval. Use timestamped DUT event evidence, not the startup command's return time, to establish the recovery timer's start.
4. After the qualified up event and before its 5000 ms interval expires, run `config interface shutdown <server-member-interface>` again. Wait for and timestamp the second qualified operational-down event as `t_down`; require `0 < t_down - t_up < 5000 ms`, using a common DUT time base. If the event ordering or timing cannot be established, the cancellation scenario has not been exercised and shall not be reported as passing; repeat from Common Per-Test Teardown and Setup before retrying.
5. Keep the member operationally down beyond `t_up + 5000 ms` while the UDP/IPv4 fixture continues transmitting. Poll the protection state and capture the stream to verify it remains on the protection path, with no stale recovery transition to PRIMARY after the original timer deadline.

**Validation:**
- With `revertive=false`, `protection_state` shall remain PROTECTION after the protected bridge port recovers.
- The cancellation check requires a qualified operational-up event followed by a qualified operational-down event within 5000 ms, with protection still selected before the second failure. A shutdown before operational-up or an unverified event sequence shall not count as a pass.
- A second member failure during wait-to-restore shall keep `protection_state=PROTECTION` past `t_up + 5000 ms`; stale recovery work shall not select PRIMARY while the member is down.
- Traffic shall not remain pinned to a failed primary path.

**System-test limitation:** The HLD guarantees no observable dwell time between the recovery override to `admin_mode=PRIMARY` and its release to AUTO; `wait_to_restore_time_ms` delays entry into PRIMARY, not the release to AUTO. CLI polling cannot deterministically inject a failure in that interval. Coverage of a new failure after PRIMARY is committed but before AUTO release requires a separate orchestrator unit test with deterministic synchronization before AUTO release; it is not claimed by this system test.

#### Test Case 11: Restart, removal, and cleanup


**Test steps:**
1. With the protection binding active, start the PTF runtime traffic fixture and keep it running while `fpmsyncd` is stopped and restarted; capture traffic throughout the restart and route resynchronization, and inspect member/group/binding state.
2. Restart the SWSS Docker container; this restarts `orchagent` and the other SWSS services. Inspect the protection binding and NHG reference and capture traffic after the container returns.
3. While PortChannel1001 is up, run `vtysh -c 'configure terminal' -c 'interface PortChannel1001' -c 'no evpn mh bridge-port-protection'`.
4. Poll the binding, NHG, and bridge-port protection state after feature removal.

**Validation:**
- During the isolated `fpmsyncd` restart, existing traffic shall continue on the primary path without an unintended protection-state transition; after restart, route synchronization and protection NHG membership shall remain correct while `orchagent` stays running.
- After the SWSS Docker container restart, the BPP policy, binding, and NHG shall be restored without stale IDs or an unintended transition from the primary path.
- Feature removal shall clear the protection attribute before releasing the NHG reference.
- No stale protection forwarding shall remain.

### Northbound and East-West Traffic Tests

#### Test Case 12: Northbound traffic and server LAG hashing

**Objective:** Verify northbound IPv4 unicast forwarding and that server LAG hashing uses only active host links after one dT0 link fails.

**Setup:** Configure both physical-host NIC links in the 802.3ad bond, one link to each dT0. Configure an IPv4 remote endpoint reachable through the existing northbound IPv4 unicast route in the default VRF via T2. Record the route and both member transmit counters. On the physical host, save the original policy name from `cat /sys/class/net/<host-bond>/bonding/xmit_hash_policy`, then run `sudo ip link set dev <host-bond> type bond xmit_hash_policy layer3+4` and read it back to verify `layer3+4` is active. Substitute the testbed's bond name for `<host-bond>`. Require host support for this policy; do not evaluate port-varying flows with `layer2` or `layer2+3`. Keep packets below the path MTU to avoid IP fragmentation. Common Per-Test Teardown shall restore the saved policy.

**Test steps:**
1. Generate at least 64 host-originated TCP/IPv4 and UDP/IPv4 streams with distinct 5-tuples by invoking the runtime traffic fixture from the physical host bond to the remote endpoint.
2. Record each host bond member's `ip -s link` transmit counters and use PTF to capture packets on the mapped server-facing and T2-facing uplink ports.
3. Use PTF to capture the routed packets on the T2-facing uplink port or ports selected by ECMP; verify they leave without VXLAN encapsulation.
4. Run `config interface shutdown <server-member-interface>` on one dT0 while the host-originated flows continue.
5. Read the failed dT0 PortChannel state, record per-member counters, and use PTF to capture the routed, unencapsulated packets on the surviving T2-facing uplink port or ports selected by ECMP.
6. Capture both fixture-generated stream types at the remote endpoint.
7. Run `config interface startup <server-member-interface>`; record bond counters and use PTF to capture the routed packets on the T2-facing uplink port or ports selected by ECMP through link recovery.

**Validation:**
- TCP and UDP streams shall be distributed approximately evenly across the two active bond members; per-member counters shall be recorded to verify balance.
- The dT0 shall route northbound streams through the default VRF's IPv4 unicast route, without VXLAN encapsulation.
- After one link fails, that bond member's transmit counter shall stop increasing and all streams shall use the remaining member.
- The remote endpoint shall continue receiving the streams; after recovery, the failed member shall rejoin the bond and be eligible for hashing.
- Host-originated streams shall use normal northbound routing and shall not use the BPP protection path.

#### Test Case 13: East-west routed traffic to a protected host


**Setup:** Server-0 and Server-1 shall each be multihomed to both dT0s using an 802.3ad bond, with separate server-facing PortChannels and ESIs. Configure both servers and the anycast SVI gateways in the default VRF, with IPv4/IPv6 routes so traffic between the servers follows the routed anycast-gateway path. On Server-0, save the original bond transmit-hash policy, set and verify `layer3+4` using the host commands in Test Case 12, and keep packets below the path MTU. Common Per-Test Teardown shall restore the saved policy. From Server-0, resolve Server-1 and send a probe to establish the routed path.

**Test steps:**
1. Start continuous sequenced TCP/IPv4 and UDP/IPv4 traffic from Server-0 to Server-1 using multiple distinct 5-tuples. Use PTF captures and per-member counters to confirm before failure that traffic reaches both dT0s and Server-1 receives it through the local PortChannels.
2. On the destination-side dT0 that will be tested, run `config interface shutdown <server-member-interface>` for Server-1's member. Keep the traffic running; verify the protected PortChannel becomes operationally down and `protection_state=PROTECTION`.
3. Use PTF to capture the affected dT0's protection VXLAN packet to the peer and correlate it to the Server-0-to-Server-1 flow by its inner IP 5-tuple and sequence data. Capture the decapsulated flow on Server-1's surviving PortChannel.
4. Run `config interface startup <server-member-interface>` on the affected dT0; keep traffic running and capture the return to local delivery as `protection_state` returns to PRIMARY.

**Validation:**
- Before failure, captures shall confirm that traffic is distributed across links to both dT0s.
- Server-1 shall receive every sequenced packet with zero packet loss during steady-state primary and protection forwarding. Measure packet loss and convergence separately across failure and recovery transitions and compare them with the agreed software-mode packet-loss and convergence budget. Until that budget is agreed, report the transition measurements without declaring transition-budget compliance.
- Traffic entering the affected dT0 while Server-1's member is down shall use the BPP protection path; captures shall show the affected dT0 as the outer source VTEP, the peer as the outer destination VTEP, the packet-VRF-selected L3VNI, and the peer RMAC as the inner destination MAC.
- The peer dT0 shall decapsulate and deliver the flow to Server-1 over its surviving PortChannel. After recovery, the affected dT0 shall return to PRIMARY and deliver locally without BPP VXLAN encapsulation.
- `protection_state` shall be PROTECTION while the Server-1 bridge port is down and PRIMARY after recovery.
- Packets shall not be bridged directly between server ports or re-tunneled into a loop.

## Open Items

- The [sonic-utilities PR #5003](https://github.com/sonic-net/sonic-utilities/pull/5003) currently defaults `revertive` to `false`, while the HLD specifies `true`; this discrepancy shall be resolved before Test Case 1 is treated as passing.
- A software-mode packet-loss and convergence budget shall be agreed before test execution.
- FDB-flush behavior when protection is withdrawn while the protected bridge port is down shall be resolved before a dedicated test case is added.

## References

- [Bridge-Port Protection HLD](https://github.com/pbrisset/SONiC/blob/bef148a8e02acf95edd694da481c4c8212d75ee6/doc/vxlan/EVPN/BridgePort_Protection_HLD.md)
- [sonic-mgmt EVPN-MH test-plan PR #26752](https://github.com/sonic-net/sonic-mgmt/pull/26752)
