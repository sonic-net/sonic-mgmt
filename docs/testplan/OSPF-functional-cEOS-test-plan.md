# OSPF Functional Test Plan (SONiC DUT with EOS/vEOS/cEOS Neighbors)

## Test Plan Revision History

| Rev | Date       | Author         | Change Description |
| --- | ---------- | -------------- | ------------------ |
| 1   | 06/03/2026 | Adarsh Patil(adarshbheemr@marvell.com) | Initial version for tests/ospf/test_ospf_functional.py |

## Objective
Validate OSPFv2 functional behavior on SONiC DUT with EOS/vEOS/cEOS neighbors for t0/t1 topologies.

## Scope
- Module under test: tests/ospf/test_ospf_functional.py
- Topology: t0, t1
- Focus: adjacency behavior, auth, area types (stub/NSSA), LSDB, route installation, recovery/timers

## Pre-Conditions
1. DUT is reachable and supports `vtysh` OSPF commands.
2. EOS/vEOS/cEOS neighbors are reachable via Ansible inventory.
3. Topology is `t0` or `t1` and links are operational.
4. `ospf_setup` fixture successfully enables OSPF and at least one Full adjacency.

## Test Cases and Detailed Validation

### TC1 - test_ospf_router_id_preference
Objective: Verify explicit router-id configuration takes precedence over auto-selected router-id.
Why this matters: Stable router-id is required for predictable OSPF identity and LSDB behavior.
Steps:
1. Configure manual OSPF router-id on DUT.
2. Clear OSPF process to force re-initialization.
3. Check `show ip ospf` for configured router-id.
4. Remove manual router-id and clear process in cleanup.
Expected Result: DUT reports the configured router-id while the override is present.

### TC2 - test_ospf_and_static_preference
Objective: Verify route selection prefers static route over OSPF for the same prefix.
Why this matters: Correct administrative distance behavior is required for deterministic failover and policy.
Steps:
1. Advertise a test prefix from neighbor via OSPF.
2. Add the same prefix as static route on DUT.
3. Validate route lookup prefers static entry.
4. Remove static route and neighbor advertisement.
Expected Result: Static route is selected while both routes are present.

### TC3 - test_ospf_route_in_rib_and_fib
Objective: Verify OSPF-learned routes are installed in both control plane and forwarding path.
Why this matters: A route seen in protocol output must also be usable for forwarding.
Steps:
1. Configure neighbor loopback and advertise it via OSPF.
2. Verify prefix appears in DUT OSPF RIB output.
3. Verify prefix resolves with next hop in route lookup.
4. Remove test loopback and network statement.
Expected Result: Prefix is visible in OSPF RIB and resolvable in forwarding route output.

### TC4 - test_ospf_mtu_mismatch_breaks_adjacency
Objective: Verify adjacency fails when MTU mismatch is enforced.
Why this matters: MTU validation is a common real-world cause of OSPF ExStart/Exchange issues.
Steps:
1. Select an active DUT-neighbor interface.
2. Remove `ip ospf mtu-ignore` on DUT interface.
3. Lower DUT interface MTU to create mismatch.
4. Verify selected neighbor leaves Full state.
5. Restore MTU and mtu-ignore configuration.
Expected Result: Neighbor drops out of Full while mismatch is active and recovers after rollback.

### TC5 - test_ospf_md5_authentication
Objective: Verify matching MD5 authentication restores/maintains adjacency.
Why this matters: Authentication interoperability is required in secured deployments.
Steps:
1. Resolve DUT and EOS neighbor facing interfaces.
2. Configure matching MD5 key/auth mode on both sides.
3. Verify adjacency reaches Full.
4. Remove auth and key from both sides.
Expected Result: Adjacency is Full with matching auth settings.

### TC6 - test_ospf_external_type5_redistribute
Objective: Verify redistributed static routes are advertised as Type-5 LSAs and installed on DUT.
Why this matters: External route propagation is central to OSPF inter-domain behavior.
Steps:
1. Add static route on neighbor.
2. Enable `redistribute static` under neighbor OSPF.
3. Verify DUT external LSDB contains prefix.
4. Verify DUT OSPF route table contains prefix.
5. Remove redistribution and static route.
Expected Result: Prefix appears in external LSDB and OSPF route table while redistribution is enabled.

### TC7 - test_ospf_stub_area_no_type5
Objective: Verify Type-5 externals are suppressed in stub area operation.
Why this matters: Stub area behavior prevents flooding of external LSAs by design.
Steps:
1. Move one DUT-neighbor link from area 0 to area 2.
2. Configure area 2 as stub on DUT and neighbor.
3. Verify adjacency reaches Full in the new area.
4. Verify self-originated external LSDB does not show Type-5 entries.
5. Restore original area-0 configuration.
Expected Result: No Type-5 external entries are present for the stub area validation point.

### TC8 - test_ospf_nssa_type7
Objective: Verify NSSA external routes are represented as Type-7 LSAs.
Why this matters: NSSA behavior differs from normal areas and must be validated separately.
Steps:
1. Move one link to area 1.
2. Configure area 1 as NSSA on DUT and neighbor.
3. Inject static route on neighbor and redistribute.
4. Verify DUT NSSA external LSDB contains prefix.
5. Remove test route/redistribution and restore area 0.
Expected Result: Prefix is present in NSSA external database as Type-7 during test.

### TC9 - test_ospf_passive_interface
Objective: Verify passive interface blocks adjacency formation and recovery works after revert.
Why this matters: Passive interface is commonly used to advertise networks without forming neighbors.
Steps:
1. Resolve DUT interface connected to selected neighbor.
2. Configure `passive-interface` and clear OSPF process.
3. Verify selected adjacency is not Full and the interface subnet is still present as a stub 
link in the DUT's self-originated Type-1 Router LSA.
4. Remove passive-interface and verify Full recovery.
Expected Result: Adjacency drops while passive is configured and returns after removal.

### TC10 - test_ospf_neighbor_count
Objective: Verify minimum stable convergence level in the topology.
Why this matters: Large virtual topologies may not always converge all peers simultaneously.
Steps:
1. Derive expected neighbor count from fixture data.
2. Calculate majority threshold (`expected/2`).
3. Verify Full neighbors reach threshold.
Expected Result: Full neighbor count reaches or exceeds majority threshold within timeout.

### TC11 - test_ospf_dr_bdr_election
Objective: Verify DUT interfaces report valid steady-state OSPF network roles/states.
Why this matters: Different link types show different state semantics (P2P vs DR/BDR).
Steps:
1. Put a DUT–neighbor link into ip ospf network broadcast.
2. Priority: set higher ip ospf priority on one router → verify it becomes DR, next-highest becomes BDR (show ip ospf neighbor/interface).
3. Router-id tie-break: set equal priorities → verify higher router-id wins DR.
4. Set DUT priority 0 → verify it's excluded and a new DR is elected.
Expected: both priority and router-id tie-break paths produce correct DR/BDR.

### TC12 - test_ospf_router_lsa_self_originated
Objective: Verify DUT originates Router LSA entries.
Why this matters: Self-originated Router LSA is foundational for SPF topology computation.
Steps:
1. Run `show ip ospf database router self-originate`.
2. Verify router LSA section markers are present.
Expected Result: Output contains Router Link States with link-state identifiers.

### TC13 - test_ospf_loopback_advertised
Objective: Verify DUT originates external LSA when static redistribution is enabled.
Why this matters: Confirms DUT-side redistribute-static path and LSDB programming.
Steps:
1. Add DUT static /32 route to Null0.
2. Enable `redistribute static` under DUT OSPF.
3. Verify self-originated external LSDB contains the prefix.
4. Disable redistribution and remove static route.
Expected Result: DUT external self-originated LSDB shows test prefix while redistribution is active.

### TC14 - test_ospf_clear_process_recovers_full
Objective: Verify adjacencies recover after OSPF process restart.
Why this matters: Operational recovery after daemon restart is a key resiliency check.
Steps:
1. Record baseline Full neighbor count.
2. Execute `clear ip ospf process`.
3. Verify Full neighbor count returns to baseline.
Expected Result: Neighbor count returns to pre-clear baseline within timeout.

### TC15 - test_ospf_hello_dead_mismatch_breaks_adjacency
Objective: Verify timer mismatch causes adjacency failure and recovery after rollback.
Why this matters: Timer mismatch is a common configuration fault and must fail safe.
Steps:
1. Configure non-default hello/dead intervals on DUT interface.
2. Verify selected adjacency leaves Full state.
3. Remove timer overrides.
4. Verify selected adjacency returns to Full.
Expected Result: Adjacency drops during mismatch and recovers after defaults are restored.

### TC16 - test_ospf_reference_bandwidth_affects_cost
Objective: Verify reference-bandwidth configuration is applied to OSPF process config.
Why this matters: Reference bandwidth influences interface cost calculation and path selection.
Steps:
1. Use two parallel DUT→neighbor links to the same destination.
2. Set auto-cost reference-bandwidth 1000000.
3. Verify command in `show running-config ospfd`.
4. Change cost/speed on one link (via bandwidth/speed or ip ospf cost) so the two links differ in OSPF cost.
5. Verify recomputed cost in show ip ospf interface.
6. Verify show ip route ospf installs the lower-cost (higher-speed) link, with failover when it's penalized.

Expected Result: Running config contains and then removes the configured auto-cost line and cost recomputes 
per reference-bandwidth and the higher-speed link is chosen.

### TC17 - test_ospf_default_information_originate
Objective: Verify DUT can originate default route into OSPF.
Why this matters: Default route advertisement is common in edge/core role designs.
Steps:
1. Enable `default-information originate always` on DUT.
2. Verify neighbor sees `0.0.0.0/0` in OSPF routes.
3. Remove default-information originate.
Expected Result: Neighbor learns OSPF default route while feature is enabled.

### TC18 - test_ospf_auth_mismatch_breaks_adjacency
Objective: Verify authentication mismatch prevents stable adjacency.
Why this matters: Ensures protocol security checks are enforced and misconfigurations are detected.
Steps:
1. Configure MD5 auth only on DUT side.
2. Verify selected adjacency does not stay Full.
3. Verify the syslog messages for auth-failure signature
4. Remove DUT auth settings.
5. Verify adjacency returns to Full.
Expected Result: Adjacency fails during mismatch and restores after configuration rollback.

### TC19 - test_ospf_redistribute_connected
Objective: Verify DUT connected subnets are advertised into OSPF as external routes when redistribute 
connected is enabled, and withdrawn when disabled.
Why this matters: Redistributing connected interfaces is a common way to inject local subnets into OSPF
without per-network statements; withdrawal on disable must be clean.
Steps:
1. Pick a DUT connected subnet not already covered by a network statement (e.g. a Loopback or unused L3 
interface with a known /24).
2. On DUT OSPF: redistribute connected.
3. On the neighbor, verify the connected prefix appears in the OSPF route table 
(show ip ospf route / show ip route ospf) as an external (E2) route.
4. Remove no redistribute connected on DUT.
5. Verify the prefix is withdrawn from the neighbor's OSPF routes and from the DUT external LSDB.
Expected Result: Connected prefix is learned by the neighbor as an OSPF external route and present as a 
self-originated Type-5 LSA while redistribution is enabled, and fully withdrawn after it is disabled.

###TC20 - test_ospf_spf_throttle_timers
Objective: Verify SPF throttle timers (timers throttle spf) are applied and govern SPF scheduling.
Steps:
1. timers throttle spf 200 400 5000.
2. Verify line in show running-config ospfd.
3. Verify values in show ip ospf (SPF delay/hold fields).
4. Trigger a topology change, confirm OSPF stays stable and SPF runs are scheduled.
5. no timers throttle spf.
Expected: configured values appear, SPF runs under new delay/hold, defaults restored.

###TC21 - test_ospf_lsa_throttle_timers
Objective: Verify LSA throttle / min-arrival timers are applied.
Steps:
1. timers throttle lsa all 500 and timers lsa min-arrival 2000.
2. Verify both in show running-config ospfd.
3. Verify values in show ip ospf.
4. Repeatedly add/remove a redistributed /32; confirm OSPF stable and adjacencies stay Full.
5. no timers throttle lsa all, no timers lsa min-arrival.
Expected: values appear, adjacencies stay Full under repeated LSA changes, defaults restored.

###TC22 - test_ospf_type2_network_lsa
Objective: Verify a Type-2 Network LSA is originated on a multi-access segment with an elected DR.
Steps:
1. Configure ip ospf network broadcast on a DUT–neighbor link (P2P /31 links don't create Type-2).
2. Let DR/BDR election complete.
3. Run show ip ospf database network on DUT.
4. Revert interface to default network type.
Expected: A Type-2 Network LSA for the segment, originated by the DR, is present.

###TC23 - test_ospf_type3_summary_lsa
Objective: Verify Type-3 Summary LSA is generated across areas by the ABR.
Steps:
1. Use the existing multi-area setup (area 0 + area 1/2).
2. Advertise an intra-area prefix in one area.
3. Run show ip ospf database summary and confirm it appears as Type-3 in the other area.
4. Remove the test prefix.
Expected: Intra-area prefix appears as a Type-3 summary in the adjacent area.

###TC24 - test_ospf_type4_asbr_summary_lsa
Objective: Verify Type-4 ASBR-Summary LSA describing the ASBR is originated by the ABR.
Steps:
1. Place the ASBR (redistributing static) in a non-backbone area.
2. Enable redistribute static on the ASBR.
3. Run show ip ospf database asbr-summary on the DUT in another area.
4. Remove redistribution.
Expected: A Type-4 ASBR-Summary LSA referencing the ASBR router-id is present.


## Pass Criteria
1. All listed test cases pass on supported topology.
2. Fixture teardown restores baseline configuration state.

## Risks and Known Limits
1. Neighbor convergence variability: In larger virtual topologies, not all neighbors may reach Full at exactly the same time. The plan validates functional behavior with reasonable wait windows and threshold-based checks where appropriate.
2. Timing sensitivity: Tests that clear OSPF process or change interface/timer settings can be sensitive to environment load. Additional convergence time may be needed on busy testbeds.
3. CLI/output differences by image: Some FRR/EOS builds present different show command formatting. Validation relies on stable keywords and route/LSDB presence checks to reduce parser fragility.
4. Topology dependency: This plan is intended for t0/t1 topologies with EOS/vEOS/cEOS neighbors. Behavior may differ on non-standard labs or partially connected testbeds.
5. Configuration side effects: Cases intentionally mutate OSPF and interface settings. Reliable teardown and config restoration are mandatory; unexpected fixture interruption can leave transient state until cleanup completes.
