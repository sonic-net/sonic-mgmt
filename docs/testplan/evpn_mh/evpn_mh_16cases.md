# EVPN multihoming native-PTF test plan

## Scope

This plan adds exactly sixteen EVPN multihoming functional tests to
`sonic-mgmt`. The tests translate the packet intent of a legacy hardware
traffic-generator suite to native PTF/Scapy. They cover deterministic forwarding, replication,
DF/NDF suppression, ECMP distribution, bounded loss, duplicate detection, and
recovery. They do not claim line-rate, latency, microburst, congestion, scale,
or capacity equivalence with a hardware traffic generator.

The tests run only on the existing `dualtor-aa` topology. The topology YAML is
a read-only dependency: this feature does not add a topology, topology alias,
EOS template, inventory registration, or shared `vm_topology.py` behavior.

## Existing-topology role binding

`dualtor-aa` supplies two SONiC DUTs, four T1 neighbor VMs, paired PTF server
links, and a shared VM/PTF backplane. The feature fixture assigns the following
temporary roles:

| Test role | Existing resource |
| --- | --- |
| EVPN-MH PE 1 | upper ToR |
| EVPN-MH PE 2 | lower ToR |
| Independent underlay paths | `ARISTA01T1`, `ARISTA02T1`, `ARISTA03T1` |
| Remote EVPN/VXLAN peer | `ARISTA04T1` |
| H1 / ES-H1 LACP leg A | disabled paired server link 0, pinned upper-only |
| SH1 single-homed access | active-active paired server link 1, temporarily pinned upper-only |
| H2 / ES-H2 LACP leg A | disabled paired server link 25, pinned upper-only |
| H2 / ES-H2 LACP leg B | disabled paired server link 26, pinned lower-only |
| H1 / ES-H1 LACP leg B | disabled paired server link 27, pinned lower-only |
| H3 remote L2 endpoint | isolated tagged PTF backplane attachment |
| H4 remote routed endpoint | isolated tagged PTF backplane attachment |

Interface aliases, bridge members, PTF port numbers, neighbor addresses, and
current DF/NDF roles are discovered at runtime. The numeric paired-server link
identities above are stock semantic resources, not platform port names.
H1 and H2 are separate Ethernet Segments with distinct ESIs, PortChannels,
system MACs, and PTF bonds. Both participate in VLAN10/L2VNI5010 so a remote
BUM verdict must resolve and grade the DF/NDF state of each segment
independently. SONiC derives each Type-3 ESI with `auto-system-mac`; the service
model records the expected PortChannel-derived values (`...:69` for H1 on
PortChannel105 and `...:64` for H2 on PortChannel100) for control-plane checks.

```text
                  ARISTA01T1   ARISTA02T1   ARISTA03T1
                    path 1       path 2       path 3
                         \          |          /
                    +-----+---------+---------+-----+
                    |                               |
                upper ToR <--- EVPN ES-H1 ---> lower ToR
                  VTEP 1  \---- H1 LACP -------/  VTEP 2
                    |      \                   /
                   SH1      +-- H2 LACP ------+
                         EVPN ES-H2 (independent DF)

       tagged shared backplane
       H3 VLAN10 ---- ARISTA04T1 ---- H4 VLAN20
                     remote VTEP
```

The stock direct ARISTA04T1-to-DUT links must not become a VXLAN shortcut. The
feature fixture uses tagged VLAN 4094 on the existing shared backplane for
A01--A04 transit and owns the exact UDP/4789 OVS flows needed to make
ARISTA01T1 through ARISTA03T1 the three graded paths.

## Reversible fixture lifecycle

The module fixture performs these operations transactionally:

1. Require the exact `dualtor-aa` topology, two DUTs, four expected neighbors,
   disabled pairs 0/25/26/27, and stock active-active pair 1.
2. Verify the read-only prerequisites before mutation: four reachable EOS
   hosts with parseable EVPN show commands, two model-driven SONiC images,
   exact PTF/OVS bindings, and a provable MUX service state. Configuration-path
   syntax and image feature support are then proved during guarded setup under
   the already-created EOS snapshots and SONiC checkpoints; failure is explicit
   and triggers rollback rather than a target-test skip.
3. Checkpoint both untouched stock DUT configurations and capture their BGP,
   SWSS, and critical-service baseline before EOS changes any stock peer.
   Remove stale suite-owned PTF objects, require the selected links/backplane
   operational, and normalize them to the explicit state described below.
   Pair 1 must match the expected stock Vlan1000/MUX/ACL ownership before the
   fixture removes only those conflicts under checkpoint protection.
4. Snapshot exact OVS bridge flows and MUX-simulator state. Stop only the
   task-owned MUX-simulator control path, pin links 0/1/25/26/27 to their
   intended DUTs, and install only the temporary UDP/4789 flows on the selected
   DUT/T1 bridges.
5. Snapshot all four EOS running configurations, then configure the reversible
   EOS transit/EVPN/VXLAN state under that recovery guard.
6. Configure model-driven SONiC EVPN-MH service state. Do not mutate an
   uncheckpointed SONiC FRR file.
7. Create independent H1 and H2 Linux 802.3ad bonds plus the SH1 interface and
   isolated tagged PTF backplane VLAN endpoints for H3 and H4; prove every
   member reaches only its intended DUT and that SH1 is never a bond slave.
8. Establish a control-plane and native-PTF baseline before yielding to tests.
9. On success, assertion failure, setup failure, or a pytest-managed interrupt
   that runs fixture finalizers, execute the enclosing cleanup guards and every
   registered rollback action in reverse order. A hard process/host loss is
   outside this guarantee and requires the preserved recovery artifacts.
10. Restore EOS before the SONiC checkpoint finalizer compares the original
    stock BGP/SWSS baseline, then prove the original DUT, neighbor, OVS, and
    simulator state is restored.
    On PTF, prove feature bonds/macvlans are absent, their physical members are
    unmastered and administratively up, the backplane is up, and `ptf_nn_agent`
    has been restarted. Preserve a failed DUT checkpoint or EOS flash snapshot
    for recovery instead of deleting the last known-good artifact.

No teardown step assumes that all setup steps completed. An enclosing
checkpoint, full EOS snapshot, or pre-resolved OVS snapshot owns state before
the first related mutation; fine-grained callbacks are registered where that
mechanism is used. The PTF contract is a deliberate normalized end-state rather
than restoration of an arbitrary PTF prestate; the exact before/after guarantee
applies to DUT, EOS, OVS and MUX state.

## Packet and verdict model

Traffic profiles are vendor-neutral YAML compiled to the existing PTF remote
test. Every flow declares:

- transmit endpoint and packet fields;
- deterministic packet count, pacing, and optional varied fields;
- one or more accepted receive groups;
- forbidden endpoints;
- maximum loss and duplicate count;
- optional minimum distribution per accepted path; and
- VLAN tagging or tag translation required by backplane endpoints.

Continuous traffic uses a unique remote job directory, an explicit receive
barrier, monotonic sequence numbers, bounded start/stop/kill behavior, and a
machine-readable result. A controller thread alone is not accepted as evidence
that traffic is still running. Clean start enumerates only exact suite-owned
continuous-job names, proves a live process group's full command line contains
the exact native PTF test and job/result/log paths before signalling it, and
removes the directory only after bounded shutdown. Every launch persists a
random job cookie, Linux process start time, and proven `PGID == PID` before a
controller-created launch gate permits PTF to execute. Both fresh and
rediscovered jobs must match that identity and the original group-leader
command row on every probe and signal. Only the proven process group is ever
signalled; there is no positive-PID fallback. An ambiguous name, PID, process
ownership result, or liveness result is preserved and fails preflight.

Control-plane counters support the verdict but never replace packet capture.
The tests require expected delivery and forbidden-copy checks.

## Exact testcase inventory

### Local bias and BUM

1. `test_local_bias`
   - Send local unknown-unicast from upper-ToR SH1 toward both ES-H1 and
     ES-H2, while also requiring the remote H3 copy.
   - Require both upper local-bias legs, forbid both lower overlay copies,
     move the ES-H2 DF with preference, repeat the forwarding proof, and
     restore the original DF.
2. `test_remote_broadcast_traffic`
   - Send remote VLAN10 broadcast H3 toward SH1, H1, and H2.
   - Require SH1 plus exactly one DF copy per ES, forbid both NDF legs, and
     reject duplicate copies.
3. `test_remote_multicast_traffic`
   - Send Ethernet multicast H3 to both Ethernet Segments and SH1.
   - This is L2 BUM behavior, not multicast routing; require single-copy DF
     delivery and NDF suppression.
4. `test_unknown_unicast`
   - Send an intentionally unknown VLAN10 destination from H3.
   - Require ingress replication through VXLAN, SH1 delivery, and exactly one
     delivery from each independent ES.

### L2, L3, and ECMP

5. `test_inter_subnet_ping`
   - Exercise bidirectional IPv4 H1/H4 and H2/H4 routing.
   - Require exact Type-5, neighbor, host-route, VXLAN, and two-VTEP aliasing
     evidence plus end-to-end packets.
6. `test_intra_subnet_ping`
   - Exercise H1/H2 and SH1/H2 known unicast plus selected H1/H2-to-H3
     unknown/BUM traffic. The SH1 pair is also the post-restore proof reused by
     `test_vlan_member_flap`.
   - Require Type-2/FDB state, L2 aliasing, VLAN isolation, and single-copy
     remote delivery.
7. `test_remote_unicast_for_ecmp`
   - Send exactly 500 deterministic varied UDP flows H3 to H2.
   - Require meaningful use of both VTEPs, then shut one access leg and require
     complete delivery through the surviving VTEP with no forbidden copy.

### PortChannel, VLAN, and underlay disruption

8. `test_portchannel_deconf`
   - Remove one peer's ES system MAC, ESI, VLAN membership, member, and
     PortChannel; prove absence; recreate exactly; prove DF and traffic recovery.
9. `test_portchannel_flap`
   - Shut each complete H2 PortChannel in turn.
   - Grade DF takeover and traffic during each outage, then verify restoration.
10. `test_interface_to_spine_flap`
    - Reduce one PE's installed paths `3 -> 2 -> 1`, grade every stage, and
      restore `1 -> 3` with exact next-hop counts.
11. `test_vlan_member_flap`
    - Remove and re-add SH1's VLAN membership while leaving the physical link
      present. Require the expected outage and single-copy recovery.
12. `test_portchannel_shut_noshut`
    - Save ES-H2 DF preferences, make the upper ToR deterministic DF, and create
      a temporary tagged VLAN20 orphan on upper-only SH1.
    - Route it to H2 through the anycast gateway, shut the current DF's physical
      H2 member, prove peer/tunnel failover, restore, prove local re-homing, and
      restore the original DF preferences.
13. `test_portchannel_member_flap`
    - Run paced sequence-numbered H3-to-H2 traffic while flapping one physical
      member at a time. Require a pre-event receive barrier and PTF marker
      acknowledgement, then grade an either-leg-valid down-transition window,
      a survivor-only/forbidden-leg steady-outage window, and an either-leg-valid
      recovery window. Bound loss and duplicates in every phase and prove traffic
      again after each member returns.

### Persistence, reboot, and IPv6

14. `test_config_reload`
    - Establish routed and BUM baselines, save fixture-owned configuration, and
      reload the current DF.
    - Require the reloaded DUT itself to recover ES, DF/NDF, EVPN, VNI, Type-5,
      and pre/post packet parity without compatibility re-provisioning.
15. `test_continuous_traffic_reboot_df`
    - Corresponds to the legacy `test_continous_traffic_reboot_df` case name.
    - Start sequence-numbered BUM/unknown and routed traffic, cross a positive
      receive barrier, then cold-reboot the current DF.
    - Require NDF takeover, bounded event loss/duplicates, an explicit recovery
      deadline, DUT recovery, and restored baseline.
16. `test_ipv6_traffic`
    - Exercise IPv6 H1/H4, H2/H4, H3/H2 ECMP, NDP, Type-2/Type-5, and genuine
      Ethernet frames carrying IPv6 broadcast/unknown payloads.
    - Require exact IPv6 packet matching, aliasing, DF suppression, and cleanup.

## Independent-run contract

Each test follows the same seven stages:

1. establish topology and control-plane baseline;
2. capture relevant state;
3. run baseline traffic;
4. apply and prove the event;
5. grade control plane and packets during the event;
6. restore in a `finally` path; and
7. prove convergence, traffic recovery, and baseline restoration.

No test relies on a fixed DF. Tests may run individually or in any order.

## Qualification layers

Static parser/unit tests, pytest collection, virtual deployment, functional PTF
traffic, and hardware/performance qualification are separate proof layers.

The feature-local unit contracts run without loading the integration fixtures:

```bash
python3 -m pytest --noconftest \
  --confcutdir=tests/evpn_mh/unit_tests \
  tests/evpn_mh/unit_tests/ -q
```

The upstream acceptance target is:

```text
16 unique tests collected
16 tests executed
16 tests passed
0 unexpected skips
0 xfails or xpasses
0 parametrized count inflation
2 consecutive clean full-suite runs
2 successful teardown and health checks
clean upstream-safety audit
```

Virtual PTF success does not establish ASIC/PHY, line-rate, latency,
congestion, scale, or hardware-specific reboot performance.
