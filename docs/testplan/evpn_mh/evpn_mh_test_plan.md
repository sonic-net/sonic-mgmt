# EVPN multihoming native-PTF test plan

## Scope

This plan adds baseline EVPN multihoming functional coverage to `sonic-mgmt`.
The baseline can be extended with additional scenarios. The tests translate
the packet intent of a legacy hardware traffic-generator suite to native
PTF/Scapy. They cover deterministic forwarding, replication,
DF/NDF suppression, ECMP distribution, bounded loss, duplicate detection, and
recovery. They do not claim line-rate, latency, microburst, congestion, scale,
or capacity equivalence with a hardware traffic generator.

The tests run only on the existing
[`dualtor-aa`](../../../ansible/vars/topo_dualtor-aa.yml) topology. The topology
YAML is a read-only dependency: this feature does not add a topology, topology
alias, EOS template, inventory registration, or shared `vm_topology.py`
behavior.

## Optional MAC-over-FPM execution mode

The same 16 test functions can qualify either the default kernel MAC-sync path
or the MAC-over-FPM path. MAC-over-FPM is strictly opt-in:

```text
# Existing/default execution
pytest tests/evpn_mh

# Explicit MAC-over-FPM execution
pytest tests/evpn_mh --evpn-mh-mac-over-fpm
```

Without `--evpn-mh-mac-over-fpm`, the suite does not write `FDB_SYNC`, save a
new MAC-sync setting, or restart BGP for mode selection. Preflight requires the
two ToRs to be in the default kernel mode so that an FPM-configured testbed is
not reported as a kernel-mode result.

An image whose `DEVICE_METADATA|localhost/subtype` is `L3EvpnMH` forces the
FPM path. It is therefore accepted only for the flagged execution; the default
kernel-mode invocation fails preflight instead of silently running in FPM.

With the flag, preflight first verifies that both SONiC images provide the
MAC-sync CLI, Zebra external-MAC support, the SONiC FPM dataplane module,
`fpmsyncd`, `fdbsyncd`, and FPM socket inspection. The suite then performs this
checkpoint-owned setup on both ToRs before any topology mutation:

1. configure `FDB_SYNC|global/mac_sync_mode=fpm` through
   `config fdb mac-sync-mode fpm` on both ToRs;
2. prove both CONFIG_DB writes before restarting either ToR;
3. save the configuration so config reload and cold reboot retain the mode;
4. restart the BGP service so its container re-renders Zebra's arguments;
5. require Zebra and `fpmsyncd` in the BGP container and `fdbsyncd` in the
   SWSS container to be running;
6. require Zebra to use `dplane_fpm_sonic` and `--kernel-mac-ext-learn`;
7. require CONFIG_DB to report `fpm` and require the live Zebra to `fpmsyncd`
   connection on TCP port 2620; and
8. only then continue with EVPN-MH provisioning and packet tests.

An explicitly requested FPM run fails before functional test execution when
either image lacks a required capability or either ToR fails readiness. It
never skips or silently falls back to kernel mode. The config-reload and
cold-reboot cases revalidate operational FPM mode after the event. At suite
teardown the existing SONiC checkpoint restores the exact original CONFIG_DB,
then BGP is restarted again before the restored peer, process, and MAC-sync
state is accepted.

This flag selects a DUT operating mode; it does not modify the stock
`dualtor-aa` topology and does not create additional parametrized testcases.
The target image must already contain the coordinated FRR, SWSS, utilities,
schema, container-startup, and kernel support required by MAC-over-FPM.

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

## Traffic generation and pass/fail criteria

Traffic profiles in
[`traffic_profiles.yml`](../../../tests/evpn_mh/files/traffic_profiles.yml) are
vendor-neutral YAML compiled to the existing PTF remote test. Every flow
resolves the following fields from its explicit profile definition or the
versioned defaults:

- transmit endpoint and packet fields;
- deterministic packet count, pacing, and optional varied fields;
- one or more accepted receive groups;
- forbidden endpoints;
- maximum loss and duplicate count;
- optional minimum distribution per accepted path; and
- VLAN tagging or tag translation required by backplane endpoints.

Unless a profile overrides them, finite flows send 100 packets at 20 packets
per second, allow at most 2% loss, and allow no duplicate or forbidden copies.
The ECMP profiles send 500 varied flows at 100 packets per second, require at
least 490 deliveries, and require at least 50 deliveries on each accepted leg.
The continuous reboot and member-flap profiles use explicit event windows and
allow at most 8% loss and 8% duplicates during event grading.

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

Control-plane state supports the verdict but never replaces packet-level PTF
receive and forbidden-copy checks.

## Exact testcase inventory

The testcase files are `tests/evpn_mh/test_traffic.py` and
`tests/evpn_mh/test_resiliency.py`; filenames below refer to those files.
H1 and H2 are independent multihomed hosts, SH1 is single-homed to the upper
ToR (PE1), H3 is the remote VLAN10 host, and H4 is the remote VLAN20 host.
The lower ToR is PE2. All hosts are emulated by PTF.

L2 checks bridge traffic within a VLAN; L3 checks route traffic between
subnets. DF is the designated forwarder for remote BUM traffic on an Ethernet
Segment; the NDF suppresses that copy. BUM means broadcast, unknown unicast,
and multicast; ECMP means equal-cost multipath forwarding. EVPN Type-2 routes
carry MAC/IP reachability, Type-3 routes identify BUM replication members,
and Type-5 routes carry IP prefixes. Test names containing `ping` identify
reachability scenarios implemented with deterministic UDP packets.

### Local bias and BUM

1. `test_local_bias` (`test_resiliency.py`)
   - **Layer and traffic:** L2 unknown unicast from PE1's SH1 to H1, H2, and remote H3.
   - **Event and expected result:** Move H2's DF to the other ToR. Delivery to H1/H2
     must continue through PE1's local access legs, regardless of DF placement;
     neither PE2 leg may deliver an extra overlay copy. H3 must also receive its
     copy. Restore DF preferences and verify forwarding again.
2. `test_remote_broadcast_traffic` (`test_traffic.py`)
   - **Layer and traffic:** L2 Ethernet broadcast from H3 to H1, H2, and SH1 in VLAN10.
   - **Expected result:** Verify VNI and Type-3 replication state. SH1 receives a
     copy; H1 and H2 each receive one copy through their own DF. Neither NDF leg
     receives a copy.
3. `test_remote_multicast_traffic` (`test_traffic.py`)
   - **Layer and traffic:** L2 Ethernet multicast from H3 to H1, H2, and SH1 in VLAN10.
   - **Expected result:** Verify replication state and single-copy DF delivery for
     each Ethernet Segment, with NDF suppression. This checks Ethernet flooding;
     it does not exercise IP multicast routing or group membership protocols.
4. `test_unknown_unicast` (`test_traffic.py`)
   - **Layer and traffic:** L2 frames from H3 with an unlearned destination MAC in VLAN10.
   - **Expected result:** VXLAN ingress replication delivers a copy to SH1 and one
     copy per Ethernet Segment through its DF, with no NDF copies or excess duplicates.

### L2, L3, and ECMP

5. `test_inter_subnet_ping` (`test_traffic.py`)
   - **Layer and traffic:** L3 IPv4/UDP between H1 and H4, and between H2 and H4,
     in both directions, across VLAN10 and VLAN20.
   - **Expected result:** Verify routing through the tenant VRF and VXLAN overlay,
     correct routed packet headers, Type-2/Type-5 reachability, and neighbor state.
     The remote leaf must resolve both multihomed hosts through both ToR VTEPs.
6. `test_intra_subnet_ping` (`test_traffic.py`)
   - **Layer and traffic:** L2 forwarding of IPv4/UDP between H1 and H2, and between
     SH1 and H2, in both directions. Additional unknown-unicast and broadcast
     frames travel from H1/H2 toward H3 in VLAN10.
   - **Expected result:** Verify MAC/IP learning and remote MAC forwarding entries,
     both ToR paths for multihomed hosts, and single-copy remote delivery. H4 in
     VLAN20 must not receive the VLAN10 flooded traffic.
7. `test_remote_unicast_for_ecmp` (`test_resiliency.py`)
   - **Layer and traffic:** L2 forwarding of IPv4/UDP from H3 to H2 using 500 varied
     UDP port tuples.
   - **Event and expected result:** Both H2 legs must carry traffic and meet the
     minimum path-share limit. Shut PE1's H2 member; the remote leaf must remove
     that VTEP from H2's forwarding paths and deliver through PE2 only. Restore
     the member and verify both paths and traffic recover.

### PortChannel, VLAN, and underlay disruption

8. `test_portchannel_deconf` (`test_resiliency.py`)
   - **Layer and traffic:** L2 broadcast from H3 to H1, H2, and SH1 before removal
     and after restoration.
   - **Event and expected result:** Remove PE1's H2 PortChannel, member, VLAN
     membership, ESI, and system MAC. Verify the local segment is absent and PE2
     becomes H2's DF. Recreate the saved configuration and verify EVPN convergence
     and broadcast forwarding recover.
9. `test_portchannel_flap` (`test_resiliency.py`)
   - **Layer and traffic:** L2 broadcast from H3 to H1, H2, and SH1.
   - **Event and expected result:** Shut each complete H2 PortChannel in turn.
     Confirm the PortChannel is down, the peer becomes DF, and broadcast traffic
     uses the valid DF for each segment during the outage. Restore each
     PortChannel and verify forwarding before testing the other side.
10. `test_interface_to_spine_flap` (`test_resiliency.py`)
    - **Layer and traffic:** L3 underlay path resilience, checked with L2 broadcast
      from H3 to H1, H2, and SH1 across VXLAN.
    - **Event and expected result:** Shut PE1's uplinks one at a time to reduce the
      installed paths to the remote VTEP from three to two to one. Verify the path
      count and DF/NDF delivery at each stage. Restore all three paths and traffic.
11. `test_vlan_member_flap` (`test_resiliency.py`)
    - **Layer and traffic:** L2 IPv4/UDP from SH1 to H2 in VLAN10.
    - **Event and expected result:** Remove SH1's VLAN membership while keeping its
      physical link up. H2 must receive none of the test packets. Restore membership
      and run the intra-subnet profile to verify forwarding and VLAN isolation recover.
12. `test_portchannel_shut_noshut` (`test_resiliency.py`)
    - **Layer and traffic:** L3 IPv4/UDP from the temporary tagged VLAN20 source on
      SH1's attachment to H2 in VLAN10, through the anycast gateway.
    - **Event and expected result:** Make PE1 H2's DF and verify local routed
      delivery. Shut PE1's physical H2 member and require delivery through the
      surviving PE2/tunnel path. Restore the member, verify local delivery returns,
      and remove the temporary service and restore DF preferences. The event acts
      on a physical member, unlike the complete PortChannel shutdown above.
13. `test_portchannel_member_flap` (`test_resiliency.py`)
    - **Layer and traffic:** Continuous sequence-numbered L2 unknown unicast from
      H3 toward H2's Ethernet Segment.
    - **Event and expected result:** Flap each physical H2 member separately.
      Measure loss and duplicates during the down transition, stable outage, and
      recovery. During the stable outage, only the surviving leg may deliver.
      After restoration, verify overlay state and the remote broadcast profile.

### Persistence, reboot, and IPv6

14. `test_config_reload` (`test_resiliency.py`)
    - **Layer and traffic:** L3 IPv4/UDP between H2 and H4 in both directions, plus
      L2 unknown unicast from H2 toward H3.
    - **Event and expected result:** Reload configuration on H2's current DF.
      Require the affected ToR to recover its Ethernet Segments, DF state, VNIs,
      EVPN peers, and tenant IPv4/IPv6 routes. Repeat the traffic profile to verify
      forwarding recovers from the saved configuration.
15. `test_continuous_traffic_reboot_df` (`test_resiliency.py`)
    - **Layer and traffic:** Concurrent continuous L2 unknown unicast from H3
      toward H2 and L3 IPv4/UDP between H2 and H4 in both directions.
    - **Event and expected result:** Cold-reboot H2's current DF after confirming
      traffic is running. Observe the peer becoming DF, measure loss and duplicates
      during the event, and require the rebooted ToR and forwarding to recover
      within the configured deadlines.
16. `test_ipv6_traffic` (`test_resiliency.py`)
    - **Layer and traffic:** L3 IPv6/UDP between H1/H2 and H4 in both directions;
      L2 forwarding of varied IPv6/UDP flows from H3 to H2; and Ethernet broadcast
      and unknown-unicast frames carrying IPv6/UDP from H3.
    - **Expected result:** Verify IPv6 routing, Neighbor Discovery, Type-2/Type-5
      reachability, and both ToR forwarding paths. BUM frames must reach SH1 and
      each segment's DF without NDF copies. Ethernet broadcast here is a deliberate
      L2 test envelope; IPv6 itself has no network-layer broadcast.

## Independent-run contract

Each disruptive test follows the same seven-stage lifecycle:

1. establish topology and control-plane baseline;
2. capture relevant state;
3. run baseline traffic;
4. apply and prove the event;
5. grade control plane and packets during the event;
6. restore in a `finally` path; and
7. prove convergence, traffic recovery, and baseline restoration.

Nondisruptive traffic tests use the applicable baseline, traffic-verdict, and
final-state stages without introducing a configuration event.

No test relies on a fixed DF. Tests may run individually or in any order.
