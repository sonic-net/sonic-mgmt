# IPv4 Match Condition Based DHCP Server Test Plan

- [Related Documents](#related-documents)
- [Overview and Scope](#overview-and-scope)
- [Testbed and Common Setup](#testbed-and-common-setup)
- [Test Cases](#test-cases)
  - [Address Assignment](#address-assignment)
  - [Runtime Configuration and Recovery](#runtime-configuration-and-recovery)
  - [CLI Validation](#cli-validation)
  - [Lease Clearing](#lease-clearing)
  - [Multiple VLANs and Regression](#multiple-vlans-and-regression)
  - [Scale and Stress](#scale-and-stress)
- [Deferred Coverage](#deferred-coverage)

## Related Documents

| Document | Reference |
| --- | --- |
| MATCH mode HLD | [SONiC PR #2535](https://github.com/sonic-net/SONiC/pull/2535) |
| YANG model | [sonic-buildimage PR #29925](https://github.com/sonic-net/sonic-buildimage/pull/29925) |
| Config, show and clear CLI | [sonic-buildimage PR #30159](https://github.com/sonic-net/sonic-buildimage/pull/30159) |
| Core implementation | [sonic-buildimage PR #30361](https://github.com/sonic-net/sonic-buildimage/pull/30361) |
| PORT mode regression coverage | [IPv4 Port Based DHCP Server Test Plan](IPv4-Port-Based-DHCP-Server-test-plan.md) |
| DHCP protocol and options | [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131), [RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132), [RFC 3046](https://datatracker.ietf.org/doc/html/rfc3046) |

## Overview and Scope

`MATCH` mode selects DHCPv4 pools using named `circuit_id` (Option 82 sub-option 1) and `option60` (Vendor Class Identifier) conditions. Conditions within a binding are ANDed; bindings sharing an identical pool provide OR behaviour. More-specific bindings take precedence without falling back to less-specific pools on exhaustion.

This plan covers on-DUT packet behaviour, runtime configuration, CLI validation, lease clearing, persistence, mixed PORT/MATCH operation and scale. The existing PORT suite remains regression coverage. Exhaustive argument/YANG validation and generated class naming remain unit-test coverage; smart-switch mid-plane testing is outside this plan.

## Testbed and Common Setup

Use the `mx` topology and existing `tests/dhcp_server` fixtures. Run supported scenarios with both relay implementations (`isc-relay-agent`, `sonic-relay-agent`), and assignment/configuration scenarios through CLI and GCU where applicable. KVM `t0` can provide development coverage with suitable feature, VLAN and PTF connectivity prerequisites; it does not replace the target topology.

Discover VLAN prefixes, aliases and PTF-connected members from the DUT rather than hardcoding them. Use member ports `P1`, `P2`, `P3` and a non-member `PX`. Match conditions are `port_p1`, `port_p2`, `vendor_a=VendorA` and `vendor_b=VendorB`. The baseline bindings are:

| Binding | Conditions | Pool |
| --- | --- | --- |
| `a_on_p1` | `port_p1`, `vendor_a` | `.21` |
| `b_on_p1` | `port_p1`, `vendor_b` | `.22` |
| `any_on_p1` | `port_p1` | `.100`-`.104` |
| `any_on_p2` | `port_p2` | `.30` |

Addresses above are illustrative host offsets; select valid, unused addresses within the discovered prefix, excluding gateway/network/broadcast addresses. Individual scenarios may replace the baseline bindings.

Reuse packet helpers to perform DORA, RENEW, INIT-REBOOT and RELEASE with explicit Option 60 values. Verify address, netmask, gateway, lease time and Option 54 (the VLAN SVI); correlate ACKed leases with Kea, State DB and show output. Check Kea's running configuration and wait for convergence rather than using fixed sleeps. Isolate clients/leases between scenarios so pool exhaustion does not mask classification results.

Save and restore the original configuration and feature/relay state. Remove test leases, bindings, matches, ranges and temporary VLAN/PortChannel configuration; restore PTF MAC addresses. Use bounded waits for reload and lease synchronization, and allowlist only expected diagnostic errors.

## Test Cases

The module names below are proposed implementation locations, not existing tests.

### Address Assignment

Proposed module: `test_dhcp_server_match.py`.

| ID | Scenario | Expected result |
| --- | --- | --- |
| F01 | Capture a relayed DISCOVER on each relay implementation. | Circuit ID is `<hostname>:<port alias>` (or aliasless port/PortChannel name) and matches the bytes tested by the generated Kea class. |
| F02 | Circuit-ID-only binding; vary Option 60 and FDB state. | Only the configured ingress port receives its pool; vendor value and stale/missing FDB entries do not change classification. |
| F03 | Option-60-only binding; send matching, different and absent values on member/non-member ports. | Matching clients on VLAN members receive distinct addresses from the vendor pool; nonmatching/non-member clients receive no offer. |
| F04 | Combined port and vendor binding. | Both conditions are required; matching only one condition produces no offer. |
| F05 | Baseline specificity rules; reverse binding insertion order. | P1/VendorA gets `.21`, P1/VendorB `.22`, other P1 clients `.100`-`.104`, P2 clients `.30`; unmatched ports get no offer. Order does not change results. |
| F06 | Exhaust a more-specific single-address pool, then release its lease. | Another matching client receives no offer despite free less-specific addresses; it can obtain the specific address after release. |
| F07 | Two vendor bindings share an identical pool (OR). | Both vendors use one shared pool without duplicate allocation; unrelated vendors get no offer. Class-to-binding logging identifies both bindings. |
| F08 | One binding references several ranges, including a single-address range. | Only configured addresses are allocated, exhaustion produces no offer, and release makes the address reusable. |
| F09 | Option 60 case, prefixes, whitespace, NUL padding and UTF-8 bytes. | Exact case-sensitive matching; trailing NUL padding is accepted by packaged Kea, while leading NULs, whitespace and prefix/substring differences do not match. |
| F10 | Change/omit Option 60 between DISCOVER and REQUEST; repeat on RENEW and INIT-REBOOT. | Classification is per packet: ACK only when the requested address remains reachable; otherwise NAK in the baseline configuration. A shared specific/general pool permits the request without Option 60. |
| F11 | RENEW and RELEASE of a MATCH lease. | Renewal ACKs the same address and advances lease expiry; release removes the State DB lease. |
| F12 | Move or swap client MACs between P1 and P2. | Fresh allocation follows the current ingress port, not the previous MAC/FDB location. |
| F13 | Configure customized DHCP options on a MATCH interface. | OFFER and ACK contain the configured options. |
| F14 | PortChannel Circuit ID, including a PortChannel created after daemon startup. | Its binding serves the expected pool without restarting dhcpservd. |

### Runtime Configuration and Recovery

Proposed module: `test_dhcp_server_match_config_change.py`.

| ID | Scenario | Expected result |
| --- | --- | --- |
| C01 | Add, update and delete bindings; change matches and switch IP/range pools. | Kea applies each valid change without service restart; fresh allocations follow the current binding. |
| C02 | Add a more-specific binding while a client holds a general-pool lease. | No immediate lease deletion; renewal of the now-ineligible address is NAKed, then DORA obtains the specific address. |
| C03 | Update vendor values or the port referenced by a match condition. | All affected bindings reclassify clients using the updated value; old values stop matching. |
| C04 | Update a referenced range. | New clients use the updated endpoints. |
| C05 | Switch PORT to MATCH and back with both kinds of configuration present. | Only the active mode's pools are served; switching does not proactively delete leases. Ineligible renewals are NAKed; switching back restores PORT behaviour. |
| C06 | Disable/enable a MATCH interface; remove its final binding; enable with no bindings. | Disabled/empty interfaces send no offers, commands succeed, and Kea remains running; restoring bindings resumes service. |
| C07 | Remove and restore a matched port's VLAN membership. | Affected bindings are skipped with warnings; unaffected bindings keep serving; restoration recovers without restart. |
| C08 | Change and restore the VLAN IPv4 prefix. | Pools outside the prefix are skipped; restoring the prefix restores service. |
| C09 | Write equal-specificity conflicts, partial pool overlap or multi-prefix MATCH pools directly to Config DB. | Compilation errors are logged; last-known-good Kea configuration keeps serving. Removing the invalid entry permits recovery without restart. |
| C10 | Delete/restore referenced matches or ranges directly in Config DB, including one range of a multi-range binding. | Missing matches skip the whole dependent binding with a warning. Missing ranges drop only their pools; remaining usable pools continue serving. Skip the binding only when no usable pool remains. Restoration triggers regeneration without restart. |
| C11 | Save configuration, then config reload, service restart and cold reboot. | Match/binding configuration and unexpired leases persist; clients renew successfully after recovery. |
| C12 | Terminate each listed critical process separately. | Normal container/process recovery restores the MATCH configuration and packet service. |

### CLI Validation

Proposed module: `test_dhcp_server_match_cli.py`.

| ID | Scenario | Expected result |
| --- | --- | --- |
| V01 | Show matches, bindings, interface info and leases; exercise name/VLAN filters. | Correct values and columns, including numeric-looking strings, MATCH mode and learned lease port mapping. |
| V02 | Unknown alias/type, non-member Circuit ID, repeated condition type, duplicate binding, invalid IP/range or both pool forms. | Non-zero exit and actionable error; Config DB and running Kea configuration remain unchanged. |
| V03 | Equal-specificity condition conflict, partial pool overlap and pools spanning two IPv4 prefixes on a MATCH VLAN. | Rejected before Config DB is changed; rejection does not extend to PORT mode. |
| V04 | Delete referenced matches/ranges/interfaces, or update a condition/mode so enabled MATCH bindings become invalid. | Dependency/validation error without partial writes; supported force semantics are tested separately from guarded deletion. |
| V05 | Apply YANG-invalid binding configuration through GCU. | Patch is rejected without changing the existing configuration. |
| V06 | Apply equivalent configuration through CLI and GCU, in different valid orders. | Equivalent deterministic Kea configuration and identical packet behaviour. |

### Lease Clearing

Proposed module: `test_dhcp_server_lease_clear.py`. Run applicable cases in both PORT and MATCH modes with packaged Kea and real SWSS/State DB. Disconnect old clients before clearing; deletion does not revoke an address on a connected client.

| ID | Scenario | Expected result |
| --- | --- | --- |
| L01 | Clear one IP among several active leases. | Only that lease disappears from Kea and State DB before successful return; synchronization request is acknowledged. |
| L02 | Clear all leases on one of two VLANs. | Target VLAN has no leases; the other VLAN is unchanged. |
| L03 | Clear leases, then restart Kea, restart dhcp_server and reboot. | Deleted leases do not reappear from persistent storage. |
| L04 | Replace a disconnected client on a single-address pool. | New MAC cannot allocate the occupied address before clear, and can obtain it immediately after clear. |
| L05 | Missing lease, empty VLAN, invalid arguments/IP, unknown interface, non-root invocation or disabled feature. | Appropriate non-zero/usage error without unintended deletion. |
| L06 | State DB contains a lease absent from Kea. | Clear reports no matching Kea lease and reconciles the stale State DB entry. |
| L07 | Issue concurrent clear commands. | Operations serialize or one reports clear-in-progress; final Kea and State DB contents agree. |

### Multiple VLANs and Regression

Proposed module: `test_dhcp_server_match_multi_vlans.py`; retain the existing PORT suite.

| ID | Scenario | Expected result |
| --- | --- | --- |
| M01 | Run PORT and MATCH VLANs together; update or inject invalid MATCH configuration. | Each VLAN follows its own mode; PORT allocation and leases remain unaffected. |
| M02 | Reuse an Option 60 condition on two MATCH VLANs with different prefixes. | Clients obtain addresses only from their own VLAN's pool. |

### Scale and Stress

Proposed module: `test_dhcp_server_match_stress.py`.

| ID | Scenario | Expected result |
| --- | --- | --- |
| S01 | Configure a port-only binding plus four vendor bindings per available member; exercise every combination. | Correct compilation and allocation for all clients; record convergence time against the agreed scale target. |
| S02 | Send mixed matching/nonmatching DISCOVER traffic at 100 packets/s across several ports, with adequate pool capacity. | No wrong-pool offers or offers to unmatched clients; monitor offer rate/loss and ensure server/relay remain healthy. |