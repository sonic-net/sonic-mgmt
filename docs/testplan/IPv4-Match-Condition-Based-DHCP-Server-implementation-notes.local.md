# IPv4 Match Condition Based DHCP Server Test Plan
<!-- TOC -->

- [IPv4 Match Condition Based DHCP Server Test Plan](#ipv4-match-condition-based-dhcp-server-test-plan)
    - [Related Documents](#related-documents)
    - [Overview](#overview)
    - [Scope](#scope)
        - [Test Scenario](#test-scenario)
        - [Out of Scope](#out-of-scope)
        - [Supported Topology](#supported-topology)
    - [Test Setup](#test-setup)
        - [Port Roles](#port-roles)
        - [Match Conditions](#match-conditions)
        - [Common Bindings](#common-bindings)
    - [Test Case](#test-case)
        - [Common Function](#common-function)
        - [Common Setup and Teardown](#common-setup-and-teardown)
        - [Test Module #1 test_dhcp_server_match.py](#test-module-1-test_dhcp_server_matchpy)
        - [Test Module #2 test_dhcp_server_match_config_change.py](#test-module-2-test_dhcp_server_match_config_changepy)
        - [Test Module #3 test_dhcp_server_match_cli.py](#test-module-3-test_dhcp_server_match_clipy)
        - [Test Module #4 test_dhcp_server_lease_clear.py](#test-module-4-test_dhcp_server_lease_clearpy)
        - [Test Module #5 test_dhcp_server_match_multi_vlans.py](#test-module-5-test_dhcp_server_match_multi_vlanspy)
        - [Test Module #6 test_dhcp_server_match_stress.py](#test-module-6-test_dhcp_server_match_stresspy)
    - [Requirement Coverage](#requirement-coverage)
    - [Deferred Test Cases](#deferred-test-cases)

<!-- /TOC -->

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| IPv4 Match Condition Based DHCP_SERVER in SONiC (HLD) | [SONiC PR #2535](https://github.com/sonic-net/SONiC/pull/2535) |
| IPv4 Port Based DHCP_SERVER in SONiC (HLD) | [port_based_dhcp_server_high_level_design.md](https://github.com/sonic-net/SONiC/blob/master/doc/dhcp_server/port_based_dhcp_server_high_level_design.md) |
| IPv4 Port Based DHCP Server Test Plan | [IPv4-Port-Based-DHCP-Server-test-plan.md](IPv4-Port-Based-DHCP-Server-test-plan.md) |
| Phase 1: YANG model | [sonic-buildimage PR #29925](https://github.com/sonic-net/sonic-buildimage/pull/29925) |
| Phase 2: Config, show and clear CLI | [sonic-buildimage PR #30159](https://github.com/sonic-net/sonic-buildimage/pull/30159) |
| Phase 3: dhcpservd Kea configuration generation | [sonic-buildimage PR #30361](https://github.com/sonic-net/sonic-buildimage/pull/30361) |
| RFC 2131: Dynamic Host Configuration Protocol | [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131) |
| RFC 2132: DHCP Options (Option 60, Vendor Class Identifier) | [RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132) |
| RFC 3046: DHCP Relay Agent Information Option (Option 82) | [RFC 3046](https://datatracker.ietf.org/doc/html/rfc3046) |

## Overview

The port based DHCP server assigns an address based only on the port a client is connected to. Match condition based assignment adds a new `MATCH` mode for a DHCP interface. In `MATCH` mode, the address pool for a client is chosen by named match conditions that are evaluated against each DHCP packet:

* `circuit_id`: the Circuit ID sub-option of Option 82, stamped by `dhcp_relay` as `<hostname>:<port alias>`. This identifies the ingress port.
* `option60`: the Vendor Class Identifier sent by the client.

A binding combines one or more match conditions (AND logic) with an IP list or a list of named ranges. OR logic is expressed by several bindings that use the same pool. When a client satisfies more than one binding, the binding with the most match conditions wins. `dhcpservd` compiles the bindings into mutually exclusive Kea client classes and guarded pools, so the result does not depend on declaration order.

The following Config DB tables are used:

| Table | Key | Purpose |
|:-|:-|:-|
| `DHCP_SERVER_IPV4` | `<vlan>` | `mode` accepts `PORT` or `MATCH` |
| `DHCP_SERVER_IPV4_MATCH` | `<match_name>` | `type` (`circuit_id` or `option60`) and exact `value` |
| `DHCP_SERVER_IPV4_BINDING` | `<vlan>\|<binding_name>` | `matches` and exactly one of `ips` or `ranges` |
| `DHCP_SERVER_IPV4_RANGE` | `<range_name>` | Shared with `PORT` mode |

The following CLI is added: `config dhcp_server ipv4 match add|update|del`, `config dhcp_server ipv4 binding add|update|del`, `show dhcp_server ipv4 match`, `show dhcp_server ipv4 binding` and `sonic-clear dhcp_server ipv4 lease`.

## Scope

### Test Scenario

The tests will include:

1. Functionality test
    1. A client is offered and acknowledged an address from the pool of the binding it matches, for `circuit_id` only, `option60` only and combined bindings.
    2. Specificity ordering: the most specific matching binding wins, and a less specific pool is never used as a fallback when the more specific pool is exhausted.
    3. OR logic through several bindings that share a pool.
    4. Option 60 matching is exact and case sensitive, and is evaluated again on every DHCP packet, including REQUEST, RENEW and INIT-REBOOT.
    5. A client that matches no binding does not receive an offer, and clients on other ports or VLANs are not affected.
2. Configuration test
    1. Configuration through CLI and through GCU produces the same result.
    2. Runtime changes to match conditions, bindings, ranges, mode, VLAN membership and VLAN IP take effect without a service restart.
    3. Configuration that cannot be compiled is rejected by the CLI. Configuration written directly to Config DB that cannot be compiled is logged and the last known good Kea configuration continues to be served.
    4. Configuration and leases persist across `config reload`, service restart and reboot.
3. Lease management test
    1. `sonic-clear dhcp_server ipv4 lease` removes the selected leases from Kea and State DB, does not affect other leases, and the deletion persists across restart.
4. Regression and scale test
    1. `PORT` mode behaviour is unchanged, including on a DUT where other VLANs use `MATCH` mode.
    2. A large number of bindings and concurrent clients are handled correctly.

### Out of Scope

* Exhaustive CLI argument and YANG validation. These are covered by the unit tests in `dockers/docker-dhcp-server/cli-plugin-tests` and `src/sonic-yang-models/tests`. Module #3 covers only the on-DUT behaviour of the most important rejections.
* Kea class name format and generated JSON layout. These are covered by the unit tests in `src/sonic-dhcp-utilities/tests`.
* Smart switch mid-plane DHCP. `MATCH` mode on the mid-plane bridge is covered by unit tests only.
* Items described in the HLD that are not implemented yet. See [Deferred Test Cases](#deferred-test-cases).

### Supported Topology

The tests are supported on the `mx` topology, the same as the existing `dhcp_server` tests. Each test is parametrized with `relay_agent` (`isc-relay-agent` and `sonic-relay-agent`), as in `tests/dhcp_server/test_dhcp_server.py`.

The `circuit_id` match depends on the exact Circuit ID that the relay stamps. Test case `test_dhcp_server_match_circuit_id_format` verifies this for each relay agent before the functional tests run.

The tests can be developed on the KVM `t0` topology (`vms-kvm-t0`) by removing the topology restriction locally, because `Vlan1000` has several members connected to the PTF.

## Test Setup

### Port Roles

The tests read the VLAN, its IPv4 prefix and its members from the running configuration, in the same way as `parse_vlan_setting_from_running_config` in the existing tests. Four ports are selected:

| Name | Role |
|:-|:-|
| `P1` | VLAN member that is used in `circuit_id` matches |
| `P2` | VLAN member that is used in `circuit_id` matches |
| `P3` | VLAN member that is not used by any `circuit_id` match |
| `PX` | Port that is not a member of the VLAN, used for negative checks |

`alias(Pn)` is the port alias from the `PORT` table. If the port has no alias, the port name is used.

### Match Conditions

| Match name | Type | Value |
|:-|:-|:-|
| `port_p1` | `circuit_id` | `alias(P1)` |
| `port_p2` | `circuit_id` | `alias(P2)` |
| `vendor_a` | `option60` | `VendorA` |
| `vendor_b` | `option60` | `VendorB` |

### Common Bindings

Unless a test states otherwise, the following bindings are configured on the test VLAN. `.N` means the Nth host address of the VLAN prefix, chosen so that every pool is inside the prefix and does not include the gateway address.

| Binding | Matches | Pool | Specificity |
|:-|:-|:-|:-|
| `a_on_p1` | `port_p1,vendor_a` | `.21` | 2 |
| `b_on_p1` | `port_p1,vendor_b` | `.22` | 2 |
| `any_on_p1` | `port_p1` | range `.100` to `.104` | 1 |
| `any_on_p2` | `port_p2` | `.30` | 1 |

The expected assignment for this configuration is:

| Ingress port | Option 60 | Expected result |
|:-|:-|:-|
| `P1` | `VendorA` | `.21` |
| `P1` | `VendorB` | `.22` |
| `P1` | absent or `VendorC` | from `.100` to `.104` |
| `P2` | any or absent | `.30` |
| `P3` | any or absent | no offer |
| `PX` | any or absent | no offer |

## Test Case

### Common Function

The existing helpers in `tests/dhcp_server/dhcp_server_test_common.py` are reused. The following helpers are added.

#### create_dhcp_client_packet with Option 60

`create_dhcp_client_packet(src_mac, message_type, client_options, xid, ciaddr)` already accepts `client_options`. Option 60 is added as `("vendor_class_id", value)`, where `value` is bytes so that NUL and whitespace cases can be expressed exactly.

#### send_and_verify_match

* Sends a DHCP DISCOVER from a PTF port with an optional Option 60, and verifies on the DUT port whether an OFFER is received. When an OFFER is expected, the test checks `yiaddr`, netmask, gateway (Option 3), lease time (Option 51) and server identifier (Option 54).
* Sends a DHCP REQUEST for the offered address, with an optional Option 60 that can differ from the DISCOVER, and verifies whether an ACK, a NAK or no reply is received.
* When an ACK is expected, verifies the lease through `show dhcp_server ipv4 lease` and the `DHCP_SERVER_IPV4_LEASE|<vlan>|<mac>` entry in State DB.

#### apply_match_config

Applies match conditions, ranges and bindings through either the CLI or GCU, selected by the `config_tool` parameter (`cli` or `gcu`), in the same way as `dhcp_server_config` in the existing tests.

#### get_kea_running_config

Runs `config-get` on the Kea control socket inside the `dhcp_server` container and returns the running `Dhcp4` configuration. It is used to check that Kea has applied a change, and that a rejected change did not replace the running configuration.

#### get_kea_leases

Runs `lease4-get-all` on the Kea control socket and returns the leases. It is used to compare the Kea lease database with State DB.

#### wait_for_kea_reload

Waits until the Kea running configuration reflects the expected change (`get_kea_running_config`), with a timeout. The tests do not use fixed sleeps after a configuration change.

### Common Setup and Teardown

#### Common setup

* Check that `dhcrelay` runs as expected, as in the port based tests.
* Enable the `dhcp_server` feature and add the DHCP interface in `MATCH` mode:

  ```
  config dhcp_server ipv4 add --mode MATCH --dup_gw_nm --lease_time 300 <vlan>
  config dhcp_server ipv4 enable <vlan>
  ```

* Add the [match conditions](#match-conditions) and the bindings required by the test.

#### Common teardown

* Remove the bindings, match conditions, ranges and DHCP interface.
* Disable the `dhcp_server` feature and check that `dhcrelay` runs as expected.
* Config reload, and remove the `dhcp_server` container.
* Restore any PTF MAC address changes.

### Test Module #1 test_dhcp_server_match.py

This module verifies address assignment. Unless stated otherwise, each test case is parametrized with `config_tool` (`cli` and `gcu`).

#### test_dhcp_server_match_circuit_id_format

* **Test objective**

  Verify that the relay stamps the Circuit ID that a `circuit_id` match condition is compiled against. Otherwise every `circuit_id` test fails for an unrelated reason.

* **Test detail**

  * Send a DHCP DISCOVER from `P1`.
  * Capture the relayed packet towards the `dhcp_server` container, and check that Option 82 sub-option 1 is exactly `<hostname>:<alias(P1)>`.
  * Check that the Kea running configuration contains a client class that tests `relay4[1]` against the same bytes.

#### test_dhcp_server_match_circuit_id_only

* **Test objective**

  Verify that a binding with only a `circuit_id` match behaves like `PORT` mode.

* **Setup**

  Configure only `any_on_p1` with a single IP `.20`.

* **Test detail**

  * DORA from `P1` with no Option 60. Expected: `.20` is offered and acknowledged.
  * DORA from `P1` with Option 60 `VendorA`. Expected: `.20`, because a `circuit_id` only binding ignores Option 60.
  * DORA from `P2`, `P3` and `PX`. Expected: no offer.
  * The client MAC address is not in the FDB, is in the FDB, and is learnt on another port, as in `test_dhcp_server_port_based_assignment_single_ip_tc1` to `tc4`. Expected: the result depends only on the ingress port.

#### test_dhcp_server_match_option60_only

* **Test objective**

  Verify that a binding with only an `option60` match serves that vendor on every member port of the VLAN.

* **Setup**

  Configure only the binding `a_anywhere` with matches `vendor_a` and range `.40` to `.43`.

* **Test detail**

  * DORA with Option 60 `VendorA` from `P1`, `P2` and `P3`. Expected: each client gets a different address from `.40` to `.43`.
  * DORA with Option 60 `VendorB` and with no Option 60. Expected: no offer.
  * DORA with Option 60 `VendorA` from `PX`. Expected: no offer, because `PX` is not a member of the VLAN.

#### test_dhcp_server_match_and_logic

* **Test objective**

  Verify that a binding with a `circuit_id` and an `option60` match requires both conditions.

* **Setup**

  Configure only `a_on_p1`.

* **Test detail**

  * DORA from `P1` with `VendorA`. Expected: `.21`.
  * DORA from `P1` with `VendorB`, and from `P1` with no Option 60. Expected: no offer.
  * DORA from `P2` with `VendorA`. Expected: no offer.

#### test_dhcp_server_match_specificity

* **Test objective**

  Verify that the most specific binding wins when a client satisfies several bindings, independent of binding names and the order in which bindings are added.

* **Setup**

  Configure the [common bindings](#common-bindings). The test is also parametrized with the order in which the bindings are added (most specific first, and least specific first).

* **Test detail**

  * Run DORA for each row of the [expected assignment table](#common-bindings), each with a new client MAC address. Expected: each result matches the table.
  * Check that the `VendorA` client on `P1` is never offered an address from `.100` to `.104`, even though it satisfies `any_on_p1`.

#### test_dhcp_server_match_specificity_no_fallback

* **Test objective**

  Verify that a less specific pool is not used when the most specific pool is exhausted.

* **Setup**

  Configure the [common bindings](#common-bindings).

* **Test detail**

  * DORA from `P1` with `VendorA` and client MAC address `M1`. Expected: `.21`.
  * DORA from `P1` with `VendorA` and a different client MAC address `M2`. Expected: no offer, because `.21` is leased to `M1`. The address must not come from `.100` to `.104`.
  * Release from `M1`, then DORA from `M2`. Expected: `.21`.

#### test_dhcp_server_match_or_logic

* **Test objective**

  Verify that two bindings with the same pool are served from one shared pool.

* **Setup**

  Configure `a_on_p1` and `b_on_p1` with the same range `.50` to `.53`.

* **Test detail**

  * DORA from `P1` with `VendorA` and with `VendorB`. Expected: both get an address from `.50` to `.53`, and the addresses differ.
  * DORA from `P1` with `VendorC`. Expected: no offer.
  * Check syslog for one `DHCP MATCH class <class> maps to bindings <vlan>|a_on_p1,<vlan>|b_on_p1` message, which shows that one class guards the shared pool.

#### test_dhcp_server_match_range_assignment

* **Test objective**

  Verify range based bindings, including ranges with a single address, several ranges in one binding, and pool exhaustion.

* **Setup**

  Add range `r1` (`.100` to `.101`) and range `r2` (`.110`), and bind both to `any_on_p1`.

* **Test detail**

  * DORA from `P1` with three client MAC addresses. Expected: each gets a different address from `.100`, `.101` and `.110`.
  * DORA with a fourth client MAC address. Expected: no offer.
  * Release one lease, then DORA with the fourth client MAC address. Expected: the released address is offered.

#### test_dhcp_server_match_option60_value_semantics

* **Test objective**

  Verify that Option 60 matching is exact and case sensitive.

* **Setup**

  Configure only `a_anywhere` with matches `vendor_a` and range `.40` to `.43`.

* **Test detail**

  Run DORA from `P1` with each Option 60 value below.

  | Option 60 bytes | Expected |
  |:-|:-|
  | `VendorA` | Offer |
  | `vendora` | No offer (case sensitive) |
  | `VendorA2` | No offer (no prefix match) |
  | `Vendor` | No offer (no substring match) |
  | `VendorA ` (trailing space) | No offer |
  | ` VendorA` (leading space) | No offer |
  | `VendorA\x00` (trailing NUL) | Offer. Kea removes trailing NUL bytes from string options |
  | `\x00VendorA` (leading NUL) | No offer |

  * Add a match condition whose value contains UTF-8 characters outside ASCII, bind it, and run DORA with the same UTF-8 bytes. Expected: offer.

#### test_dhcp_server_match_option60_per_packet

* **Test objective**

  Verify that Kea classifies every DHCP packet independently, so Option 60 is required in the DISCOVER and in every REQUEST. This is described in the HLD Design Considerations.

* **Setup**

  Configure the [common bindings](#common-bindings).

* **Test detail**

  | Step | DISCOVER Option 60 | REQUEST Option 60 | Expected |
  |:-|:-|:-|:-|
  | 1 | `VendorA` | `VendorA` | OFFER `.21`, ACK `.21` |
  | 2 | `VendorA` | absent | OFFER `.21`, NAK, because `.21` is not reachable by a `P1` client without a vendor |
  | 3 | absent | `VendorA` for the offered address from `.100` to `.104` | NAK, because that pool is not reachable by a `VendorA` client on `P1` |
  | 4 | `VendorA` | `VendorA`, then a RENEW (unicast, `ciaddr` set) with `VendorA` | ACK for the same address |
  | 5 | `VendorA` | `VendorA`, then a RENEW without Option 60 | NAK for the RENEW |
  | 6 | `VendorA` | `VendorA`, then an INIT-REBOOT REQUEST (`requested_addr`, no `server_id`) without Option 60 | NAK |

  * For the shared pool case, configure `a_on_p1` and `any_on_p1` with the same range, and repeat step 2. Expected: ACK, because the address remains reachable through the less specific binding.

#### test_dhcp_server_match_renew_and_release

* **Test objective**

  Verify RENEW and RELEASE in `MATCH` mode.

* **Test detail**

  * DORA from `P1` with `VendorA`, then RENEW with `VendorA`. Expected: ACK for the same address, with a later `lease_end` in State DB.
  * RELEASE. Expected: the lease is removed from State DB.

#### test_dhcp_server_match_mac_move

* **Test objective**

  Verify that the assignment follows the ingress port when a client moves.

* **Setup**

  Configure the [common bindings](#common-bindings). Save the PTF MAC addresses.

* **Teardown**

  Restore the PTF MAC addresses.

* **Test detail**

  * DORA with MAC `M1` from `P1` with no Option 60. Expected: an address from `.100` to `.104`.
  * DORA with `M1` from `P2`. Expected: `.30`.
  * Swap the MAC addresses of two clients between `P1` and `P2`, as in `test_dhcp_server_port_based_assigenment_single_ip_mac_swap`. Expected: each client gets the address for its new port.

#### test_dhcp_server_match_customized_options

* **Test objective**

  Verify that customized options bound to the DHCP interface are sent to clients in `MATCH` mode.

* **Setup**

  Add a customized string option and bind it to the VLAN.

* **Test detail**

  * DORA from `P1` with `VendorA`. Expected: the OFFER and ACK contain the customized option.

#### test_dhcp_server_match_portchannel_circuit_id

* **Test objective**

  Verify a `circuit_id` match for a PortChannel that is a VLAN member. The relay stamps PortChannels with their name.

* **Setup**

  Create a PortChannel with a PTF facing member, add it to the VLAN, add a match `port_pc` with type `circuit_id` and the PortChannel name as value, and add a binding.

* **Teardown**

  Remove the binding, match, VLAN member and PortChannel.

* **Test detail**

  * DORA through the PortChannel. Expected: an address from the binding pool.
  * Repeat with the PortChannel created after `dhcpservd` has started. Expected: the same result without restarting the service.

### Test Module #2 test_dhcp_server_match_config_change.py

This module verifies runtime configuration changes. Each change is verified with `wait_for_kea_reload` and then with DORA. No service restart is done unless the test says so.

#### test_dhcp_server_match_binding_add_update_del

* **Test objective**

  Verify that binding changes take effect at runtime.

* **Test detail**

  | Step | Change | Expected |
  |:-|:-|:-|
  | 1 | Add `a_on_p1` | `P1` with `VendorA` gets `.21` |
  | 2 | `binding update` to IP `.25` | `P1` with `VendorA` gets `.25` |
  | 3 | `binding update --match port_p1,vendor_b` | `VendorA` gets no offer, `VendorB` gets `.25` |
  | 4 | `binding update --range r1` | `VendorB` gets an address from `r1` |
  | 5 | `binding del` | `VendorB` gets no offer |

#### test_dhcp_server_match_add_more_specific_binding

* **Test objective**

  Verify the lease behaviour when a more specific binding is added after a client already holds a less specific lease. This is described in HLD Specificity Ordering.

* **Test detail**

  * Configure only `any_on_p1`. DORA from `P1` with `VendorA`. Expected: an address from `.100` to `.104`.
  * Add `a_on_p1`. Expected: the existing lease is not deleted from Kea or State DB.
  * RENEW from the client with `VendorA`. Expected: NAK.
  * DORA from the client. Expected: `.21`.

#### test_dhcp_server_match_condition_update

* **Test objective**

  Verify that updating a match condition value changes the classification at runtime.

* **Test detail**

  * `match update vendor_a --value VendorA2`. Expected: `VendorA` no longer matches and `VendorA2` matches `a_on_p1`.
  * Remove the `port_p2` bindings, then `match update port_p1 --value <alias(P2)>`. Expected: the `P1` bindings now serve clients on `P2`, and clients on `P1` get no offer.

#### test_dhcp_server_match_range_update

* **Test objective**

  Verify that updating a range that is used by a binding moves the pool at runtime.

* **Test detail**

  * Bind `r1` to `any_on_p1`, then `range update r1` to new endpoints inside the prefix. Expected: new clients are offered addresses from the new endpoints.

#### test_dhcp_server_match_mode_switch

* **Test objective**

  Verify switching a DHCP interface between `PORT` and `MATCH` mode. This is described in HLD Mode switching.

* **Setup**

  Configure a `DHCP_SERVER_IPV4_PORT` entry for `P1` with IP `.60`, and the bindings `a_on_p1` and `any_on_p1`.

* **Test detail**

  | Step | Action | Expected |
  |:-|:-|:-|
  | 1 | Mode `PORT` | `P1` gets `.60`. Bindings are ignored |
  | 2 | `update --mode MATCH` | `P1` with `VendorA` gets `.21`. The PORT entry is ignored |
  | 3 | RENEW of the `.60` lease from step 1 | NAK. The lease is not deleted when the mode changes |
  | 4 | `update --mode PORT` | `P1` gets `.60` again, and the Kea running configuration equals the configuration of step 1 |

#### test_dhcp_server_match_interface_enable_disable

* **Test objective**

  Verify enabling and disabling a `MATCH` interface, including an interface with no bindings.

* **Test detail**

  * Disable the interface. Expected: no offer on any port. Enable the interface. Expected: the bindings are served again.
  * Delete every binding while the interface is enabled. Expected: the command succeeds, no offer is sent, and Kea keeps running.
  * Enable a `MATCH` interface that has no bindings. Expected: the command succeeds and no offer is sent.

#### test_dhcp_server_match_vlan_member_change

* **Test objective**

  Verify that a binding whose `circuit_id` port leaves the VLAN is skipped, and the other bindings continue to be served. This is the same behaviour as `PORT` mode.

* **Test detail**

  * Remove `P1` from the VLAN. Expected: syslog contains `Binding <vlan>|a_on_p1: circuit ID value <alias(P1)> is not a member of <vlan>, skip`. `P2` clients still get `.30`.
  * Add `P1` back to the VLAN. Expected: `P1` clients are served again without a service restart.

#### test_dhcp_server_match_vlan_intf_change

* **Test objective**

  Verify the behaviour when the VLAN IP changes so that the binding pools are outside the prefix.

* **Setup**

  Change the VLAN IP in `VLAN_INTERFACE` to another prefix.

* **Teardown**

  Restore the VLAN IP.

* **Test detail**

  * DORA from `P1` and `P2`. Expected: no offer, and Kea keeps running.
  * Restore the VLAN IP. Expected: the bindings are served again.

#### test_dhcp_server_match_invalid_config_keeps_last_known_good

* **Test objective**

  Verify that configuration that cannot be compiled, written without the CLI, does not replace the running Kea configuration.

* **Test detail**

  Write each configuration below directly to Config DB with `sonic-db-cli`, on top of the [common bindings](#common-bindings):

  | Invalid configuration | Expected syslog error |
  |:-|:-|
  | Binding `a_anywhere` with matches `vendor_a`, which has equal specificity with `any_on_p1` and can match the same client | `Bindings ... overlap with equal specificity` |
  | Binding with a pool that partially overlaps the pool of another binding | `Bindings ... have partially overlapping pools` |
  | Binding with a pool in a second IPv4 prefix of the VLAN | `DHCP MATCH pools on <vlan> cannot span multiple IPv4 prefixes` |

  * For each case, expected: the error is logged, the Kea running configuration is unchanged, and clients continue to get the addresses of the [expected assignment table](#common-bindings).
  * Remove the invalid entry. Expected: the configuration is regenerated without a service restart.

#### test_dhcp_server_match_missing_reference_is_skipped

* **Test objective**

  Verify that a binding whose match condition or range is deleted directly from Config DB is skipped with a warning, and that the rest of the configuration is still served.

* **Test detail**

  * Delete `DHCP_SERVER_IPV4_MATCH|vendor_a` directly from Config DB. Expected: syslog contains `Binding <vlan>|a_on_p1: match vendor_a does not exist, skip`, and the other bindings are served.
  * Restore the match condition. Expected: `a_on_p1` is served again.
  * Repeat with a range referenced by `any_on_p1`. Expected: the same behaviour.

#### test_dhcp_server_match_persistence

* **Test objective**

  Verify that the configuration and leases persist.

* **Test detail**

  * DORA for several clients, then `config save`.
  * For each of `config reload`, `systemctl restart dhcp_server` and a cold reboot:
    * Check that `show dhcp_server ipv4 match` and `show dhcp_server ipv4 binding` are unchanged.
    * Check that the Kea running configuration is the same as before.
    * Check that the existing leases are present in Kea and State DB.
    * RENEW from each client. Expected: ACK for the same address.

#### test_dhcp_server_match_critical_process

* **Test objective**

  Verify critical process handling in `MATCH` mode.

* **Test detail**

  * Kill each process in `dhcp_server:/etc/supervisor/critical_processes`. Expected: the container restarts, and the `MATCH` configuration is served again, with the same Kea running configuration.

### Test Module #3 test_dhcp_server_match_cli.py

This module verifies the most important CLI behaviour on the DUT. Detailed argument validation is covered by unit tests.

#### test_dhcp_server_match_show

* **Test objective**

  Verify the show commands.

* **Test detail**

  * `show dhcp_server ipv4 match` and `show dhcp_server ipv4 match <name>`. Expected: the columns `Match`, `Type` and `Value`, with values exactly as configured, including values that look like numbers.
  * `show dhcp_server ipv4 binding` and `show dhcp_server ipv4 binding <vlan>`. Expected: the columns `Interface`, `Binding`, `Matches`, `IPs` and `Ranges`.
  * `show dhcp_server ipv4 info <vlan>`. Expected: `Mode` is `MATCH`.
  * `show dhcp_server ipv4 lease <vlan>`. Expected: the interface column shows `<vlan>|<ingress port>` for each lease.

#### test_dhcp_server_match_cli_rejection

* **Test objective**

  Verify that the CLI rejects configuration that cannot be compiled, and that Config DB and the Kea running configuration are unchanged after a rejection.

* **Test detail**

  Run each command on top of the [common bindings](#common-bindings). Expected: non-zero exit status, the error below, and no change to Config DB. `port_px` is a `circuit_id` match for `PX`.

  | Command | Expected error |
  |:-|:-|
  | `match add m1 --type circuit_id --value <nonexistent alias>` | `Circuit ID alias ... does not exist` |
  | `match add m1 --type mac --value x` | `Only match types circuit_id, option60 are supported` |
  | `binding add <vlan> x --match port_px .70` | `Circuit ID alias ... is not a member of vlan ...` |
  | `binding add <vlan> x --match port_p1,port_p2 .70` | `Binding x cannot reference multiple matches of type circuit_id` |
  | `binding add <vlan> x --match vendor_a,vendor_b .70` | `Binding x cannot reference multiple matches of type option60` |
  | `binding add <vlan> x --match vendor_a .70` | `Bindings ... overlap with equal specificity on <vlan>` |
  | `binding add <vlan> x --match port_p2,vendor_a --range <range partially overlapping .100 to .104>` | `Bindings ... have partially overlapping pools on <vlan>` |
  | `binding add <vlan> x --match port_p2,vendor_a <IP outside the VLAN prefix>` | `IP ... is not in any subnet of vlan ...` |
  | `binding add <vlan> x --match port_p2,vendor_a <IP in a second prefix of the VLAN>` | `DHCP pools on <vlan> cannot span multiple IPv4 prefixes` |
  | `binding add <vlan> x --match port_p2,vendor_a --range r1 .70` | `Exactly one of IP list or range list must be provided` |
  | `binding add <vlan> a_on_p1 --match port_p1,vendor_a .21` | `Binding a_on_p1 already exists on <vlan>` |
  | `match del vendor_a` | `Match vendor_a is referenced in ... and cannot be deleted` |
  | `match update vendor_b --type circuit_id --value <alias(P2)>`, which makes `b_on_p1` reference two `circuit_id` matches | `Binding b_on_p1 cannot reference multiple matches of type circuit_id` |
  | `range del <range used by a binding>` | `Range ... is referenced in ...` |
  | `dhcp_server ipv4 del <vlan>` | `Dhcp interface <vlan> has match bindings and cannot be deleted` |
  | `update --mode MATCH <vlan>` on an enabled `PORT` interface whose bindings are not valid | Binding validation error |

  * The rejections that are expressed in the YANG model (for example, both `ips` and `ranges` in one binding) are also applied with GCU. Expected: the patch is rejected.

#### test_dhcp_server_match_cli_order_independence

* **Test objective**

  Verify that the same configuration applied in a different order, or with CLI and with GCU, produces the same Kea running configuration.

* **Test detail**

  * Apply the [common bindings](#common-bindings) through the CLI, and save the Kea running configuration.
  * Remove the configuration, apply it through GCU in the reverse order, and compare the Kea running configuration. Expected: identical.

### Test Module #4 test_dhcp_server_lease_clear.py

This module verifies `sonic-clear dhcp_server ipv4 lease <vlan> (<ip> | --all)` with the packaged Kea and the real State DB. The test cases are parametrized with `mode` (`PORT` and `MATCH`), because the clear command does not depend on the mode.

#### test_dhcp_server_lease_clear_single_ip

* **Test objective**

  Verify that clearing one lease removes only that lease, from both Kea and State DB.

* **Test detail**

  * DORA for three clients.
  * `sonic-clear dhcp_server ipv4 lease <vlan> <ip of client 2>`. Expected: exit status 0. When the command returns, the lease is absent from `lease4-get-all` and from State DB, and the leases of clients 1 and 3 are unchanged.
  * Check that `DHCP_SERVER_IPV4_LEASE_SYNC|GLOBAL` in State DB has `completed_id` equal to `request_id`, which shows that State DB was refreshed after the deletion.

#### test_dhcp_server_lease_clear_all

* **Test objective**

  Verify clearing all leases of a DHCP interface.

* **Test detail**

  * DORA for several clients on two VLANs, using the Module #5 configuration.
  * `sonic-clear dhcp_server ipv4 lease <vlan> --all`. Expected: exit status 0, no lease for this VLAN in Kea or State DB, and the leases of the other VLAN are unchanged.

#### test_dhcp_server_lease_clear_persistence

* **Test objective**

  Verify that the deletion persists in the Kea lease file.

* **Test detail**

  * Clear a lease, then restart the `kea-dhcp4` process with `supervisorctl`. Expected: the lease is not restored in Kea or State DB.
  * Clear all leases, then `systemctl restart dhcp_server`. Expected: no lease is restored.
  * Clear all leases, `config save`, and reboot. Expected: no lease is restored.

#### test_dhcp_server_lease_clear_device_replacement

* **Test objective**

  Verify the device replacement use case from the HLD: a new device gets the address of the old device without waiting for the lease to expire.

* **Test detail**

  * Configure a binding with a single IP. DORA with client MAC `M1`. Expected: the IP is leased.
  * DORA with a new client MAC `M2` on the same port. Expected: no offer, because the IP is leased to `M1`.
  * Clear the lease. DORA with `M2`. Expected: the IP is offered and acknowledged.

#### test_dhcp_server_lease_clear_negative

* **Test objective**

  Verify the error handling of the clear command.

* **Test detail**

  | Command | Expected |
  |:-|:-|
  | Clear an IP that has no lease | Exit status 1, `No matching Kea lease on <vlan>` |
  | Clear `--all` on a VLAN with no lease | Exit status 1, `No matching Kea lease on <vlan>` |
  | Clear with both an IP and `--all`, or with neither | Usage error, exit status 2 |
  | Clear with an invalid IP address | Usage error, exit status 2 |
  | Clear on a VLAN that is not a DHCP interface | Exit status 1, `DHCP interface <vlan> is not configured` |
  | Clear without root privileges | Exit status 1, `Root privileges are required; run with sudo` |
  | Clear when the `dhcp_server` feature is disabled | `Feature dhcp_server is not enabled` |

  * A State DB lease entry that has no lease in Kea: insert the entry directly, then clear its IP. Expected: exit status 1, and the stale entry is removed from State DB.

#### test_dhcp_server_lease_clear_concurrency

* **Test objective**

  Verify that two clear commands do not run at the same time.

* **Test detail**

  * Run two clear commands in parallel. Expected: one succeeds and the other fails with `Another DHCP lease clear is in progress`, or both succeed one after the other. At the end, State DB matches Kea.

### Test Module #5 test_dhcp_server_match_multi_vlans.py

#### Common setup

* Use GCU to create two VLANs with different prefixes and members, as in `test_dhcp_server_multi_vlans.py`.
* Configure the first VLAN in `MATCH` mode with the [common bindings](#common-bindings), and the second VLAN in `PORT` mode.

#### test_dhcp_server_match_and_port_mode_coexist

* **Test objective**

  Verify that `MATCH` and `PORT` interfaces work at the same time on one DUT.

* **Test detail**

  * DORA on each VLAN. Expected: the `MATCH` VLAN follows the [expected assignment table](#common-bindings), and the `PORT` VLAN follows its port configuration.
  * Change a binding on the `MATCH` VLAN. Expected: the `PORT` VLAN leases and assignments are unaffected.
  * Write invalid `MATCH` configuration directly to Config DB, as in Module #2. Expected: the `PORT` VLAN continues to be served.

#### test_dhcp_server_match_shared_conditions

* **Test objective**

  Verify that one `option60` match condition can be used by bindings on several `MATCH` VLANs.

* **Test detail**

  * Switch both VLANs to `MATCH` mode, with a binding that has only `vendor_a` on each VLAN, using a pool in the prefix of that VLAN.
  * DORA with `VendorA` on each VLAN. Expected: each client gets an address from the pool of its own VLAN.

### Test Module #6 test_dhcp_server_match_stress.py

#### test_dhcp_server_match_scale

* **Test objective**

  Verify generation and assignment with many bindings.

* **Test detail**

  * On every available VLAN member, configure a port only binding and bindings for four vendors, so that there are 5 bindings per port.
  * Measure the time from the last configuration change to `wait_for_kea_reload`. Expected: within 30 seconds.
  * DORA for each port and vendor combination. Expected: every client gets an address from the expected pool.

#### test_dhcp_server_match_flood

* **Test objective**

  Verify assignment with flooding packets.

* **Test detail**

  * Send DHCP DISCOVER packets at 100 packets per second from several PTF ports, with a mix of Option 60 values, as in `test_dhcp_server_stress.py`.
  * Expected: every client that matches a binding receives an OFFER from the correct pool, every client that does not match receives no OFFER, and `dhcp_server` and `dhcp_relay` remain running.

## Requirement Coverage

| HLD functional requirement | Test cases |
|:-|:-|
| 1. IP assignment based on configurable DHCP packet field matching | Module #1 |
| 2. `circuit_id` match type | `test_dhcp_server_match_circuit_id_format`, `test_dhcp_server_match_circuit_id_only`, `test_dhcp_server_match_portchannel_circuit_id` |
| 3. `option60` match type | `test_dhcp_server_match_option60_only`, `test_dhcp_server_match_option60_value_semantics`, `test_dhcp_server_match_option60_per_packet` |
| 4. Several match conditions per binding (AND logic) | `test_dhcp_server_match_and_logic`, `test_dhcp_server_match_specificity` |
| 5. Different pools for different conditions in one VLAN | `test_dhcp_server_match_specificity`, `test_dhcp_server_match_or_logic` |
| 6. New `MATCH` mode | `test_dhcp_server_match_mode_switch`, `test_dhcp_server_match_interface_enable_disable` |
| 7. `PORT` mode backward compatibility | `test_dhcp_server_match_and_port_mode_coexist`, `test_dhcp_server_match_mode_switch`. The existing `tests/dhcp_server` tests run unchanged |
| 8. Extensible match types | Unit tests only |
| Lease clearing (Clear CLI) | Module #4 |

## Deferred Test Cases

The HLD describes the following items that are not implemented in the sonic-buildimage PRs listed in [Related Documents](#related-documents). Test cases will be added to this plan when they are implemented.

| HLD item | Planned verification |
|:-|:-|
| `config dhcp_server ipv4 log-level` and `show dhcp_server ipv4 log-level` | The Kea logger `severity` and `debuglevel` change in the running configuration, `EVAL_RESULT` messages appear at `debug`, the setting survives `config reload`, and a syslog warning is raised at a level other than `info` |
| `mode`, `binding` and `assign_time` fields in `DHCP_SERVER_IPV4_LEASE` | The fields are set on ACK, `assign_time` is kept across RENEW and reset when the address changes, and `binding` lists every binding of a shared pool |
| `DHCP_SERVER_MATCH_CLASS` and `DHCP_SERVER_LEASE_ASSIGNED` syslog messages | The message format and content. The current implementation logs `DHCP MATCH class <class> maps to bindings <bindings>` |
| `sonic-clear dhcp_server ipv4 lease <vlan> --mac <MAC>` | Clearing by MAC address. The current implementation supports an IP address or `--all` |
| Log rotation for the Kea log file | The log is rotated by `logrotate` |
