# Snappi GCU Port Speed Upgrade Test Plan and HLD

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
  - [Assumptions](#assumptions)
- [High Level Design](#high-level-design)
- [Setup Configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [test_snappi_gcu_port_speed_upgrade_100g_to_400g](#test-case-test_snappi_gcu_port_speed_upgrade_100g_to_400g)
- [Pass and Fail Criteria](#pass-and-fail-criteria)
- [Run Command](#run-command)
- [Cleanup](#cleanup)

## Revision

| Rev | Date | Author | Change Description |
|:---:|:----:|:-------|:-------------------|
| 0.1 | 07/25/2026 | anamehra | Initial test plan and HLD for Snappi GCU 100G to 400G port speed upgrade coverage. |

## Overview

The purpose of this test is to validate that a Snappi-connected downlink line-card port can be converted from a 100G runtime state back to 400G using Generic Config Updater (GCU), and that the port can then be used by the Snappi traffic framework.

The test does not alter minigraph content. It starts from an existing 400G Snappi-connected downlink LC port, uses GCU to create the temporary 100G state, uses GCU again to restore 400G with the applicable selected-port cluster patch data, then validates Snappi setup, ARP, and traffic when a traffic peer is available.

## Scope

In scope:

- Select a Snappi-connected 400G port on the T2 downlink line card.
- Convert the selected DUT port from 400G to 100G by applying a PORT-only GCU patch.
- Convert the selected DUT port from 100G to 400G by applying a GCU patch that includes applicable selected-port restore data, including `QUEUE`.
- When the selected 400G port is a PortChannel member, convert all external members of that PortChannel together and restore PortChannel configuration as part of the 400G patch.
- Verify speed, lanes, FEC, and oper state after the GCU transitions.
- Reuse an existing downlink Snappi 100G port as a traffic peer when the setup has one.
- Run Snappi all-to-all traffic when at least two Snappi ports are selected.
- Validate zero packet loss and nonzero received packets for Snappi flows.
- Apply Snappi config and ARP validation without traffic when only one Snappi port is available.

Out of scope:

- Minigraph modification or minigraph generation.
- Fanout speed reconfiguration.
- Full generic_config_updater add-cluster test coverage such as telemetry, ACL counters, or bidirectional PTF dataplane traffic.
- Upstream LC port selection.
- Multiple-line-card traffic patterns.

## Testbed

Supported topology:

- `multidut-tgen`
- T2 chassis topology detected from `tbinfo`

Required physical setup:

- A T2 chassis testbed with Snappi/Ixia connectivity.
- The testbed DUT list must include the downlink LC as the second DUT entry in `tbinfo["duts"]`.
- At least one Snappi-connected 400G port must exist on the downlink LC.
- If the selected 400G port is a PortChannel member, all external members of that PortChannel must have 400G Snappi links.
- For traffic validation, at least one additional Snappi-connected downlink LC port should exist. This peer may already be 100G and is not modified by GCU.

Minimum setup:

- One downlink LC 400G Snappi port is sufficient for GCU conversion validation.
- If only one total Snappi port is selected, the test applies Snappi config and waits for ARP, but does not generate traffic.

## Assumptions

- The selected 400G GCU target port is present in the DUT `PORT` table and in Snappi port metadata.
- The platform has lane-count data for 100G and 400G conversion in `tests/snappi_tests/gcu/files/gcu_port_speed_platforms.yaml`.
- The selected port supports a FEC mode that is valid for the target speed.
- Running config and minigraph facts are available as sources for applicable selected-port and PortChannel restore data.
- Expected transient errors can appear while `PORT`, `BUFFER_PG`, `QUEUE`, `PORT_QOS_MAP`, `PFC_WD`, and related tables converge during speed changes; the test configures loganalyzer ignores for those known transient patterns, including transient `sonic_yang` validation messages emitted while GCU tries patch orderings.

## High Level Design

The test implementation is in `tests/snappi_tests/gcu/test_gcu_port_speed_upgrade.py`.

The design has four phases:

1. Port selection
   - Restrict execution to T2.
   - Select only downlink LC Snappi ports.
   - Select at least one 400G downlink LC Snappi port as the GCU target.
   - If the selected target is a PortChannel member, include all external PortChannel members in the GCU target set.
   - If fewer 400G target ports exist than the traffic shape prefers, select additional downlink LC Snappi ports as non-GCU traffic peers.
   - Prefer a 100G peer when one is available.

2. GCU speed transition
   - Snapshot running CONFIG_DB and minigraph facts for each target DUT/ASIC context.
   - Read platform lane-count and FEC data from `tests/snappi_tests/gcu/files/gcu_port_speed_platforms.yaml`.
   - Build a 100G PORT entry preserving non-speed fields and updating speed, lanes, and FEC.
   - Apply the 100G PORT-only patch through GCU.
   - Verify the selected port is configured as 100G. Oper-up is not required after the downgrade.
   - Build the 400G restore patch from the current 100G state and original 400G port data.
   - Include applicable selected-port restore data for the 400G upgrade patch, including `DEVICE_NEIGHBOR`, `INTERFACE`, `BUFFER_PG`, `QUEUE`, `PORT_QOS_MAP`, `PFC_WD`, `CABLE_LENGTH`, PortChannel tables, and neighbor metadata when present.
   - Apply the 400G patch through GCU.
   - Verify the selected port is 400G and oper-up.

3. Snappi setup
   - Build Snappi testbed configuration from the selected ports.
   - Use the regular Snappi base config when all selected ports have the same speed.
   - Use the mixed-speed Snappi base config when the selected target and peer ports have different speeds.
   - Configure DUT-side test IPs through the Snappi fixture path.

4. Snappi validation
   - If two or more Snappi ports are selected, generate all-to-all IPv4 traffic.
   - Use a lossless priority from the existing Snappi QoS fixtures.
   - Cap mixed-speed flow rates by the slower side so a 400G source does not overdrive a 100G peer.
   - Assert zero packet loss and nonzero received frames.
   - For single-speed traffic, also validate expected frame count tolerance.
   - For mixed-speed traffic, skip exact expected frame count validation because each port has its own L1 speed profile.
   - If fewer than two ports are selected, apply Snappi config and wait for ARP only.

## Setup Configuration

The test uses existing sonic-mgmt Snappi setup files and fixtures:

- Snappi device inventory and link metadata from the lab inventory.
- `get_snappi_ports` to discover Snappi-connected DUT ports.
- `tests/snappi_tests/gcu/files/gcu_port_speed_platforms.yaml` for platform lane-count and FEC data used by the Snappi GCU conversion.
- `snappi_dut_base_config` for same-speed selected ports.
- `snappi_multi_base_config` for mixed-speed selected ports.
- `lossless_prio_list` and `prio_dscp_map` for traffic priority and DSCP mapping.

No new minigraph content is generated by this test.

## Test Cases

## Test case test_snappi_gcu_port_speed_upgrade_100g_to_400g

### Test objective

Verify that a Snappi-connected downlink LC 400G port can be moved to a temporary 100G runtime state and restored back to 400G through GCU, then validated through Snappi configuration, ARP, and traffic when a downlink Snappi peer is available.

### Test setup

- Select Snappi ports for the `multidut-tgen` topology.
- Detect the T2 downlink LC.
- Select at least one 400G Snappi port on the downlink LC as the GCU target.
- If the selected 400G target is a PortChannel member, add all external PortChannel members to the GCU target set.
- Select a non-GCU downlink traffic peer if available, preferring an existing 100G peer.
- Capture running config facts and extended minigraph facts for each target DUT/ASIC context.
- Register loganalyzer ignores for expected transient speed-change messages.

### Test steps

1. Verify the selected GCU target starts as 400G in DUT config and Snappi metadata.
2. Build the 100G PORT config for the selected target.
3. Apply the 100G PORT-only GCU patch.
4. Verify the target port shows 100G speed, expected lanes, and expected FEC.
5. Build the 400G PORT config using the original 400G PORT data and the current 100G config.
6. Build applicable selected-port restore patch data from the original running config and minigraph facts, including `QUEUE` entries for the selected port and PortChannel restore data when the selected target is a PortChannel member.
7. Apply the 400G GCU patch.
8. Verify the target port shows 400G speed, expected lanes, expected FEC, and oper-up.
9. Build Snappi base config from the selected target and optional peer ports.
10. If only one Snappi port is selected, apply Snappi config, wait for ARP, and end the test.
11. If two or more Snappi ports are selected, generate all-to-all IPv4 traffic.
12. Run traffic for the configured duration.
13. Verify every flow has equal Tx/Rx frame counts and nonzero received frames.
14. For same-speed traffic, verify the received frame count is within expected tolerance.

### Test teardown

- Clear Snappi DUT port configuration through `setup_dut_ports(..., setup=False)` when Snappi setup was created.
- Restore every GCU-touched DUT through minigraph config reload.
- Delete temporary GCU patch files as part of the shared GCU helper path.

## Pass and Fail Criteria

Pass criteria:

- The test selects only downlink LC ports.
- At least one downlink LC 400G GCU target is selected.
- The target port successfully transitions to 100G through GCU.
- The target port successfully transitions back to 400G through GCU.
- The target port is oper-up after the 400G restore.
- Snappi config and ARP succeed.
- If traffic is generated, all flows have zero loss and nonzero received packets.

Skip criteria:

- The topology is not T2.
- No downlink LC 400G Snappi port is available.
- The selected 400G target is a PortChannel member and not all external PortChannel members have 400G Snappi links.

Fail criteria:

- Any GCU apply-patch operation fails or times out.
- The target port speed, lanes, or FEC do not match the expected post-GCU state.
- The target port does not become oper-up after 400G restore.
- Snappi config or ARP fails.
- Any generated Snappi flow has packet loss or no received packets.

## Run Command

Run from the `tests` directory in the sonic-mgmt container. Replace inventory, DUT hostname, testbed, and log path with the lab-specific values.

```bash
./run_tests.sh \
  -n <testbed-name> \
  -d <dut-hostname> \
  -c snappi_tests/gcu/test_gcu_port_speed_upgrade.py \
  -f ../ansible/testbed.yaml \
  -i ../ansible/<inventory> \
  -u \
  -l info \
  -p <log-path> \
  -e "--skip_sanity"
```

## Cleanup

The test mutates runtime config through GCU. Cleanup restores touched DUTs with minigraph config reload. This restore is registered in the fixture cleanup path so it runs after normal pass, assertion failure, and partial setup failure.
