# Spanning Tree Test Plan (PVST and MSTP)

## Revision

| Rev | Date | Change |
|:---:|:----------:|--------|
| 0.1 | 2026-11-03 | Initial version: `tests/stp` replaces `tests/pvst`, adds MSTP, config, PortChannel and upgrade cases |

## Overview

This plan covers the spanning-tree suite in `tests/stp`. One suite tests both modes SONiC supports: PVST (one tree per VLAN) and MSTP (IEEE 802.1s, a CIST plus MST instances). It grew from the PVST suite in `tests/pvst`, described in [PVST-testplan.md](PVST-testplan.md); every case of that plan is still here, in `test_stp_pvst.py`.

## Scope

In scope: the bridge and port state the stp daemon publishes to APPL_DB, the BPDUs the DUT sends, the DUT's reaction to BPDUs sent from the PTF, the CLI and CONFIG_DB configuration of both modes, BPDU guard, root guard, portfast, uplink fast, statistics, MAC flush on topology change, a static PortChannel as an STP port, and the STP configuration across a config replace and an image switch.

Out of scope: trees with more than one SONiC bridge, interoperability with other vendors' bridges, and scale.

## Testbed

Topology `t0`. The DUT's VLAN members are connected to the PTF, which plays the neighbouring bridge: it captures the BPDUs the DUT sends and sends BPDUs of its own (superior, inferior, topology change, foreign region) to drive the DUT's state machine. Most cases use the two lowest-numbered members of the first minigraph VLAN as `port_1` and `port_2`; the config cases create a second VLAN and a spare PortChannel and remove them afterwards.

The image must include the stp feature. When `show feature status` has no `stp` row, every case skips.

On a KVM DUT the software datapath forwards nothing between two forwarding VLAN members, so `test_stp_pvst.py` and `test_mstp.py` are skipped there through conditional_mark, as are the CIST enrolment checks a virtual DUT does not model. The CONFIG_DB and APPL_DB checks in `test_pvst_config.py` run on KVM.

## Suite layout

| File | Content |
|------|---------|
| `conftest.py` | Fixtures: the feature check, the test ports and VLAN, the mode under test (from the class's `STP_MODE`), `stp_config_env` for the config cases, `spare_portchannel` |
| `stp_base.py` | Mode-parametrised helpers and `StpTestBase`: enable and disable, timers, priorities, port settings, waits on APPL_DB state, PTF runners, BPDU streams |
| `stp_utils.py` | Readers for the PVST and MST tables in CONFIG_DB and APPL_DB |
| `test_stp_pvst.py` | PVST protocol cases |
| `test_mstp.py` | MSTP protocol cases |
| `test_pvst_config.py`, `test_mstp_config.py` | Enrolment and configuration cases per mode |
| `test_stp_portchannel.py` | The same checks with a static PortChannel as the STP port, both modes |
| `test_stp_upgrade.py` | PVST configuration across an image switch |
| `unit_tests/unit_test_stp_config_env.py` | DUT-free tests of the `stp_config_env` helpers |

PTF side, in `ansible/roles/test/files/ptftests/py3`:

| File | Content |
|------|---------|
| `stp_bpdu_base.py` | Common sender, threaded capture and scenario dispatch |
| `pvst_bpdu_test.py` | PVST BPDU scenarios: config and TCN BPDUs, timers, backup port, root path cost, bridge id and priority |
| `mstp_lib.py` | MST BPDU encode and decode and the MST configuration digest, with a self-test against the IEEE 802.1s reference vector |
| `mstp_bpdu_test.py` | MSTP BPDU scenarios |

## Testbed hygiene

Every fixture puts the DUT back as it found it. The feature check snapshots the STP-owned CONFIG_DB rows and restores them at the end of the module. `stp_config_env` reads the running CONFIG_DB, creates only what is missing (VLAN, members, PortChannel), removes only what it created, and fails the case when a command it depends on fails. The upgrade case puts back both images' saved configuration files.

## Test cases

### PVST protocol (`test_stp_pvst.py`)

| Case | What it checks |
|------|----------------|
| `test_pvst_validate_root_bridge` | A lone DUT is root for the VLAN, its ports go LISTENING, LEARNING, FORWARDING, its BPDU carries its bridge id, priority and timers, and an L2 frame forwards between its ports (PVST TC1) |
| `test_pvst_designated_bridge` | Under a superior neighbour the DUT roots on `port_1`, `port_2` blocks, and a frame from the forwarding port is learned there (PVST TC2) |
| `test_pvst_shutdown_root_port` | Shutting the root port moves the root to `port_2`; startup restores it (PVST TC3) |
| `test_pvst_bridge_priority_change_in_bpdu` | Lowering the VLAN priority past the neighbour's makes the DUT root and its BPDU carries the new priority (PVST TC4) |
| `test_pvst_port_priority_change_in_bpdu` | A better port priority received on `port_2` moves the root port there (PVST TC5) |
| `test_pvst_path_cost_validation` | The root path cost the DUT sends on its designated port follows the configured cost of the root port, read only from BPDUs the DUT sent (PVST TC6) |
| `test_pvst_root_guard_functionality` | With root guard on, a superior BPDU puts the port in root-inconsistent state (PVST TC7) |
| `test_pvst_bpdu_guard_with_shutdown` | A BPDU err-disables a `bpdu-guard --shutdown` port; with the guard off the port stays up (PVST TC8) |
| `test_pvst_bpdu_timer_validation` | Per-VLAN hello, forward delay and max age are carried in the DUT's BPDU on both ports (PVST TC9) |
| `test_pvst_backup_port_functionality` | The DUT's own BPDU replayed on `port_2` makes it a backup port; it forwards again when the replay stops (PVST TC10) |
| `test_pvst_mac_flush` | A TCN BPDU flushes the MACs learned on the other port (PVST TC11) |
| `test_pvst_portfast` | A portfast port skips the two forward delays at link up, a BPDU turns portfast off, and without portfast the same bounce takes the full delay |
| `test_pvst_uplink_fast` | With uplink fast, losing the root port moves the tree to the blocked uplink within seconds; without it the failover takes two forward delays |
| `test_pvst_statistics_and_clear` | Per-port counters count the DUT's BPDUs and the TCNs it receives, the show command agrees, and the clear command resets them |
| `test_pvst_bpdu_flood_is_survived` | A burst of superior BPDUs sent as fast as the PTF can leaves stpd running with the same pid, every BPDU it received counted, and the DUT root again within a max age |

### MSTP protocol (`test_mstp.py`)

The class enables MSTP with a test region and maps the VLAN under test to instance 1. The PTF sends with the same region name, revision and VLAN map, so its configuration digest matches the DUT's and the DUT treats it as in-region.

| Case | What it checks |
|------|----------------|
| `test_mstp_validate_root_bridge` | A lone DUT is CIST regional root, its ports forward, and its BPDU carries the region name, revision and matching digest |
| `test_mstp_region_and_instance` | The region and the instance 1 VLAN map show in the DUT's operational state and BPDU |
| `test_mstp_boundary_on_region_mismatch` | A BPDU from another region marks the receiving port a region boundary |
| `test_mstp_superior_root_takes_over` | An in-region superior CIST BPDU takes the CIST root from the DUT |
| `test_mstp_shutdown_root_port` | Shutting the CIST root port moves the root to `port_2`; startup restores it |
| `test_mstp_bridge_priority_change_in_bpdu` | Lowering the CIST priority past the neighbour's makes the DUT root and its BPDU carries the new priority |
| `test_mstp_port_priority_change_in_bpdu` | A better CIST port priority received on `port_2` moves the root port there |
| `test_mstp_path_cost_validation` | The CIST internal root path cost the DUT sends follows the configured cost of the root port |
| `test_mstp_bpdu_guard_with_shutdown` | A BPDU err-disables a guarded port; with the guard off the port stays up |
| `test_mstp_bpdu_guard_without_shutdown` | Without `--shutdown` the guard only logs; the port stays up |
| `test_mstp_bpdu_guard_shutdown_survives_feature_restart` | The guard still err-disables the port after a feature disable and enable |
| `test_mstp_bpdu_timer_validation` | Global MST timers are carried in the DUT's BPDU on both ports |
| `test_mstp_mac_flush` | A CIST BPDU with the TC flag flushes the MACs learned on the other port |

### Configuration (`test_pvst_config.py`, `test_mstp_config.py`)

| Case | What it checks |
|------|----------------|
| `test_pvst_enrol_on_feature_start`, `test_mstp_enrol_on_feature_start` | With two VLANs and their members created first, enabling the mode and the feature enrols every member; disabling the mode clears it |
| `test_pvst_member_lifecycle_per_vlan` | A port in two VLANs has independent state in each tree and loses each only when it leaves that VLAN |
| `test_mstp_member_lifecycle_across_vlans` | A port in two VLANs keeps its CIST state until it leaves the last one |
| `test_pvst_portchannel_delete_leaves_no_stp_state` | Deleting a PortChannel that was in a PVST VLAN leaves no STP row keyed on its name |
| `test_pvst_disable_leaves_valid_config_and_no_tree`, `test_mstp_disable_leaves_valid_config_and_no_tree` | Disabling the mode removes the daemon's APPL_DB rows, keeps the configuration, and the kept configuration still passes YANG validation |
| `test_pvst_config_replace_round_trip` | A config replace of the running configuration is accepted, every STP row reads back unchanged, and the tree is still there |
| `test_pvst_bridge_priority_must_be_a_multiple_of_4096`, `test_mstp_instance_priority_must_be_a_multiple_of_4096` | The YANG model refuses a bridge priority that is not a multiple of 4096 (the case skips when the model has no such rule) |
| `test_mstp_instance_created_from_cli` | An MST instance created from the CLI reaches APPL_DB with its VLAN, the VLAN's member enrols in it and leaves the CIST, and deleting the mapping removes it |
| `test_mstp_after_runtime_switch_from_pvst` | Switching from PVST to MSTP on a running switch brings up the CIST with every member and leaves no PVST row behind |

### Static PortChannel (`test_stp_portchannel.py`)

Three VLAN members leave the VLAN and become a static PortChannel (loadbalance runner, no LACP), which takes their place in the VLAN; on the PTF the matching ports form a balance-xor bond. Each case runs in both modes. The cases skip when no spare PortChannel name is free or the image's teamd has no static runner.

| Case | What it checks |
|------|----------------|
| `test_portchannel_is_static` | The PortChannel runs the loadbalance runner and sends no LACPDUs |
| `test_portchannel_has_role_and_state` | With the DUT as root the PortChannel is a forwarding designated port and the DUT's BPDUs leave through one of its members |
| `test_portchannel_cost_and_priority_apply` | The PortChannel's port cost decides the root port against the plain port, and its port priority reaches the daemon |
| `test_portchannel_bpdu_guard` | BPDU guard trips on the PortChannel; with the guard off it comes back and stays up |
| `test_portchannel_root_guard` | A superior BPDU on a root-guarded PortChannel blocks it instead of taking the root |
| `test_portchannel_topology_change_flushes` | A topology change arriving on the PortChannel flushes the MACs learned on the plain port |
| `test_portchannel_keeps_the_tree_through_member_churn` | Removing and re-adding one member keeps the PortChannel forwarding with its cost and role |
| `test_portchannel_returns_with_its_settings` | When all members go and come back, the PortChannel leaves and rejoins the tree with its port cost intact |

### Upgrade (`test_stp_upgrade.py`)

| Case | What it checks |
|------|----------------|
| `test_pvst_config_survives_image_switch` | A saved PVST configuration boots on the other installed image and back, every STP row reads back unchanged, and the tree comes up both times (skips with one image) |

## Case names carried over from tests/pvst

| tests/pvst/test_pvst.py | tests/stp/test_stp_pvst.py |
|-------------------------|----------------------------|
| `test_pvst_validate_root_bridge` | `test_pvst_validate_root_bridge` |
| `test_pvst_verify_sonic_dut_as_designated_bridge` | `test_pvst_designated_bridge` |
| `test_shutdown_root_port_on_sonic_and_verify` | `test_pvst_shutdown_root_port` |
| `test_bridge_priority_change_in_bpdu` | `test_pvst_bridge_priority_change_in_bpdu` |
| `test_port_priority_change_in_bpdu` | `test_pvst_port_priority_change_in_bpdu` |
| `test_pvst_path_cost_validation` | `test_pvst_path_cost_validation` |
| `test_pvst_root_guard_functionality` | `test_pvst_root_guard_functionality` |
| `test_pvst_bpdu_guard_with_shutdown` | `test_pvst_bpdu_guard_with_shutdown` |
| `test_pvst_bpdu_timer_validation` | `test_pvst_bpdu_timer_validation` |
| `test_pvst_backup_port_functionality` | `test_pvst_backup_port_functionality` |
| `test_pvst_mac_flush` | `test_pvst_mac_flush` |

## Abbreviations

| Term | Meaning |
|------|---------|
| BPDU | Bridge Protocol Data Unit |
| CIST | Common and Internal Spanning Tree |
| MSTI | Multiple Spanning Tree Instance |
| MSTP | Multiple Spanning Tree Protocol |
| PVST | Per-VLAN Spanning Tree |
| TC, TCN | Topology Change, Topology Change Notification |
