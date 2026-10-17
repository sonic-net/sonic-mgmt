# Monitor Link Group Tests

End-to-end tests for the SONiC Monitor Link Group feature.

## What the feature does

A monitor link group tracks a set of uplink interfaces and automatically
forces a set of downlink interfaces admin-down when the operational uplink
count drops below a configured `min-uplinks` threshold. This prevents
traffic black-holing in topologies where downlinks have no value
without their uplinks.

See the HLD for design details:
[`doc/monitor_link/monitor-link_HLD.md`](https://github.com/sonic-net/SONiC/blob/master/doc/monitor_link/monitor-link_HLD.md)

## Prerequisites

The DUT image must include:

* `MONITOR_LINK_GROUP` CONFIG_DB table support (swss / sonic-swss-common)
* `sonic-monitor-link-group` YANG module (sonic-yang-models)
* `show monitor-link-group` CLI command (sonic-utilities)

The tests require enough usable Ethernet interfaces on the DUT for the
scenarios that share uplinks and downlinks across multiple groups:

* Most tests: 2–5 usable interfaces.
* `test_scenario_15_three_groups_share_downlinks`: 8 usable interfaces
  (6 uplinks across 3 groups + 2 shared downlinks).
* `test_many_groups_apply_simultaneously`: 16 usable interfaces.

PortChannel tests (`test_portchannel_uplink`, `test_portchannel_downlink`)
are skipped if no PortChannels are operational on the DUT.

## Layout

```
tests/monitor-link-group/
├── README.md                  # This file
├── conftest.py                # session-scoped InterfacePool + per-test cleanup ctx
├── monitor_link_helpers.py    # config_load, STATE_DB readers, wait_* helpers
└── test_monitor_link.py       # one test per HLD scenario + corner cases
```

Helpers are plain functions; tests are flat pytest functions.
Interface discovery uses `duthost.get_interfaces_status()` filtered to
oper-up Ethernet ports and PortChannels; no auto-bring-up of admin-down
interfaces.

## How it works

Configuration is applied via `config load` of a JSON file holding only
the `MONITOR_LINK_GROUP` table. Cleanup deletes group keys directly from
CONFIG_DB via `sonic-db-cli` since there is no user-facing imperative
remove operation.

Link state is toggled via `config interface shutdown` / `startup`
(`duthost.shutdown` / `duthost.no_shutdown`) so the tests run on both
physical DUTs and KVM topologies.

State is observed by polling STATE_DB:

* `MONITOR_LINK_GROUP_STATE|<group>` — group `state` is `up` / `down` / `pending`
* `MONITOR_LINK_GROUP_MEMBER|<intf>` — downlink `state` is `allow_up` / `force_down`

## Supported topologies

The module declares `topology("t0", "t1", "any")`. Validated on `t0` and
`t1`; the feature is topology-agnostic (control-plane only, no SAI changes),
so additional topologies should work but have not been explicitly tested.

## HLD scenarios covered

| HLD # | Test |
|-------|------|
| 1 | `test_scenario_01_create_with_uplinks_up` |
| 4 | `test_scenario_04_create_with_uplinks_down` |
| 6 | `test_scenario_06_runtime_uplinks_go_down` |
| 7 | `test_scenario_07_uplink_recovers` |
| 8 | `test_scenario_08_admin_down_downlink_overrides_group` |
| 14 | `test_scenario_14_three_groups_share_uplinks` |
| 15 | `test_scenario_15_three_groups_share_downlinks` |

## Corner cases

| Area | Test |
|------|------|
| Cross-role chaining | `test_corner_chained_groups_cross_role` |
| link-up-delay PENDING → UP | `test_corner_link_up_delay_pending_then_up` |
| link-up-delay flap cancels + restarts timer | `test_corner_link_up_delay_flap_resets_pending` |
| link-up-delay → 0 while pending | `test_corner_link_up_delay_zero_while_pending` |
| min-uplinks > configured uplinks | `test_corner_min_uplinks_exceeds_available_stays_down` |
| min-uplinks=2 threshold | `test_corner_min_uplinks_threshold_above_one` |
| Config rollback A → B → A | `test_corner_config_rollback` |

## Additional coverage

### Runtime config mutation
- `test_runtime_add_uplink_keeps_group_up`
- `test_runtime_remove_only_uplink_drops_group`
- `test_runtime_add_downlink_to_down_group_force_down`
- `test_runtime_min_uplinks_increase_drops_group`
- `test_description_only_update_no_state_flap`

### Delay edge cases
- `test_delay_reduced_past_elapsed_brings_up_immediately`
- `test_delay_increase_while_pending_extends_timer`
- `test_delete_group_during_pending_releases_downlinks`

### Group lifecycle
- `test_delete_up_group_releases_downlinks`
- `test_delete_and_recreate_same_name`

### Boundary configs
- `test_min_uplinks_zero_always_up`
- `test_group_with_no_downlinks_tracks_state_only`

### PortChannel
- `test_portchannel_uplink`
- `test_portchannel_downlink`

### Multi-group / multi-role
- `test_interface_in_three_roles_multi_fanout`
- `test_many_groups_apply_simultaneously`

### YANG validation (negative)
- `test_yang_rejects_same_intf_as_uplink_and_downlink`
- `test_yang_rejects_non_ethernet_member`

### Resilience
- `test_swss_restart_recovers_state` (slow, ~2 min)
- `test_config_save_then_reload_persists` (slow, ~3 min; disruptive)

### Stress / timing
- `test_rapid_uplink_flap_converges`
- `test_concurrent_groups_share_pending`

### CLI
- `test_show_monitor_link_group_matches_state_db`

## Running

```
cd tests
./run_tests.sh -n <testbed> -i <inventory> -f <topo>.yaml -c monitor-link-group/test_monitor_link.py
```

To exclude the slow disruptive tests:

```
./run_tests.sh -n <testbed> -i <inventory> -f <topo>.yaml \
    -c monitor-link-group/test_monitor_link.py \
    -e 'test_swss_restart_recovers_state or test_config_save_then_reload_persists'
```
