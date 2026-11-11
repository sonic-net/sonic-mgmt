# High Level Design: RIB End-to-end Scaling, Optimization and Performance Tests.

## 1. Overview

### 1.1 Purpose

This document describes the high-level design of the **RIB end-to-end optimization and performance** test suite, which measures control-plane-to-data-plane convergence time for BGP route advertisement under different DUT configuration profiles and orchagent tuning parameters. The tests are used to evaluate RIB-IN performance and SONiC optimizations (e.g., northbound ZMQ, synchronous mode, orchagent bulk/batch settings) across multiple dimensions in a single parameterized framework.

### 1.2 Goals

- **Parameterized coverage**: Run RIB convergence (default 300K routes) for each combination of:
  - **Fine-tuning profile** (config parameters from `fine-tunings.yml`)
  - **Orchagent bulk/batch pair** (e.g. `-b` / `-k` from `bk_values.json`)
  - **Route type** (IPv4, IPv6, IPv4v6)
- **Clean state**: Each test applies profile + b/k, reboots, runs the convergence test, then reverts config and orchagent so the next parameterized run starts from a known state.
- **Memory observability**: The memory-utilization is disabled for this test using pytest.marker functionality. Instead, the optional per-process CPU / memory monitor (`mem_cpu_monitor`, Section 8.4) samples the DUT(s) during the convergence run.
- **Multi-ASIC / multi-DUT support**: The same test runs on single-ASIC DUTs, on single-DUT multi-ASIC DUTs and on testbeds whose test ports are spread across several DUTs / line cards (see Section 7).

---

## 2. Scope

### 2.1 In Scope

| Item | Description |
|------|-------------|
| Test modules | `test_bgp_rib_route_optimztn_perf.py` (with optional `--bgp_pc_config`) |
| Helper | `bgp_convergence_helper.py` (e.g. `run_rib_in_convergence_test`, `get_rib_in_convergence`, BGP/traffic config) |
| Monitoring | `mem_cpu_monitor` fixture (`tests/common/plugins/proc_mem_cpu_monitor`): CPU / memory sampling of the DUT(s) during the run (see Section 8.4) |
| DUT setup helper | `rib_combo_dut_setup.py` (per-(DUT, ASIC) config_db backup / revert, profile merge and orchagent `-b` / `-k` patching; see Section 7) |
| Fixtures | `tgen_ports` (in `tests/common/snappi_tests/snappi_fixtures.py`); behavior depends on `--bgp_pc_config` and, for multi-ASIC / multi-DUT setups, on the module opt-in `TGEN_PORTS_MULTI_ASIC_SUPPORT` (see Section 7) |
| Config inputs | `files/fine-tunings.yml`, `files/bk_values.json` |
| DUT changes | Config DB DEVICE_METADATA merge; orchagent.sh `-b` / `-k` args in swss container; cold reboot |
| Traffic | Snappi/IXIA traffic generator; BGP route withdraw ; advertise; convergence metrics |

### 2.2 Out of Scope

- RIB capacity tests, outbound convergence, or other BGP tests not part of this test.
- Changes to Snappi API or testbed topology definition (assumed existing).
- Definition of new fine-tuning knobs beyond what is already in DEVICE_METADATA / orchagent.

---

## 3. Architecture

### 3.1 High-Level Flow

```
+-----------------------------------------------------------------------------+
¦  For each (profile_name, bulk_value, batch_value, route_type):              ¦
¦                                                                             ¦
¦  1. SETUP                                                                   ¦
¦      Backup config_db.json on DUT and CONFIG_DB_BACKUP_PATH                 ¦
¦      Merge profile DEVICE_METADATA into config_db and apply to DUT          ¦
¦      Backup orchagent.sh in swss container; optionally patch -b / -k        ¦
¦      Cold reboot DUT and wait for critical services                         ¦
¦                                                                             ¦
¦  2. RUN RIB-IN CONVERGENCE                                                  ¦
¦      Build BGP/traffic config (IPv4 / IPv6 / IPv4v6, 300K routes)           ¦
¦      Withdraw all routes, start protocols and start traffic                 ¦
¦      Advertise all routes and measure control-plane_data-plane convergence  ¦
¦      Log/convergence time (ms)                                              ¦
¦                                                                             ¦
¦  3. REVERT                                                                  ¦
¦      Restore config_db from backup and config reload                        ¦
¦      Restore orchagent.sh from backup                                       ¦
+-----------------------------------------------------------------------------+
```

Note: On multi-ASIC and multi-DUT setups, SETUP and REVERT are executed per (DUT, ASIC) of the ports used by the test (config_db of each ASIC, orchagent.sh of each swss container) and the cold reboot is done on every distinct DUT / line card involved (see Section 7.3).

### 3.2 Component Overview

| Component | Role |
|-----------|------|
| **Test modules** | Pytest parametrization; setup/revert helpers; call into helper for convergence run |
| **bgp_convergence_helper** | BGP/traffic config (e.g. `__tgen_bgp_config`), `run_rib_in_convergence_test`, `get_rib_in_convergence`; Snappi control/state and metrics |
| **rib_combo_dut_setup** | DUT setup helpers: resolve the (DUT, ASIC) targets of the test ports, back up / revert the config_db of each ASIC (`config_db.json` or `config_db<N>.json`), apply the profile and the orchagent `-b` / `-k` values in the right swss container (`swss` or `swss<N>`) |
| **fine-tunings.yml** | Named profiles for DEVICE_METADATA sections (e.g. ZMQ on/off, synchronous_mode, suppress-fib-pending, nexthop_group) |
| **bk_values.json** | List of [bulk_value, batch_value] pairs for orchagent `-b` and `-k` |
| **DUT** | SONiC device; config_db; swss/orchagent; reboot |
| **Snappi / TGEN** | Traffic generator; BGP emulation; convergence metrics |

---

## 4. Topology and Test Parameters

### 4.1 Topology

- **Mark**: `pytest.mark.topology('multidut-tgen', 'tgen')`, `pytest.mark.disable_memory_utilization`, `pytest.mark.disable_loganalyzer` (the DUTs are cold rebooted) and `pytest.mark.enable_proc_mem_cpu_monitor` (enables the `mem_cpu_monitor` fixture, Section 8.4).
- **Logical**: TGEN1  DUT  TGEN(2..N); multipath = 1; number_of_routes = 300,000.
- **Route types**: IPv4, IPv6, or IPv4v6 (e.g. 150K v4 + 150K v6 for IPv4v6).
- **Supported DUT topologies**: single-ASIC DUT, single-DUT multi-ASIC DUT, and test ports spread across multiple DUTs / line cards (`multidut-tgen`). See Section 7.
- **Port usage**: Only the first `MULTIPATH + 1` entries of `tgen_ports` are used. The first port is the traffic source (no BGP session); every other port is a BGP peer that advertises the routes.

### 4.2 Fixed Test Parameters (in code)

| Parameter | Value | Meaning |
|-----------|--------|---------|
| MULTIPATH | 1 | ECMP / multipath for BGP/traffic |
| CONVERGENCE_TEST_ITERATIONS | 1 | Iterations per RIB-IN convergence run |
| NUMBER_OF_ROUTES | 300000 | Total BGP routes (v4, v6, or split) |
| RIB_TIMEOUT | 90 | Timeout (seconds) for routes advertisement/withdrawal |
| WAIT_INTERVAL | 30 | Timeout (seconds) for traffic/protocol start/stop |
| CONTAINER | swss | Container where orchagent.sh is modified |
| ORCHAGENT_PATH | /usr/bin/orchagent.sh | Script patched for -b / -k |

### 4.3 Parameterization (from files + route_type)

- **profile_name**: From `fine-tunings.yml` (each key with a DEVICE_METADATA section).
- **bulk_value, batch_value**: One pair per test from `bk_values.json` | `pairs` (e.g. `["default","default"]`, `[5000,5000]`, `[10000,10000]`, ).
- **route_type**: `IPv4` | `IPv6` | `IPv4v6`.
- **NUMBER_OF_ROUTES**: `300000`.
- **MULTIPATH**: `1`

Total cases = |profiles| × |pairs| × |route types|

Note:-
- 'NUMBER_OF_ROUTES' and 'MULTIPATH' are list with single value and will add to total cases if extended.
- 'route_type' of 'IPv4v6' will be skipped due to an outstanding keysight issue.
---

## 5. Configuration Files

### 5.1 fine-tunings.yml

- **Purpose**: Define named profiles whose DEVICE_METADATA is merged into the DUTs config_db (localhost section) before reboot.
- **Structure**: Top-level keys = profile names; each value must contain a `DEVICE_METADATA.localhost` map.
- **Example knobs**: `orch_northbond_route_zmq_enabled`, `synchronous_mode`, `suppress-fib-pending`, `nexthop_group`.
- **Default-config_db**: Use of customized profile-name with following key `config_db_wo_tuning: true`.
Example:
`
baseline_config_db:
	config_db_wo_tuning: true
`
- **Usage**: Test backs up config_db, merges selected profile into a copy, copies merged config to DUT; after test, config_db is reverted from backup.
- **Failure to load fine-tunings.yml**: In case of failure to load fine-tunings.yml file, test sets profile_name to '_no_profile_' and will execute the test with this profile.

### 5.2 bk_values.json

- **Purpose**: Define (bulk, batch) pairs for orchagent `-b` and `-k` arguments.
- **Structure**:\
  `"pairs": [ [bulk, batch], ... ]`\
  Values are either the string `"default"` or integers (e.g. 5000, 5200).
- **Legacy support**: Loader also accepts a single list (same value for both) or separate `bulk_values` / `batch_values` arrays (zipped into pairs).
- **DUT impact**: orchagent.sh is backed up; if either value is not `"default"`, the script is patched (e.g. replace default `-b 1024` with `-b <bulk> -k <batch>`); revert restores from backup.
- **Fallback**: If bk_values.json is empty or fails to load, script will use default configured in the test.

---

## 6. Port-Channel / Preconfigured BGP Mode (`--bgp_pc_config`)

### 6.1 Purpose

For testbeds where **port-channels and BGP are already configured** (e.g. minigraph/config_db), tests can avoid reconfiguring the DUT BGP and port-channels. A single CLI flag controls both how port data is derived and whether the helper configures BGP on the DUT.

### 6.2 CLI Flag

- **Flag**: `--bgp_pc_config` (defined in `tests/conftest.py`).
- **Type**: Store-true (boolean); default `False`.
- **Usage**: Pass at test start, e.g.\
  `pytest tests/snappi_tests/bgp/test_bgp_rib_route_optimztn_perf.py --bgp_pc_config ...`

### 6.3 Behavior When Flag Is Set

| Aspect | Behavior |
|--------|----------|
| **tgen_ports** | Built from **config_db** using **PORTCHANNEL_INTERFACE** and **PORTCHANNEL_MEMBER** (and optionally **BGP_NEIGHBOR** for TGEN IPs). One entry per PortChannel; same list-of-dict format as the default path (location, peer_port, peer_ip, ip, prefix, ipv6, etc.). |
| **DUT BGP config** | **Skipped**: `run_rib_in_convergence_test(..., skip_duthost_bgp_config=True)` so `duthost_bgp_config` is not called; port-channels and BGP are assumed preconfigured. |
| **TGEN BGP config** | Unchanged: `__tgen_bgp_config` still runs and uses the global `temp_tg_port`, which is set from `tgen_ports` at the start of `run_rib_in_convergence_test` so it is always valid whether or not `duthost_bgp_config` runs. |

Note:
- Test expects all the portchannels in the test to have single port members.
- If CLI flag is set, then all test interfaces on DUT should be **PORTCHANNEL_INTERFACES**.
- If CLI flag is not set, then all test interfaces on DUT should be **ROUTER_INTERFACES**.
- On multi-ASIC DUTs and on setups with ports on several DUTs / line cards, the flag is handled per ASIC namespace and per DUT (see Section 7.2 and 7.6).

### 6.4 tgen_ports Port-Channel Path (snappi_fixtures.py)

When `--bgp_pc_config` is set, the fixture uses an internal helper **`_tgen_ports_from_portchannel`**:

- Reads **PORTCHANNEL_INTERFACE** and **PORTCHANNEL_MEMBER** from config_db (supports key formats such as `PortChannel1` or `PortChannel1|ip/prefix` and member keys such as `PortChannel1|Ethernet0` or nested dict).
- Builds one tgen_ports entry per PortChannel: `peer_port` = PortChannel name (e.g. `PortChannel1`); IPs from PORTCHANNEL_INTERFACE; location/speed from the first members Snappi port.
- Test will skip portchannels if they are empty or contain 2 or more ports as **PORTCHANNEL_MEMBER**. Test looks for portchannels with one member port.
- **TGEN (neighbor) IP** for each PortChannel: preferred source is **config_db `BGP_NEIGHBOR`**: for each neighbor, key = neighbor (TGEN) IP, value has `local_addr` = DUT IP; the fixture maps `local_addr` to neighbor IP and uses it for `entry['ip']` and `entry['ipv6']`. If no matching BGP neighbor exists, it falls back to deriving an IP in the same subnet (e.g. via `get_addrs_in_subnet`).
- **TGEN AS_NUM** for each PortChannel: Uses **config_db `BGP_NEIGHBOR`**: for each neighbor. It looks for both asnv4 and asnv6 for each IPv4 and IPv6 neighbor. For each IPv4 neighbor ASN, it will assert if there is mistmatch with ASN configured for IPv6 neighor on same interface.
- **DUT_AS_NUM** for the DUT: Returns DUT ASN configured in **config_db `DEVICE_METADATA`**.

The **tgen_ports output format is unchanged** in both code paths so downstream code (e.g. `__tgen_bgp_config`) does not need to branch.

### 6.5 Behavior When Flag Is Not Set (Default)

- **tgen_ports**: Built from **INTERFACE** in config_db (existing behavior): one entry per physical port; IPs may be preconfigured or added by the fixture.
- **DUT BGP config**: **Run**: `duthost_bgp_config` creates port-channels and BGP neighbors on the DUT as before. Test will create portchannels with one port.

### 6.6 Helper: run_rib_in_convergence_test and temp_tg_port

- **`skip_duthost_bgp_config`** (default `False`): When `True`, `duthost_bgp_config` is not called (port-channels/BGP preconfigured).
- **`mem_cpu_monitor`** (default `None`): The `mem_cpu_monitor` fixture of the test. When given, `get_rib_in_convergence` records timeline events around the RIB-IN steps and stops the monitor (Section 8.4).
- **`tag_tier2_leak_communities`** (default `False`): When `True`, the IXIA routes are tagged with the tier-2 leak community when the DUT needs it (Section 8.3).
- **`skip_cleanup`** (default `True`): When `False`, `cleanup_config` is called at the end of the run to revert the DUT config done by `duthost_bgp_config`. The test passes `True`; the config_db is then reverted by the fixture teardown (Section 7.3).
- **`temp_tg_port`**: Global used by `__tgen_bgp_config` (and related TGEN config). It is set at the start of `run_rib_in_convergence_test`: `temp_tg_port = tgen_ports`, so TGEN BGP config always has correct port data whether or not `duthost_bgp_config` runs.

### 6.7 Setup requirement with --bgp_pc_config` set

- The DUT requires at least 2 portchannels with IPv4/IPv6 address set in **`PORTCHANNEL_INTERFACE`** connected to IXIA and present in *links.csv file.
- BGP ASN config (DUT and peer) is read dynamically from config_facts on the DUT.

---

## 7. Multi-ASIC and Multi-DUT Support

### 7.1 Purpose and Scope

The test runs on:

- **Single-ASIC, single-DUT** testbeds: behavior is unchanged.
- **Single-DUT multi-ASIC** DUTs: each test port is handled in the ASIC (namespace `asic<N>`, config_db `config_db<N>.json`, container `swss<N>`) that owns the port.
- **Multi-DUT / line-card** testbeds (`multidut-tgen`): test ports are spread across several DUTs / line cards, each of which can again be single-ASIC or multi-ASIC.

Opt-in: the multi-ASIC / multi-DUT handling in the shared `tgen_ports` fixture is enabled only for test modules that set the module attribute `TGEN_PORTS_MULTI_ASIC_SUPPORT = True` (done in `test_bgp_rib_route_optimztn_perf.py`). Other tests that use `tgen_ports` are not affected.

### 7.2 Port Discovery (`tgen_ports` in snappi_fixtures.py)

| Mode | Condition | Behavior |
|------|-----------|----------|
| **`--bgp_pc_config`, single DUT** | Module opt-in | `_tgen_ports_from_portchannel_all_asics`: reads PORTCHANNEL_INTERFACE, PORTCHANNEL_MEMBER and BGP_NEIGHBOR from the config_facts of **every front-end ASIC namespace** (on multi-ASIC devices these tables live in the per-ASIC config_db, not in the host config_db) and merges the entries. |
| **`--bgp_pc_config`, multi-DUT** | Module opt-in and a multi-DUT testbed (`is_snappi_multidut`) | `_tgen_ports_modular_chassis_bgp_pc`: same as above for every DUT / line card; the test fails if no port-channel is found on any of them. |
| **No flag, per-ASIC plan** | Module opt-in, and the ports are on more than one DUT or any DUT involved is multi-ASIC | `_tgen_ports_non_pc_all_asics`: builds the port list as a **read-only plan**. It does not change the DUT. |
| **No flag, otherwise** | Single-ASIC, single-DUT | Original flow (Section 6.5). |

Each entry built by the multi-ASIC paths has the same format as before, plus:

- **`duthost`**: DUT / line card that owns the port.
- **`asic_value`**: ASIC namespace that owns the port (for example `asic0`).
- **`multi_asic_flow`** (no-flag plan only): marks the port as handled per ASIC by the helper.

Details of the paths:

- With `--bgp_pc_config`, port speeds may differ between ports (the speed is set per port); the original single-ASIC path still requires one common speed. The DUT ASN falls back to the host `DEVICE_METADATA` when the ASIC config_db has none.
- Without the flag, the plan reads the config of the ASIC that owns each port: `autoneg`, `fec` and `link_training` come from the port; an IPv4 / IPv6 address already configured on the port is reused (the TGEN IP is taken from the BGP_NEIGHBOR whose `local_addr` is that DUT IP, otherwise a free address in the same subnet); if the port has no address, IPs from the standard IP pools are planned. Nothing is configured on the DUT at this stage.

### 7.3 Setup and Revert per (DUT, ASIC) (fixture `dut_ready_for_rib_combo`)

1. Skip when there is no valid profile (`_no_profile_`) or when `route_type` is `IPv4v6` (outstanding keysight issue). These skips happen before the DUT is touched.
2. Without `--bgp_pc_config`, when the DUT is multi-ASIC or the ports were planned per ASIC: check the ports for ACL / VLAN binding in the **saved** config_db and skip if found (Section 7.4).
3. Build the list of targets: the distinct (DUT, ASIC) pairs of the first `MULTIPATH + 1` ports.
4. Back up the config_db of every targeted ASIC on its DUT: `/etc/sonic/config_db.json` on single-ASIC DUTs, `/etc/sonic/config_db<N>.json` on multi-ASIC DUTs, to `config_db_rib_combo_v1_backup.json` / `config_db<N>_rib_combo_v1_backup.json`.
5. Merge the selected profile into the config_db of every targeted ASIC (not done for `config_db_wo_tuning`), and patch `-b` / `-k` in `/usr/bin/orchagent.sh` of the swss container of every targeted ASIC (`swss` or `swss<N>`).
6. Cold reboot **every distinct DUT** of the targets, wait for the critical services, then run `TSB` and `config save`.
7. Teardown: restore orchagent.sh, restore each config_db from its backup and run `config reload -y` on each DUT.

### 7.4 Ports Bound to ACL Tables or VLANs

Without `--bgp_pc_config`, the helper later removes the test ports from their port-channel and builds new ones. This cannot work for ports bound to an ACL table or a VLAN, and the DUT is not changed to resolve it.

- The check runs at the **start of the fixture**, before any backup, profile change or reboot, so that the skip is clean (no second reboot / config reload on teardown).
- The **saved** config_db is the source of truth: the cold reboot of the fixture loads it, so it is assumed to be the same as the running config. For ports of multi-ASIC DUTs it is read per ASIC.
- If any port of the first `MULTIPATH + 1` ports is bound to an ACL table (`ACL_TABLE` ports) or is a `VLAN_MEMBER`, the test is **skipped** with the list of affected ports (`<dut>/<port> (asic <N>): ACL table(s) ..., VLAN(s) ...`). Unbind the ports on the DUT, run `config save` and re-run.
- The helper repeats the check against the running config before it changes anything, as a safety net.
- With `--bgp_pc_config` no check is done, because the DUT config is not changed.

### 7.5 DUT BGP Configuration Without `--bgp_pc_config`

`duthost_bgp_config` uses the multi-ASIC implementation (`_duthost_bgp_config_multi_asic`) when the DUT is multi-ASIC or any port has `multi_asic_flow`; otherwise the original single-ASIC code is used. Every change is made in the ASIC that owns the port, on the DUT that owns the port.

| Step | Action |
|------|--------|
| 1 (read-only) | For each port read the running config of its ASIC. Resolve the DUT ASN and the peer ASN (below). Plan the IP addresses and PortChannel memberships to remove. Re-check for ACL / VLAN binding (Section 7.4). |
| 2 | Run `config save` and back up the config_db of every involved ASIC (backup tag `bgp_convergence_helper`). Done only after step 1 has passed. |
| 3 | Free each port: remove its IP addresses and remove it from its PortChannel(s). |
| 4 | Create one PortChannel per port with the port as its only member. Name: `PortChannel<i+1>`, or the next free `PortChannel<N>` on that ASIC when the name is taken. Configure the IPv4 and IPv6 addresses of the plan on the PortChannel. |
| 5 | Per ASIC, in the ASIC namespace through `vtysh`: `router bgp <DUT ASN>`, `no bgp ebgp-requires-policy`, `bgp bestpath as-path multipath-relax`, `maximum-paths <number of BGP peers on that ASIC>`, then one neighbor (IPv4 or IPv6 according to `route_type`) with its peer ASN for every BGP peer port on that ASIC. |

`cleanup_config` restores the config_db backed up in step 2 of every involved ASIC and reloads the config; the helper calls it only when `run_rib_in_convergence_test` is called with `skip_cleanup=False`. This test uses `skip_cleanup=True`, so the changes of steps 3 to 5 are reverted by the teardown of the fixture (Section 7.3), which restores the config_db backed up before the helper changed anything.

**ASN resolution** (replaces the fixed values when the DUT has a configuration):

| ASN | Source, in order |
|-----|------------------|
| **DUT ASN** | `DEVICE_METADATA.localhost.bgp_asn` of the ASIC; on multi-ASIC DUTs the host `DEVICE_METADATA`; else `DUT_AS_NUM` (65100). |
| **Peer (TGEN) ASN** | `asn` of the `BGP_NEIGHBOR` configured on that ASIC for the TGEN IP (or, failing that, for the neighbor whose `local_addr` is the DUT IP); else `TGEN_AS_NUM` (65200). |

The resolved values are stored in the port entries (`bgp_dut_asn`, `bgp_peer_asn`) and are used when the TGEN BGP config is built, so both sides use the same ASNs.

### 7.6 Behavior With `--bgp_pc_config` on Multi-ASIC / Multi-DUT

- The DUT is not changed: port-channels and BGP must be preconfigured in the ASIC that owns each port (Section 6).
- `tgen_ports` reads the port-channels of every ASIC namespace and every DUT / line card (Section 7.2); the DUT and TGEN ASNs are read from each ASIC's config_db.
- The setup requirement of Section 6.7 applies: at least 2 port-channels with IPv4 / IPv6 addresses, connected to IXIA and present in the links csv file. The port-channels may be in different ASICs and on different DUTs.

### 7.7 Limitations and Notes

- Without `--bgp_pc_config`, ports bound to an ACL table or a VLAN are not supported (the test is skipped, Section 7.4).
- Each port-channel / PortChannel used by the test has a single member port.
- The cold reboot is done on every DUT / line card used by the test ports, so the setup time grows with the number of DUTs.
- BGP neighbors configured through `vtysh` are part of the running config only; they are removed by the config reload when the config_db is reverted.
- The CPU / memory monitor samples every DUT / line card used by the test ports (Section 8.4), and the tier-2 community tagging also applies on multi-ASIC DUTs (Section 8.3).

## 8. RIB-IN Convergence Logic (Helper)

### 8.1 run_rib_in_convergence_test

- Builds BGP/traffic config via helper (using `tgen_ports`, route_type, number_of_routes, multipath).
- Sets up Snappi config and runs the RIB-IN convergence scenario: withdraw routes, start protocols, start traffic, advertise routes, collect convergence metrics.
- Uses a global route-name list (e.g. NG_LIST) populated during config build; cleared after the run (e.g. in `get_rib_in_convergence`) for clean state.
- Sets global **temp_tg_port = tgen_ports** at the start so that `__tgen_bgp_config` (and any other code using `temp_tg_port`) has valid port data whether or not `duthost_bgp_config` is run (see Section 6).

### 8.2 get_rib_in_convergence (core sequence)

1. Withdraw all BGP routes (control state).
2. Start all protocols; wait.
3. Start traffic; verify TX rate non-zero, RX zero (traffic blackholed).
4. Advertise all routes; wait.
5. Check traffic convergence (TX/RX rates); read control-plane_data-plane convergence time from Snappi metrics.
6. Stop traffic; stop protocols.
7. Report convergence time (e.g. in ms); reset global list for next run.

### 8.3 Tier-2 Leak Community Tagging (`tag_tier2_leak_communities`)

- **Purpose**: Some DUT configurations (e.g. T2 devices) have `FROM_TIER2` deny route-maps (`UPSTREAM_PREFIX_DENY`) that reject routes learned from a lower tier unless they carry the tier-2 leak community. To let the 300K IXIA routes through, the routes are tagged with that community.
- **What is added**: Every IXIA route range (IPv4 and IPv6) gets the BGP community `COMMUNITY_LOWER_TIER_LEAK` (from `tests/snappi_tests/variables.py`, `8075:54000`; the same value is used as a fallback if that module cannot be imported). The community is added when the TGEN BGP config is built.
- **Control**: `run_rib_in_convergence_test(..., tag_tier2_leak_communities=False)`. It is **opt-in** and defaults to `False`, so other tests that use the helper are not changed. `test_bgp_rib_route_optimztn_perf.py` passes `True`. The helper keeps the decision in a module flag that is reset on every call.
- **When the tag is applied** (only when the option is `True`), if either condition holds:
  - the vtysh running-config of any ASIC used by the test ports contains `UPSTREAM_PREFIX_DENY`, on a single-ASIC DUT as well; or
  - the DUT (`duthost` fixture) is multi-ASIC, with no check of the config.
- **Otherwise** no community is added and the routes are advertised as before.

Note:
- The multi-ASIC condition looks only at the main `duthost` fixture, not at every DUT used by the test ports. On a multi-DUT setup the tag is therefore applied on the multi-ASIC condition only when the main DUT is multi-ASIC; any DUT with `UPSTREAM_PREFIX_DENY` still triggers it.

### 8.4 Memory / CPU Monitoring (`mem_cpu_monitor`)

- **Purpose**: Record CPU and memory usage of the BGP processes (`bgpd`, `zebra`) and of the host processes on the DUT(s) while the routes are withdrawn, advertised and converge, so that the footprint can be compared between profiles and `-b` / `-k` values. It does not change the DUT configuration.
- **Plugin**: `tests/common/plugins/proc_mem_cpu_monitor` provides the `mem_cpu_monitor` fixture. It samples `top` (and `free`, and tcmalloc stats of bgp) on the DUT(s) in a background thread. It is separate from the autouse `memory_utilization` plugin, which stays disabled for this test (Section 4.1).
- **Opt-in**: The fixture is a no-op unless it is enabled with `pytest.mark.enable_proc_mem_cpu_monitor` (set in the `pytestmark` of this test) or with the `--enable_proc_mem_cpu_monitor` option for the whole session. Because the marker is set at module level, the monitor is always active for this test.

| Where | What |
|-------|------|
| **Test, before the run** | `start(monitor_hosts, ["bgpd", "zebra"], interval=2.0, include_host_free=True, host_top_all_procs=True, capture_raw_stdout=True, include_tcmalloc_stats=True, output_basename_style="short_node")`. `monitor_hosts` has one DUT per distinct DUT / line card of the first `MULTIPATH + 1` ports, so on multi-DUT setups every DUT used by the test is monitored. |
| **Helper, `get_rib_in_convergence`** | The monitor is passed through `run_rib_in_convergence_test(..., mem_cpu_monitor=...)`. A timeline event is recorded in every iteration: `Route_Withdrawal_started_iter_<N>`, `Protocols_started_iter_<N>`, `Before_route_advertise_iter_<N>`, `After_route_advertise_iter_<N>`, `After_traffic_stop_metrics_iter_<N>` and `After_protocol_stop_iter_<N>`. |
| **Helper, `finally` block** | Sampling continues for `MEM_CPU_MONITOR_RIB_IN_POST_SUCCESS_SEC` (300 s) after all iterations finished, to capture the state after convergence; after a failure or early exit it waits only `MEM_CPU_MONITOR_RIB_IN_POST_FAILURE_SEC` (7 s). Then `stop()` is called. |
| **Test, `finally` block** | `stop()` (already stopped by the helper in the normal case), `plot(out_dir=tmp_path)` and `export_samples(out_dir=tmp_path)`. The written paths are logged. |

- **Output**: Written under the pytest `tmp_path` of the test: a PNG plot (CPU idle, per-process CPU, memory, RSS), JSON / CSV samples with the timeline events, and raw `top` / command / tcmalloc logs. File names use the `short_node` style (`<test node name>__<dut>__<timestamp>`). See the plugin README for the details of the options and files.
- **Impact**: With `interval=2.0` the DUT runs `top` and `free` every 2 seconds on every monitored DUT, and the success path adds 300 s to every test case.

---

## 9. Dependencies and Interfaces

### 9.1 Fixtures

- **snappi_api**, **tgen_ports**: Snappi/IXIA and port mapping. **tgen_ports** behavior depends on `--bgp_pc_config`: if set, built from PORTCHANNEL_* and BGP_NEIGHBOR in config_db; otherwise from INTERFACE (see Section 6). On multi-ASIC / multi-DUT setups the config_db of every ASIC and DUT is used (see Section 7).
- **duthost**, **localhost**: DUT and local host for reboot/shell/copy. On multi-DUT setups the DUT that owns each port is taken from the `duthost` field of the `tgen_ports` entry; the reboot, shell and copy actions are run on every DUT used by the test ports.
- **duthosts**: Used by `tgen_ports` to detect a multi-DUT / line-card testbed.
- **conn_graph_facts**, **fanout_graph_facts**: Connectivity/graph data (for topology). **fanout_graph_facts_multidut** is used by `tgen_ports` on multi-DUT testbeds.
- **mem_cpu_monitor**, **tmp_path**: CPU / memory monitor (Section 8.4) and the pytest directory where its plot, samples and logs are written.
- **request**: Used in `test_bgp_rib_route_optimztn_perf.py` to read `--bgp_pc_config`, and in `tgen_ports` to read `--bgp_pc_config` and the module opt-in `TGEN_PORTS_MULTI_ASIC_SUPPORT`.

### 9.2 File Paths

- **Config files**: Under `tests/snappi_tests/bgp/files/` (e.g. `fine-tunings.yml`, `bk_values.json`).
- **DUT backup**: config_db backup at e.g. `/etc/sonic/config_db_rib_combo_v1_backup.json` so it survives reboot; removed after revert. On multi-ASIC DUTs one backup per ASIC is kept, e.g. `/etc/sonic/config_db0_rib_combo_v1_backup.json`; the DUT BGP config of Section 7.5 uses the tag `bgp_convergence_helper` instead of `rib_combo_v1`.

### 9.3 Assumptions

- Testbed has tgen topology; Correct Snappi API version exists and BGP/traffic config is valid.
- DUT is in healthy state and has swss container running; default orchagent args contain the expected pattern (e.g. `-b 1024`) so sed replacement is correct.
- Reboot and service wait timeouts are sufficient for the platform.
- fine-tunings.yml and bk_values.json are present and well-formed; fallbacks exist in code if load fails (e.g. default profile list, default pairs).
- IPv4 network group used for the test is 200.1.0.1/32 and IPv6 network is 3000::1/64.

### 9.4 Known Limitations

- Outstanding sonic-mgmt issue 23744 needs setting of BGP segment as 'AS-SEQ' via restPy in file/bgp_convergence_helper.py. This will be removed on resolution of the issue.
- Skip for IPv4v6 routes will be removed on resolution of sonic-mgmt issue 22717.

---

## 10. Possible enhancements

Following possible enhancements can be added:
  - Support for extended BGP messages with MTU of 9100 bytes via Snappi.
  - Measure route-capacity for routes with optimization parameters.
  - Remove reboot after configuration change to config_reload to save time.
  - Support to save RFC report generated by IXIA locally.


## 11. Summary

The RIB-IN optimization and performance tests provide a parameterized framework to measure RIB-IN convergence time (300K routes) across:

- **Profiles** (DEVICE_METADATA from fine-tunings.yml),
- **Orchagent tuning** (bulk/batch pairs from bk_values.json),
- **Route type** (IPv4, IPv6, IPv4v6),
- **MULTIPATH** (1),
- **NUMBER_OF_ROUTES** (300000).

Each test applies a single (profile, bulk, batch, route_type), reboots the DUT, runs the convergence scenario once, then reverts config and orchagent. The **`--bgp_pc_config`** option (Section 6) allows using preconfigured port-channels and BGP on the testbed via port data from config_db and skipping DUT BGP configuration in the helper. Section 7 describes how the test runs on single-DUT multi-ASIC DUTs and on testbeds with ports on several DUTs / line cards, with or without that option.
