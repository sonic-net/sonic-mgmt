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
- **Memory observability**: The memory-utilization is disabled for this test using pytest.marker functionality.

---

## 2. Scope

### 2.1 In Scope

| Item | Description |
|------|-------------|
| Test modules | `test_bgp_rib_route_optimztn_perf.py` (with optional `--bgp_pc_config`) |
| Helper | `bgp_convergence_helper.py` (e.g. `run_rib_in_convergence_test`, `get_rib_in_convergence`, BGP/traffic config) |
| Fixtures | `tgen_ports` (in `tests/common/snappi_tests/snappi_fixtures.py`); behavior depends on `--bgp_pc_config` |
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

### 3.2 Component Overview

| Component | Role |
|-----------|------|
| **Test modules** | Pytest parametrization; setup/revert helpers; call into helper for convergence run |
| **bgp_convergence_helper** | BGP/traffic config (e.g. `__tgen_bgp_config`), `run_rib_in_convergence_test`, `get_rib_in_convergence`; Snappi control/state and metrics |
| **fine-tunings.yml** | Named profiles for DEVICE_METADATA sections (e.g. ZMQ on/off, synchronous_mode, suppress-fib-pending, nexthop_group) |
| **bk_values.json** | List of [bulk_value, batch_value] pairs for orchagent `-b` and `-k` |
| **DUT** | SONiC device; config_db; swss/orchagent; reboot |
| **Snappi / TGEN** | Traffic generator; BGP emulation; convergence metrics |

---

## 4. Topology and Test Parameters

### 4.1 Topology

- **Mark**: `pytest.mark.topology('tgen')` and `pytest.mark.disable_memory_utilization`.
- **Logical**: TGEN1  DUT  TGEN(2..N); multipath = 1; number_of_routes = 300,000.
- **Route types**: IPv4, IPv6, or IPv4v6 (e.g. 150K v4 + 150K v6 for IPv4v6).
- **pytest-skip**: skip for single DUT multi-asic setup.

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
- **`temp_tg_port`**: Global used by `__tgen_bgp_config` (and related TGEN config). It is set at the start of `run_rib_in_convergence_test`: `temp_tg_port = tgen_ports`, so TGEN BGP config always has correct port data whether or not `duthost_bgp_config` runs.

### 6.7 Setup requirement with --bgp_pc_config` set

- The DUT requires at least 2 portchannels with IPv4/IPv6 address set in **`PORTCHANNEL_INTERFACE`** connected to IXIA and present in *links.csv file.
- BGP ASN config (DUT and peer) is read dynamically from config_facts on the DUT.

---

## 7. RIB-IN Convergence Logic (Helper)

### 7.1 run_rib_in_convergence_test

- Builds BGP/traffic config via helper (using `tgen_ports`, route_type, number_of_routes, multipath).
- Sets up Snappi config and runs the RIB-IN convergence scenario: withdraw routes, start protocols, start traffic, advertise routes, collect convergence metrics.
- Uses a global route-name list (e.g. NG_LIST) populated during config build; cleared after the run (e.g. in `get_rib_in_convergence`) for clean state.
- Sets global **temp_tg_port = tgen_ports** at the start so that `__tgen_bgp_config` (and any other code using `temp_tg_port`) has valid port data whether or not `duthost_bgp_config` is run (see Section 6).

### 7.2 get_rib_in_convergence (core sequence)

1. Withdraw all BGP routes (control state).
2. Start all protocols; wait.
3. Start traffic; verify TX rate non-zero, RX zero (traffic blackholed).
4. Advertise all routes; wait.
5. Check traffic convergence (TX/RX rates); read control-plane_data-plane convergence time from Snappi metrics.
6. Stop traffic; stop protocols.
7. Report convergence time (e.g. in ms); reset global list for next run.

---

## 8. Dependencies and Interfaces

### 8.1 Fixtures

- **snappi_api**, **tgen_ports**: Snappi/IXIA and port mapping. **tgen_ports** behavior depends on `--bgp_pc_config`: if set, built from PORTCHANNEL_* and BGP_NEIGHBOR in config_db; otherwise from INTERFACE (see Section 6).
- **duthost**, **localhost**: DUT and local host for reboot/shell/copy.
- **conn_graph_facts**, **fanout_graph_facts**: Connectivity/graph data (for topology).
- **request**: Used in `test_bgp_rib_route_optimztn_perf.py` to read `--bgp_pc_config`.

### 8.2 File Paths

- **Config files**: Under `tests/snappi_tests/bgp/files/` (e.g. `fine-tunings.yml`, `bk_values.json`).
- **DUT backup**: config_db backup at e.g. `/etc/sonic/config_db_rib_combo_v1_backup.json` so it survives reboot; removed after revert.

### 8.3 Assumptions

- Testbed has tgen topology; Correct Snappi API version exists and BGP/traffic config is valid.
- DUT is in healthy state and has swss container running; default orchagent args contain the expected pattern (e.g. `-b 1024`) so sed replacement is correct.
- Reboot and service wait timeouts are sufficient for the platform.
- fine-tunings.yml and bk_values.json are present and well-formed; fallbacks exist in code if load fails (e.g. default profile list, default pairs).
- IPv4 network group used for the test is 200.1.0.1/32 and IPv6 network is 3000::1/64.

### 8.4 Known Limitations

- Outstanding sonic-mgmt issue 23744 needs setting of BGP segment as 'AS-SEQ' via restPy in file/bgp_convergence_helper.py. This will be removed on resolution of the issue.
- Skip for IPv4v6 routes will be removed on resolution of sonic-mgmt issue 22717.

---

## 9. Possible enhancements

Following possible enhancements can be added:
  - Support for extended BGP messages with MTU of 9100 bytes via Snappi.
  - Measure route-capacity for routes with optimization parameters.
  - Remove reboot after configuration change to config_reload to save time.
  - Make the test available for single-dut multi-asic and multi-DUT topologies.
  - Support to capture memory and CPU footprints during the test for various processes (e.g. bgp, frr etc.)
  - Support to save RFC report generated by IXIA locally.


## 10. Summary

The RIB-IN optimization and performance tests provide a parameterized framework to measure RIB-IN convergence time (300K routes) across:

- **Profiles** (DEVICE_METADATA from fine-tunings.yml),
- **Orchagent tuning** (bulk/batch pairs from bk_values.json),
- **Route type** (IPv4, IPv6, IPv4v6),
- **MULTIPATH** (1),
- **NUMBER_OF_ROUTES** (300000).

Each test applies a single (profile, bulk, batch, route_type), reboots the DUT, runs the convergence scenario once, then reverts config and orchagent. The **`--bgp_pc_config`** option (Section 6) allows using preconfigured port-channels and BGP on the testbed via port data from config_db and skipping DUT BGP configuration in the helper.
