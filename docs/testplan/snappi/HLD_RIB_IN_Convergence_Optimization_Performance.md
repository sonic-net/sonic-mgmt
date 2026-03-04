# High Level Design: RIB-IN Convergence Optimization and Performace Tests

## 1. Overview

### 1.1 Purpose

This document describes the high-level design of the **RIB-IN optimization and performance** test suite, which measures control-plane-to-data-plane convergence time for BGP route advertisement under different DUT configuration profiles and orchagent tuning parameters. The tests are used to evaluate RIB-IN performance and optimize SONiC behavior (e.g., northbound ZMQ, synchronous mode, orchagent bulk/batch settings) across multiple dimensions in a single parameterized framework.

### 1.2 Goals

- **Parameterized coverage**: Run RIB-IN convergence (250K routes) for each combination of:
  - **Fine-tuning profile** (DEVICE_METADATA from `fine-tunings.yml`)
  - **Orchagent bulk/batch pair** (e.g. `-b` / `-k` from `bk_values.json`)
  - **Route type** (IPv4, IPv6, IPv4v6)
- **Clean state**: Each test applies profile + b/k, reboots, runs the convergence test, then reverts config and orchagent so the next parameterized run starts from a known state.
- **Optional memory observability**: A fixture-based variant (v1) allows memory utilization plugin to capture before/after on the same boot for meaningful delta.

---

## 2. Scope

### 2.1 In Scope

| Item | Description |
|------|-------------|
| Test modules | `test_bgp_rib_route_optimztn_perf.py` |
| Helper | `bgp_convergence_helper.py` (e.g. `run_rib_in_convergence_test`, `get_rib_in_convergence`, BGP/traffic config) |
| Config inputs | `files/fine-tunings.yml`, `files/bk_values.json` |
| DUT changes | Config DB DEVICE_METADATA merge; orchagent.sh `-b` / `-k` args in swss container; cold reboot |
| Traffic | Snappi/IXIA traffic generator; BGP route withdraw ? advertise; convergence metrics |

### 2.2 Out of Scope

- RIB capacity tests, outbound convergence, or other BGP tests not part of this combo flow.
- Changes to Snappi API or testbed topology definition (assumed existing).
- Definition of new fine-tuning knobs beyond what is already in DEVICE_METADATA / orchagent.

---

## 3. Architecture

### 3.1 High-Level Flow

```
+-----------------------------------------------------------------------------+
¦  For each (profile_name, bulk_value, batch_value, route_type):             ¦
¦                                                                             ¦
¦  1. SETUP                                                                   ¦
¦      Backup config_db.json on DUT ? CONFIG_DB_BACKUP_PATH                  ¦
¦      Merge profile DEVICE_METADATA into config_db ? apply to DUT          ¦
¦      Backup orchagent.sh in swss container; optionally patch -b / -k       ¦
¦      Cold reboot DUT ? wait for critical services                          ¦
¦                                                                             ¦
¦  2. RUN RIB-IN CONVERGENCE                                                  ¦
¦      Build BGP/traffic config (IPv4 / IPv6 / IPv4v6, 250K routes)         ¦
¦      Withdraw all routes ? start protocols ? start traffic                 ¦
¦      Advertise all routes ? measure control-planedata-plane convergence   ¦
¦      Log/convergence time (ms)                                              ¦
¦                                                                             ¦
¦  3. REVERT                                                                  ¦
¦      Restore config_db from backup ? config reload                        ¦
¦      Restore orchagent.sh from backup                                      ¦
+-----------------------------------------------------------------------------+
```

### 3.2 Component Overview

| Component | Role |
|-----------|------|
| **Test modules** | Pytest parametrization; setup/revert helpers; call into helper for convergence run |
| **bgp_convergence_helper** | BGP/traffic config (e.g. `__tgen_bgp_config`), `run_rib_in_convergence_test`, `get_rib_in_convergence`; Snappi control/state and metrics |
| **fine-tunings.yml** | Named profiles ? DEVICE_METADATA sections (e.g. ZMQ on/off, synchronous_mode, suppress-fib-pending, nexthop_group) |
| **bk_values.json** | List of [bulk_value, batch_value] pairs for orchagent `-b` and `-k` |
| **DUT** | SONiC device; config_db; swss/orchagent; reboot |
| **Snappi / TGEN** | Traffic generator; BGP emulation; convergence metrics |

---

## 4. Topology and Test Parameters

### 4.1 Topology

- **Mark**: `pytest.mark.topology('tgen')`
- **Logical**: TGEN1  DUT  TGEN(2..N); multipath = 1; number_of_routes = 250,000.
- **Route types**: IPv4, IPv6, or IPv4v6 (e.g. 125K v4 + 125K v6 for IPv4v6).

### 4.2 Fixed Test Parameters (in code)

| Parameter | Value | Meaning |
|-----------|--------|---------|
| MULTIPATH | 1 | ECMP / multipath for BGP/traffic |
| CONVERGENCE_TEST_ITERATIONS | 1 | Iterations per RIB-IN convergence run |
| NUMBER_OF_ROUTES | 250000 | Total BGP routes (v4, v6, or split) |
| RIB_TIMEOUT | 60 | Timeout (seconds) for protocol/traffic steps |
| CONTAINER | swss | Container where orchagent.sh is modified |
| ORCHAGENT_PATH | /usr/bin/orchagent.sh | Script patched for -b / -k |

### 4.3 Parameterization (from files + route_type)

- **profile_name**: From `fine-tunings.yml` (each key with a DEVICE_METADATA section).
- **bulk_value, batch_value**: One pair per test from `bk_values.json` ? `pairs` (e.g. `["default","default"]`, `[5000,5200]`, `[10000,10500]`, ).
- **route_type**: `IPv4` | `IPv6` | `IPv4v6`.

Total cases = |profiles| × |pairs| × 3 (route types).

---

## 5. Configuration Files

### 5.1 fine-tunings.yml

- **Purpose**: Define named profiles whose DEVICE_METADATA is merged into the DUTs config_db (localhost section) before reboot.
- **Structure**: Top-level keys = profile names; each value must contain a `DEVICE_METADATA.localhost` map.
- **Example knobs**: `orch_northbond_route_zmq_enabled`, `synchronous_mode`, `suppress-fib-pending`, `nexthop_group`.
- **Usage**: Test backs up config_db, merges selected profile into a copy, copies merged config to DUT; after test, config_db is reverted from backup.

### 5.2 bk_values.json

- **Purpose**: Define (bulk, batch) pairs for orchagent `-b` and `-k` arguments.
- **Structure**:  
  `"pairs": [ [bulk, batch], ... ]`  
  Values are either the string `"default"` or integers (e.g. 5000, 5200).
- **Legacy support**: Loader also accepts a single list (same value for both) or separate `bulk_values` / `batch_values` arrays (zipped into pairs).
- **DUT impact**: orchagent.sh is backed up; if either value is not `"default"`, the script is patched (e.g. replace default `-b 1024` with `-b <bulk> -k <batch>`); revert restores from backup.

---

## 6. Test Enhancements:

- **Utilization**: Test case monitors the various processes but has increased the memory thresholds for certain processes to display the utilization. The testcase will monitor the processes after each iteration, before the reload/reboot to avoid false-positives.
- **Addition of IPv4v6 Routes**: 'create_v4v6_topo' is added in the helper file to test withdrawal of IPv4v6 routes.

---

## 7. RIB-IN Convergence Logic (Helper)

### 7.1 run_rib_in_convergence_test

- Builds BGP/traffic config via helper (using `tgen_ports`, route_type, number_of_routes, multipath).
- Sets up Snappi config and runs the RIB-IN convergence scenario: withdraw routes, start protocols, start traffic, advertise routes, collect convergence metrics.
- Uses a global route-name list (e.g. NG_LIST) populated during config build; cleared after the run (e.g. in `get_rib_in_convergence`) for clean state.

### 7.2 get_rib_in_convergence (core sequence)

1. Withdraw all BGP routes (control state).
2. Start all protocols; wait.
3. Start traffic; verify TX rate non-zero, RX zero (traffic blackholed).
4. Advertise all routes; wait.
5. Check traffic convergence (TX/RX rates); read control-planedata-plane convergence time from Snappi metrics.
6. Stop traffic; stop protocols.
7. Report convergence time (e.g. in ms); reset global list for next run.

---

## 8. Dependencies and Interfaces

### 8.1 Fixtures

- **snappi_api**, **tgen_ports**: Snappi/IXIA and port mapping.
- **duthost**, **localhost**: DUT and local host for reboot/shell/copy.
- **conn_graph_facts**, **fanout_graph_facts**: Connectivity/graph data (for topology).

### 8.2 File Paths

- **Config files**: Under `tests/snappi_tests/bgp/files/` (e.g. `fine-tunings.yml`, `bk_values.json`).
- **DUT backup**: config_db backup at e.g. `/etc/sonic/config_db_rib_combo_bkup.json` (or v1-specific path) so it survives reboot; removed after revert.

### 8.3 Assumptions

- Testbed has tgen topology; Snappi API and BGP/traffic config are valid.
- DUT has writable config_db and swss container with orchagent.sh; default orchagent args contain the expected pattern (e.g. `-b 1024`) so sed replacement is correct.
- Reboot and service wait timeouts are sufficient for the platform.
- fine-tunings.yml and bk_values.json are present and well-formed; fallbacks exist in code if load fails (e.g. default profile list, default pairs).

---

## 9. Possible enhancements:

Following possible enhancements can be added:
  - Support for extended BGP messages with MTU of 9100 bytes via Snappi along .
  - Measure route-capacity for routes with optimization parameters.
  - Parameterize the max-routes (e.g. - 250k, 500k and so on).


## 10. Summary

The RIB-IN optimization and performance tests provide a parameterized framework to measure RIB-IN convergence time (250K routes) across:

- **Profiles** (DEVICE_METADATA from fine-tunings.yml),
- **Orchagent tuning** (bulk/batch pairs from bk_values.json),
- **Route type** (IPv4, IPv6, IPv4v6).

Each test applies a single (profile, bulk, batch, route_type), reboots the DUT, runs the convergence scenario once, then reverts config and orchagent. Two structural variants exist: inline setup/revert in the test (combo and route_optimztn_perf) and fixture-based setup/revert (rib_combo_v1) for memory delta analysis on the same boot.
