# Test Plan for High Frequency Telemetry

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
  - [Supported Counters](#supported-counters)
- [Setup Configuration](#setup-configuration)
  - [Prerequisites](#prerequisites)
  - [Platform Support](#platform-support)
- [Test Cases](#test-cases)
  - [Basic Functionality Tests](#basic-functionality-tests)
    - [Test HFT Port Counters](#test-case-test-hft-port-counters)
    - [Test HFT Full Queue Counters](#test-case-test-hft-full-queue-counters)
    - [Test HFT Full Ingress Priority Group Counters](#test-case-test-hft-full-ingress-priority-group-counters)
    - [Test HFT Full Buffer Pool Counters](#test-case-test-hft-full-buffer-pool-counters)
    - [Test HFT Full Counters](#test-case-test-hft-full-counters)
    - [Test HFT Full Port Counters](#test-case-test-hft-full-port-counters)
  - [State Transition Tests](#state-transition-tests)
    - [Test HFT Disabled Stream](#test-case-test-hft-disabled-stream)
    - [Test HFT Config Deletion Stream](#test-case-test-hft-config-deletion-stream)
    - [Test HFT Poll Interval Validation](#test-case-test-hft-poll-interval-validation)
    - [Test HFT Port Shutdown Stream](#test-case-test-hft-port-shutdown-stream)
  - [End-to-End Tests](#end-to-end-tests)
    - [Test HFT End-to-End InfluxDB](#test-case-test-hft-end-to-end-influxdb)
- [Open/Action Items](#openaction-items)

---

## Overview

This test plan outlines the approach for validating the [High Frequency Telemetry (HFT)](https://github.com/sonic-net/SONiC/blob/master/doc/high-frequency-telemetry/high-frequency-telemetry-hld.md) feature in SONiC.

HFT enables microsecond-level polling and streaming of network statistics (port counters, queue counters, ingress priority group counters, buffer pool counters) via the `countersyncd` daemon running inside the `swss` container. The tests verify that the system can accurately collect and report real-time telemetry data, respond correctly to dynamic configuration changes, and handle port state transitions gracefully.

### Scope

The test suite covers:
- **Counter data collection**: Verifying that HFT correctly polls and reports PORT, QUEUE, INGRESS_PRIORITY_GROUP, and BUFFER_POOL counters.
- **Platform-aware counter support**: Ensuring tests dynamically select supported counters per platform using the `counter_profiles` module.
- **Stream state management**: Testing dynamic enable/disable of HFT streams and verifying InfluxDB write watermarks stop and resume.
- **Configuration lifecycle**: Validating create → delete → recreate of HFT profiles/groups while `countersyncd` runs continuously.
- **Poll interval accuracy**: Verifying the measured message rate matches expected rate based on configured poll interval.
- **Port state interaction**: Confirming counter behavior (increasing vs. stable) when monitored ports are shut down/started up under traffic.
- **Test infrastructure**: Validation of fixtures (`ensure_swss_ready`, `cleanup_high_frequency_telemetry`, `disable_flex_counters`) and utility functions for HFT config management.

### Testbed

The test will run on the following testbeds:
- `any` topology (marked with `pytest.mark.topology('any')`)

Supported testbed topologies verified on:
- t0-isolated-d32u32s2
- t1-isolated-d56u2

### Supported Counters

HFT Phase 1 supports key AI data center statistics across four object types:

| Object Type | Counters |
|---|---|
| **PORT** | `SAI_PORT_STAT_IF_IN_OCTETS`, `SAI_PORT_STAT_IF_IN_UCAST_PKTS`, `SAI_PORT_STAT_IF_IN_DISCARDS`, `SAI_PORT_STAT_IF_IN_ERRORS`, `SAI_PORT_STAT_IN_CURR_OCCUPANCY_BYTES`, `SAI_PORT_STAT_IF_OUT_OCTETS`, `SAI_PORT_STAT_IF_OUT_DISCARDS`, `SAI_PORT_STAT_IF_OUT_ERRORS`, `SAI_PORT_STAT_IF_OUT_UCAST_PKTS`, `SAI_PORT_STAT_OUT_CURR_OCCUPANCY_BYTES`, `SAI_PORT_STAT_TRIM_PACKETS` |
| **QUEUE** | `SAI_QUEUE_STAT_PACKETS`, `SAI_QUEUE_STAT_BYTES`, `SAI_QUEUE_STAT_DROPPED_PACKETS`, `SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES`, `SAI_QUEUE_STAT_WATERMARK_BYTES`, `SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS`, `SAI_QUEUE_STAT_TRIM_PACKETS` |
| **BUFFER_POOL** | `SAI_BUFFER_POOL_STAT_DROPPED_PACKETS`, `SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES`, `SAI_BUFFER_POOL_STAT_WATERMARK_BYTES`, `SAI_BUFFER_POOL_STAT_XOFF_ROOM_WATERMARK_BYTES` |
| **INGRESS_PRIORITY_GROUP** | `SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS`, `SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES`, `SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES`, `SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES`, `SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES`, `SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES`, `SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS` |

> **Note**: Not all counters are supported on all platforms. The `counter_profiles.py` module provides per-platform counter definitions. Tests dynamically query supported counters and skip when none are available.
>
> `SAI_PORT_STAT_TRIM_PACKETS` and `SAI_QUEUE_STAT_TRIM_PACKETS` have limited platform availability and are not currently enabled in `counter_profiles.py` for any tested platform.
>
> NVIDIA images before release 202605 use the legacy Spectrum counter set.
> Newer SDKs add port/queue/PG/buffer-pool counters that older SDKs reject at
> SAI session creation time.

---

## Setup Configuration

### Prerequisites
- DUT must have the `swss` container running and stable (uptime ≥ 10 seconds).
- The `countersyncd` daemon must be functional inside the `swss` container.
- The supervisor-owned `countersyncd` daemon must be running with `--enable-otel`; tests never start or stop it.
- The DUT must provide the `otel` container image.
- InfluxDB 3 Core (`influxdb3`) must be installed on the PTF host.
- HFT CLI commands (`config hft add/del/enable/disable`) must be available on the DUT.
- CONFIG_DB (database 4) must be accessible for HFT table management.
- COUNTERS_DB (database 2) must be accessible for queue/buffer object discovery.
- For port shutdown tests: PTF adapter must be available for traffic injection.

### Platform Support

HFT tests are conditionally skipped via `tests_mark_conditions.yaml` on unsupported platforms:

| Platform | Status |
|---|---|
| `x86_64-nvidia_sn5600-r0` | Supported |
| `x86_64-nvidia_sn5640-r0` | Supported (partial counter support) |
| `x86_64-arista_7060x6_64pe_b` | Supported (limited) |
| All other platforms | Skipped |

Per-platform supported counters are defined in `tests/high_frequency_telemetry/counter_profiles.py`. Tests dynamically query supported counters and skip if none are available.

---

## Test Cases

All HFT cases use the function-scoped `hft_influxdb` fixture. Before each
invocation, including every parametrized poll interval, the fixture starts a
test-owned in-memory InfluxDB process and verifies its database is empty. After
the test removes its HFT configuration, the fixture drains buffered writes,
hard-deletes and recreates the database, verifies it is empty, and stops only
the InfluxDB process it owns. Multi-phase cases retain data between phases and
isolate phases with database watermarks.

For counter coverage tests, the expected set is generated independently from
the configured object and counter lists. Validation requires every expected
`(SAI object type, SAI stat, object name)` series, nonnegative values, enough
samples, and source timestamp interval/CPS within the configured tolerance.

### Basic Functionality Tests

#### Test Case: Test HFT Port Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_port_counters` |
| **Objective** | Verify basic HFT functionality for port counters with a single counter type (`IF_IN_OCTETS`). |
| **Fixtures** | `disable_flex_counters`, `tbinfo` |
| **Topology** | `any` |

**Test Steps**
1. Get available ports from topology (desired: 2, minimum: 1).
2. Create an HFT profile (`port_profile`) with poll interval 10ms (10,000 μs) and stream state `enabled`.
3. Create a PORT group with the selected ports monitoring `IF_IN_OCTETS`.
4. Wait until every expected InfluxDB series contains enough samples.
5. Validate complete object/counter coverage, nonnegative values, source timestamp interval, and CPS.
6. Verify the supervisor-owned `countersyncd` remains running.
7. Clean up HFT profile and group.

**Expected Results**
- All monitored counters report values ≥ 0.
- Per-series CPS and average source interval match the configured 10ms poll interval.
- `countersyncd` remains running in `swss` after test.

---

#### Test Case: Test HFT Full Queue Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_queue_counters` |
| **Objective** | Verify HFT for all configured queue objects with platform-supported queue counters. |
| **Fixtures** | `disable_flex_counters` |
| **Topology** | `any` |

**Test Steps**
1. Query all queue objects from `COUNTERS_QUEUE_NAME_MAP` in COUNTERS_DB. Skip if none found.
2. Get supported queue counters for the current platform. Skip if none supported.
3. Create an HFT profile (`queue_profile`) with poll interval 10ms and stream state `enabled`.
4. Create a QUEUE group with all discovered queue objects and supported counters.
5. Wait for and validate every configured queue/counter series in InfluxDB.
6. Validate values, interval, and CPS per series.
7. Clean up HFT configuration.

**Expected Results**
- Every configured queue/counter combination is present with nonnegative values.

---

#### Test Case: Test HFT Full Ingress Priority Group Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_ingress_priority_group_counters` |
| **Objective** | Verify HFT for all configured ingress priority groups (buffer queues) with platform-supported counters. |
| **Fixtures** | `disable_flex_counters` |
| **Topology** | `any` |

**Test Steps**
1. Query all buffer queue objects from `COUNTERS_PG_NAME_MAP` in COUNTERS_DB. Skip if none found.
2. Get supported ingress priority group counters for the current platform. Skip if none supported.
3. Create an HFT profile (`ingress_pg_profile`) with poll interval 10ms and stream state `enabled`.
4. Create an INGRESS_PRIORITY_GROUP group with all discovered objects and supported counters.
5. Wait for and validate every configured PG/counter series in InfluxDB.
6. Validate values, interval, and CPS per series.
7. Clean up HFT configuration.

**Expected Results**
- Counter values ≥ 0 are reported for ingress priority group objects.
- Every configured PG/counter combination is present.

---

#### Test Case: Test HFT Full Buffer Pool Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_buffer_pool_counters` |
| **Objective** | Verify HFT for all configured buffer pools with platform-supported counters. |
| **Fixtures** | `disable_flex_counters` |
| **Topology** | `any` |

**Test Steps**
1. Query buffer pool names from `COUNTERS_BUFFER_POOL_NAME_MAP` in COUNTERS_DB. Skip if none found.
2. Get supported buffer pool counters for the current platform. Skip if none supported.
3. Create an HFT profile (`buffer_pool_profile`) with poll interval 10ms and stream state `enabled`.
4. Create a BUFFER_POOL group with all discovered pools and supported counters.
5. Wait for and validate every configured pool/counter series in InfluxDB.
6. Validate values, interval, and CPS per series.
7. Clean up HFT configuration.

**Expected Results**
- Counter values ≥ 0 are reported for buffer pool objects.
- Every configured pool/counter combination is present.

---

#### Test Case: Test HFT Full Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_counters` |
| **Objective** | Verify HFT when monitoring all supported object types (PORT, QUEUE, INGRESS_PRIORITY_GROUP, BUFFER_POOL) under a single profile. |
| **Fixtures** | `disable_flex_counters`, `tbinfo` |
| **Topology** | `any` |
| **Status** | **Skipped** — Full counters HFT isn't supported. On SN5640, multiple types in one session are not supported. On 7060X6, HFT tests are not yet supported. |

The test remains capability-skipped until a supported platform can carry
multiple object types in one HFT session. When enabled, it will use the same
complete InfluxDB series coverage and cadence validation as the individual
object-type tests.

---

#### Test Case: Test HFT Full Port Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_port_counters` |
| **Objective** | Verify HFT when monitoring all available ports with all supported port counters simultaneously. |
| **Fixtures** | `disable_flex_counters`, `tbinfo` |
| **Topology** | `any` |

**Test Steps**
1. Get all available ports from topology (minimum 1 required).
2. Get all supported port counters for the current platform. Skip if none supported.
3. Create an HFT profile (`full_port_counter_profile`) with poll interval 10ms and stream state `enabled`.
4. Create a PORT group with all available ports and all supported counters.
5. Wait for every expected port/counter series in InfluxDB.
6. Require complete port/counter coverage and validate each series.
7. Log per-series point count, values, interval, and CPS.
8. Clean up HFT configuration.

**Expected Results**
- Every configured port/counter combination is reported and validated.

---

### State Transition Tests

#### Test Case: Test HFT Disabled Stream

| Item | Description |
|---|---|
| **Test Name** | `test_hft_disabled_stream` |
| **Objective** | Verify that dynamically enabling/disabling an HFT stream correctly starts/stops telemetry output. |
| **Fixtures** | `disable_flex_counters`, `tbinfo` |
| **Topology** | `any` |

**Test Steps**
1. Get available ports from topology (desired: 2, minimum: 1).
2. Create an HFT profile (`state_transition_profile`) with poll interval 10ms and stream state `disabled`.
3. Create a PORT group monitoring `IF_IN_OCTETS`.
4. Enable the stream and require all expected InfluxDB series.
5. Disable it, drain the exporter, and require series point counts to remain unchanged.
6. Re-enable it and require every point-count watermark to advance.
7. Clean up HFT configuration.

**Expected Results**
- Phase 1: Expected series are active.
- Phase 2: No new points are written.
- Phase 3: Every expected series resumes writing.

---

#### Test Case: Test HFT Config Deletion Stream

| Item | Description |
|---|---|
| **Test Name** | `test_hft_config_deletion_stream` |
| **Objective** | Verify that `countersyncd` correctly responds to dynamic HFT configuration lifecycle changes (create → delete → recreate) without requiring process restart. |
| **Fixtures** | `disable_flex_counters`, `tbinfo` |
| **Topology** | `any` |

**Test Steps**
1. Get available ports from topology (desired: 2, minimum: 1).
2. Create the profile/group and require all expected InfluxDB series.
3. Delete the configuration, drain the exporter, and require point counts to remain unchanged.
4. Recreate the configuration and require every point-count watermark to advance.
5. Clean up any remaining HFT configuration.

**Expected Results**
- Phase 1: Expected series are active.
- Phase 2: No new points are written.
- Phase 3: Every expected series resumes writing.

---

#### Test Case: Test HFT Poll Interval Validation

| Item | Description |
|---|---|
| **Test Name** | `test_hft_poll_interval_validation` |
| **Objective** | Verify source timestamp interval and per-series CPS for each configured poll interval. |
| **Fixtures** | `disable_flex_counters`, `tbinfo` |
| **Topology** | `any` |
| **Status** | Active on supported platforms. |

**Parametrized Inputs**

| Poll Interval (μs) | Expected CPS |
|---|---|
| 1,000 (1ms) | 1000 |
| 10,000 (10ms) | 100 |
| 100,000 (100ms) | 10 |
| 1,000,000 (1s) | 1 |
| 10,000,000 (10s) | 0.1 |

Parameters outside a platform's reported or known SAI range are capability
skipped before HFT configuration. For NVIDIA releases before 202605, the SDK
range is 100–12,750 μs, so the 1 ms and 10 ms parameters execute while slower
parameters remain visible as capability skips.

**Test Steps**
1. Get available ports from topology (desired: 2, minimum: 1).
2. Create an HFT profile with the parametrized poll interval and stream state `enabled`.
3. Create a PORT group monitoring `IF_IN_OCTETS`.
4. Wait for an interval-specific minimum number of points in every expected series.
5. Calculate average source interval and CPS from the first and last samples.
6. Compare interval and CPS against tolerance bands:
   - ≥ 10 CPS: ±20% tolerance
   - 1–10 CPS: ±30% tolerance
   - < 1 CPS: ±50% tolerance
7. Clean up HFT configuration.

**Expected Results**
- Average source interval and per-series CPS fall within the acceptable range.

---

#### Test Case: Test HFT Port Shutdown Stream

| Item | Description |
|---|---|
| **Test Name** | `test_hft_port_shutdown_stream` |
| **Objective** | Verify correct HFT counter behavior when a monitored port is shut down and restarted while PTF test traffic is continuously injected. |
| **Fixtures** | `disable_flex_counters`, `tbinfo`, `ptfadapter` |
| **Topology** | `any` |

**Test Steps**
1. Get one available port from topology.
2. Resolve PTF port index and router MAC for traffic injection.
3. Create an HFT profile (`port_shutdown_profile`) with poll interval 10ms and stream state `enabled`.
4. Create a PORT group monitoring `IF_IN_OCTETS` on the test port.
5. Start PTF traffic injection (100 packets/s); use the existing daemon for telemetry.
6. Execute three bounded, condition-driven phases:
   - **Phase 1 (port up)**: Port up + traffic → expect counters **increasing**.
   - **Phase 2 (port down)**: Shut down port via `config interface shutdown` + traffic continues → expect the last counter value to remain stable and the InfluxDB point watermark to stop.
   - **Phase 3 (port up)**: Start up port via `config interface startup` + traffic continues → expect counters **increasing** again.
7. Query InfluxDB values and point counts in each phase.
8. Ensure port is brought back up before cleanup.
9. Clean up HFT configuration.

**Expected Results**
- Phase 1: Counter trend is `increasing` (port up, receiving traffic).
- Phase 2: Counter value is stable and no new points are exported (port down).
- Phase 3: Counter trend is `increasing` (port back up, receiving traffic again).

---

### End-to-End Tests

#### Test Case: Test HFT End-to-End InfluxDB

| Item | Description |
|---|---|
| **Test Name** | `test_hft_end_to_end_influxdb` |
| **Test File** | `tests/high_frequency_telemetry/test_hft_end_to_end.py` |
| **Objective** | Validate the full HFT telemetry pipeline end-to-end: `countersyncd` → OpenTelemetry collector → InfluxDB. Confirms that HFT metrics actually flow through the otel collector and arrive in an external time-series database. |
| **Fixtures** | `disable_flex_counters`, `tbinfo`, `ptfhost` |
| **Topology** | `any` |
| **Dependencies** | Requires InfluxDB 3 Core (`influxdb3`) installed in PTF container ([sonic-buildimage PR #26755](https://github.com/sonic-net/sonic-buildimage/pull/26755)). Requires `otel` container support on DUT. |

**Test Steps**
1. **Start InfluxDB 3 on PTF host**: Start a test-owned in-memory process on port 8181 and capture its exact PID.
2. **Initialize InfluxDB 3**: Create and verify an empty `hft_test` database.
3. **Enable otel collector on DUT**: Run `config feature state otel enabled` and wait up to 60 seconds for the `otel` container to be running.
4. **Install otel collector config**: Render the Jinja2 template (`otel_collector_influxdb.yaml.j2`) with PTF IP and database, copy it to `/etc/sonic/otel_config.yml`, and restart only the collector process inside the existing `otel` container.
5. **Configure HFT**: Get available ports (desired: 2, minimum: 1). Create HFT profile (`e2e_port_profile`, poll interval 10ms, stream `enabled`) and PORT group monitoring `IF_IN_OCTETS`.
6. **Verify countersyncd**: Require the supervisor daemon to be running with `--enable-otel`; do not alter it.
7. **Poll InfluxDB for metrics**: Query the exact expected measurements and object tags.
8. **Verify data arrived**: Require complete series coverage, values, interval, and CPS.
9. **Cleanup**: Remove HFT config, clear and verify the database, then stop only the owned InfluxDB PID.

**Otel Collector Config** (`otel_collector_influxdb.yaml.j2`)
```
Receivers:  otlp (gRPC :4317, HTTP :4318)
Processors: batch (timeout 1s, batch size 10)
Exporters:  influxdb (PTF host :8181, retry and queue disabled)
Pipeline:   metrics → [otlp] → [batch] → [influxdb]
```

**Expected Results**
- InfluxDB 3 health endpoint returns `OK` (HTTP 200) after startup.
- Otel container starts successfully on DUT.
- InfluxDB query returns ≥ 1 data row within 60 seconds, confirming metrics flowed through the full pipeline.

---

## Open/Action Items

| Item | Notes |
|---|---|
| `test_hft_full_counters` | Currently skipped. Enable once platforms support multiple object types in a single HFT session. |
| Arista 7060X6 support | Platform is listed in conditional marks but has empty counter definitions — HFT tests not yet functional. |
