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
- **Platform-aware counter support**: Ensuring tests select a release-independent supported counter subset per platform using the `counter_profiles` module.
- **Stream state management**: Testing dynamic enable/disable of HFT streams and verifying InfluxDB write watermarks stop and resume.
- **Configuration lifecycle**: Validating create → delete → recreate of HFT profiles/groups while `countersyncd` runs continuously.
- **Poll interval accuracy**: Verifying the measured message rate matches expected rate based on configured poll interval.
- **Port state interaction**: Confirming counter behavior (increasing vs. stable) when monitored ports are shut down/started up under traffic.
- **Test infrastructure**: Validation of fixtures (`ensure_swss_ready`, `cleanup_high_frequency_telemetry`, `hft_influxdb`) and utility functions for HFT config management.

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

> **Note**: Not all counters are supported on all platforms. The `counter_profiles.py` module provides conservative per-platform counter definitions that work across supported image releases. Tests skip when no counters are available.
>
> `SAI_PORT_STAT_TRIM_PACKETS` and `SAI_QUEUE_STAT_TRIM_PACKETS` have limited platform availability and are not currently enabled in `counter_profiles.py` for any tested platform.

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

Per-platform supported counters are defined in `tests/high_frequency_telemetry/counter_profiles.py`. Definitions use counters known to work across supported releases rather than selecting behavior from a branch or release number. Tests skip if none are available.

---

## Test Cases

Each HFT test module starts one test-owned in-memory InfluxDB process. Every
case creates a uniquely named database, proves it is empty, installs an OTEL
configuration targeting it, restarts the systemd-managed OTEL service, and
hard-deletes the database during teardown. Unique databases prevent delayed
high-fanout exporter data from leaking across hardware sessions without paying
the process startup cost for every case. The fixture stops only the InfluxDB PID
it owns at module teardown. Multi-phase cases retain data between phases and
isolate phases with database watermarks. Standard DUT memory-utilization
monitoring remains enabled for all HFT cases.

Each case declares its counter, object, and port prerequisites with the
`hft_requirements` marker. Before that case can request HFT infrastructure, the
`skip_unsupported_hft_test` fixture checks those prerequisites and returns the
validated objects and counters. A capability-skipped case therefore performs no
InfluxDB startup, OTEL change, or HFT cleanup of its own. Infrastructure already
owned by an earlier supported case remains module-scoped until module teardown.

For counter coverage tests, the expected set is generated independently from
the configured object and counter lists. Validation requires every expected
`(SAI object type, SAI stat, object name)` series, exact SAI tags, nonnegative
values, and enough samples at a shared cutoff equal to the earliest latest
timestamp across all expected series. The wait condition uses that same cutoff
as final validation, so staggered series cannot be truncated below the sample
minimum. Full Queue requires at least 100 samples for every series and enforces
average source interval and CPS within 10%. Ingress-PG requires at least 20
samples for every series but does not enforce cadence. Port, poll-interval, and
end-to-end cadence checks use at least 100 samples and a 5% tolerance.

Session cleanup first disables the profile and waits for `STATE_DB` to report
the stream as disabled. It then deletes the group, waits for the session entry
to disappear, and deletes the profile. The Queue coverage case runs before the
other active cases so the full directory verifies that a non-Queue session can
start after the highest-fanout session is removed.

### Basic Functionality Tests

#### Test Case: Test HFT Full Queue Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_queue_counters` |
| **Objective** | Verify HFT for all configured queue objects with platform-supported queue counters. |
| **Fixtures** | `hft_influxdb` |
| **Topology** | `any` |

**Test Steps**
1. Query all queue objects from `COUNTERS_QUEUE_NAME_MAP` in COUNTERS_DB. Skip if none found.
2. Get supported queue counters for the current platform. Skip if none supported.
3. Atomically create an HFT profile (`queue_profile`) and QUEUE group with poll interval 10ms, stream state `enabled`, all discovered queue objects, and supported counters.
4. Wait for at least 100 points in every configured queue/counter series.
5. Validate complete series/tag coverage, nonnegative values, and average source interval and CPS within 10%.
6. Disable the profile and wait for the session to stop, then delete the group
   and profile.

**Expected Results**
- Every configured queue/counter combination is present with nonnegative values.
- Every series reports an average interval and CPS within 10% of the configured 10ms cadence; counter values are not required to increase.

---

#### Test Case: Test HFT Full Ingress Priority Group Counters

| Item | Description |
|---|---|
| **Test Name** | `test_hft_full_ingress_priority_group_counters` |
| **Objective** | Verify HFT for all configured ingress priority groups (buffer queues) with platform-supported counters. |
| **Fixtures** | `hft_influxdb` |
| **Topology** | `any` |

**Test Steps**
1. Query all buffer queue objects from `COUNTERS_PG_NAME_MAP` in COUNTERS_DB. Skip if none found.
2. Get supported ingress priority group counters for the current platform. Skip if none supported.
3. Atomically create an HFT profile (`ingress_pg_profile`) and INGRESS_PRIORITY_GROUP group with poll interval 10ms, stream state `enabled`, all discovered objects, and supported counters.
5. Wait for and validate every configured PG/counter series in InfluxDB.
6. Validate complete series/tag coverage and nonnegative values. Log cadence
   diagnostics without applying a tolerance to this exhaustive fanout case.
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
| **Fixtures** | `skip_unsupported_hft_test`, `hft_influxdb` |
| **Topology** | `any` |

**Test Steps**
1. Query buffer pool names from `COUNTERS_BUFFER_POOL_NAME_MAP` in COUNTERS_DB. Skip if none found.
2. Get supported buffer pool counters for the current platform. Skip if none supported.
3. Atomically create an HFT profile (`buffer_pool_profile`) and BUFFER_POOL group with poll interval 10ms, stream state `enabled`, all discovered pools, and supported counters.
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
| **Fixtures** | `hft_influxdb`, `tbinfo` |
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
| **Fixtures** | `hft_influxdb`, `tbinfo` |
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
| **Fixtures** | `hft_influxdb`, `tbinfo` |
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
| **Fixtures** | `hft_influxdb`, `tbinfo` |
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
| **Fixtures** | `hft_influxdb`, `tbinfo` |
| **Topology** | `any` |
| **Status** | Active on supported platforms. |

**Covered Inputs**

| Poll Interval (μs) | Expected CPS | Coverage |
|---|---|---|
| 1,000 (1ms) | 1000 | `test_hft_poll_interval_validation` |
| 10,000 (10ms) | 100 | `test_hft_end_to_end_influxdb` |

The 1ms and 10ms values are supported across the target images and avoid
branch- or release-specific poll-range assumptions. The 10ms case is not
duplicated here because the end-to-end test applies the same 100-point, 5%
cadence validation to two port series.

**Test Steps**
1. Get available ports from topology (desired: 2, minimum: 1).
2. Create an HFT profile with the parametrized poll interval and stream state `enabled`.
3. Create a PORT group monitoring `IF_IN_OCTETS`.
4. Wait for an interval-specific minimum number of points in every expected series.
5. Calculate average source interval and CPS from the first and last samples.
6. Compare interval and CPS against a ±5% tolerance.
7. Clean up HFT configuration.

**Expected Results**
- Average source interval and per-series CPS fall within the acceptable range.

---

#### Test Case: Test HFT Port Shutdown Stream

| Item | Description |
|---|---|
| **Test Name** | `test_hft_port_shutdown_stream` |
| **Objective** | Verify correct HFT counter behavior when a monitored port is shut down and restarted while PTF test traffic is continuously injected. |
| **Fixtures** | `hft_influxdb`, `tbinfo`, `ptfadapter` |
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
| **Fixtures** | `hft_influxdb`, `tbinfo` |
| **Topology** | `any` |
| **Dependencies** | Requires InfluxDB 3 Core (`influxdb3`) installed in PTF container ([sonic-buildimage PR #26755](https://github.com/sonic-net/sonic-buildimage/pull/26755)). Requires `otel` container support on DUT. |

**Test Steps**
1. **Start isolated infrastructure**: Reuse the module's test-owned in-memory InfluxDB process on port 8181.
2. **Isolate the case**: Stop the collector, create a unique empty database, and install an OTEL configuration targeting it.
3. **Restart OTEL safely**: Restart the systemd-managed `otel.service` and require its critical collector process to become healthy.
4. **Verify countersyncd**: Require the supervisor daemon to be running with `--enable-otel`; do not alter it.
5. **Configure HFT**: Get available ports (desired: 2, minimum: 1). Atomically create HFT profile `e2e_port_profile` (poll interval 10ms, stream `enabled`) and its PORT group monitoring `IF_IN_OCTETS`.
6. **Poll InfluxDB for metrics**: Query the exact expected measurements and object tags.
7. **Verify data arrived**: Require complete series coverage, values, interval, and CPS within 5%.
8. **Cleanup**: Remove HFT config, stop the collector, hard-delete the case database, stop the owned InfluxDB PID at module teardown, and restore OTEL state.

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
- Every expected series contains at least 100 points within 45 seconds,
  confirming metrics flowed through the full pipeline.

---

## Open/Action Items

| Item | Notes |
|---|---|
| `test_hft_full_counters` | Currently skipped. Enable once platforms support multiple object types in a single HFT session. |
| Arista 7060X6 support | Platform is listed in conditional marks but has empty counter definitions — HFT tests not yet functional. |
