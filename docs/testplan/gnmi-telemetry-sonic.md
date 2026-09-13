# SONiC gNMI Telemetry - CLI to gNMI Analysis

## Purpose

This document records every CLI command used in SONiC tests that was
evaluated for replacement with gNMI, along with the mapping status and
planned handling in the Telemetry Abstraction Layer.

---

## Architecture Context

This gap analysis underpins the Telemetry Abstraction Layer (Option B)
implemented in `tests/common/telemetry/adapters/`.

```
Test → SonicTelemetryAdapter -> gNMI (AUTO) -> Structured data -> Validation
                             -> CLI (fallback)
```

The adapter exposes field names identical to `portstat -j` so that
existing test helpers require zero changes when adopting the adapter.

---
## Quick Start

```python
from tests.common.telemetry.adapters import SonicTelemetryAdapter

# AUTO transport: gNMI first, CLI fallback
adapter = SonicTelemetryAdapter(duthost, ptfhost=ptfhost)

counters = adapter.get_interface_counters("Ethernet0")
print(counters.RX_OK, counters.TX_OK)   # same field names as portstat -j

all_counters = adapter.get_all_interface_counters()  # dict: iface -> InterfaceCounters
queue_stats  = adapter.get_queue_stats("Ethernet0")  # QueueCounters
adapter.clear_interface_counters()                   # sonic-clear counters
```
---
## Methodology

For each CLI command:

1. Identify which SONiC DB tables back the command.
2. Construct the gNMI YANG path (sonic-db origin).
3. Verify the path exists and the field is populated on a running DUT.
4. Map SAI keys to portstat field names and document any aggregation.
5. Classify the mapping status.

Status values used in the tables below:

- DONE: Fully implemented in the adapter today, 1:1 or aggregated mapping.
- PARTIAL: Implemented with a known limitation; usable with caller-side workaround.
- PLANNED: SAI key exists in COUNTERS_DB; implementation is planned, not yet done.
- NOT AVAILABLE: No SAI key or gNMI path exists; CLI is the only option.

---

## 1. `show interface counters` (portstat)

CLI output columns: RX_OK TX_OK RX_ERR TX_ERR RX_DRP TX_DRP RX_BPS TX_BPS RX_UTIL TX_UTIL RX_OVR TX_OVR

### gNMI Path Pattern

```
/sonic-db:COUNTERS_DB/localhost/COUNTERS_PORT_NAME_MAP/<iface>   → OID
/sonic-db:COUNTERS_DB/localhost/COUNTERS/<oid>                    → SAI hash
```

### Field Mapping

| portstat field | SAI stat(s) | Status | Notes |
|----------------|-------------|--------|-------|
| RX_OK | SAI_PORT_STAT_IF_IN_UCAST_PKTS + SAI_PORT_STAT_IF_IN_MULTICAST_PKTS + SAI_PORT_STAT_IF_IN_BROADCAST_PKTS | DONE | Sum of 3 SAI stats |
| TX_OK | SAI_PORT_STAT_IF_OUT_UCAST_PKTS + SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS + SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS | DONE | Sum of 3 SAI stats |
| RX_ERR | SAI_PORT_STAT_IF_IN_ERRORS | DONE | 1:1 |
| TX_ERR | SAI_PORT_STAT_IF_OUT_ERRORS | DONE | 1:1 |
| RX_DRP | SAI_PORT_STAT_IF_IN_DISCARDS | DONE | 1:1 |
| TX_DRP | SAI_PORT_STAT_IF_OUT_DISCARDS | DONE | 1:1 |
| RX_BPS | SAI_PORT_STAT_IF_IN_OCTETS | PARTIAL | Returns cumulative bytes, not a rate. Caller must compute: (bytes2 - bytes1) / elapsed * 8 |
| TX_BPS | SAI_PORT_STAT_IF_OUT_OCTETS | PARTIAL | Same as RX_BPS |
| RX_UTIL | not in COUNTERS_DB | PLANNED | Requires port speed from CONFIG_DB. Adapter returns 0.0 today. Plan: read speed from CONFIG_DB INTERFACE_TABLE |
| TX_UTIL | not in COUNTERS_DB | PLANNED | Same as RX_UTIL |
| RX_OVR | not in COUNTERS_DB | NOT AVAILABLE | No SAI equivalent exposed via gNMI. Adapter always returns 0 |
| TX_OVR | not in COUNTERS_DB | NOT AVAILABLE | Same as RX_OVR |

### Summary

- 6 of 12 fields: DONE - fully mapped and implemented
- 2 of 12 fields: PARTIAL - BPS returns bytes, not rate; caller computes rate
- 2 of 12 fields: PLANNED - UTIL requires CONFIG_DB port speed lookup
- 2 of 12 fields: NOT AVAILABLE - OVR not exposed in COUNTERS_DB

Impact on tests: Tests that use only RX_OK, TX_OK, RX_ERR, TX_ERR, RX_DRP, TX_DRP
can adopt gNMI via the adapter today with no code changes. Tests that require RX_UTIL
or TX_UTIL should use CLI transport or compute the value from RX_BPS and port speed.

---

## 2. `show queue counters`

CLI output columns: UC<n>_PKTS UC<n>_BYTES UC<n>_DROP_PKTS UC<n>_DROP_BYTES (one row per queue)

### gNMI Path Pattern

```
/sonic-db:COUNTERS_DB/localhost/COUNTERS_QUEUE_NAME_MAP/<iface>:<q>   → OID
/sonic-db:COUNTERS_DB/localhost/COUNTERS/<oid>                         → SAI hash
```

### Field Mapping

| portstat field | SAI stat | Status | Notes |
|----------------|----------|--------|-------|
| UC<n>_PKTS | SAI_QUEUE_STAT_PACKETS | DONE | 1:1 |
| UC<n>_BYTES | SAI_QUEUE_STAT_BYTES | DONE | 1:1 |
| UC<n>_DROP_PKTS | SAI_QUEUE_STAT_DROPPED_PACKETS | DONE | 1:1 |
| UC<n>_DROP_BYTES | SAI_QUEUE_STAT_DROPPED_BYTES | DONE | 1:1 |

All 4 fields are fully implemented.

---

## 3. `show pfc counters`

CLI output columns: RX_0 through RX_7 and TX_0 through TX_7 (per priority)

### gNMI Path Pattern

```
/sonic-db:COUNTERS_DB/localhost/COUNTERS/<oid>
  → SAI_PORT_STAT_PFC_<n>_RX_PKTS / SAI_PORT_STAT_PFC_<n>_TX_PKTS
```

### Field Mapping

| portstat field | SAI stat | Status | Notes |
|----------------|----------|--------|-------|
| RX_<n> | SAI_PORT_STAT_PFC_<n>_RX_PKTS | PLANNED | SAI key exists; requires per-priority loop. Not yet implemented in adapter |
| TX_<n> | SAI_PORT_STAT_PFC_<n>_TX_PKTS | PLANNED | Same as RX |

Plan: implement `get_pfc_stats(interface)` in GNMIAdapter iterating priorities 0-7.
Until then, PFC counter tests must use CLI transport.

---

## Gap Classification Summary

| Category | Count | Status | Plan |
|----------|-------|--------|------|
| Packet counters (RX/TX OK, ERR, DRP) | 6 | DONE | No further work needed |
| Byte counters (BPS) | 2 | PARTIAL | Document rate computation pattern |
| Utilisation (UTIL) | 2 | PLANNED | Read port speed from CONFIG_DB |
| Overrun (OVR) | 2 | NOT AVAILABLE | Accept 0 or use CLI |
| PFC per-priority counters | 16 | PLANNED | Implement get_pfc_stats() in adapter |
| Queue counters | 4 | DONE | No further work needed |

---
## POC test

> `tests/gnmi/test_gnmi_telemetry_adapter.py` - 6 test classes covering structural correctness, monotonicity, batch retrieval, queue stats, gNMI vs CLI consistency, and Snappi drop-in replacement.
---

## Planned Work

The following items are prioritised for future adapter development:

**Priority 1 - UTIL calculation**

Extend GNMIAdapter to read port speed from CONFIG_DB INTERFACE_TABLE and compute
RX_UTIL and TX_UTIL as (bps / port_speed_bps) * 100. This unblocks tests that
currently require CLI transport for utilisation-based assertions.

**Priority 2 - PFC counters**

Implement `get_pfc_stats(interface)` in GNMIAdapter. SAI keys
SAI_PORT_STAT_PFC_<n>_RX_PKTS and SAI_PORT_STAT_PFC_<n>_TX_PKTS are
present in COUNTERS_DB for priorities 0 through 7. The method should return
a dict keyed by priority index with RX and TX packet counts.

**Priority 3 - BPS rate helper**

Add a `get_interface_rate(interface, interval_seconds)` convenience method to
SonicTelemetryAdapter that internally calls get_interface_counters() twice with
a sleep and returns bits-per-second rates. This removes the boilerplate from
tests that need live rate values.

---

## References

- PR #23635: Fix gNMI and telemetry service startup and cert deployment
- `tests/gnmi/test_gnmi_countersdb.py` - existing gNMI COUNTERS_DB tests
- `tests/common/telemetry/adapters/gnmi_adapter.py` - SAI mapping implementation
- `tests/gnmi/test_gnmi_telemetry_adapter.py` - POC integration tests
