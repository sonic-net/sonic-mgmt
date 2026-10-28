# SONiC BMC Redfish API Test Plan

# Test Plan Revision History

| Rev | Date             | Author         | Change Description                                                                                                                                                  |
| --- | ---------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | 26th March 2026  | Chinmoy Dey    | Initial Version of SONiC BMC Redfish API test plan                                                                                                                 |
| 2   | 2nd April 2026   | Shreyansh Jain | Add certificate-based authentication test cases                                                                                                                    |
| 3   | 8th October 2026 | Chinmoy Dey    | Align with the sonic-mgmt test code: ComputerSystem, Chassis leak detection, event subscriptions, Rack Manager alert, pmon interaction, concurrency and restart recovery |
| 4   | 28th October 2026 | Shreyansh Jain | Align the certificate section with `test_redfish_certificates.py` and the Redfish certificate provisioning HLD |

# Related documents

| Document Name                | Link                                                                                                   |
| :--------------------------- | :----------------------------------------------------------------------------------------------------- |
| SONiC-BMC-OS HLD             | [https://github.com/sonic-net/SONiC/pull/2043](https://github.com/sonic-net/SONiC/pull/2043)           |
| sonic-redfish HLD            | [https://github.com/sonic-net/sonic-redfish/pull/2](https://github.com/sonic-net/sonic-redfish/pull/2) |
| sonic-redfish Implementation | [https://github.com/sonic-net/sonic-redfish/pull/1](https://github.com/sonic-net/sonic-redfish/pull/1) |
| Redfish Certificate Provisioning HLD | [https://github.com/sonic-net/SONiC/pull/2461](https://github.com/sonic-net/SONiC/pull/2461) |

# Definitions/Abbreviation

| Term              | Description                                                                                                   |
| :---------------- | :------------------------------------------------------------------------------------------------------------ |
| SONiC             | Software for Open Networking in the Cloud                                                                     |
| BMC               | Baseboard Management Controller                                                                               |
| Redfish           | DMTF industry-standard RESTful API for hardware management                                                    |
| bmcweb            | OpenBMC's industry-standard Redfish HTTP server                                                               |
| D-Bus             | Linux inter-process communication system                                                                      |
| sonic-dbus-bridge | SONiC service that bridges platform data to OpenBMC-compatible D-Bus interfaces                               |
| ObjectMapper      | OpenBMC D-Bus discovery service (`xyz.openbmc_project.ObjectMapper`), hosted by sonic-dbus-bridge             |
| bmcctld           | Daemon in the BMC `pmon` container that controls switch-host power and owns `HOST_STATE` and `RACK_MANAGER_COMMAND` |
| Rack Manager (RMC)| External controller that polls the BMC, pushes coolant alerts/telemetry and subscribes to events              |
| Switch host       | The x86 switch the BMC manages, exposed as `/redfish/v1/Systems/system`                                       |
| STATE_DB          | SONiC Redis database on the BMC; the observable contract between bmcweb, sonic-dbus-bridge and bmcctld       |
| mTLS              | Mutual TLS; bmcweb asks every client for a certificate, and every resource except the service root requires one |
| PTF host          | Packet Test Framework host of the testbed; runs the rack manager webhook receiver                             |
| DUT               | Device Under Test — the SONiC BMC system being tested                                                         |

# Overview

The sonic-redfish project provides Redfish API support for SONiC BMC platforms. It consists of two components packaged in a single Docker container named `redfish` (built from `docker-redfish`):

1. **bmcweb** — The upstream OpenBMC Redfish HTTP server, with the SONiC OEM Rack Manager extension and the rmc-events leak/host-power monitors.
2. **sonic-dbus-bridge** — A systemd daemon that reads SONiC data sources (Redis CONFIG\_DB/STATE\_DB, FRU EEPROMs, platform.json), exposes OpenBMC-compatible D-Bus objects (`xyz.openbmc_project.*`) for bmcweb, and forwards Rack Manager actions and reset requests into STATE\_DB.

The end-to-end data flow is:

```text
Inventory (read path)
  SONiC Redis / FRU EEPROM / platform.json
    -> sonic-dbus-bridge (D-Bus objects + ObjectMapper)
      -> bmcweb -> Redfish REST API (HTTPS, mTLS)

Switch-host power (write path)
  Redfish ComputerSystem.Reset -> bmcweb -> D-Bus RequestedHostTransition
    -> sonic-dbus-bridge -> STATE_DB RACK_MANAGER_COMMAND|CMD_*
      -> bmcctld (pmon) -> STATE_DB HOST_STATE|switch-host
        -> sonic-dbus-bridge State.Host -> bmcweb PowerState + ResourcePower* events

Rack Manager push (write path)
  SONiC.SubmitAlert / SONiC.SubmitTelemetry -> bmcweb -> D-Bus com.sonic.RackManager
    -> sonic-dbus-bridge -> STATE_DB RACK_MANAGER_ALERT / RACK_MANAGER_DATA
```

This test plan validates the Redfish API exposed by sonic-redfish on SONiC BMC platforms end to end: from the Redfish response down to the D-Bus objects and STATE\_DB rows behind it, and from STATE\_DB back out to a subscribed rack manager.

# Scope

This test plan covers:

- Authentication (certificate-based mTLS with common name validation; the service root answers without a certificate, every other resource requires one)
- Redfish service root discovery (`/redfish/v1`)
- Chassis inventory and the leak detection tree (`/redfish/v1/Chassis/chassis`, `LeakDetectors`, `ThermalSubsystem/LeakDetection`)
- Computer system inventory, power state and `ResetActionInfo` (`/redfish/v1/Systems/system`)
- Computer system reset actions and their `RACK_MANAGER_COMMAND` rows (`ComputerSystem.Reset`)
- Firmware inventory (`/redfish/v1/UpdateService/FirmwareInventory`)
- Rack Manager alert and telemetry persistence to STATE\_DB (`SONiC.SubmitAlert`, `SONiC.SubmitTelemetry`)
- Event service, push subscriptions, leak events and switch-host power events (`/redfish/v1/EventService`)
- Redfish to pmon (bmcctld) interaction over STATE\_DB, including the CRITICAL alert power-on interlock
- Behaviour under concurrent rack manager requests
- Recovery after restarting sonic-dbus-bridge, bmcweb, bmcctld and the `redfish` container

# Scale and Performance

No scale and performance testing is involved in this test plan. The concurrency tests issue a handful of parallel requests to prove functional correctness, not throughput. Each Redfish endpoint is tested with a single BMC DUT.

# Test Infrastructure

## Testbed Requirements

| Component         | Requirement                                                                                                            |
| :---------------- | :--------------------------------------------------------------------------------------------------------------------- |
| DUT               | SONiC BMC platform (Aspeed AST2720/AST2700) running sonic-aspeed-arm64.bin; the testbed DUT is the `<switch>-bmc` host |
| Switch host       | The host-side switch referenced by the BMC's `bmc_host` field, reachable over SSH (power-cycle test reads its boot id) |
| PTF host          | On the BMC management subnet, reachable from the `redfish` container; hosts the rack manager webhook receiver         |
| Network           | Management network connectivity between test server and BMC on HTTPS port 443                                         |
| Docker            | `redfish` feature present in the image (`INCLUDE_REDFISH=y`); the suite enables it if the image ships it disabled     |
| pmon              | `bmcctld` running in the BMC `pmon` container for the reset, event and interaction tests                               |
| Image features    | bmcweb built with the SONiC OEM extension and rmc-events (leak event tests skip otherwise)                             |
| Authentication    | Admin user on the BMC; TLS certificates are generated and installed by the suite                                       |

## Rack Manager Stand-in

No external Rack Manager is required. The sonic-mgmt host plays the rack manager over mTLS: it polls inventory, submits alerts and telemetry, issues resets and creates subscriptions. A stdlib-only webhook receiver (`redfish_event_listener.py`) is copied to the PTF host and started on port 18081 to receive event deliveries from bmcweb; each delivery is recorded as one JSON line that the tests read back. Reachability is probed from inside the `redfish` container before any subscription is created.

STATE\_DB on the BMC is the observable boundary for every write path: the tests read `RACK_MANAGER_ALERT`, `RACK_MANAGER_DATA`, `RACK_MANAGER_COMMAND` and `HOST_STATE` directly over SSH and compare them with the Redfish side.

## Test Utilities

Tests use the `requests` Python library for REST API validation (no PTF/scapy needed, as these are management-plane API tests, not data-plane packet tests).

- `redfish_utils.py` — `RedfishClient` (mTLS session), field/status/member assertion helpers, `assert_redfish_error` for registry message checks, and the `HOST_FINAL_POWER_STATES` map used to decide when the switch host is settled.
- `redfish_event_listener.py` — the webhook receiver described above; runs in-process or as a standalone script.
- `conftest.py` session fixtures — `bmc_duthost` (requires a BMC DUT), `redfish_feature_enabled`, `bmc_clock_in_sync`, `bmc_tls_certs` (provisions certificates through `REDFISH|certs` the way a provisioning agent does and restores the original state at teardown, see Section 12) and `redfish_client`.

Per-module fixtures snapshot and restore the STATE\_DB tables they touch, remove subscriptions before and after each test, and power the switch host back on if a power test leaves it off.

## Test Directory Structure

```text
sonic-mgmt/tests/redfish/
├── __init__.py
├── conftest.py                            # BMC fixtures, TLS certificate lifecycle
├── redfish_utils.py                       # Shared Redfish client and assertion helpers
├── redfish_event_listener.py              # Rack manager webhook receiver (runs on the PTF host)
├── test_redfish_service_root.py           # Service root tests
├── test_redfish_chassis.py                # Chassis identity and leak detection tree
├── test_redfish_computer_system.py        # ComputerSystem, PowerState, ResetActionInfo
├── test_redfish_computer_reset.py         # ComputerSystem.Reset action tests
├── test_redfish_firmware_inventory.py     # Firmware inventory tests
├── test_redfish_rack_manager_alert.py     # SONiC.SubmitAlert tests
├── test_redfish_rack_manager_telemetry.py # SONiC.SubmitTelemetry tests
├── test_redfish_event_subscription.py     # EventService, subscriptions, leak and power events
├── test_redfish_pmon_interaction.py       # Redfish <-> bmcctld over STATE_DB
├── test_redfish_concurrency.py            # Concurrent rack manager requests
├── test_redfish_restart_recovery.py       # Service and container restart recovery
└── test_redfish_certificates.py           # Certificate staging, rotation, fail-closed and client authentication
```

# Supported Topology

The tests run on the `bmc` topology, where the testbed DUT is the BMC itself and the switch host is a separate inventory device. Each test module carries its own in-file `pytest.mark.topology("bmc")` marker (the offline test-info pipeline greps for it statically, so it is kept in the test file rather than in `conftest.py`). The `bmc_duthost` fixture skips the suite on a DUT that is not a BMC.

Tests whose prerequisites are absent skip rather than fail: no OEM Rack Manager extension, no rmc-events leak monitor, no PTF host, bmcctld not running, the switch host not settled on, or a `LEAK_CONTROL_POLICY` under which a CRITICAL alert would power the host off.

# Redfish Endpoints Under Test

| \# | Method     | Endpoint                                                                                | Priority | Description                                   |
| :- | :--------- | :-------------------------------------------------------------------------------------- | :------- | :-------------------------------------------- |
| 1  | GET        | `/redfish/v1`                                                                           | P0       | Service root — device discovery               |
| 2  | GET        | `/redfish/v1/Chassis`                                                                   | P0       | Chassis collection                            |
| 3  | GET        | `/redfish/v1/Chassis/chassis`                                                           | P0       | Chassis identity and leak detection links     |
| 4  | GET        | `/redfish/v1/Chassis/chassis/LeakDetectors[/{id}]`                                      | P1       | Canonical leak detector collection and member |
| 5  | GET        | `/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection[/LeakDetectors/{id}]`       | P1       | Leak detection resource and deprecated collection |
| 6  | GET        | `/redfish/v1/Systems`                                                                   | P0       | Systems collection                            |
| 7  | GET        | `/redfish/v1/Systems/system`                                                            | P0       | Switch host identity and power state          |
| 8  | GET        | `/redfish/v1/Systems/system/ResetActionInfo`                                            | P1       | Allowed ResetTypes                            |
| 9  | POST       | `/redfish/v1/Systems/system/Actions/ComputerSystem.Reset`                               | P0       | Switch host power control                     |
| 10 | GET        | `/redfish/v1/UpdateService/FirmwareInventory[/{bmc,bios,switch}]`                       | P1       | Firmware version collection and members       |
| 11 | GET        | `/redfish/v1/Managers/bmc`                                                              | P0       | Manager with OEM Rack Manager action links    |
| 12 | GET        | `/redfish/v1/Managers/bmc/Oem/SONiC/RackManager`                                        | P1       | OEM Rack Manager resource                     |
| 13 | POST       | `/redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert`              | P0       | Rack Manager alert submission                 |
| 14 | POST       | `/redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry`          | P0       | Rack Manager telemetry submission             |
| 15 | GET        | `/redfish/v1/EventService`                                                              | P0       | Event service capabilities and filters        |
| 16 | GET/POST   | `/redfish/v1/EventService/Subscriptions`                                                | P0       | List / create push subscriptions              |
| 17 | GET/DELETE | `/redfish/v1/EventService/Subscriptions/{id}`                                           | P0       | Read / delete a subscription                  |
| 18 | GET        | `/redfish/v1/Managers`                                                                  | P0       | Privileged resource for client authorization checks |
| 19 | GET        | `/redfish/v1/UpdateService`                                                             | P0       | Authenticated resource reached with a client certificate alone |

# BMC Data Paths Under Test

## D-Bus Objects

| D-Bus Interface                                | Object Path                                   | Purpose                                              |
| :--------------------------------------------- | :-------------------------------------------- | :--------------------------------------------------- |
| `xyz.openbmc_project.ObjectMapper`             | `/xyz/openbmc_project/object_mapper`          | Object discovery for bmcweb (GetSubTree, GetObject)  |
| `xyz.openbmc_project.Inventory.Item.Chassis`   | `/xyz/openbmc_project/inventory/system/chassis` | Chassis identity                                   |
| `xyz.openbmc_project.Inventory.Item.LeakDetector` | `/xyz/openbmc_project/sensors/leak/<sensor>` | `DetectorState` driving leak events and LeakDetector resources |
| `xyz.openbmc_project.State.Host`               | `/xyz/openbmc_project/state/host0`            | `CurrentHostState` (PowerState) and `RequestedHostTransition` (reset) |
| `com.sonic.RackManager`                        | (bridge-owned)                                | `SubmitAlert` / `SubmitTelemetry` forwarding         |

## Redis Tables

| Database  | Key                                | Written by                      | Checked for                                        |
| :-------- | :--------------------------------- | :------------------------------ | :------------------------------------------------- |
| CONFIG_DB | `DEVICE_METADATA\|localhost`       | platform                        | Chassis identity source                            |
| CONFIG_DB | `FEATURE\|redfish`                 | suite                           | Redfish feature enabled for the session            |
| STATE_DB  | `HOST_STATE\|switch-host`          | bmcctld                         | `device_power_state`, `device_status` vs PowerState |
| STATE_DB  | `CHASSIS_MODULE_TABLE\|SWITCH-HOST`| bmcctld                         | `oper_status` agrees with `HOST_STATE`             |
| STATE_DB  | `RACK_MANAGER_COMMAND\|CMD_*`      | sonic-dbus-bridge, bmcctld      | One row per reset: `command`, `status`, `result`   |
| STATE_DB  | `RACK_MANAGER_ALERT\|<sensor>`     | sonic-dbus-bridge               | Alert records; CRITICAL gates bmcctld POWER_ON     |
| STATE_DB  | `RACK_MANAGER_DATA\|<sensor>`      | sonic-dbus-bridge               | Telemetry records                                  |
| STATE_DB  | `LIQUID_COOLING_INFO\|<sensor>`    | thermalctld (seeded by suite)   | Leak sensor state mirrored to D-Bus                |
| STATE_DB  | `LEAK_CONTROL_POLICY`              | platform                        | Whether a CRITICAL alert is enforced and what it does |
| CONFIG_DB | `REDFISH\|certs`                   | suite (`bmc_tls_certs`)         | Delivery paths (`server_crt`, `server_key`, `ca_crt`) and trusted common names (`client_crt_cname`) |
| CONFIG_DB | `REDFISH\|config`                  | suite (port cases)              | Listening `port` |
| STATE_DB  | `REDFISH_CERT_STATUS\|global`      | `stage-credentials.sh` watcher  | `in_sync`, `mtls_enforced`, `served_serial`, `last_error`, `last_update` |

# Test Cases

## Pre-Test Preparation

Performed by session fixtures before the first test:

- Verify the DUT is a BMC (`bmc_duthost`); skip the suite otherwise
- Enable the `redfish` feature if the image ships it disabled and wait for the container (`redfish_feature_enabled`)
- Verify the BMC clock is not behind the certificate `NotBefore` time (`bmc_clock_in_sync`)
- Generate CA, server and client certificates, deliver them through `REDFISH|certs` and wait for STATE_DB to report them staged (`bmc_tls_certs`, see Section 12)
- Build the mTLS `redfish_client` used by every test

Priorities are assigned in this plan; the test code carries no priority markers. Parametrized tests list their case count in brackets.

---

## Section 1: Service Root Discovery

Module: `test_redfish_service_root.py` — `GET /redfish/v1`

| \# | Test Case                    | Priority | Verifies                                                                    |
| :- | :--------------------------- | :------- | :-------------------------------------------------------------------------- |
| 1  | `test_service_root_accessible` | P0     | HTTP 200 with `Content-Type: application/json`                              |
| 2  | `test_service_root_fields`   | P0       | DMTF-required fields (`@odata.id`, `RedfishVersion`, `UUID`, `Product`) and the Chassis/Systems navigation links |

---

## Section 2: Chassis Inventory and Leak Detection

Module: `test_redfish_chassis.py` — `GET /redfish/v1/Chassis`, `/Chassis/chassis`, `/Chassis/chassis/LeakDetectors`, `/Chassis/chassis/ThermalSubsystem/LeakDetection`

The single Chassis is the switch, built from the chassis object sonic-dbus-bridge exports. Leak detectors hang off it at the DMTF canonical `Chassis/<id>/LeakDetectors` collection and at the deprecated `ThermalSubsystem/LeakDetection/LeakDetectors` collection that leak events name in `OriginOfCondition`. These tests work with whatever detectors the platform exposes.

| \# | Test Case                                           | Priority | Verifies                                                                                   |
| :- | :-------------------------------------------------- | :------- | :----------------------------------------------------------------------------------------- |
| 3  | `test_chassis_collection_lists_chassis`             | P0       | Collection lists `/redfish/v1/Chassis/chassis`                                             |
| 4  | `test_chassis_identity_matches_config_db`           | P0       | `SerialNumber`, `Manufacturer`, `Model`, `PartNumber` are non-empty and equal the CONFIG_DB `DEVICE_METADATA` values where set |
| 5  | `test_chassis_links_leak_detection`                 | P1       | `Chassis.LeakDetectors` and `ThermalSubsystem` link into the leak detection tree          |
| 6  | `test_leak_detection_resource`                      | P1       | `LeakDetection` identifies itself, links the `LeakDetectors` collection, Status Enabled/OK |
| 7  | `test_leak_detector_collections_serve_same_detectors` | P1     | Canonical and deprecated collections list the same detectors, each under its own URI form |
| 8  | `test_leak_detection_unknown_ids_rejected` [5]      | P1       | Unknown chassis or detector id answers 404 `ResourceNotFound` naming the segment and id, on both URI forms |

---

## Section 3: Computer System

Module: `test_redfish_computer_system.py` — `GET /redfish/v1/Systems`, `/Systems/system`, `/Systems/system/ResetActionInfo`

The ComputerSystem is the switch host, built from the `State.Host` object the bridge mirrors from bmcctld's `HOST_STATE|switch-host` row. Nothing here changes the switch host's power state.

| \# | Test Case                                                  | Priority | Verifies                                                                                      |
| :- | :--------------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 9  | `test_systems_collection_lists_system`                     | P0       | Collection lists `/redfish/v1/Systems/system`                                                 |
| 10 | `test_system_advertises_reset_action`                      | P0       | 200 without optional OpenBMC providers; identity, `PowerState`, reset action target and `ResetActionInfo` link |
| 11 | `test_system_power_state_follows_host_state`               | P0       | `PowerState` reads `On`/`Off`/`PoweringOn`/`PoweringOff` consistently with `HOST_STATE\|switch-host` |
| 12 | `test_reset_action_info_advertises_supported_reset_types`  | P1       | `AllowableValues` is exactly `On`, `ForceOff`, `GracefulShutdown`, `PowerCycle`               |
| 13 | `test_reset_rejects_unsupported_reset_types` [4]           | P1       | `ForceOn`, `ForceRestart`, `GracefulRestart`, `Nmi` answer 400 `ActionParameterNotSupported`, create no `RACK_MANAGER_COMMAND` row and leave `HOST_STATE` unchanged |

---

## Section 4: Firmware Inventory

Module: `test_redfish_firmware_inventory.py` — `GET /redfish/v1/UpdateService/FirmwareInventory[/{id}]`

| \# | Test Case                            | Priority | Verifies                                                                              |
| :- | :----------------------------------- | :------- | :------------------------------------------------------------------------------------ |
| 14 | `test_firmware_inventory_collection` | P1       | 200 with at least one member and the expected components                             |
| 15 | `test_firmware_bmc`                  | P1       | `bmc` entry has a real build `Version` and `RelatedItem` to `/redfish/v1/Managers/bmc` |
| 16 | `test_firmware_bios`                 | P1       | `bios` entry has the SoftwareInventory shape (`Version` is `N/A` in this build)       |
| 17 | `test_firmware_switch`               | P1       | `switch` entry links to `/redfish/v1/Systems/system/Bios` via `RelatedItem`           |

---

## Section 5: Computer System Reset

Module: `test_redfish_computer_reset.py` — `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset`

**These tests change the switch host's power state.** The CPU reset state is read through the SWITCH-HOST module's hardware reset pin, independent of Redfish, and each test restores the CPU to running afterwards.

| \# | Test Case                        | Priority | Verifies                                                                                       |
| :- | :------------------------------- | :------- | :--------------------------------------------------------------------------------------------- |
| 18 | `test_reset_on_when_already_on`  | P0       | `On` with the CPU running is accepted and leaves it running (no-op)                            |
| 19 | `test_reset_on_when_in_reset`    | P0       | `On` brings a CPU held in reset out of reset                                                   |
| 20 | `test_reset_graceful_shutdown`   | P0       | `GracefulShutdown` is accepted and holds the CPU in reset                                      |
| 21 | `test_reset_force_off`           | P0       | `ForceOff` is accepted, becomes one `RACK_MANAGER_COMMAND` row with `command=POWER_OFF` and holds the CPU in reset |
| 22 | `test_reset_power_cycle`         | P0       | `PowerCycle` is proven by the switch host's boot id changing                                   |
| 23 | `test_reset_invalid_type`        | P1       | A `ResetType` outside the Redfish enum answers 400 `ActionParameterUnknown`                    |

---

## Section 6: Rack Manager Alert

Module: `test_redfish_rack_manager_alert.py` — `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert`

bmcweb validates auth, manager id, the 64 KiB body cap, JSON and the `redfish*` envelope, then forwards to the bridge, which writes `RACK_MANAGER_ALERT|<sensor>`. bmcctld consumes this table: a CRITICAL entry blocks POWER_ON, so CRITICAL is only injected when `LEAK_CONTROL_POLICY` cannot power the host off, and the table is restored after every test.

| \# | Test Case                                        | Priority | Verifies                                                                                            |
| :- | :----------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------------- |
| 24 | `test_submit_alert_persists_to_state_db`         | P0       | Flat payload answers 204 with an empty body; each sensor row carries exactly the schema fields (severity/leak + timestamp) |
| 25 | `test_submit_alert_wrapped_form_inherits_severity` | P1     | `ShutdownAlert` wrapped form yields the same records; leaves inherit the wrapper severity           |
| 26 | `test_submit_alert_clear_overwrites_critical`    | P0       | A later Normal alert overwrites the Critical on the same keys with `NORMAL` and a later timestamp   |
| 27 | `test_submit_alert_minor_only`                   | P1       | A single Minor measurement writes only that sensor's record                                         |
| 28 | `test_submit_alert_rejects_bad_requests` [6]     | P1       | Empty body 400 `MalformedJSON`; missing or wrong-case envelope 400 `PropertyMissing`; unknown manager 404; body over 64 KiB 400 `PayloadTooLarge`; GET 405; nothing written |

---

## Section 7: Rack Manager Telemetry

Module: `test_redfish_rack_manager_telemetry.py` — `GET /redfish/v1/Managers/bmc`, `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry`

Telemetry is persisted to `RACK_MANAGER_DATA|<sensor>` and consumed by nothing on the BMC, so STATE_DB is the only observable boundary. These tests never drive power actions.

| \# | Test Case                                        | Priority | Verifies                                                                                            |
| :- | :----------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------------- |
| 29 | `test_manager_advertises_telemetry_action`       | P0       | `Managers/bmc` embeds `Oem.SONiC.RackManager` with both action targets; the standalone resource has the SonicManager type |
| 30 | `test_submit_telemetry_persists_to_state_db`     | P0       | Reference payload answers 204; each sensor row carries exactly the schema fields, units, severity and ISO-8601 timestamp |
| 31 | `test_submit_telemetry_updates_existing_record`  | P1       | A later all-Normal sample overwrites every record with the new value and a later timestamp          |
| 32 | `test_submit_telemetry_payload_shapes` [7]       | P1       | `*Alarms*` envelope matching, severity inheritance, default and case normalisation, unknown fields dropped, multiple envelopes merged |
| 33 | `test_submit_telemetry_rejects_bad_requests` [5] | P1       | Empty body 400 `MalformedJSON`; missing envelope 400 `PropertyMissing`; unknown manager 404; body over 64 KiB 400 `PayloadTooLarge`; GET 405; table stays empty |
| 34 | `test_submit_telemetry_bridge_unavailable`       | P1       | With sonic-dbus-bridge stopped the POST gets no 2xx (503, or 500/401) and persists nothing; the next POST after restart succeeds |

---

## Section 8: Event Service and Subscriptions

Module: `test_redfish_event_subscription.py` — `GET /redfish/v1/EventService`, `GET/POST/DELETE /redfish/v1/EventService/Subscriptions[/{id}]`

The test plays the rack manager: it subscribes with the PTF webhook URL, raises events on the BMC and checks what the webhook received. Leak events come from a synthetic `LIQUID_COOLING_INFO|<sensor>` row the test flips (standing in for thermalctld), mirrored by the bridge as a `LeakDetector` and turned into `Environmental.1.1.0.LeakDetected*` events by bmcweb. Switch-host power events come from real `ComputerSystem.Reset` transitions and bmcctld's `HOST_STATE` row, turned into `ResourceEvent.1.3.0.ResourcePower*` events. `SubmitTestEvent`, SSE, PATCH and retry policies are out of scope.

| \# | Test Case                                            | Priority | Verifies                                                                                            |
| :- | :--------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------------- |
| 35 | `test_event_service_advertised`                      | P0       | `ServiceEnabled`, the `Subscriptions` link and at least the `Base` and `OpenBMC` registry prefixes  |
| 36 | `test_event_service_advertises_rack_manager_filters` | P0       | `Environmental` and `ResourceEvent` registry prefixes and `LeakDetector` and `ComputerSystem` resource types are advertised |
| 37 | `test_subscription_lifecycle`                        | P0       | POST 201 with `Location`; GET echoes `Destination`, `Context` and bmcweb defaults; listed; DELETE then GET 404 |
| 38 | `test_subscription_rejects_bad_requests` [7]         | P1       | Missing, malformed or userinfo `Destination`, unsupported `Protocol`, unknown `RegistryPrefix`, `MessageIds` with prefixes, unknown retry policy answer a Redfish error and create nothing |
| 39 | `test_leak_event_delivered`                          | P0       | A Critical leak delivers one `LeakDetectedCritical` event with `Severity`, the sensor in `MessageArgs` and `OriginOfCondition` on its LeakDetector; clearing delivers `LeakDetectedNormal` |
| 40 | `test_leak_warning_event_delivered`                  | P1       | A Minor leak delivers `LeakDetectedWarning` with `Severity: Warning`                                |
| 41 | `test_resource_type_filter`                          | P1       | Unfiltered and `ResourceTypes=[LeakDetector]` subscriptions receive the leak event; `[Task]` and `RegistryPrefixes=[Base]` do not |
| 42 | `test_subscription_persists_across_bmcweb_restart`   | P1       | After `supervisorctl restart bmcweb` the subscription is still listed and receives a new leak event |
| 43 | `test_leak_detector_resource_tracks_state`           | P1       | The LeakDetector named by `OriginOfCondition` reports `DetectorState` and `Status.Health` OK, Critical, OK with the STATE_DB row |
| 44 | `test_leak_detector_resource_shape`                  | P1       | The detector is served in full under both its canonical and deprecated URI                          |
| 45 | `test_host_power_events_delivered`                   | P0       | Real `GracefulShutdown` then `On` deliver `ResourcePoweringOff`, `ResourcePoweredOff`, `ResourcePoweringOn`, `ResourcePoweredOn` in order with increasing Ids **(changes host power)** |
| 46 | `test_host_power_off_event_drives_power_on_request`  | P0       | After a real `ForceOff` the subscriber receives `ResourcePoweredOff`, answers `ResetType=On`, one `POWER_ON` row completes DONE/SUCCESS, the host settles on and `ResourcePoweredOn` arrives **(changes host power)** |

---

## Section 9: Redfish to pmon (bmcctld) Interaction

Module: `test_redfish_pmon_interaction.py` — `POST ComputerSystem.Reset`, `SONiC.SubmitAlert`, STATE_DB

bmcweb never touches the switch host itself: a reset becomes a `RACK_MANAGER_COMMAND` row that bmcctld drives from PENDING to DONE or FAILED and reflects in `HOST_STATE`. Every reset here is `On` against a host already on, so the host is never power cycled.

| \# | Test Case                                   | Priority | Verifies                                                                                                     |
| :- | :------------------------------------------ | :------- | :----------------------------------------------------------------------------------------------------------- |
| 47 | `test_reset_command_consumed_by_bmcctld`    | P0       | `On` writes exactly one row with `command=POWER_ON` that bmcctld drives to `DONE`/`SUCCESS` and retains; `HOST_STATE` unchanged |
| 48 | `test_power_state_consistent_across_layers` | P0       | `HOST_STATE` `device_power_state` and `device_status` and `CHASSIS_MODULE_TABLE` `oper_status` agree and are settled |
| 49 | `test_critical_alert_blocks_power_on_command` | P1     | A CRITICAL LeakDetected alert makes bmcctld fail `POWER_ON` with `result=CRITICAL_LEAK_PRESENT`; after a Normal alert the next `On` is DONE/SUCCESS |
| 50 | `test_bmcctld_restart_resyncs_host_state`   | P1       | `supervisorctl restart bmcctld` yields a new pid, refreshed `HOST_STATE`, no command row of its own, and a later `On` still DONE/SUCCESS |

---

## Section 10: Concurrency

Module: `test_redfish_concurrency.py` — inventory GETs, `ComputerSystem.Reset`, `EventService/Subscriptions`

| \# | Test Case                                       | Priority | Verifies                                                                                                 |
| :- | :---------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------- |
| 51 | `test_reset_concurrent_with_inventory_poll`     | P1       | `On` requests during parallel inventory polls: every poll 200 with unchanged members, every reset becomes a command row, `HOST_STATE` unchanged, nothing restarts |
| 52 | `test_duplicate_subscription_create_and_delete` | P1       | The same body POSTed concurrently answers 201 with distinct ids; concurrent DELETEs answer 2xx or 404, never 5xx; collection ends empty |
| 53 | `test_interleaved_create_delete_churn`          | P1       | Callers repeatedly create, read and delete their own subscription at once; no step fails and the collection ends empty |

---

## Section 11: Restart Recovery

Module: `test_redfish_restart_recovery.py` — `systemctl restart sonic-dbus-bridge`, `systemctl restart redfish`

bmcweb owns no inventory; everything is assembled per request from the bridge's D-Bus objects and ObjectMapper. Each test snapshots the Redfish view and the ObjectMapper view, restarts, and checks both come back identical.

| \# | Test Case                                          | Priority | Verifies                                                                                                   |
| :- | :------------------------------------------------- | :------- | :--------------------------------------------------------------------------------------------------------- |
| 54 | `test_bridge_restart_rediscovered_by_running_bmcweb` | P1     | After a bridge restart bmcweb (same supervisord pid) serves the same inventory and ObjectMapper tree        |
| 55 | `test_redfish_container_restart`                   | P1       | After `systemctl restart redfish` mTLS is still enforced, inventory is identical and a pre-existing subscription persists |

---

## Section 12: Certificates and Client Authentication (mTLS)

Module: `test_redfish_certificates.py`. It covers certificate staging, rotation, fail-closed behaviour, client certificate authentication and common name validation.

The design is in the [Redfish Certificate Provisioning HLD](https://github.com/sonic-net/SONiC/pull/2461). Certificates are not copied into the container: a provisioning agent delivers them on the host at the paths named in CONFIG_DB `REDFISH|certs` (`server_crt`, `server_key`, `ca_crt`), and `stage-credentials.sh` in the `redfish` container stages them into what bmcweb reads (`server.pem` and the CA truststore), bounces bmcweb, and publishes its state to STATE_DB `REDFISH_CERT_STATUS|global`. Once provisioned, the device fails closed rather than fall back to a self-signed certificate. bmcweb runs with `TLS` on and `TLSStrict` off: every client is asked for a certificate, the service root answers without one, and every other resource needs a certificate issued by the staged CA whose common name is in `client_crt_cname`. There are no local users or passwords.

The `bmc_tls_certs` fixture plays the provisioning agent. It records the `REDFISH|config` and `REDFISH|certs` fields and sets aside the device files it will overwrite (the delivered certificates, the provisioned marker and the staging stamp), generates a CA, server and client chain in the sonic-mgmt container, writes the delivery paths and `client_crt_cname`, delivers the files to `/etc/sonic/credentials`, and waits for `in_sync`. Its teardown restores the recorded fields and files and recreates the container, so the device returns to the state it was in. Cases that unprovision, corrupt or rotate certificates return the device to the provisioned state after themselves.

### Provisioning and status

| \# | Test Case                                             | Priority | Verifies                                                                                      |
| :- | :---------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 56 | `test_delivered_certs_are_staged`                     | P0       | The delivered certificate, key and CA are staged into `server.pem` and the CA truststore bmcweb reads |
| 57 | `test_provisioned_state_is_recorded`                  | P0       | The provisioned marker and the staging stamp are written on the host mount `/var/lib/bmcweb`  |
| 58 | `test_status_is_published`                            | P0       | STATE_DB reports `in_sync` and `mtls_enforced` `true`, and `served_serial` names the served certificate |
| 59 | `test_rotation_is_picked_up`                          | P0       | A rotated server certificate is staged and served with no operator action                     |
| 60 | `test_mismatched_pair_is_not_staged`                  | P0       | A certificate delivered without its matching key is not staged: served serial and bmcweb unchanged, `in_sync` `false`; the pair is staged once the key arrives |
| 61 | `test_every_failure_reports_a_reason`                 | P1       | Missing files, an unparseable certificate and a mismatched pair each report `in_sync` `false` with a non-empty `last_error` |
| 62 | `test_last_update_shows_whether_the_watcher_is_alive` | P1       | `last_update` advances while the watcher runs and stops when it stops                         |

### Client certificate authentication

| \# | Test Case                                            | Priority | Verifies                                                                                      |
| :- | :--------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 63 | `test_valid_cert_accepted`                           | P0       | A client certificate issued by the provisioned CA is accepted                                 |
| 64 | `test_cert_auth_on_authenticated_endpoint`           | P0       | `GET /redfish/v1/UpdateService` with only the client certificate answers 200; no user or password is involved |
| 65 | `test_service_root_readable_without_a_certificate`   | P0       | `GET /redfish/v1` without a client certificate answers 200, as DSP0266 13.3.2 requires        |
| 66 | `test_privileged_path_refused_without_a_certificate` | P0       | `GET /redfish/v1/Managers` without a client certificate answers 401 or 403                    |
| 67 | `test_wrong_ca_rejected`                             | P1       | A certificate from an untrusted CA answers 401 or 403 on `FirmwareInventory`, while the trusted certificate is still accepted |

### Common name validation

| \# | Test Case                                        | Priority | Verifies                                                                                      |
| :- | :----------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 68 | `test_unset_list_refuses_every_common_name`      | P0       | With `client_crt_cname` unset, a certificate from the staged CA answers 403: an unset list fails closed |
| 69 | `test_exact_match_is_enforced`                   | P0       | A listed name is admitted and any other name answers 403                                      |
| 70 | `test_wildcard_matches_subdomains_only`          | P1       | `*.example.com` admits names under the domain, not `example.com` itself                       |
| 71 | `test_list_entries_are_independent`              | P1       | Any entry in a comma separated list admits a client                                           |
| 72 | `test_service_root_stays_reachable_when_refused` | P1       | A refused client still reads the service root (200), and nothing that needs a privilege (403) |

### Restart, fail-closed and container recreate

| \# | Test Case                                                | Priority | Verifies                                                                                      |
| :- | :------------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 73 | `test_bmcweb_restart_keeps_serving`                      | P1       | Restarting bmcweb alone reuses the staged files and serves the same certificate; the oneshot does not re-run |
| 74 | `test_restart_with_source_removed`                       | P1       | bmcweb restarts on the staged copy with the delivered files removed                           |
| 75 | `test_guard_self_heals_damaged_staged_cert`              | P1       | With the watcher stopped, a damaged staged certificate is re-staged from the source by the guard at the next bmcweb start |
| 76 | `test_fails_closed_with_nothing_valid`                   | P0       | A provisioned device with no valid certificate anywhere does not start bmcweb, rather than serve a self-signed certificate |
| 77 | `test_recovers_when_certificates_return`                 | P0       | Once certificates are delivered again, the watcher stages them and starts bmcweb with no operator action |
| 78 | `test_recreate_without_certificates_fails_closed`        | P1       | Recreating the container with no delivered certificates fails closed: the marker remembers the device was provisioned |
| 79 | `test_recreate_with_certificates_comes_back_provisioned` | P1       | Recreating the container with certificates present comes back serving them: not self-signed, marker kept, `in_sync` and `mtls_enforced` `true` |

### Bad input and watcher behaviour

| \# | Test Case                                           | Priority | Verifies                                                                                      |
| :- | :-------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 80 | `test_corrupt_server_certificate_is_not_staged`     | P1       | A delivered server certificate that does not parse is not staged                              |
| 81 | `test_corrupt_ca_does_not_cause_flapping`           | P1       | A corrupt CA is refused before staging, so bmcweb is never bounced                            |
| 82 | `test_deleting_the_source_keeps_the_service_running`| P1       | Deleting the delivered files leaves the service on its staged certificate: deletion is not revocation |
| 83 | `test_mismatched_first_install_stays_in_bootstrap`  | P1       | On a device never provisioned, a mismatched pair stages nothing and writes no marker; the matching pair then provisions it |
| 84 | `test_change_made_while_down_is_reconciled`         | P1       | A rotation delivered while the watcher is stopped is applied when it starts                   |
| 85 | `test_unchanged_content_does_not_bounce_bmcweb`     | P1       | Re-delivering identical bytes causes no restage and no bmcweb restart                         |

### Bootstrap, configuration and CA rotation

| \# | Test Case                                                 | Priority | Verifies                                                                                      |
| :- | :-------------------------------------------------------- | :------- | :-------------------------------------------------------------------------------------------- |
| 86 | `test_unprovisioned_device_serves_self_signed`            | P0       | Before any delivery the device serves a self-signed certificate with no marker; the service root answers 200, `/redfish/v1/Managers` 401, and `in_sync` and `mtls_enforced` are `false` |
| 87 | `test_certificates_are_read_from_the_configured_paths`    | P1       | Delivery paths come from `REDFISH|certs`, including a server pair and a CA in different directories |
| 88 | `test_nothing_is_staged_without_configuration`            | P1       | With no `REDFISH|certs` entry, delivered files are not picked up and the device stays on its self-signed certificate |
| 89 | `test_default_port_is_443`                                | P1       | With no port configured, the API listens on 443                                               |
| 90 | `test_configured_port_is_applied_by_a_service_restart`    | P1       | A `REDFISH|config` `port` takes effect after a service restart, and the same provisioned certificate is served on it |
| 91 | `test_invalid_port_falls_back_to_the_default`             | P1       | An unusable port value does not stop the container from starting; the API listens on 443      |
| 92 | `test_ca_rotation_replaces_the_truststore`                | P0       | After the CA is rotated, client certificates from the old CA are refused and those from the new CA are accepted: CA rotation is how access is revoked |

---

# Test Execution Summary

Counts are test functions; parametrized cases expand to the collected total in the last column.

| Section                              | \# Tests | Collected | Priority | Status |
| :----------------------------------- | :------- | :-------- | :------- | :----- |
| Service Root Discovery               | 2        | 2         | P0       | NA     |
| Chassis Inventory and Leak Detection | 6        | 10        | P0/P1    | NA     |
| Computer System                      | 5        | 8         | P0/P1    | NA     |
| Firmware Inventory                   | 4        | 4         | P1       | NA     |
| Computer System Reset                | 6        | 6         | P0/P1    | NA     |
| Rack Manager Alert                   | 5        | 10        | P0/P1    | NA     |
| Rack Manager Telemetry               | 6        | 16        | P0/P1    | NA     |
| Event Service and Subscriptions      | 12       | 18        | P0/P1    | NA     |
| Redfish to pmon Interaction          | 4        | 4         | P0/P1    | NA     |
| Concurrency                          | 3        | 3         | P1       | NA     |
| Restart Recovery                     | 2        | 2         | P1       | NA     |
| Certificates and Client Authentication | 37     | 37        | P0/P1    | NA     |
| **Total**                            | **92**   | **120**   |          |        |

# Open Items

1. Standalone D-Bus health and graceful degradation tests from revision 2 are not implemented. Their intent is partly covered by the restart recovery tests (ObjectMapper re-registration) and by the telemetry bridge-unavailable test (bridge stopped).
2. Standalone error handling tests (404 on an unknown resource, 405 on an unsupported method) are covered inside the leak detection unknown-id cases and the alert/telemetry bad-request cases rather than as separate tests.
3. `SubmitTestEvent`, SSE, subscription PATCH and delivery retry policies of the EventService are not exercised.
4. The `bios` firmware entry reports `Version: N/A` in the current BMC build, so only its schema shape is asserted.
