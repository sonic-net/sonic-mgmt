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

Priorities are assigned in this plan; the test code carries no priority markers. Parametrized tests give their case count next to the test ID. The steps of each test are taken from the test code.

---

## Section 1: Service Root Discovery

Module: `test_redfish_service_root.py` — `GET /redfish/v1`

### Test Case \#1: Service root is accessible

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_service_root_accessible` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Send `GET /redfish/v1` with the mTLS client.
2. Validate the status is `200` and `Content-Type` contains `application/json`.

### Test Case \#2: Service root contains required fields

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_service_root_fields` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Send `GET /redfish/v1` with the mTLS client and validate the status is `200`.
2. Validate the body has `@odata.type`, `@odata.id`, `RedfishVersion`, `UUID` and `Links`, with `@odata.id` equal to `/redfish/v1`, `@odata.type` containing `ServiceRoot`, and `RedfishVersion` and `UUID` non-empty strings.
3. Read `mac` from CONFIG_DB `DEVICE_METADATA|localhost` on the BMC and validate `Product` equals `SONiCBMC-<mac>` (lowercased), or `SONiCBMC` when no MAC is set.
4. Validate `UpdateService.@odata.id` is `/redfish/v1/UpdateService`, `Systems.@odata.id` is `/redfish/v1/Systems`, and `Links` contains `Sessions`.

---

## Section 2: Chassis Inventory and Leak Detection

Module: `test_redfish_chassis.py` — `GET /redfish/v1/Chassis`, `/Chassis/chassis`, `/Chassis/chassis/LeakDetectors`, `/Chassis/chassis/ThermalSubsystem/LeakDetection`

The single Chassis is the switch, built from the chassis object sonic-dbus-bridge exports. Leak detectors hang off it at the DMTF canonical `Chassis/<id>/LeakDetectors` collection and at the deprecated `ThermalSubsystem/LeakDetection/LeakDetectors` collection that leak events name in `OriginOfCondition`. These tests work with whatever detectors the platform exposes.

### Test Case \#3: The Chassis collection lists the switch as `/redfish/v1/Chassis/chassis`

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_chassis_collection_lists_chassis` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Chassis` |

**Steps:**

1. Send `GET /redfish/v1/Chassis` and validate the status is `200`.
2. Validate `@odata.id` is `/redfish/v1/Chassis`, `@odata.type` contains `ChassisCollection`, and `Members@odata.count` is at least 1.
3. Validate `Members` includes `/redfish/v1/Chassis/chassis`.

### Test Case \#4: Chassis identity fields are populated and agree with CONFIG_DB

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_chassis_identity_matches_config_db` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis` |

**Steps:**

1. Send `GET /redfish/v1/Chassis/chassis` and validate the status is `200`.
2. Validate `@odata.id` is `/redfish/v1/Chassis/chassis`, `Id` is `chassis`, `@odata.type` contains `#Chassis.`, and `ChassisType` is a non-empty string.
3. Read CONFIG_DB `DEVICE_METADATA|localhost` on the BMC.
4. Validate `SerialNumber`, `Manufacturer`, `Model` and `PartNumber` are non-empty strings, and each equals its CONFIG_DB source when set (`serial_number`, `manufacturer`, `model` falling back to `platform`, `part_number`); a field with no CONFIG_DB source is only checked for non-empty.

### Test Case \#5: The chassis advertises both ways into its leak detectors

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_chassis_links_leak_detection` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis`<br>`GET /redfish/v1/Chassis/chassis/ThermalSubsystem` |

**Steps:**

1. Send `GET /redfish/v1/Chassis/chassis` and validate the status is `200`.
2. Validate `LeakDetectors.@odata.id` is `/redfish/v1/Chassis/chassis/LeakDetectors` and `ThermalSubsystem.@odata.id` is `/redfish/v1/Chassis/chassis/ThermalSubsystem`.
3. Send `GET /redfish/v1/Chassis/chassis/ThermalSubsystem` and validate the status is `200`.
4. Validate `LeakDetection.@odata.id` is `/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection`.

### Test Case \#6: ThermalSubsystem/LeakDetection groups the detectors and reports an aggregate Status

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_detection_resource` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection` |

**Steps:**

1. Send `GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection` and validate the status is `200`.
2. Validate `@odata.id` is the requested path, `@odata.type` contains `#LeakDetection.`, `Id` is `LeakDetection` and `Name` is `Leak Detection`.
3. Validate `LeakDetectors.@odata.id` is `/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors`.
4. Validate `Status.State` is `Enabled` and `Status.Health` is `OK`.

### Test Case \#7: Both LeakDetectors collection forms list the same detectors

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_detector_collections_serve_same_detectors` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis/LeakDetectors`<br>`GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors` |

**Steps:**

1. Send `GET /redfish/v1/Chassis/chassis/LeakDetectors` (canonical) and `GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors` (deprecated), validating `200` for each.
2. For each, validate `@odata.id` is the requested path, `@odata.type` contains `LeakDetectorCollection` and `Name` is `Leak Detector Collection`.
3. For each, validate `Members@odata.count` equals the number of `Members` and every member `@odata.id` lives under the requested collection path.
4. Validate both collections list the same sorted set of detector ids (last URI segment).

### Test Case \#8: An unknown chassis or detector id on the leak detection tree answers 404 ResourceNotFound

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_detection_unknown_ids_rejected` (5 cases) |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis/{id}/.../LeakDetectors/{id} (unknown ids)` |

**Steps:**

1. Send `GET` on each parametrized path: `/redfish/v1/Chassis/nochassis/LeakDetectors`, `/redfish/v1/Chassis/nochassis/ThermalSubsystem/LeakDetection/LeakDetectors`, `/redfish/v1/Chassis/nochassis/ThermalSubsystem/LeakDetection`, `/redfish/v1/Chassis/chassis/LeakDetectors/DoesNotExist`, `/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/DoesNotExist`.
2. Validate the status is `404` with an `@Message.ExtendedInfo` entry whose `MessageId` ends in `.ResourceNotFound`.
3. Validate `MessageArgs` is `["Chassis", "nochassis"]` for the three unknown chassis cases and `["LeakDetector", "DoesNotExist"]` for the two unknown detector cases.

---

## Section 3: Computer System

Module: `test_redfish_computer_system.py` — `GET /redfish/v1/Systems`, `/Systems/system`, `/Systems/system/ResetActionInfo`

The ComputerSystem is the switch host, built from the `State.Host` object the bridge mirrors from bmcctld's `HOST_STATE|switch-host` row. Nothing here changes the switch host's power state.

### Test Case \#9: The Systems collection lists the switch host as `/redfish/v1/Systems/system`

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_systems_collection_lists_system` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Systems` |

**Steps:**

1. Send `GET /redfish/v1/Systems` and validate the status is `200`.
2. Validate `@odata.id` is `/redfish/v1/Systems`, `@odata.type` contains `ComputerSystemCollection`, and `Members@odata.count` is at least 1.
3. Validate `Members` includes `/redfish/v1/Systems/system`.

### Test Case \#10: The ComputerSystem is served with its identity, a PowerState and the reset action

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_system_advertises_reset_action` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Systems/system` |

**Steps:**

1. Send `GET /redfish/v1/Systems/system` and validate the status is `200`.
2. Validate `@odata.id` is `/redfish/v1/Systems/system`, `Id` is `system` and `@odata.type` contains `#ComputerSystem.`.
3. Validate `PowerState` is one of `On`, `Off`, `PoweringOn`, `PoweringOff`.
4. Validate `Actions.#ComputerSystem.Reset.target` is `/redfish/v1/Systems/system/Actions/ComputerSystem.Reset` and its `@Redfish.ActionInfo` is `/redfish/v1/Systems/system/ResetActionInfo`.

### Test Case \#11: PowerState agrees with bmcctld's `HOST_STATE|switch-host` row

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_system_power_state_follows_host_state` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Systems/system` |

**Steps:**

1. Skip unless STATE_DB `HOST_STATE|switch-host` exists (bmcctld running).
2. Poll for up to 30s (every 2s): read `HOST_STATE|switch-host` and `GET /redfish/v1/Systems/system` until `PowerState` matches the value derived from the row.
3. Derive the expected value as `PoweringOn` for `POWERING_ON`/`POWER_CYCLING`, `PoweringOff` for `POWERING_OFF`/`GRACEFUL_SHUTTING_DOWN`, otherwise `On`/`Off` from `device_status` `ONLINE`/`OFFLINE` (falling back to the settled `device_power_state`).
4. Validate the row resolves to a PowerState and the last Redfish `PowerState` equals it.

### Test Case \#12: ResetActionInfo offers exactly the ResetTypes the reset action accepts

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_action_info_advertises_supported_reset_types` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Systems/system/ResetActionInfo` |

**Steps:**

1. Send `GET /redfish/v1/Systems/system/ResetActionInfo` and validate the status is `200`.
2. Validate `Parameters` holds exactly one entry with `Name` `ResetType`.
3. Validate `@odata.id` is `/redfish/v1/Systems/system/ResetActionInfo` and `Id` is `ResetActionInfo`.
4. Validate `AllowableValues` is exactly `On`, `ForceOff`, `GracefulShutdown`, `PowerCycle` with no extras or duplicates.

### Test Case \#13: A standard ResetType the switch host cannot perform is refused and reaches nobody

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_rejects_unsupported_reset_types` (4 cases) |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Run for each of `ForceOn`, `ForceRestart`, `GracefulRestart`, `Nmi`; skip the case if `ResetActionInfo` `AllowableValues` offers it.
2. Record the STATE_DB `RACK_MANAGER_COMMAND|*` keys and the `HOST_STATE|switch-host` row.
3. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "<case>"}`.
4. Validate the status is `400` with `MessageId` ending in `.ActionParameterNotSupported` and `MessageArgs` `["ResetType", "Reset"]`.
5. Wait 5s, then validate no new `RACK_MANAGER_COMMAND|*` key appeared and `HOST_STATE|switch-host` `device_power_state` is unchanged.

---

## Section 4: Firmware Inventory

Module: `test_redfish_firmware_inventory.py` — `GET /redfish/v1/UpdateService/FirmwareInventory[/{id}]`

### Test Case \#14: Firmware inventory collection

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_firmware_inventory_collection` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService/FirmwareInventory` and validate the status is `200`.
2. Validate `Members@odata.count` is at least 1.
3. Validate the member ids (last segment of each `@odata.id`) include `bmc`, `bios` and `switch`.

### Test Case \#15: BMC firmware inventory entry

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_firmware_bmc` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory/bmc` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService/FirmwareInventory/bmc` and validate the status is `200`.
2. Validate `@odata.id` is the requested path, `Id` is `bmc`, `@odata.type` contains `SoftwareInventory`, `Name` is `Software Inventory` and `Description` is `BMC image`.
3. Validate `Status.State` is `Enabled`, `Status.Health` and `Status.HealthRollup` are `OK`, and `Updateable` is a boolean.
4. Validate `Version` is a non-empty string other than `N/A`.
5. Validate `RelatedItem` includes `/redfish/v1/Managers/bmc`.

### Test Case \#16: BIOS firmware inventory entry

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_firmware_bios` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory/bios` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService/FirmwareInventory/bios` and validate the status is `200`.
2. Validate `@odata.id` is the requested path, `Id` is `bios`, `@odata.type` contains `SoftwareInventory`, `Name` is `Software Inventory` and `Description` is `Other image`.
3. Validate `Status.State` is `Enabled`, `Status.Health` and `Status.HealthRollup` are `OK`, `Updateable` is a boolean, and `Version` is a non-empty string (`N/A` accepted).

### Test Case \#17: Switch host firmware inventory entry

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_firmware_switch` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory/switch` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService/FirmwareInventory/switch` and validate the status is `200`.
2. Validate `@odata.id` is the requested path, `Id` is `switch`, `@odata.type` contains `SoftwareInventory`, `Name` is `Software Inventory` and `Description` is `Host image`.
3. Validate `Status.State` is `Enabled`, `Status.Health` and `Status.HealthRollup` are `OK`, `Updateable` is a boolean, and `Version` is a non-empty string.
4. Validate `RelatedItem` includes `/redfish/v1/Systems/system/Bios`.

---

## Section 5: Computer System Reset

Module: `test_redfish_computer_reset.py` — `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset`

**These tests change the switch host's power state.** The CPU reset state is read through the SWITCH-HOST module's hardware reset pin, independent of Redfish, and each test restores the CPU to running afterwards.

### Test Case \#18: ResetType=On when the CPU is already running is a no-op

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_on_when_already_on` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Ensure the switch host CPU is running (read via the platform API `SWITCH-HOST` module oper status `Online`); if not, send `ResetType=On` and wait up to 120s.
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "On"}`.
3. Validate the status is `204` with an empty body.
4. Validate the CPU is still running immediately after.

### Test Case \#19: ResetType=On brings the CPU out of reset

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_on_when_in_reset` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Ensure the switch host CPU is held in reset (`SWITCH-HOST` oper status `Offline`); if running, send `ResetType=GracefulShutdown` and wait up to 120s.
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "On"}`.
3. Validate the status is `204` with an empty body.
4. Validate the CPU comes out of reset within 120s (polled every 5s).

### Test Case \#20: Reset with valid ResetType "GracefulShutdown"

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_graceful_shutdown` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Ensure the switch host CPU is running (send `ResetType=On` and wait up to 120s if not).
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "GracefulShutdown"}`.
3. Validate the status is `204` with an empty body.
4. Validate the CPU is held in reset within 120s (polled every 5s).
5. Restore the CPU to running with `ResetType=On` and validate it comes up within 120s.

### Test Case \#21: Reset with valid ResetType "ForceOff"

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_force_off` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Ensure the switch host CPU is running and record the STATE_DB `RACK_MANAGER_COMMAND|*` keys.
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "ForceOff"}` and validate `204` with an empty body.
3. Validate a new `RACK_MANAGER_COMMAND|*` row appears within 30s, exactly one new row exists, and its `command` field is `POWER_OFF`.
4. Validate the CPU is held in reset within 120s.
5. Restore the CPU to running with `ResetType=On` and validate it comes up within 120s.

### Test Case \#22: Reset with valid ResetType "PowerCycle"

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_power_cycle` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Ensure the switch host CPU is running, resolve the switch host over SSH (retrying up to 300s), and read its `/proc/sys/kernel/random/boot_id`.
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "PowerCycle"}`.
3. Validate the status is `204` with an empty body.
4. Validate the switch host becomes reachable again with a different `boot_id` within 600s (polled every 10s).

### Test Case \#23: Reset with a ResetType outside the Redfish enum is rejected

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_invalid_type` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "InvalidType"}`.
2. Validate the status is `400` with `MessageId` ending in `.ActionParameterUnknown` and `MessageArgs` `["Reset", "InvalidType"]`.

---

## Section 6: Rack Manager Alert

Module: `test_redfish_rack_manager_alert.py` — `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert`

bmcweb validates auth, manager id, the 64 KiB body cap, JSON and the `redfish*` envelope, then forwards to the bridge, which writes `RACK_MANAGER_ALERT|<sensor>`. bmcctld consumes this table: a CRITICAL entry blocks POWER_ON, so CRITICAL is only injected when `LEAK_CONTROL_POLICY` cannot power the host off, and the table is restored after every test.

### Test Case \#24: A flat-form alert is accepted and persisted per the platform DB schema

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_alert_persists_to_state_db` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers/bmc`<br>`POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert` |

**Steps:**

1. Resolve the `#SONiC.SubmitAlert` target from `GET /redfish/v1/Managers/bmc` (`Oem.SONiC.RackManager.Actions`), skip if absent; skip unless `LEAK_CONTROL_POLICY` has `rack_mgr_leak_policy=disabled` or `rack_mgr_critical_alert_action=syslog_only` (defaults: enabled, syslog_only); snapshot and clear all `RACK_MANAGER_ALERT|*` keys in STATE_DB.
2. Send `POST .../SONiC.SubmitAlert` with the flat form `redfish_alert_data`: `Alerts` {`InletTemperature` 18, `FlowRate` 58, `Severity` Minor}, `LiquidPressureDeviation` {`LiquidPressure` 68, `Severity` Major}, `LeakDetected` {`Severity` Critical}.
3. Validate HTTP 204 with an empty body.
4. Validate within 20s that STATE_DB has `RACK_MANAGER_ALERT|Inlet_liquid_temperature` and `|Inlet_liquid_flow_rate` with `severity=MINOR`, `|Inlet_liquid_pressure` with `severity=MAJOR`, and `|Rack_level_leak` with `leak=CRITICAL`, each holding exactly those fields plus a `timestamp` in `%Y-%m-%dT%H:%M:%S.%fZ` format.
5. Validate no other `RACK_MANAGER_ALERT|*` key was written; restore the snapshotted table on teardown.

### Test Case \#25: The ShutdownAlert wrapped form resolves to the same canonical records

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_alert_wrapped_form_inherits_severity` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert` |

**Steps:**

1. Resolve the `SubmitAlert` target, require the CRITICAL-safe policy and start from an empty `RACK_MANAGER_ALERT` table (as in #24).
2. Send `POST .../SONiC.SubmitAlert` with `redfish_alert_data.ShutdownAlert` {`Severity` Major, `FlowRateDeviation` {`FlowRate` 58}, `TempDeviation` {`InletTemperature` 17}, `LiquidPressureDeviation` {`LiquidPressure` 68}, `LeakDetected` {`Severity` Critical}}.
3. Validate HTTP 204 with an empty body.
4. Validate within 20s that temperature, flow rate and pressure records have `severity=MAJOR` (inherited from the wrapper) and `Rack_level_leak` has `leak=CRITICAL`, each with exactly those fields plus a well-formed `timestamp`, and no other `RACK_MANAGER_ALERT|*` key exists.

### Test Case \#26: A follow-up Normal alert clears an earlier Critical in place

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_alert_clear_overwrites_critical` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert` |

**Steps:**

1. Resolve the `SubmitAlert` target, require the CRITICAL-safe policy and start from an empty `RACK_MANAGER_ALERT` table.
2. Send `POST .../SONiC.SubmitAlert` with the flat payload from #24; validate HTTP 204 and the same four records (MINOR, MINOR, MAJOR, leak CRITICAL).
3. Send `POST .../SONiC.SubmitAlert` with the cleared payload: `Alerts` {`InletTemperature` 20, `FlowRate` 60, `Severity` Normal}, `LiquidPressureDeviation` {`LiquidPressure` 70, `Severity` Normal}, `LeakDetected` {`Severity` Normal}; validate HTTP 204 with an empty body.
4. Validate within 20s that every one of the four keys has a `timestamp` lexically later than after the first POST.
5. Validate the same keys now hold `severity=NORMAL` (three measurements) and `leak=NORMAL`, with exact field sets and no stray keys.

### Test Case \#27: A single Minor measurement alert writes only that sensor's record

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_alert_minor_only` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert` |

**Steps:**

1. Resolve the `SubmitAlert` target and start from an empty `RACK_MANAGER_ALERT` table (no policy gate, nothing CRITICAL is sent).
2. Send `POST .../SONiC.SubmitAlert` with `redfish_alert_data.FlowRateDeviation` {`FlowRate` 40, `Severity` Minor}.
3. Validate HTTP 204 with an empty body.
4. Validate within 20s that only `RACK_MANAGER_ALERT|Inlet_liquid_flow_rate` exists, holding exactly `severity=MINOR` and a well-formed `timestamp`.

### Test Case \#28: bmcweb rejects malformed alert requests with the right Redfish error and writes nothing

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_alert_rejects_bad_requests` (6 cases) |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert` |

**Steps:**

1. Resolve the `SubmitAlert` target and start from an empty `RACK_MANAGER_ALERT` table.
2. Send one request per case: empty body with `Content-Type: application/json` (400 `MalformedJSON`); `{"Alarms": {...}}` with no `redfish*` envelope (400 `PropertyMissing`, args `["redfish"]`, on `redfish@Message.ExtendedInfo`); `Redfish_alert_data` with wrong case (400 `PropertyMissing`, args `["redfish"]`); POST to `/Managers/notbmc/...` (404 `ResourceNotFound`, args `["Manager", "notbmc"]`); body with a 64 KiB padding string (400 `PayloadTooLarge`); `GET` on the target (405).
3. Validate the status code and, for all but the GET case, a Redfish error whose `@Message.ExtendedInfo` holds a `MessageId` ending in the expected message (and matching `MessageArgs` where given).
4. Validate after a 3s settle that no `RACK_MANAGER_ALERT|*` key exists.

---

## Section 7: Rack Manager Telemetry

Module: `test_redfish_rack_manager_telemetry.py` — `GET /redfish/v1/Managers/bmc`, `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry`

Telemetry is persisted to `RACK_MANAGER_DATA|<sensor>` and consumed by nothing on the BMC, so STATE_DB is the only observable boundary. These tests never drive power actions.

### Test Case \#29: The BMC advertises the SONiC OEM RackManager interface

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_manager_advertises_telemetry_action` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers/bmc`<br>`GET /redfish/v1/Managers/bmc/Oem/SONiC/RackManager` |

**Steps:**

1. Send `GET /redfish/v1/Managers/bmc` and validate HTTP 200.
2. Validate `Oem.SONiC.RackManager` is present with `@odata.id` `/redfish/v1/Managers/bmc/Oem/SONiC/RackManager` and `@odata.type` `#SonicManager.v1_0_0.RackManager`.
3. Validate its `Actions` advertise `#SONiC.SubmitTelemetry` and `#SONiC.SubmitAlert` with targets `.../RackManager/Actions/SONiC.SubmitTelemetry` and `.../RackManager/Actions/SONiC.SubmitAlert`.
4. Send `GET /redfish/v1/Managers/bmc/Oem/SONiC/RackManager` and validate HTTP 200, the same `@odata.id` and `@odata.type`, `Id` `RackManager`, `Name` `SONiC Rack Manager Interface`, a non-empty `Description`, and `Actions.#SONiC.SubmitTelemetry.target` equal to the telemetry target.

### Test Case \#30: Valid telemetry is accepted and persisted per the platform DB schema

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_telemetry_persists_to_state_db` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers/bmc`<br>`POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry` |

**Steps:**

1. Resolve the `#SONiC.SubmitTelemetry` target from `GET /redfish/v1/Managers/bmc` (skip if absent); snapshot and clear all `RACK_MANAGER_DATA|*` keys in STATE_DB.
2. Send `POST .../SONiC.SubmitTelemetry` with `Alarms`: `InletTempDeviation` {`InletTemperature` 16.87, `Severity` Normal}, `FlowRateDeviation` {`FlowRate` 28, `Severity` Normal}, `LiquidPressureDeviation` {`LiquidPressure` 2, `Severity` Critical}, `LeakDetected` {`Severity` Critical}.
3. Validate HTTP 204 with an empty body.
4. Validate within 20s: `RACK_MANAGER_DATA|Inlet_liquid_temperature` {`InletTemperature` 16.87, `unit` C, `severity` NORMAL}; `|Inlet_liquid_flow_rate` {`value` 28, `unit` gallons_per_min, `severity` NORMAL}; `|Inlet_liquid_pressure` {`value` 2, `unit` psi, `severity` CRITICAL}; `|Rack_level_leak` {`leak` CRITICAL}; numbers compared as floats, each with exactly those fields plus a `%Y-%m-%dT%H:%M:%S.%fZ` `timestamp`.
5. Validate no other `RACK_MANAGER_DATA|*` key was written; restore the snapshotted table on teardown.

### Test Case \#31: A later sample overwrites the previous one, so alert clearing is visible

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_telemetry_updates_existing_record` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry` |

**Steps:**

1. Resolve the `SubmitTelemetry` target and start from an empty `RACK_MANAGER_DATA` table.
2. Send `POST .../SONiC.SubmitTelemetry` with the reference payload from #30; validate HTTP 204 and the four records from #30.
3. Send `POST .../SONiC.SubmitTelemetry` with an all-Normal sample (`InletTemperature` 18.5, `FlowRate` 30, `LiquidPressure` 5.25, `LeakDetected` Normal); validate HTTP 204 with an empty body.
4. Validate within 20s that all four keys have a `timestamp` lexically later than after the first POST.
5. Validate the records now hold the new values (18.5 C, 30 gallons_per_min, 5.25 psi) with `severity=NORMAL` and `leak=NORMAL`, exact field sets and no stray keys.

### Test Case \#32: The bridge's classification rules hold for the payload shapes a rack manager may send

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_telemetry_payload_shapes` (7 cases) |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry` |

**Steps:**

1. Resolve the `SubmitTelemetry` target and start from an empty `RACK_MANAGER_DATA` table.
2. Send `POST .../SONiC.SubmitTelemetry` per case: `alternate_envelope_name` (`SystemAlarms` envelope, flow 31 Minor); `wrapper_severity_inherited` (`Alarms.ShutdownAlert` Major with temp 40, pressure 90, leak Critical); `missing_severity_defaults_normal` (flow 27, no Severity); `severity_case_normalised` (pressure 1, `critical`); `unknown_fields_dropped` (`EnergyValveActive`, `PumpSpeedDeviation`, `RscmPosition` alongside temp 21 Normal); `multiple_envelopes_merged` (`Alarms` temp 19 Normal plus `RackAlarms` flow 33 Minor); `unrecognised_only_persists_nothing` (only `PumpSpeedDeviation`).
3. Validate HTTP 204 with an empty body for every case.
4. Validate within 20s the expected records with exact fields plus `timestamp` and no stray keys: flow MINOR; temp and pressure MAJOR plus leak CRITICAL; flow NORMAL; pressure CRITICAL; temp only, NORMAL; temp NORMAL plus flow MINOR.
5. For `unrecognised_only_persists_nothing`, validate after a 3s settle that `RACK_MANAGER_DATA` stays empty.

### Test Case \#33: bmcweb rejects malformed requests with the right Redfish error and writes nothing

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_telemetry_rejects_bad_requests` (5 cases) |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry` |

**Steps:**

1. Resolve the `SubmitTelemetry` target and start from an empty `RACK_MANAGER_DATA` table.
2. Send one request per case: empty body with `Content-Type: application/json` (400 `MalformedJSON`); `{"NotPresent": {}}` with no `*Alarms*` envelope (400 `PropertyMissing`, args `["Alarms"]`, on `Alarms@Message.ExtendedInfo`); reference payload to `/Managers/notbmc/...` (404 `ResourceNotFound`, args `["Manager", "notbmc"]`); `Alarms` with a 64 KiB padding string (400 `PayloadTooLarge`); `GET` on the target (405).
3. Validate the status code and, for all but the GET case, a Redfish error carrying a `MessageId` ending in the expected message (and matching `MessageArgs` where given).
4. Validate after a 3s settle that no `RACK_MANAGER_DATA|*` key exists.

### Test Case \#34: Telemetry is refused, not lost, while sonic-dbus-bridge is stopped

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_submit_telemetry_bridge_unavailable` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry` |

**Steps:**

1. Resolve the `SubmitTelemetry` target and start from an empty `RACK_MANAGER_DATA` table.
2. Stop the bridge with `docker exec redfish supervisorctl stop sonic-dbus-bridge` and validate it reaches `STOPPED` within 30s.
3. Send `POST .../SONiC.SubmitTelemetry` with the reference payload; validate bmcweb answers (no connection error or client timeout) with HTTP 401, 500 or 503, and after a 3s settle `RACK_MANAGER_DATA` is still empty.
4. Start `sonic-dbus-bridge` again (also in a `finally`) and validate it reaches `RUNNING` within 30s.
5. Repeat the reference POST every 2s until it returns 204, within 60s.
6. Validate the four records from #30 are persisted with exact fields and no stray keys.

---

## Section 8: Event Service and Subscriptions

Module: `test_redfish_event_subscription.py` — `GET /redfish/v1/EventService`, `GET/POST/DELETE /redfish/v1/EventService/Subscriptions[/{id}]`

The test plays the rack manager: it subscribes with the PTF webhook URL, raises events on the BMC and checks what the webhook received. Leak events come from a synthetic `LIQUID_COOLING_INFO|<sensor>` row the test flips (standing in for thermalctld), mirrored by the bridge as a `LeakDetector` and turned into `Environmental.1.1.0.LeakDetected*` events by bmcweb. Switch-host power events come from real `ComputerSystem.Reset` transitions and bmcctld's `HOST_STATE` row, turned into `ResourceEvent.1.3.0.ResourcePower*` events. `SubmitTestEvent`, SSE, PATCH and retry policies are out of scope.

### Test Case \#35: EventService is enabled and advertises what a rack manager needs to subscribe

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_event_service_advertised` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/EventService` |

**Steps:**

1. Send `GET /redfish/v1/EventService` and validate HTTP 200.
2. Validate `@odata.id` is `/redfish/v1/EventService`, `ServiceEnabled` is `true` and `Status.State` is `Enabled`.
3. Validate `Subscriptions.@odata.id` is `/redfish/v1/EventService/Subscriptions`.
4. Validate `RegistryPrefixes` includes `Base` and `OpenBMC`.

### Test Case \#36: EventService advertises the filters the rack manager's subscriptions use

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_event_service_advertises_rack_manager_filters` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/EventService` |

**Steps:**

1. Send `GET /redfish/v1/EventService` and validate HTTP 200.
2. Validate `RegistryPrefixes` includes `Environmental` and `ResourceEvent`.
3. Validate `ResourceTypes` includes `LeakDetector` and `ComputerSystem`.

### Test Case \#37: A push subscription can be created, read back and removed

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_subscription_lifecycle` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions`<br>`GET <Location>`<br>`DELETE <Location>` |

**Steps:**

1. Start the webhook listener (`redfish_event_listener.py`) on the PTF at port 18081 and confirm a probe POST from inside the `redfish` container gets 204; delete all existing subscriptions.
2. Send `POST /redfish/v1/EventService/Subscriptions` with `Destination` `http://<ptf>:18081/lifecycle`, `Protocol` `Redfish`, `Context` `ctx-lifecycle`; validate HTTP 201 and a `Location` under `.../Subscriptions/`.
3. Send `GET <Location>` and validate HTTP 200 with `@odata.id`, `Id`, `Destination` and `Context` echoed, `Protocol` `Redfish`, `SubscriptionType` `RedfishEvent`, `EventFormatType` `Event`, empty `RegistryPrefixes` and `MessageIds`, and the id listed in the collection.
4. Send `DELETE <Location>` and validate HTTP 200 or 204.
5. Validate a follow-up `GET <Location>` returns 404 and the id is no longer listed in the collection.

### Test Case \#38: Invalid subscription requests are refused with a Redfish error and create nothing

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_subscription_rejects_bad_requests` (7 cases) |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions` |

**Steps:**

1. Start the PTF webhook listener and delete all existing subscriptions.
2. Send `POST /redfish/v1/EventService/Subscriptions` per case: no `Destination` (`PropertyMissing`); `Protocol` `Kafka` (`PropertyValueNotInList`); `Destination` `not a url` (`PropertyValueFormatError`); `Destination` with userinfo `http://rmc:secret@10.0.0.1/` (`PropertyValueFormatError`); `RegistryPrefixes` `["NoSuchRegistry"]` (`PropertyValueNotInList`); `RegistryPrefixes` `["OpenBMC"]` plus `MessageIds` `["PowerSupplyFailed"]` (`PropertyValueConflict`); `DeliveryRetryPolicy` `Never` (`PropertyValueNotInList`).
3. Validate HTTP 400 with an `@Message.ExtendedInfo` `MessageId` ending in the expected message.
4. Validate the Subscriptions collection is still empty.

### Test Case \#39: A leak detected on the BMC is pushed to the subscribed rack manager

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_event_delivered` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions` |

**Steps:**

1. Require `EventService` to list the `Environmental` registry and `LeakDetector` resource type; seed STATE_DB `LIQUID_COOLING_INFO|rmc_test_leak` (`leaking`/`leak_status` No, `leak_severity` None, `leak_sensor_status` Good, `type` leak), restart `sonic-dbus-bridge` and wait for the D-Bus `LeakDetector` `DetectorState` to read OK; start the PTF webhook listener with no subscriptions.
2. Send `POST /redfish/v1/EventService/Subscriptions` with `Destination` `.../events`, `Protocol` `Redfish`, `Context` `ctx-events`; validate HTTP 201.
3. Set the sensor row to Critical (`leaking`/`leak_status` Yes, `leak_severity` CRITICAL) and validate within 30s one POST at the listener with `@odata.type` `#Event.v1_4_0.Event`, numeric `Id` and exactly one event: `MessageId` `Environmental.1.1.0.LeakDetectedCritical`, `Severity` Critical, `Message` "Leak detector 'rmc_test_leak' reports a critical level leak.", `MessageArgs` `["rmc_test_leak"]`, `MemberId` 0, `OriginOfCondition` `/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/rmc_test_leak`, non-empty `EventTimestamp`, numeric `EventId`.
4. Set the sensor row back to OK and validate exactly two deliveries in total, the second carrying `Environmental.1.1.0.LeakDetectedNormal` with `Severity` OK and "has returned to normal." message, and a payload `Id` greater than the first.

### Test Case \#40: A MINOR leak is reported as LeakDetectedWarning with Severity Warning

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_warning_event_delivered` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions` |

**Steps:**

1. Use the seeded `rmc_test_leak` sensor reset to OK, the PTF webhook listener and no existing subscriptions (as in #39).
2. Send `POST /redfish/v1/EventService/Subscriptions` with `Destination` `.../warning`, `Context` `ctx-warning`; validate HTTP 201.
3. Set the sensor row to Warning (`leaking`/`leak_status` Yes, `leak_severity` MINOR).
4. Validate within 30s a delivered `#Event.v1_4_0.Event` whose first event has `MessageId` `Environmental.1.1.0.LeakDetectedWarning`, `Severity` Warning, the "reports a warning level leak." message, `MessageArgs` `["rmc_test_leak"]`, `MemberId` 0, the LeakDetector `OriginOfCondition`, and non-empty timestamp and numeric `EventId`.

### Test Case \#41: ResourceTypes and RegistryPrefixes limit what a subscriber is sent

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_resource_type_filter` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions` |

**Steps:**

1. Use the seeded `rmc_test_leak` sensor reset to OK, the PTF webhook listener and no existing subscriptions.
2. Create four subscriptions (each 201): `.../all` unfiltered, `.../leak` with `ResourceTypes` `["LeakDetector"]`, `.../task` with `ResourceTypes` `["Task"]`, `.../base` with `RegistryPrefixes` `["Base"]`.
3. Set the sensor row to Critical.
4. Validate within 30s that `all` and `leak` each receive a delivery whose first event is the full `LeakDetectedCritical` record (as in #39).
5. Wait 8s and validate `task` and `base` received no deliveries.

### Test Case \#42: A subscription survives a bmcweb restart and keeps delivering

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_subscription_persists_across_bmcweb_restart` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions`<br>`GET /redfish/v1`<br>`GET <Location>` |

**Steps:**

1. Use the seeded `rmc_test_leak` sensor reset to OK, the PTF webhook listener and no existing subscriptions.
2. Send `POST /redfish/v1/EventService/Subscriptions` with `Destination` `.../persist`, `Context` `ctx-persist`; validate HTTP 201.
3. Restart bmcweb with `docker exec redfish supervisorctl restart bmcweb` and wait up to 90s for `RUNNING` and `GET /redfish/v1` returning 200.
4. Validate the subscription id is still listed and `GET <Location>` returns the same `Destination` and `Context`.
5. Set the sensor row to Critical and validate within 30s a delivery at `.../persist` carrying the full `LeakDetectedCritical` event.

### Test Case \#43: The LeakDetector resource a leak event points at reflects the live sensor state

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_detector_resource_tracks_state` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors`<br>`GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/rmc_test_leak` |

**Steps:**

1. Use the seeded `rmc_test_leak` sensor reset to OK (DetectorState OK on D-Bus).
2. Send `GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors` and validate HTTP 200 with `.../LeakDetectors/rmc_test_leak` among `Members`.
3. Set the sensor row to Critical and validate within 30s that `GET .../LeakDetectors/rmc_test_leak` reports `DetectorState` Critical and `Status.Health` Critical, with `@odata.id` the detector URI and `Id` `rmc_test_leak`.
4. Set the sensor row back to OK and validate within 30s `DetectorState` OK and `Status.Health` OK, with the same `@odata.id` and `Id`.

### Test Case \#44: The LeakDetector a leak event points at is served in full at both of its URIs

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_leak_detector_resource_shape` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis/LeakDetectors/{id}`<br>`GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/{id}` |

**Steps:**

1. Use the seeded `rmc_test_leak` sensor reset to OK.
2. For both `/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/rmc_test_leak` and `/redfish/v1/Chassis/chassis/LeakDetectors/rmc_test_leak`, send `GET` on the parent collection and validate HTTP 200 with the member listed.
3. Send `GET` on each member and validate HTTP 200 with `@odata.id` equal to that URI, `@odata.type` containing `#LeakDetector.`, `Id` `rmc_test_leak`, `Name` `Leak Detector rmc_test_leak`, non-empty `LeakDetectorType`, `DetectorState` OK, and `Status` `State` Enabled with `Health` OK.

### Test Case \#45: Taking the switch host down and back up reaches a subscribed rack manager as ResourceEvents

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_host_power_events_delivered` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Require STATE_DB `HOST_STATE|switch-host` to show the host settled on (`device_power_state` POWERED_ON or POWER_CYCLE with `device_status` ONLINE); start the PTF webhook listener with no subscriptions.
2. Create two subscriptions (each 201): `.../power` with `ResourceTypes` `["ComputerSystem"]` and `.../leak-only` with `ResourceTypes` `["LeakDetector"]`.
3. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `ResetType` `GracefulShutdown`, validate 204, and wait up to 240s for `ResourceEvent.1.3.0.ResourcePoweredOff` at `.../power`.
4. Send `ComputerSystem.Reset` with `ResetType` `On`, validate 204, wait up to 120s for `ResourcePoweredOn`, and validate `HOST_STATE|switch-host` settles on within 120s.
5. Validate the delivered MessageIds, with consecutive repeats collapsed, are exactly `ResourcePoweringOff`, `ResourcePoweredOff`, `ResourcePoweringOn`, `ResourcePoweredOn`; each delivery is a `#Event.v1_4_0.Event` with one event having `Severity` OK, the matching "The resource `system` is ..." message, `MessageArgs` `["system"]`, `MemberId` 0, `OriginOfCondition` `/redfish/v1/Systems/system` and a non-empty `EventTimestamp`; payload `Id`s strictly increase.
6. Wait 8s and validate `.../leak-only` received nothing; teardown powers the host back on with `ResetType` `On` if it is not settled on.

### Test Case \#46: A host power-off event lets the rack manager power the host back on

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_host_power_off_event_drives_power_on_request` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Require `HOST_STATE|switch-host` settled on; start the PTF webhook listener with no subscriptions; subscribe `.../rm` with `ResourceTypes` `["ComputerSystem"]` (201).
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `ResetType` `ForceOff`, validate 204, and validate within 240s a delivered `ResourceEvent.1.3.0.ResourcePoweredOff` event (Severity OK, `MessageArgs` `["system"]`, `OriginOfCondition` `/redfish/v1/Systems/system`).
3. Record existing STATE_DB `RACK_MANAGER_COMMAND|*` keys, then send `ComputerSystem.Reset` with `ResetType` `On` and validate 204.
4. Validate exactly one new `RACK_MANAGER_COMMAND|*` row appears within 30s and bmcctld completes it within 60s with `command=POWER_ON`, `status=DONE`, `result=SUCCESS`.
5. Validate `HOST_STATE|switch-host` settles on within 120s and the subscriber receives a well-formed `ResourceEvent.1.3.0.ResourcePoweredOn` event within 120s.

---

## Section 9: Redfish to pmon (bmcctld) Interaction

Module: `test_redfish_pmon_interaction.py` — `POST ComputerSystem.Reset`, `SONiC.SubmitAlert`, STATE_DB

bmcweb never touches the switch host itself: a reset becomes a `RACK_MANAGER_COMMAND` row that bmcctld drives from PENDING to DONE or FAILED and reflects in `HOST_STATE`. Every reset here is `On` against a host already on, so the host is never power cycled.

### Test Case \#47: A reset becomes one RACK_MANAGER_COMMAND row that bmcctld completes

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_command_consumed_by_bmcctld` |
| **Priority** | P0 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Require STATE_DB `HOST_STATE|switch-host` to show the host settled on (`device_power_state` in `POWERED_ON`/`POWER_CYCLE` and `device_status` `ONLINE`) and `bmcctld` RUNNING in the `pmon` container, else skip; snapshot the existing `RACK_MANAGER_COMMAND|*` keys.
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with `{"ResetType": "On"}` and validate HTTP 204 with an empty body.
3. Validate exactly one new `RACK_MANAGER_COMMAND` row appears within 30s and carries `command=POWER_ON`.
4. Validate `bmcctld` moves the row to a terminal status within 60s, ending `command=POWER_ON`, `status=DONE`, `result=SUCCESS` with a non-empty `last_change_timestamp`.
5. Wait 5s and validate the row is still present and unchanged, and `HOST_STATE|switch-host` `device_power_state` still equals its pre-reset value.

### Test Case \#48: The two STATE_DB views bmcctld keeps of the switch host agree

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_power_state_consistent_across_layers` |
| **Priority** | P0 |

**Steps:**

1. Require `bmcctld` RUNNING in the `pmon` container, else skip.
2. Read STATE_DB `HOST_STATE|switch-host` and `CHASSIS_MODULE_TABLE|SWITCH-HOST`.
3. Validate `device_power_state` is a settled value: `POWERED_ON`, `POWER_CYCLE`, `POWERED_OFF` or `GRACEFUL_SHUTDOWN` (a transitional value fails).
4. Validate `HOST_STATE` `device_status` and `CHASSIS_MODULE_TABLE` `oper_status` both equal the status mapped from it (`ONLINE` for `POWERED_ON`/`POWER_CYCLE`, `OFFLINE` for `POWERED_OFF`/`GRACEFUL_SHUTDOWN`).

### Test Case \#49: A CRITICAL rack manager alert makes bmcctld refuse POWER_ON until it is cleared

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_critical_alert_blocks_power_on_command` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert`<br>`POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Require the host settled on and `bmcctld` RUNNING; resolve the `#SONiC.SubmitAlert` target from `GET /redfish/v1/Managers/bmc` (`Oem.SONiC.RackManager.Actions`); skip unless CONFIG_DB `LEAK_CONTROL_POLICY` (defaults `enabled`/`syslog_only`) has `rack_mgr_leak_policy` not `disabled` and `rack_mgr_critical_alert_action=syslog_only`; snapshot and clear all STATE_DB `RACK_MANAGER_ALERT|*` keys (restored after the test).
2. Send `POST <SubmitAlert target>` with `{"redfish_alert_data": {"LeakDetected": {"Severity": "Critical"}}}`, validate HTTP 204 with empty body, and validate `RACK_MANAGER_ALERT|Rack_level_leak` `leak=CRITICAL` within 20s.
3. Send `POST .../ComputerSystem.Reset` `{"ResetType": "On"}` (HTTP 204), validate one new `RACK_MANAGER_COMMAND` row within 30s and that it reaches a terminal status within 60s with `command=POWER_ON`, `status=FAILED`, `result=CRITICAL_LEAK_PRESENT` and a `last_change_timestamp`.
4. Validate `HOST_STATE|switch-host` `device_power_state` is unchanged while the alert is active.
5. Send the SubmitAlert POST with `Severity` `Normal` (HTTP 204) and validate `leak=NORMAL` within 20s.
6. Send another `ResetType=On` and validate its new row ends `command=POWER_ON`, `status=DONE`, `result=SUCCESS` with a `last_change_timestamp`.

### Test Case \#50: Restarting bmcctld re-publishes HOST_STATE and leaves Redfish and the host untouched

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_bmcctld_restart_resyncs_host_state` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Require the host settled on and `bmcctld` RUNNING; record the `bmcctld` pid, the `RACK_MANAGER_COMMAND|*` keys and `HOST_STATE|switch-host`.
2. Run `docker exec pmon supervisorctl restart bmcctld` and validate `bmcctld` is RUNNING with a new pid within 120s.
3. Validate `HOST_STATE|switch-host` `last_change_timestamp` becomes newer than before within 120s, and then reads `device_power_state=POWERED_ON` and `device_status=ONLINE`.
4. Validate no new `RACK_MANAGER_COMMAND` row was created by the restart.
5. Send `POST .../ComputerSystem.Reset` `{"ResetType": "On"}` (HTTP 204) and validate its single new row ends `command=POWER_ON`, `status=DONE`, `result=SUCCESS` with a `last_change_timestamp`.

---

## Section 10: Concurrency

Module: `test_redfish_concurrency.py` — inventory GETs, `ComputerSystem.Reset`, `EventService/Subscriptions`

### Test Case \#51: Reset requests while pollers walk the inventory

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_reset_concurrent_with_inventory_poll` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Skip unless STATE_DB `HOST_STATE|switch-host` shows the host settled on; record supervisord pids in the `redfish` container (requiring `bmcweb` and `sonic-dbus-bridge` RUNNING), the existing `RACK_MANAGER_COMMAND|*` keys, and the member lists of `/redfish/v1/Chassis`, `/redfish/v1/Managers` and `/redfish/v1/UpdateService/FirmwareInventory` (each HTTP 200).
2. Start 4 poller threads looping `GET` over those collections and every member, and one thread sending 5 `POST .../ComputerSystem.Reset` `{"ResetType": "On"}` 1s apart, stopping the pollers 5s after the last reset.
3. Validate all 5 resets returned HTTP 204, every poll returned HTTP 200, and no collection's member list differed from the baseline.
4. Validate D-Bus `/xyz/openbmc_project/state/host0` `RequestedHostTransition` reads `xyz.openbmc_project.State.Host.Transition.On`.
5. Validate exactly 5 new `RACK_MANAGER_COMMAND` rows appear in STATE_DB within 30s.
6. Validate `HOST_STATE` shows the host settled on again within 30s with `device_power_state` unchanged, and the `redfish` container supervisord pids are unchanged.

### Test Case \#52: The same subscription created and deleted by several callers at once

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_duplicate_subscription_create_and_delete` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions`<br>`GET /redfish/v1/EventService/Subscriptions` |

**Steps:**

1. Delete all existing subscriptions (and again after the test); record the `redfish` container supervisord pids, requiring `bmcweb` and `sonic-dbus-bridge` RUNNING.
2. Send 8 concurrent `POST /redfish/v1/EventService/Subscriptions` with the same body (`Destination` `http://192.0.2.1:80/concurrency`, `Protocol` `Redfish`, `Context` `concurrency-duplicate`) and validate every response is HTTP 201 with a distinct id in `Location`.
3. Validate `GET /redfish/v1/EventService/Subscriptions` lists exactly those 8 ids, and `GET` on each `Location` returns HTTP 200 with the same `Destination`.
4. Send 3 concurrent `DELETE` requests per id (24 in total) and validate every response is 200, 204 or 404.
5. Validate the subscription collection is empty and the supervisord pids are unchanged.

### Test Case \#53: Several callers create, read and delete subscriptions at the same time

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_interleaved_create_delete_churn` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions` |

**Steps:**

1. Delete all existing subscriptions (and again after the test); record the `redfish` container supervisord pids, requiring `bmcweb` and `sonic-dbus-bridge` RUNNING.
2. Start 4 worker threads, each running 5 cycles of `POST /redfish/v1/EventService/Subscriptions` with a unique `Context` (`churn-<worker>-<iteration>`), `GET` on the returned `Location`, then `DELETE` of it.
3. Validate every `POST` returned 201, every `GET` returned 200 with the worker's own `Context`, and every `DELETE` returned 200 or 204.
4. Validate the subscription collection is empty and the supervisord pids are unchanged.

---

## Section 11: Restart Recovery

Module: `test_redfish_restart_recovery.py` — `systemctl restart sonic-dbus-bridge`, `systemctl restart redfish`

bmcweb owns no inventory; everything is assembled per request from the bridge's D-Bus objects and ObjectMapper. Each test snapshots the Redfish view and the ObjectMapper view, restarts, and checks both come back identical.

### Test Case \#54: A running bmcweb rediscovers a restarted sonic-dbus-bridge

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_bridge_restart_rediscovered_by_running_bmcweb` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Chassis`<br>`GET /redfish/v1/Managers`<br>`GET /redfish/v1/UpdateService/FirmwareInventory` |

**Steps:**

1. Snapshot the Redfish inventory (`/redfish/v1/Chassis`, `/redfish/v1/Managers`, `/redfish/v1/UpdateService/FirmwareInventory`, each member's identity and state fields, and any chassis `LeakDetectors` collection) and validate every GET is HTTP 200 and Chassis has members.
2. Snapshot the ObjectMapper `GetSubTreePaths` per bridge interface and validate it answers and lists objects for `Inventory.Item.Chassis` and `State.Host`; record the `bmcweb` pid.
3. Run `supervisorctl restart sonic-dbus-bridge` in the `redfish` container and validate it is RUNNING again within 60s.
4. Validate within 90s the ObjectMapper tree and then the Redfish inventory snapshot match the baselines exactly, with every GET answering 200.
5. Validate ObjectMapper `GetObject` for `/xyz/openbmc_project/state/host0` names `xyz.openbmc_project.State.Host`, and the `bmcweb` pid is unchanged.

### Test Case \#55: Redfish recovers after the redfish container restarts

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_redfish_container_restart` |
| **Priority** | P1 |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions`<br>`GET /redfish/v1`<br>`GET <Location>` |

**Steps:**

1. Take the Redfish inventory and ObjectMapper baselines as in #54.
2. Send `POST /redfish/v1/EventService/Subscriptions` (`Destination` `http://192.0.2.1:80/restart-recovery`, `Context` `restart-recovery`) and validate HTTP 201 with a `Location` under the collection.
3. Run `sudo systemctl restart redfish` and validate the service is fully started within 180s, then that `bmcweb` is RUNNING and `GET /redfish/v1` with the client certificate returns HTTP 200 within 180s.
4. Validate within 90s the ObjectMapper tree and the Redfish inventory snapshot match the baselines.
5. Send `GET <Location>` and validate HTTP 200 with the original `Destination` and `Context`; the subscription is deleted afterwards.

---

## Section 12: Certificates and Client Authentication (mTLS)

Module: `test_redfish_certificates.py`. It covers certificate staging, rotation, fail-closed behaviour, client certificate authentication and common name validation.

The design is in the [Redfish Certificate Provisioning HLD](https://github.com/sonic-net/SONiC/pull/2461). Certificates are not copied into the container: a provisioning agent delivers them on the host at the paths named in CONFIG_DB `REDFISH|certs` (`server_crt`, `server_key`, `ca_crt`), and `stage-credentials.sh` in the `redfish` container stages them into what bmcweb reads (`server.pem` and the CA truststore), bounces bmcweb, and publishes its state to STATE_DB `REDFISH_CERT_STATUS|global`. Once provisioned, the device fails closed rather than fall back to a self-signed certificate. bmcweb runs with `TLS` on and `TLSStrict` off: every client is asked for a certificate, the service root answers without one, and every other resource needs a certificate issued by the staged CA whose common name is in `client_crt_cname`. There are no local users or passwords.

The `bmc_tls_certs` fixture plays the provisioning agent. It records the `REDFISH|config` and `REDFISH|certs` fields and sets aside the device files it will overwrite (the delivered certificates, the provisioned marker and the staging stamp), generates a CA, server and client chain in the sonic-mgmt container, writes the delivery paths and `client_crt_cname`, delivers the files to `/etc/sonic/credentials`, and waits for `in_sync`. Its teardown restores the recorded fields and files and recreates the container, so the device returns to the state it was in. Cases that unprovision, corrupt or rotate certificates return the device to the provisioned state after themselves.

**Provisioning and status**

### Test Case \#56: Delivered certificates are staged for bmcweb

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_delivered_certs_are_staged` |
| **Priority** | P0 |

**Steps:**

1. Provision through the session `bmc_tls_certs` fixture: set CONFIG_DB `REDFISH|certs` `server_crt`/`server_key`/`ca_crt` to `/etc/sonic/credentials/restapiserver.crt`, `restapiserver.key`, `restapica.crt`, set `client_crt_cname=bmcweb` with a `sonic-dbus-bridge` restart, deliver the generated CA, server certificate and key to those paths, and wait up to 150s for STATE_DB `REDFISH_CERT_STATUS|global` `in_sync=true`.
2. Validate `/etc/ssl/certs/https/server.pem` inside the `redfish` container holds 2 PEM blocks (certificate and key).
3. Validate the staged certificate serial equals the delivered server certificate serial and its issuer differs from its subject (not self-signed).
4. Validate the hash symlink `/etc/ssl/certs/authority/<hash>.0` exists for the staged `CA-cert.pem`.
5. Validate `supervisorctl status bmcweb` reports RUNNING.

### Test Case \#57: Provisioning writes the marker and the staging stamp on the host mount

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_provisioned_state_is_recorded` |
| **Priority** | P0 |

**Steps:**

1. Provision through `bmc_tls_certs` as in #56.
2. Validate `/var/lib/bmcweb/provisioned` on the host exists and contains `provisioned_at=` and `Do not delete`.
3. Validate `/var/lib/bmcweb/.staged-credentials.stamp` exists and is non-empty.

### Test Case \#58: STATE_DB reports the provisioning result

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_status_is_published` |
| **Priority** | P0 |

**Steps:**

1. Provision through `bmc_tls_certs` as in #56.
2. Validate STATE_DB `REDFISH_CERT_STATUS|global` has `in_sync=true`, `mtls_enforced=true` and an empty `last_error`.
3. Validate `source_fingerprint` equals `applied_fingerprint` and `served_serial` is non-empty.

### Test Case \#59: A rotated certificate is staged and served with no operator action

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_rotation_is_picked_up` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Record the staged server certificate serial and `applied_fingerprint`.
2. Issue a new server certificate and key from the same CA and deliver the full trio to the configured paths.
3. Validate within 150s `in_sync=true` with `applied_fingerprint` changed from the recorded value.
4. Validate the staged serial changed, the certificate bmcweb presents in a live TLS handshake has the new certificate's serial, and STATE_DB `served_serial` equals the staged serial.
5. Send `GET /redfish/v1` with the existing client certificate and validate HTTP 200.

### Test Case \#60: A certificate delivered without its matching key is never staged

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_mismatched_pair_is_not_staged` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Record the staged server certificate serial and the `bmcweb` pid.
2. Issue a new server certificate and key from the same CA and deliver only the certificate to `restapiserver.crt`, then wait 90s.
3. Validate the staged serial and `bmcweb` pid are unchanged and `in_sync=false`.
4. Send `GET /redfish/v1` with the client certificate and validate HTTP 200.
5. Deliver the matching key to `restapiserver.key` and validate within 150s `in_sync=true`, the staged serial changed, and the live TLS handshake presents the new certificate's serial.

### Test Case \#61: Each kind of bad input reports a reason in `last_error`

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_every_failure_reports_a_reason` |
| **Priority** | P1 |

**Steps:**

1. Remove the three delivered files, wait up to 90s for a reported failure, and validate `in_sync=false` with a non-empty `last_error`.
2. Re-deliver the good trio and validate `in_sync=true` within 150s; overwrite `restapica.crt` with non-PEM bytes, wait up to 90s, and validate `in_sync=false` with a non-empty `last_error`.
3. Re-deliver the good trio and validate `in_sync=true` within 150s; issue a new server certificate from the same CA and deliver only it to `restapiserver.crt`, wait up to 90s, and validate `in_sync=false` with a non-empty `last_error`.
4. After the test, restart `credentials-watcher` if needed, re-deliver the good trio and wait for `in_sync=true`.

### Test Case \#62: `last_update` shows whether the watcher is alive

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_last_update_shows_whether_the_watcher_is_alive` |
| **Priority** | P1 |

**Steps:**

1. Validate `in_sync=true` within 150s.
2. Read STATE_DB `REDFISH_CERT_STATUS|global` `last_update`, wait 90s, and validate it changed.
3. Stop `credentials-watcher` in the `redfish` container, read `last_update`, wait 90s, and validate it did not change.
4. After the test, start `credentials-watcher` again, re-deliver the good trio and wait for `in_sync=true`.

**Client certificate authentication**

### Test Case \#63: A client certificate issued by the provisioned CA is accepted

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_valid_cert_accepted` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Send `GET /redfish/v1` with the client certificate issued by the provisioned CA (CN `bmcweb`), verifying the server against that CA.
2. Validate HTTP 200.

### Test Case \#64: The certificate alone authorises an authenticated endpoint

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_cert_auth_on_authenticated_endpoint` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/UpdateService` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService` with the provisioned client certificate and no username or password.
2. Validate HTTP 200 and that the body contains `@odata.id`.

### Test Case \#65: The service root answers a client that presents no certificate

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_service_root_readable_without_a_certificate` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Send `GET /redfish/v1` with no client certificate, verifying the server against the provisioned CA.
2. Validate HTTP 200 and that the body contains `@odata.id`.

### Test Case \#66: Privileged resources need a client certificate

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_privileged_path_refused_without_a_certificate` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Send `GET /redfish/v1/Managers` with no client certificate, verifying the server against the provisioned CA.
2. Validate HTTP 401 or 403.

### Test Case \#67: A certificate signed by an untrusted CA does not authenticate

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_wrong_ca_rejected` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory`<br>`GET /redfish/v1/Managers` |

**Steps:**

1. Generate a separate chain with CA `Untrusted CA` and a client certificate with CN `untrusted-client`.
2. Send `GET /redfish/v1/UpdateService/FirmwareInventory` with the untrusted client certificate, verifying the server against the provisioned CA.
3. Validate HTTP 401 or 403; if the TLS handshake is refused instead, validate `GET /redfish/v1/Managers` with the provisioned client certificate returns HTTP 200 so the refusal is not a dead listener.

**Common name validation**

### Test Case \#68: An unset trusted list refuses every common name

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_unset_list_refuses_every_common_name` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Remove `client_crt_cname` from CONFIG_DB `REDFISH|certs` (`hdel`), restart `sonic-dbus-bridge` via supervisorctl and validate it returns to `RUNNING`.
2. Issue a new client certificate from the provisioned test CA with CN `anything-at-all`.
3. Send `GET /redfish/v1/Managers` over mTLS on the session port with that certificate, verifying the server against the test CA.
4. Validate the response is HTTP 403.
5. After the class, restore `client_crt_cname` to `bmcweb` and restart `sonic-dbus-bridge`.

### Test Case \#69: A configured list admits the listed name and refuses everything else

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_exact_match_is_enforced` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Set `client_crt_cname` = `bmcweb` in CONFIG_DB `REDFISH|certs`, restart `sonic-dbus-bridge` and validate it is `RUNNING`.
2. Send `GET /redfish/v1/Managers` over mTLS with the session client certificate (CN `bmcweb`) and validate HTTP 200.
3. Set `client_crt_cname` = `someone-else`, restart `sonic-dbus-bridge` and validate it is `RUNNING`.
4. Send the same request with the same certificate and validate HTTP 403.

### Test Case \#70: A wildcard entry matches subdomains only

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_wildcard_matches_subdomains_only` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Set `client_crt_cname` = `*.example.com` in CONFIG_DB `REDFISH|certs`, restart `sonic-dbus-bridge` and validate it is `RUNNING`.
2. Issue client certificates from the test CA with CNs `host.example.com`, `deep.host.example.com`, `example.com` and `example.com.evil.net`.
3. Send `GET /redfish/v1/Managers` over mTLS with each certificate on the session port.
4. Validate HTTP 200 for `host.example.com` and `deep.host.example.com`, and HTTP 403 for `example.com` and `example.com.evil.net`.

### Test Case \#71: Any entry in a comma separated list admits a client

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_list_entries_are_independent` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Set `client_crt_cname` = `first,bmcweb,*.example.com` in CONFIG_DB `REDFISH|certs`, restart `sonic-dbus-bridge` and validate it is `RUNNING`.
2. Issue client certificates from the test CA with CNs `first`, `bmcweb`, `host.example.com` and `someone-else`.
3. Send `GET /redfish/v1/Managers` over mTLS with each certificate on the session port.
4. Validate HTTP 200 for `first`, `bmcweb` and `host.example.com`, and HTTP 403 for `someone-else`.

### Test Case \#72: A refused client can still read the service root, and nothing else

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_service_root_stays_reachable_when_refused` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1`<br>`GET /redfish/v1/Managers` |

**Steps:**

1. Set `client_crt_cname` = `someone-else` in CONFIG_DB `REDFISH|certs`, restart `sonic-dbus-bridge` and validate it is `RUNNING`.
2. Send `GET /redfish/v1` over mTLS with the session client certificate (CN `bmcweb`) and validate HTTP 200.
3. Send `GET /redfish/v1/Managers` with the same certificate and validate HTTP 403.

**Restart, fail-closed and container recreate**

### Test Case \#73: Restarting bmcweb alone reuses the staged files; the oneshot does not re-run

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_bmcweb_restart_keeps_serving` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Read the serial of the staged `/etc/ssl/certs/https/server.pem` inside the `redfish` container with `openssl x509 -serial`.
2. Restart `bmcweb` with `supervisorctl restart` and validate it returns to `RUNNING` within 60s.
3. Validate the staged certificate serial is unchanged.
4. Validate supervisord reports `stage-credentials` as `EXITED` (the oneshot did not re-run).
5. Send `GET /redfish/v1/Managers` over mTLS with the session client certificate and validate HTTP 200.

### Test Case \#74: A restart succeeds on the staged copy even with the delivery paths empty

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_restart_with_source_removed` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Delete the delivered `restapiserver.crt`, `restapiserver.key` and `restapica.crt` from `/etc/sonic/credentials`, leaving the staged copies.
2. Restart `bmcweb` with `supervisorctl restart`.
3. Validate `bmcweb` reaches `RUNNING` within 60s.
4. Send `GET /redfish/v1/Managers` over mTLS with the session client certificate and validate HTTP 200.
5. After the test (`provisioned_after_test`), redeliver the certificates, recreate the `redfish` container and wait for `bmcweb` `RUNNING` and `in_sync` = `true`.

### Test Case \#75: A damaged staged certificate is re-staged from the source at the next start

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_guard_self_heals_damaged_staged_cert` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Stop `credentials-watcher` and then `bmcweb` with supervisorctl.
2. Overwrite the staged `/etc/ssl/certs/https/server.pem` inside the container with the text `not a certificate`, then record the current `/var/log/syslog` line count.
3. Start `bmcweb` and validate it reaches `RUNNING` within 60s.
4. Validate the staged certificate serial equals the serial of the delivered server certificate.
5. Validate syslog logs `guard: staged certificates missing or invalid; re-staging from source` after the recorded line within 30s.
6. Send `GET /redfish/v1/Managers` over mTLS and validate HTTP 200; `provisioned_after_test` then recreates the container, which brings the watcher back.

### Test Case \#76: With no certificate anywhere, a provisioned device refuses to serve

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_fails_closed_with_nothing_valid` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Delete the delivered certificates from `/etc/sonic/credentials`, stop `bmcweb`, delete the staged `server.pem` inside the container, then start `bmcweb`.
2. Validate supervisord reports `bmcweb` as `FATAL` within 60s.
3. Send an unverified `GET /redfish/v1` to the session port and validate the connection fails without any TLS handshake (no self-signed fallback).
4. Validate the provisioned marker `/var/lib/bmcweb/provisioned` still exists.
5. After the test (`provisioned_after_test`), redeliver the certificates, recreate the container and wait for `bmcweb` `RUNNING` and `in_sync` = `true`.

### Test Case \#77: A failed-closed device recovers on its own once certificates are delivered

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_recovers_when_certificates_return` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Delete the delivered certificates, stop `bmcweb`, delete the staged `server.pem`, start `bmcweb`, and validate it reaches `FATAL` within 60s.
2. Redeliver the original certificate trio to `/etc/sonic/credentials` with no other action.
3. Validate `bmcweb` returns to `RUNNING` within 180s.
4. Validate STATE_DB `REDFISH_CERT_STATUS|global` `in_sync` becomes `true` within 150s.
5. Send `GET /redfish/v1/Managers` over mTLS with the session client certificate and validate HTTP 200.

### Test Case \#78: Recreating the container with no delivered certificates fails closed

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_recreate_without_certificates_fails_closed` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1` |

**Steps:**

1. Delete the delivered certificates from `/etc/sonic/credentials`.
2. Recreate the container (`systemctl reset-failed`, `systemctl stop redfish`, `docker rm -f redfish`, `systemctl start redfish`).
3. Validate supervisord reports `bmcweb` as `FATAL` within 60s.
4. Send an unverified `GET /redfish/v1` to the session port and validate the connection fails without any TLS handshake.
5. After the test (`provisioned_after_test`), redeliver the certificates, recreate the container and wait for `bmcweb` `RUNNING` and `in_sync` = `true`.

### Test Case \#79: A recreate with certificates present comes back serving them

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_recreate_with_certificates_comes_back_provisioned` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Recreate the `redfish` container with the delivered certificates in place and validate `bmcweb` reaches `RUNNING` within 60s.
2. Validate the staged `/etc/ssl/certs/https/server.pem` is not self-signed (issuer differs from subject).
3. Validate the provisioned marker `/var/lib/bmcweb/provisioned` still exists.
4. Validate STATE_DB `REDFISH_CERT_STATUS|global` `in_sync` is `true` within 150s and `mtls_enforced` is `true`.
5. Send `GET /redfish/v1/Managers` over mTLS with the session client certificate and validate HTTP 200.

**Bad input and watcher behaviour**

### Test Case \#80: A delivered server certificate that does not parse is refused

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_corrupt_server_certificate_is_not_staged` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Record the staged server certificate serial.
2. Overwrite the delivered `/etc/sonic/credentials/restapiserver.crt` with the text `not a certificate` and wait 90s.
3. Validate the staged server certificate serial is unchanged.
4. Validate STATE_DB `REDFISH_CERT_STATUS|global` `in_sync` is `false`.
5. Send `GET /redfish/v1/Managers` over mTLS and validate HTTP 200.
6. After the test (`good_certs_after_test`), redeliver the original trio and wait for `in_sync` = `true`.

### Test Case \#81: A corrupt CA is refused before staging, so bmcweb is never bounced

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_corrupt_ca_does_not_cause_flapping` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Record the staged server certificate serial and the `bmcweb` PID from `supervisorctl status`.
2. Overwrite the delivered `/etc/sonic/credentials/restapica.crt` with the text `not a certificate` and wait 180s (two reconcile windows).
3. Validate the staged server certificate serial and the `bmcweb` PID are both unchanged.
4. Validate STATE_DB `REDFISH_CERT_STATUS|global` `in_sync` is `false` and `credentials-watcher` is still `RUNNING`.
5. Send `GET /redfish/v1/Managers` over mTLS and validate HTTP 200.
6. After the test (`good_certs_after_test`), redeliver the original trio and wait for `in_sync` = `true`.

### Test Case \#82: Deleting the delivered files does not revoke access

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_deleting_the_source_keeps_the_service_running` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Record the staged server certificate serial.
2. Delete the three delivered certificate files from `/etc/sonic/credentials` and wait 90s.
3. Validate `credentials-watcher` is still `RUNNING` and the staged server certificate serial is unchanged.
4. Validate STATE_DB `REDFISH_CERT_STATUS|global` `in_sync` is `false`.
5. Send `GET /redfish/v1/Managers` over mTLS and validate HTTP 200.
6. After the test (`good_certs_after_test`), redeliver the original trio and wait for `in_sync` = `true`.

### Test Case \#83: A mismatched pair on first install leaves the device in bootstrap

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_mismatched_first_install_stays_in_bootstrap` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Unprovision the device (delete delivered files, the marker and the staging stamp, recreate the container) and validate `bmcweb` reaches `RUNNING`.
2. Issue two new server pairs from the test CA and deliver the certificate of one with the key of the other, plus the valid CA, to the configured paths; wait 90s.
3. Validate the provisioned marker `/var/lib/bmcweb/provisioned` is absent and STATE_DB `in_sync` is `false`.
4. Validate the staged `server.pem` is still self-signed.
5. Redeliver the original matching trio and validate `in_sync` becomes `true` within 150s.
6. Validate the marker now exists and `GET /redfish/v1/Managers` over mTLS returns HTTP 200.

### Test Case \#84: A rotation delivered while the watcher is stopped is applied when it starts

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_change_made_while_down_is_reconciled` |
| **Priority** | P1 |

**Steps:**

1. Record the staged server certificate serial and STATE_DB `applied_fingerprint`.
2. Stop `credentials-watcher` and validate it is not `RUNNING`.
3. Issue a new server pair from the test CA, deliver its certificate and key to the configured paths, wait 5s and validate the staged serial is unchanged.
4. Start `credentials-watcher` and validate it reaches `RUNNING`.
5. Validate `in_sync` is `true` with `applied_fingerprint` changed from the recorded value within 150s, and the staged serial differs from the recorded one.
6. Validate the certificate bmcweb presents in a live TLS handshake on the session port has the serial of the newly delivered certificate.

### Test Case \#85: Re-delivering identical bytes causes no restage and no restart

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_unchanged_content_does_not_bounce_bmcweb` |
| **Priority** | P1 |

**Steps:**

1. Validate STATE_DB `in_sync` is `true` within 150s.
2. Record the staged server certificate serial, the `bmcweb` PID and STATE_DB `applied_fingerprint`.
3. Redeliver the identical certificate trio to the configured paths and wait 90s.
4. Validate the `bmcweb` PID, the staged serial and `applied_fingerprint` are all unchanged.
5. Validate `in_sync` is still `true`.

**Bootstrap, configuration and CA rotation**

### Test Case \#86: Before any certificate is delivered, the device still answers

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_unprovisioned_device_serves_self_signed` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1`<br>`GET /redfish/v1/Managers` |

**Steps:**

1. Unprovision the device (delete delivered files, the marker and the staging stamp, recreate the container) and validate `bmcweb` reaches `RUNNING`.
2. Validate the staged `server.pem` is self-signed and the provisioned marker `/var/lib/bmcweb/provisioned` is absent.
3. Send `GET /redfish/v1` with no client certificate and no server verification on the session port and validate HTTP 200.
4. Send `GET /redfish/v1/Managers` the same way and validate HTTP 401.
5. Validate STATE_DB `REDFISH_CERT_STATUS|global` `in_sync` is `false` and `mtls_enforced` is `false`.
6. After the test (`provisioned_on_session_port`), restore the session port and `REDFISH|certs` (paths and `client_crt_cname` = `bmcweb`), redeliver the certificates, restart `redfish.service` and wait for `in_sync` = `true`.

### Test Case \#87: Delivery paths come from CONFIG_DB, including split directories

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_certificates_are_read_from_the_configured_paths` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Generate a separate CA, server and client chain (CA CN `SONiC BMC Test CA alt`, client CN `bmcweb`) and create two temp directories on the BMC under `/etc/sonic` (`redfish-alt.*` and `credentials-alt.*`); record `applied_fingerprint`.
2. Set CONFIG_DB `REDFISH|certs` `server_crt` and `server_key` to `server.cer`/`server.key` in the first directory and `ca_crt` to `ca.pem` in the second.
3. Place the alternate server certificate, key and CA at those paths, with no service restart.
4. Validate `in_sync` is `true` with `applied_fingerprint` changed within 150s, and the live TLS handshake on the session port presents the alternate server certificate serial.
5. Send `GET /redfish/v1/Managers` over mTLS with the alternate client certificate, verifying against the alternate CA, and validate HTTP 200; then delete both temp directories.

### Test Case \#88: Nothing is staged without a `REDFISH|certs` entry

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_nothing_is_staged_without_configuration` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1`<br>`GET /redfish/v1/Managers` |

**Steps:**

1. Delete CONFIG_DB `REDFISH|certs` and `REDFISH|config`, unprovision the device and validate `bmcweb` reaches `RUNNING` and listens on port 443.
2. Deliver the certificate trio to `/etc/sonic/credentials` and wait 90s.
3. Validate the staged `server.pem` is still self-signed, the provisioned marker is absent, and STATE_DB `last_error` equals `REDFISH|certs not configured`.
4. Set `REDFISH|certs` `server_crt`, `server_key` and `ca_crt` to the delivery paths (no `client_crt_cname`) and validate `in_sync` becomes `true` within 150s.
5. Send `GET /redfish/v1` over mTLS on port 443 and validate HTTP 200.
6. Send `GET /redfish/v1/Managers` over mTLS on port 443 and validate HTTP 403, since the trusted name list was removed with `REDFISH|certs`.

### Test Case \#89: With no port configured, the API is published on the standard port

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_default_port_is_443` |
| **Priority** | P1 |

**Steps:**

1. Delete CONFIG_DB `REDFISH|config`.
2. Restart the service (`systemctl reset-failed redfish.service`, `systemctl restart redfish`) and validate `bmcweb` reaches `RUNNING`.
3. Validate `bmcweb` listens on port 443 in `ss -Hltnp`.

### Test Case \#90: A configured port takes effect when the service restarts

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_configured_port_is_applied_by_a_service_restart` |
| **Priority** | P1 |
| **Endpoint** | `GET /redfish/v1/Managers`<br>`GET /redfish/v1` |

**Steps:**

1. Set CONFIG_DB `REDFISH|config` `port` to 8443 (or 8444 if the session already uses 8443).
2. Restart `redfish.service` and validate `bmcweb` reaches `RUNNING`.
3. Validate `bmcweb` listens on the new port and `GET /redfish/v1/Managers` over mTLS on the new port returns HTTP 200.
4. Send an unverified `GET /redfish/v1` to the previous session port and validate the request fails (no answer).
5. Validate STATE_DB `in_sync` is `true` within 150s and `mtls_enforced` is `true`.
6. After the test (`provisioned_on_session_port`), restore the session port and provisioned state through a service restart.

### Test Case \#91: An unusable port value must not stop the container from being created

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_invalid_port_falls_back_to_the_default` |
| **Priority** | P1 |

**Steps:**

1. Set CONFIG_DB `REDFISH|config` `port` = `notaport`.
2. Restart `redfish.service` and validate `bmcweb` reaches `RUNNING`.
3. Validate `bmcweb` listens on port 443.

### Test Case \#92: Rotating the CA revokes clients of the old CA

| Field        | Value |
| :----------- | :---- |
| **Test ID**  | `test_ca_rotation_replaces_the_truststore` |
| **Priority** | P0 |
| **Endpoint** | `GET /redfish/v1/Managers` |

**Steps:**

1. Generate a second independent chain (CA CN `SONiC BMC Test CA 2`, its own server and client certificate with CN `bmcweb`), record `applied_fingerprint`, and deliver the new server pair and CA to the configured paths.
2. Validate `in_sync` is `true` with `applied_fingerprint` changed within 150s.
3. Send `GET /redfish/v1/Managers` over mTLS with the new client certificate, verifying against the new CA, and validate HTTP 200.
4. Send the same request with the original client certificate (verifying against the new CA) and validate either HTTP 401/403 or a TLS handshake failure.
5. Redeliver the original trio, validate `in_sync` is `true` with `applied_fingerprint` changed within 150s, and validate the original client certificate gets HTTP 200 on `/redfish/v1/Managers`.

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
