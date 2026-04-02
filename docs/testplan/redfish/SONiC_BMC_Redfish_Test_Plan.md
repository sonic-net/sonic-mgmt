# SONiC BMC Redfish API Test Plan

# Test Plan Revision History


| Rev | Date            | Author      | Change Description                                 |
| ----- | ----------------- | ------------- | ---------------------------------------------------- |
| 1   | 26th March 2026 | Chinmoy Dey | Initial Version of SONiC BMC Redfish API test plan |
| 2   | 2nd April 2026  | Shreyansh Jain | Add certificate-based authentication test cases    |

# Related documents


| Document Name                | Link                                                                                                   |
| :----------------------------- | :------------------------------------------------------------------------------------------------------- |
| SONiC-BMC-OS HLD             | [https://github.com/sonic-net/SONiC/pull/2043](https://github.com/sonic-net/SONiC/pull/2043)           |
| sonic-redfish HLD            | [https://github.com/sonic-net/sonic-redfish/pull/2](https://github.com/sonic-net/sonic-redfish/pull/2) |
| sonic-redfish Implementation | [https://github.com/sonic-net/sonic-redfish/pull/1](https://github.com/sonic-net/sonic-redfish/pull/1) |

# Definitions/Abbreviation


| Term              | Description                                                                     |
| :------------------ | :-------------------------------------------------------------------------------- |
| SONiC             | Software for Open Networking in the Cloud                                       |
| BMC               | Baseboard Management Controller                                                 |
| Redfish           | DMTF industry-standard RESTful API for hardware management                      |
| bmcweb            | OpenBMC's industry-standard Redfish HTTP server                                 |
| D-Bus             | Linux inter-process communication system                                        |
| sonic-dbus-bridge | SONiC service that bridges platform data to OpenBMC-compatible D-Bus interfaces |
| ObjectMapper      | OpenBMC D-Bus discovery service (`xyz.openbmc_project.ObjectMapper`)            |
| DUT               | Device Under Test — the SONiC BMC system being tested                          |

# Overview

The sonic-redfish project provides Redfish API support for SONiC BMC platforms. It consists of two components packaged in a single Docker container (`docker-redfish`):

1. **bmcweb** — The upstream OpenBMC Redfish HTTP server, running unmodified.
2. **sonic-dbus-bridge** — A purpose-built systemd daemon that reads SONiC data sources (Redis CONFIG\_DB/STATE\_DB, FRU EEPROMs, platform.json), normalizes them into an `InventoryModel`, and exposes OpenBMC-compatible D-Bus objects (`xyz.openbmc_project.*`) so that bmcweb can discover and serve Redfish endpoints.

The end-to-end data flow is:

```
SONiC Redis / FRU EEPROM / platform.json
    -> sonic-dbus-bridge (normalizes + exposes D-Bus objects)
        -> System D-Bus
            -> bmcweb (discovers objects via ObjectMapper)
                -> Redfish REST API (HTTPS)
```

This test plan validates the Redfish API endpoints exposed by sonic-redfish on SONiC BMC platforms, verifying end-to-end functionality from data source to REST response.

# Scope

This test plan covers:

- Authentication (basic auth, certificate-based mTLS)
- Certificate generation, installation, and TLSStrict enforcement
- Redfish service root discovery (`/redfish/v1`)
- Chassis inventory and identity (`/redfish/v1/Chassis`)
- System inventory (`/redfish/v1/Systems`)
- Firmware inventory (`/redfish/v1/UpdateService/FirmwareInventory`)
- Computer system reset actions (`/redfish/v1/Systems/system/Actions/ComputerSystem.Reset`)
- Rack Manager alert (`/redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitAlert`)
- Rack Manager telemetry (`/redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitTelemetry`)
- Rack Manager Event subscription (`redfish/v1/EventService/Subscriptions`)
- D-Bus infrastructure health and D-Bus Objects (sonic-dbus-bridge, ObjectMapper)
- Graceful degradation behavior when data sources are unavailable


# Scale and Performance

No scale and performance testing is involved in this test plan. Each Redfish endpoint is tested for functional correctness with a single BMC DUT.

# Test Infrastructure

## Testbed Requirements


| Component      | Requirement                                                                |
| :--------------- | :--------------------------------------------------------------------------- |
| DUT            | SONiC BMC platform (Aspeed AST2720/AST2700) running sonic-aspeed-arm64.bin |
| Network        | Management network connectivity between test server and BMC                |
| Docker         | `docker-redfish` container running on BMC with bmcweb \+ sonic-dbus-bridge |
| Authentication | Admin user credentials or certificates configured on BMC                   |

## Test Utilities

Tests use the `requests` Python library for REST API validation (no PTF/scapy needed, as these are management-plane API tests, not data-plane packet tests).

A shared `redfish_utils.py` helper module provides:

- `RedfishClient` class for session management
- Response validation helpers
- JSON schema comparison utilities

## Test Directory Structure

```
sonic-mgmt/tests/redfish/
├── __init__.py
├── conftest.py                          # BMC-specific fixtures
├── redfish_utils.py                     # Shared Redfish test utilities
├── test_redfish_service_root.py         # Service root tests
├── test_redfish_chassis.py              # Chassis inventory tests
├── test_redfish_firmware_inventory.py   # Firmware inventory tests
├── test_redfish_computer_reset.py       # ComputerSystem.Reset action tests
├── test_redfish_rack_manager.py         # Rack Manager alert/telemetry tests
├── test_redfish_event_subscription.py   # EventService subscription tests
├── test_redfish_dbus_health.py          # D-Bus infrastructure tests
└── test_redfish_graceful_degradation.py # Degradation behavior tests
└── test_redfish_cert_auth.py            # Certificate-based authentication tests
```

# Supported Topology

The test will be supported on `any` topology with a physical BMC device (`device_type: physical`, `asic_type: aspeed`).

# Redfish Endpoints Under Test


| \# | Method | Endpoint                                                                                           | Priority | Description                       |
| :--- | :------- | :--------------------------------------------------------------------------------------------------- | :--------- | :---------------------------------- |
| 1  | GET    | `/redfish/v1`                                                                                      | P0       | Service root — device discovery  |
| 2  | GET    | `/redfish/v1/Chassis`                                                                              | P0       | Chassis collection                |
| 3  | GET    | `/redfish/v1/Chassis/chassis`                                                                      | P0       | Chassis identity and inventory    |
| 4  | GET    | `/redfish/v1/Systems`                                                                              | P0       | Systems collection                |
| 5  | GET    | `/redfish/v1/Systems/system`                                                                       | P0       | System identity and state         |
| 6  | POST   | `/redfish/v1/Systems/system/Actions/ComputerSystem.Reset`                                          | P0       | CPU power control                 |
| 7  | GET    | `/redfish/v1/UpdateService/FirmwareInventory`                                                      | P1       | Firmware version collection       |
| 8  | POST   | `/redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitAlert`               | P1       | Rack Manager alert submission     |
| 9  | POST   | `/redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitTelemetry`           | P1       | Rack Manager telemetry submission |
| 10 | GET    | `/redfish/v1/EventService/Subscriptions`                                                           | P1       | Event subscriptions list          |
| 11 | POST   | `/redfish/v1/EventService/Subscriptions`                                                           | P1       | Create event subscription         |
| 12 | DELETE | `/redfish/v1/EventService/Subscriptions/{id}`                                                      | P1       | Delete event subscription         |

# D-Bus Services Under Test


| D-Bus Service Name                 | Interface                               | Purpose                          |
| :----------------------------------- | :---------------------------------------- | :--------------------------------- |
| `xyz.openbmc_project.Inventory`    | `xyz.openbmc_project.Inventory.Manager` | Chassis/system inventory objects |
| `xyz.openbmc_project.ObjectMapper` | `xyz.openbmc_project.ObjectMapper`      | Object discovery for bmcweb      |

# Test Cases

## Pre-Test Preparation

- Verify the DUT is a SONiC BMC platform (`show platform summary` returns aspeed platform)
- Verify `docker-redfish` container is running (`docker ps | grep redfish`)
- Verify `sonic-dbus-bridge` systemd service is active (`systemctl is-active sonic-dbus-bridge`)
- Record the BMC management IP address
- Verify HTTPS connectivity to the BMC on port 443

---

## Section 1: Service Root Discovery

### Test Case \#1 — Service root is accessible


| Field        | Value                                  |
| :------------- | :--------------------------------------- |
| **Test ID**  | `test_redfish_service_root_accessible` |
| **Priority** | P0                                     |
| **Endpoint** | `GET /redfish/v1`                      |

**Steps:**

1. Send `GET /redfish/v1` to the BMC
2. Validate HTTP response status code is `200`
3. Validate `Content-Type` header contains `application/json`

### Test Case \#2 — Service root contains required fields


| Field        | Value                              |
| :------------- | :----------------------------------- |
| **Test ID**  | `test_redfish_service_root_fields` |
| **Priority** | P0                                 |
| **Endpoint** | `GET /redfish/v1`                  |

**Steps:**

1. Send `GET /redfish/v1` to the BMC
2. Validate the response JSON contains the following required fields:
   - `@odata.id` equals `/redfish/v1`
   - `@odata.type` contains `ServiceRoot`
   - `RedfishVersion` is present and non-empty
   - `Product` equals `SONiCBMC`
   - `UUID` is present and non-empty
3. Validate the response contains navigation links:
   - `Chassis.@odata.id` equals `/redfish/v1/Chassis`
   - `Systems.@odata.id` equals `/redfish/v1/Systems`

### Test Case \#3 — Unauthenticated access is not rejected


| Field        | Value                               |
| :------------- | :------------------------------------ |
| **Test ID**  | `test_redfish_service_root_no_auth` |
| **Priority** | P0                                  |
| **Endpoint** | `GET /redfish/v1`                   |

**Steps:**

1. Send `GET /redfish/v1` to the BMC
2. Validate HTTP response status code is `200`
3. Validate `Content-Type` header contains `application/json`
---

## Section 2: Chassis Inventory

### Test Case \#4 — Chassis collection is accessible


| Field        | Value                             |
| :------------- | :---------------------------------- |
| **Test ID**  | `test_redfish_chassis_collection` |
| **Priority** | P0                                |
| **Endpoint** | `GET /redfish/v1/Chassis`         |

**Steps:**

1. Send `GET /redfish/v1/Chassis`
2. Validate HTTP status is `200`
3. Validate `Members@odata.count` is \>= 1
4. Validate `Members` array contains at least one entry with `@odata.id`

### Test Case \#5 — Chassis identity fields are populated


| Field        | Value                             |
| :------------- | :---------------------------------- |
| **Test ID**  | `test_redfish_chassis_identity`   |
| **Priority** | P0                                |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis` |

**Steps:**

1. Send `GET /redfish/v1/Chassis/chassis`
2. Validate HTTP status is `200`
3. Validate the following identity fields are present and non-empty:
   - `SerialNumber`
   - `Manufacturer`
   - `Model`
   - `PartNumber`
4. Cross-validate `SerialNumber` with the value from `show platform syseeprom` on the BMC CLI
5. Cross-validate `Model` with the value stored in Redis `CHASSIS_INFO|chassis 1` → `model`

### Test Case \#6 — Chassis D-Bus objects match Redfish output


| Field        | Value                                   |
| :------------- | :---------------------------------------- |
| **Test ID**  | `test_redfish_chassis_dbus_consistency` |
| **Priority** | P1                                      |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis`       |

**Steps:**

1. SSH into the BMC DUT
2. Run `busctl get-property xyz.openbmc_project.Inventory /xyz/openbmc_project/inventory/system/chassis xyz.openbmc_project.Inventory.Decorator.Asset SerialNumber`
3. Send `GET /redfish/v1/Chassis/chassis`
4. Validate the `SerialNumber` from D-Bus matches the `SerialNumber` from the Redfish response
5. Repeat for `Manufacturer`, `Model`, and `PartNumber`

---

## Section 3: Systems Inventory

### Test Case \#7 — Systems collection is accessible


| Field        | Value                             |
| :------------- | :---------------------------------- |
| **Test ID**  | `test_redfish_systems_collection` |
| **Priority** | P0                                |
| **Endpoint** | `GET /redfish/v1/Systems`         |

**Steps:**

1. Send `GET /redfish/v1/Systems`
2. Validate HTTP status is `200`
3. Validate `Members@odata.count` is \>= 1

### Test Case \#8 — System identity and power state


| Field        | Value                            |
| :------------- | :--------------------------------- |
| **Test ID**  | `test_redfish_system_identity`   |
| **Priority** | P0                               |
| **Endpoint** | `GET /redfish/v1/Systems/system` |

**Steps:**

1. Send `GET /redfish/v1/Systems/system`
2. Validate HTTP status is `200`
3. Validate `PowerState` is one of: `On`, `Off`, `PoweringOn`, `PoweringOff`
4. Validate `@odata.type` contains `ComputerSystem`

---

## Section 4: Firmware Inventory

### Test Case \#9 — Firmware inventory collection


| Field        | Value                                             |
| :------------- | :-------------------------------------------------- |
| **Test ID**  | `test_redfish_firmware_inventory_collection`      |
| **Priority** | P1                                                |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService/FirmwareInventory`
2. Validate HTTP status is `200`
3. Validate `Members@odata.count` \>= 1
4. Validate expected members exist (e.g., `BMC`, `BIOS`, `CPLD`)

### Test Case \#10 — Individual firmware component version


| Field        | Value                                                 |
| :------------- | :------------------------------------------------------ |
| **Test ID**  | `test_redfish_firmware_component_version`             |
| **Priority** | P1                                                    |
| **Endpoint** | `GET /redfish/v1/UpdateService/FirmwareInventory/BMC` |

**Steps:**

1. Send `GET /redfish/v1/UpdateService/FirmwareInventory/BMC`
2. Validate HTTP status is `200`
3. Validate `Version` field is present and non-empty
4. Cross-validate with `show platform firmware status` on the BMC CLI for the BMC component version

---

## Section 5: Computer System Reset

### Test Case \#11 — Reset with valid ResetType "On"


| Field        | Value                                                          |
| :------------- | :--------------------------------------------------------------- |
| **Test ID**  | `test_redfish_computer_reset_on`                               |
| **Priority** | P0                                                             |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with body `{"ResetType": "On"}`
2. Validate HTTP status is `200` or `204`
3. Wait for the system to come up (if it was powered off)
4. Validate the system power state via `GET /redfish/v1/Systems/system` shows `PowerState: On`

### Test Case \#12 — Reset with valid ResetType "GracefulShutdown"


| Field        | Value                                                          |
| :------------- | :--------------------------------------------------------------- |
| **Test ID**  | `test_redfish_computer_reset_graceful_shutdown`                |
| **Priority** | P0                                                             |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Verify the system is currently powered on
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with body `{"ResetType": "GracefulShutdown"}`
3. Validate HTTP status is `200` or `204`
4. Wait for the system to shut down
5. Power the system back on via `{"ResetType": "On"}` to restore state

### Test Case \#13 — Reset with valid ResetType "ForceOff"


| Field        | Value                                                          |
| :------------- | :--------------------------------------------------------------- |
| **Test ID**  | `test_redfish_computer_reset_force_off`                        |
| **Priority** | P0                                                             |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Verify the system is currently powered on
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with body `{"ResetType": "ForceOff"}`
3. Validate HTTP status is `200` or `204`
4. Wait and validate `PowerState` transitions to `Off`
5. Power the system back on via `{"ResetType": "On"}` to restore state

### Test Case \#14 — Reset with valid ResetType "PowerCycle"


| Field        | Value                                                          |
| :------------- | :--------------------------------------------------------------- |
| **Test ID**  | `test_redfish_computer_reset_power_cycle`                      |
| **Priority** | P0                                                             |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Verify the system is currently powered on
2. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with body `{"ResetType": "PowerCycle"}`
3. Validate HTTP status is `200` or `204`
4. Wait for the system to power cycle and come back up
5. Validate `PowerState` returns to `On`

### Test Case \#15 — Reset with invalid ResetType is rejected


| Field        | Value                                                          |
| :------------- | :--------------------------------------------------------------- |
| **Test ID**  | `test_redfish_computer_reset_invalid_type`                     |
| **Priority** | P1                                                             |
| **Endpoint** | `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` |

**Steps:**

1. Send `POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset` with body `{"ResetType": "InvalidType"}`
2. Validate HTTP status is `400` (Bad Request)
3. Validate the error response body contains a Redfish error message

---

## Section 6: Rack Manager Alert

### Test Case \#16 — Submit a valid Rack Manager alert


| Field        | Value                                                                                              |
| :------------- | :--------------------------------------------------------------------------------------------------- |
| **Test ID**  | `test_redfish_rack_manager_submit_alert`                                                           |
| **Priority** | P0                                                                                                 |
| **Endpoint** | `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitAlert`          |

**Steps:**

1. Send `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitAlert` with a valid alert payload containing required fields (e.g., `MessageId`, `MessageArgs`, `OriginOfCondition`)
2. Validate HTTP status is `200` or `204`
3. Validate the response body confirms the alert was accepted

### Test Case \#17 — Submit alert with missing required fields is rejected


| Field        | Value                                                                                              |
| :------------- | :--------------------------------------------------------------------------------------------------- |
| **Test ID**  | `test_redfish_rack_manager_submit_alert_invalid`                                                   |
| **Priority** | P1                                                                                                 |
| **Endpoint** | `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitAlert`          |

**Steps:**

1. Send `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitAlert` with an empty body `{}`
2. Validate HTTP status is `400` (Bad Request)
3. Validate the error response body contains a Redfish-compliant error object

---

## Section 7: Rack Manager Telemetry

### Test Case \#18 — Submit valid Rack Manager telemetry


| Field        | Value                                                                                              |
| :------------- | :--------------------------------------------------------------------------------------------------- |
| **Test ID**  | `test_redfish_rack_manager_submit_telemetry`                                                       |
| **Priority** | P0                                                                                                 |
| **Endpoint** | `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitTelemetry`      |

**Steps:**

1. Send `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitTelemetry` with a valid telemetry payload containing required fields (e.g., `MetricReportValues`, `Timestamp`)
2. Validate HTTP status is `200` or `204`
3. Validate the response body confirms the telemetry data was accepted

### Test Case \#19 — Submit telemetry with missing required fields is rejected


| Field        | Value                                                                                              |
| :------------- | :--------------------------------------------------------------------------------------------------- |
| **Test ID**  | `test_redfish_rack_manager_submit_telemetry_invalid`                                               |
| **Priority** | P1                                                                                                 |
| **Endpoint** | `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitTelemetry`      |

**Steps:**

1. Send `POST /redfish/v1/Managers/Bmc/Oem/SONiC/RackManagerInterface/Actions/SONiC.SubmitTelemetry` with an empty body `{}`
2. Validate HTTP status is `400` (Bad Request)
3. Validate the error response body contains a Redfish-compliant error object

---

## Section 8: Rack Manager Event Subscription

### Test Case \#20 — List event subscriptions


| Field        | Value                                            |
| :------------- | :------------------------------------------------- |
| **Test ID**  | `test_redfish_event_subscriptions_list`          |
| **Priority** | P1                                               |
| **Endpoint** | `GET /redfish/v1/EventService/Subscriptions`     |

**Steps:**

1. Send `GET /redfish/v1/EventService/Subscriptions`
2. Validate HTTP status is `200`
3. Validate `Members@odata.count` is present
4. Validate `Members` is an array

### Test Case \#21 — Create and delete an event subscription


| Field        | Value                                                  |
| :------------- | :------------------------------------------------------- |
| **Test ID**  | `test_redfish_event_subscription_create_delete`        |
| **Priority** | P1                                                     |
| **Endpoint** | `POST/DELETE /redfish/v1/EventService/Subscriptions`   |

**Steps:**

1. Send `POST /redfish/v1/EventService/Subscriptions` with body:

```json
{"Destination": "https://test-listener:8443/events", "Protocol": "Redfish", "EventTypes": ["Alert"]}
```

2. Validate HTTP status is `201` (Created)
3. Extract the subscription `@odata.id` from the response
4. Send `GET` on the subscription `@odata.id`
5. Validate the subscription exists with the correct `Destination` and `Protocol`
6. Send `DELETE` on the subscription `@odata.id`
7. Validate HTTP status is `200` or `204`
8. Send `GET` on the subscription `@odata.id`
9. Validate HTTP status is `404` (subscription no longer exists)

### Test Case \#22 — Event subscription with invalid destination is rejected


| Field        | Value                                                  |
| :------------- | :------------------------------------------------------- |
| **Test ID**  | `test_redfish_event_subscription_invalid_destination`  |
| **Priority** | P1                                                     |
| **Endpoint** | `POST /redfish/v1/EventService/Subscriptions`          |

**Steps:**

1. Send `POST /redfish/v1/EventService/Subscriptions` with body containing an invalid or missing `Destination` field
2. Validate HTTP status is `400` (Bad Request)
3. Validate the error response body contains a Redfish-compliant error object

---

## Section 9: D-Bus Infrastructure Health

### Test Case \#23 — sonic-dbus-bridge service is running


| Field        | Value                             |
| :------------- | :---------------------------------- |
| **Test ID**  | `test_dbus_bridge_service_active` |
| **Priority** | P0                                |

**Steps:**

1. SSH into the BMC DUT
2. Run `systemctl is-active sonic-dbus-bridge`
3. Validate the output is `active`

### Test Case \#24 — D-Bus Inventory service is registered


| Field        | Value                            |
| :------------- | :--------------------------------- |
| **Test ID**  | `test_dbus_inventory_registered` |
| **Priority** | P0                               |

**Steps:**

1. SSH into the BMC DUT
2. Run `busctl status xyz.openbmc_project.Inventory`
3. Validate the command succeeds (return code 0)
4. Run `busctl tree xyz.openbmc_project.Inventory`
5. Validate the output contains `/xyz/openbmc_project/inventory/system/chassis`

### Test Case \#25 — D-Bus ObjectMapper is functional


| Field        | Value                               |
| :------------- | :------------------------------------ |
| **Test ID**  | `test_dbus_objectmapper_functional` |
| **Priority** | P0                                  |

**Steps:**

1. SSH into the BMC DUT
2. Run:

```
busctl call xyz.openbmc_project.ObjectMapper \
  /xyz/openbmc_project/object_mapper \
  xyz.openbmc_project.ObjectMapper \
  GetSubTree sias /xyz/openbmc_project/inventory 0 1 \
  xyz.openbmc_project.Inventory.Item.Chassis
```

3. Validate the command succeeds and returns at least one chassis object path
4. Validate the returned service name is `xyz.openbmc_project.Inventory`

---

## Section 10: Graceful Degradation

### Test Case \#26 — Redfish works when Redis is temporarily unavailable


| Field        | Value                              |
| :------------- | :----------------------------------- |
| **Test ID**  | `test_redfish_degraded_redis_down` |
| **Priority** | P1                                 |

**Steps:**

1. SSH into the BMC DUT
2. Stop the Redis service: `systemctl stop redis`
3. Wait 5 seconds for sonic-dbus-bridge to detect the change
4. Send `GET /redfish/v1/Chassis/chassis`
5. Validate HTTP status is `200` (endpoint still available)
6. Validate identity fields fall back to safe defaults (e.g., `SerialNumber` may be empty or `N/A`)
7. Restart Redis: `systemctl start redis`
8. Wait for the 30-second polling interval
9. Send `GET /redfish/v1/Chassis/chassis` again
10. Validate the identity fields are repopulated with real data

### Test Case \#27 — Redfish works when FRU EEPROM is unreadable


| Field        | Value                                   |
| :------------- | :---------------------------------------- |
| **Test ID**  | `test_redfish_degraded_fru_unavailable` |
| **Priority** | P1                                      |

**Steps:**

1. SSH into the BMC DUT and verify `sonic-dbus-bridge` logs for FRU read status
2. Send `GET /redfish/v1/Chassis/chassis`
3. Validate HTTP status is `200`
4. If FRU is not present on the test platform, validate that fields sourced from FRU (e.g., `SerialNumber`) fall back to Redis or platform.json values or safe defaults
5. Validate the `sonic-dbus-bridge` systemd journal shows appropriate fallback logging

---

## Section 11: Error Handling

### Test Case \#28 — Invalid endpoint returns 404


| Field        | Value                               |
| :------------- | :------------------------------------ |
| **Test ID**  | `test_redfish_invalid_endpoint_404` |
| **Priority** | P1                                  |
| **Endpoint** | `GET /redfish/v1/InvalidResource`   |

**Steps:**

1. Send `GET /redfish/v1/InvalidResource`
2. Validate HTTP status is `404`
3. Validate the response body contains a Redfish-compliant error object with `error.code` and `error.message`

### Test Case \#29 — Unsupported HTTP method returns 405


| Field        | Value                                 |
| :------------- | :-------------------------------------- |
| **Test ID**  | `test_redfish_unsupported_method_405` |
| **Priority** | P1                                    |
| **Endpoint** | `DELETE /redfish/v1/Chassis/chassis`  |

**Steps:**

1. Send `DELETE /redfish/v1/Chassis/chassis` (unsupported method on this resource)
2. Validate HTTP status is `405` (Method Not Allowed)

---

## Section 12: Certificate-Based Authentication (mTLS)

Certificate-based tests use a `bmc_tls_certs` pytest fixture that handles the full lifecycle:

1. **Setup** — Generates CA, server, and client certificates using `openssl` inside the sonic-mgmt container. Copies them to the BMC via `sshpass+scp`, installs them into the `redfish` Docker container, and enables `TLSStrict` in bmcweb.
2. **Tests run** — All tests in this section use the generated client certificate.
3. **Teardown** — Removes the CA certificate from the BMC truststore, restores `TLSStrict=false` in bmcweb, and restarts the service, leaving the BMC in Basic Auth mode.

### Test Case \#30 — Certificates are installed on the BMC

| Field        | Value                          |
| :------------- | :------------------------------- |
| **Test ID**  | `test_cert_installed_on_bmc`   |
| **Priority** | P0                             |

**Steps:**

1. Verify the server certificate exists at `redfish:/etc/ssl/certs/https/server.pem`
2. Verify the CA certificate exists at `redfish:/etc/ssl/certs/authority/CA-cert.pem`
3. Verify bmcweb is running (`supervisorctl status bmcweb` shows `RUNNING`)

### Test Case \#31 — Valid client certificate is accepted

| Field        | Value                          |
| :------------- | :------------------------------- |
| **Test ID**  | `test_valid_cert_accepted`     |
| **Priority** | P0                             |
| **Endpoint** | `GET /redfish/v1`              |

**Steps:**

1. Send `GET /redfish/v1` with the generated client certificate and key, verified against the CA certificate
2. Validate HTTP status is `200`

### Test Case \#32 — Certificate auth works for authenticated endpoints

| Field        | Value                                     |
| :------------- | :------------------------------------------ |
| **Test ID**  | `test_cert_auth_on_authenticated_endpoint` |
| **Priority** | P0                                        |
| **Endpoint** | `GET /redfish/v1/Chassis/chassis`         |

**Steps:**

1. Send `GET /redfish/v1/Chassis/chassis` using only the client certificate (no Basic Auth credentials)
2. Validate HTTP status is `200`
3. Validate the response contains `@odata.id`

### Test Case \#33 — Missing certificate is rejected when TLSStrict is enabled

| Field        | Value                        |
| :------------- | :----------------------------- |
| **Test ID**  | `test_no_cert_rejected`      |
| **Priority** | P0                           |
| **Endpoint** | `GET /redfish/v1`            |

**Steps:**

1. Send `GET /redfish/v1` with no client certificate (TLSStrict is enabled)
2. Validate the request fails with `TLSV13_ALERT_CERTIFICATE_REQUIRED` (TLS handshake error) or HTTP `401`/`403`

### Test Case \#34 — Certificate signed by untrusted CA is rejected

| Field        | Value                        |
| :------------- | :----------------------------- |
| **Test ID**  | `test_wrong_ca_rejected`     |
| **Priority** | P1                           |
| **Endpoint** | `GET /redfish/v1`            |

**Steps:**

1. Generate a fresh self-signed certificate not signed by the BMC's trusted CA
2. Send `GET /redfish/v1` with the untrusted certificate
3. Validate the request fails with `SSLV3_ALERT_BAD_CERTIFICATE` (TLS error) or HTTP `401`/`403`

---

# Test Execution Summary


| Section                              | \# Tests | Priority | Status |
| :------------------------------------- | :--------- | :--------- | :------- |
| Service Root Discovery               | 3        | P0       | NA     |
| Chassis Inventory                    | 3        | P0/P1    | NA     |
| Systems Inventory                    | 2        | P0       | NA     |
| Firmware Inventory                   | 2        | P1       | NA     |
| Computer System Reset                | 5        | P0/P1    | NA     |
| Rack Manager Alert                   | 2        | P0/P1    | NA     |
| Rack Manager Telemetry               | 2        | P0/P1    | NA     |
| Rack Manager Event Subscription      | 3        | P1       | NA     |
| D-Bus Infrastructure Health          | 3        | P0       | NA     |
| Graceful Degradation                 | 2        | P1       | NA     |
| Error Handling                       | 2        | P1       | NA     |
| Certificate-Based Authentication     | 5        | P0/P1    | NA     |
| **Total**                            | **34**   |          |        |

# Open Items

1. No open items at this time.


