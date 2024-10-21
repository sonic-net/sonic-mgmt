# Overview

This document captures the end-to-end verification plan for gNMI platforms hardware paths in GPINs. It covers the following hardware components:

-   CPU
-   Exhaust gas temperature sensor
-   Fan tray
-   FPGAs
-   Heatsink temperature sensor
-   Inlet temperature sensor
-   Dimm temperature sensor
-   Storage devices
-   Power supply unit
-   Integrated circuit
-   Power sequencer
-   Power brick
-   Power voltage regulator
-   Power hotswap

# Test Setup

The test setup consists of a single switch topology in which a test client initializes a gNMI client that connects to the gNMI server running on a single switch under test (SUT). The SUT must be a physical switch since tests require accessing hardware components.

## Test types

The tests that cover the hardware component gNMI paths described in this document fall into three basic test categories.

### Get

A *get* test performs a gNMI get (read) operation for a particular gNMI path. Generally, a get-only test will exercise gNMI *state* paths. These paths are read-only and cannot be modified directly by a gNMI operation. A *state* path can, however, be modified indirectly by a gNMI write operation to a corresponding gNMI *config* path or by a system operation (e.g. a new network stack installation operation).

### Set / Get (SG)

A *set-get* test performs a sequence of gNMI get, set (write), and get operations.  Generally, a *set-get* test exercises that a write to a gNMI *config* path is accepted and updates the corresponding gNMI *state* path.  These tests will perform gNMI set operations on the gNMI *config* path and gNMI get operations on both the *state* and *config* paths.

### Set Invalid / Get (Negative)

A *set-invalid* test is a negative test whose intent is to verify that invalid configuration information results in a gNMI set error or, at the very least, that the invalid configuration does not result in an update to the corresponding gNMI *state* path and that no unexpected exceptions or crashes result.

## Test Summary

<table>
  <thead>
    <tr>
      <th><strong>Area</strong></th>
      <th><strong>Get Tests</strong></th>
      <th><strong>Set/Get Tests</strong></th>
      <th><strong>Set Invalid Tests</strong></th>
      <th><strong>Total</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>CPU + Temperature Sensors</td>
      <td>3</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>3</strong></td>
    </tr>
    <tr>
      <td>Fan Tray</td>
      <td>2</td>
      <td>1</td>
      <td>N/A</td>
      <td><strong>3</strong></td>
    </tr>
    <tr>
      <td>FPGA</td>
      <td>1</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>1</strong></td>
    </tr>
    <tr>
      <td>Storage Device</td>
      <td>1</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>1</strong></td>
    </tr>
    <tr>
      <td>Power Supply Unit</td>
      <td>1</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>1</strong></td>
    </tr>
    <tr>
      <td>Integrated Circuit</td>
      <td>2</td>
      <td>3</td>
      <td>1</td>
      <td><strong>6</strong></td>
    </tr>
    <tr>
      <td>Power Sequencer</td>
      <td>3</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>3</strong></td>
    </tr>
    <tr>
      <td>Power Brick</td>
      <td>3</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>3</strong></td>
    </tr>
    <tr>
      <td>Power Voltage Regulator</td>
      <td>3</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>3</strong></td>
    </tr>
    <tr>
      <td>Power Hotswap</td>
      <td>3</td>
      <td>N/A</td>
      <td>N/A</td>
      <td><strong>3</strong></td>
    </tr>
    <tr>
      <td><strong>Totals</strong></td>
      <td><strong>22</strong></td>
      <td><strong>4</strong></td>
      <td><strong>1</strong></td>
      <td><strong>27</strong></td>
    </tr>
  </tbody>
</table>

# CPU and Temperature Sensors

This section describes the test plan for the following temperature sensors:

-   CPU
-   Exhaust Gas
-   Heatsink
-   Inlet
-   Dimm

## Path Summary

Temperature sensor components consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<cpu>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<cpu>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<cpu>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<cpu>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<cpu>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<exhaust-temperature-sensor>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<exhaust-temperature-sensor>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<exhaust-temperature-sensor>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<exhaust-temperature-sensor>]/sensor/state/sub-type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<exhaust-temperature-sensor>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<exhaust-temperature-sensor>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<heatsink-temperature-sensor>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<heatsink-temperature-sensor>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<heatsink-temperature-sensor>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<heatsink-temperature-sensor>]/sensor/state/sub-type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<heatsink-temperature-sensor>]/sensor/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<heatsink-temperature-sensor>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<inlet-temperature-sensor>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<inlet-temperature-sensor>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<inlet-temperature-sensor>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<inlet-temperature-sensor>]/sensor/state/sub-type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<inlet-temperature-sensor>]/sensor/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<inlet-temperature-sensor>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<dimm-temperature-sensor>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<dimm-temperature-sensor>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<dimm-temperature-sensor>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<dimm-temperature-sensor>]/sensor/state/sub-type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<dimm-temperature-sensor>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<dimm-temperature-sensor>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases
### Test 1: Fetch sensor information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<cpu>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<cpu>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<cpu>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<cpu>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/sensor/state/sub-type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/sensor/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/sensor/state/sub-type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/sensor/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/sensor/state/sub-type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/sensor/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/sensor/state/sub-type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/state/location</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the `name, parent,` `type sub-type `and` location` for the CPU component and exhaust, heatsink, inlet and dimm temperature sensors.
2.  Verify that the `name, parent,` `type sub-type `and` location` for the hardware components matches the following values:
    1.  CPU:
        1.  `name` is "`cpu_core_<index>`"
        2.  `parent` is "`chassis`"
        3.  `type` is "`CPU`"
        4.  `location` is "`cpu_core_0`"
    2.  Exhaust Gas: For each exhaust gas temperature sensor:
        1.  `name `is`exhaust_sensor<index>`"where `<index>` is a numeric value
        2.  `parent` is "`chassis`"
        3.  `type `is`SENSOR`"
        4.  `sub-type` is "`EXHAUST_TEMPERATURE_SENSOR`"
        5.  `location` is "`exhaust_sensor<index>`"
    3.  Heatsink: For each heatsink temperature sensor:
        1.  `name `is "`heatsink_sensor<index>`" where `<index>` is a numeric value
        2.  `parent` is "`chassis`"
        3.  `type `is "`SENSOR`"
        4.  `sub-type` is "`HEAT_SINK_TEMPERATURE_SENSOR`"
        5.  `location` is "`heatsink_sensor<index>`"
    4.  Inlet: For each inlet temperature sensor:
        1.  `name `is "`inlet_sensor<index>`" where `<index>` is a numeric value
        2.  `parent` is "`chassis`"
        3.  `type `is "`SENSOR`"
        4.  `sub-type `is "`INLET_TEMPERATURE_SENSOR`"
        5.  `location` is "`inlet_sensor<index>`"
    5.  Dimm: For each dimm temperature sensor:
        1.  `name `is "`dimm_sensor<index>`" where `<index>` is a numeric value
        2.  `parent` is "`chassis`"
        3.  `type `is "`SENSOR`"
        4.  `sub-type` is "`DIMM_TEMPERATURE_SENSOR`"
        5.  `location` is "`dimm_sensor<index>`"

### Test 2: Fetch temperature information
**Paths Verified:**

<table>
  <thead>
    <tr>
      <td><br>
/components/component[name=<cpu>]/state/temperature/instant</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/state/temperature/instant</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the `temperature` for the CPU component and exhaust, heatsink, inlet and dimm temperature sensors.
2.  Verify that the `temperature` for these hardware components are within a certain threshold. For example, the acceptable temperature range can be 20℃ - 100℃

### Test 3: Sysfs Validation

**Paths Verified:**

<table>
  <thead>
    <tr>
      <td><br>
/components/component[name=<cpu>]/state/temperature/instant</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<exhaust-temperature-sensor>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<heatsink-temperature-sensor>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<inlet-temperature-sensor>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<dimm-temperature-sensor>]/state/temperature/instant</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the `temperature` for the CPU component and exhaust, heatsink, inlet and dimm temperature sensors.
2.  In order to validate that the temperature sensor readings in `temperature` state paths are correct, these readings need to be validated by logging into the switch and fetching the temperature readings from sysfs. The readings might have changed from step 2 so the validation would require certain error margin (e.g  ±10%).

# Fan Components

This section describes the test plan for fan hardware component.

## Path Summary

Fan components consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<fan>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fan>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fan>]/state/mfg-date</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fan>]/state/part-no</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fan>]/state/serial-no</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fan>]/fan/state/speed</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fan>]/fan/state/speed-control-pct</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

### Test 1: Fan hardware information
**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<fan>]/state/type</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<fan>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fan>]/state/mfg-date</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fan>]/state/part-no</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fan>]/state/serial-no</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the `type, location, mfg-date, part-no `and` serial-no` of each fan component present in the switch.
2.  Expect the following results for each fan component:
    1.  `type` is "`FAN`"
    2.  `location` is an integral value representing the fan index.
    3.  `mfg-date, part-no `and` serial-no `are non-empty values.

### Test 2: Fan speed information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<fan>]/fan/state/speed</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<fan>]/fan/state/speed-control-pct</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the `speed `and` speed-control-pct` of each fan component present in the switch.
2.  Expect the following results for each fan component:
    1.  `speed` is a non-negative integral value which is less than the maximum permissible RPM speed of the fan.
    2.  `speed-control-pct` is between 0 and 100.
  
# FPGA

This section describes the test plan for FPGA components.

## Path Summary

FPGAs consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<fpga>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fpga>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fpga>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fpga>]/state/firmware-version</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fpga>]/state/description</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<fpga>]/state/mfg-name</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Fetch FPGA information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<fpga>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<fpga>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fpga>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fpga>]/state/firmware-version</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fpga>]/state/description</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<fpga>]/state/mfg-name</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the `name, type, parent, firmware-version, description `and` mfg-name` for each FPGA present in the switch.
2.  Expect the following results for each FPGA:
    1.  `name` is "`fpga<index>`" where `<index>` is a numeric value
    2.  `type` is "`INTEGRATED_CIRCUIT`"
    3.  `parent` is "`chassis`"
    4.  `firmware-version `and` description` have non-empty values. Valid format for these values needs to be explored.
    5.  `mfg-name` is "`GOOGLE`"

# Storage Devices

This section describes the test plan for storage device components.

## Path Summary

Storage device components consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<storage_device>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<storage_device>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<storage_device>]/state/removable</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<storage_device>]/state/part-no</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<storage_device>]/state/serial-no</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<storage_device>]/state/io-errors</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Storage device information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<storage_device>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<storage_device>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<storage_device>]/state/removable</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<storage_device>]/state/part-no</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<storage_device>]/state/serial-no</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<storage_device>]/state/io-errors</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch `name, type,removable, part-no, serial-no `and` io-errors` for each storage device present in the switch.
2.  Expect the following results for each storage device:
    1.  `name` represents a valid `/dev/<storage_device>`
    2.  `type` is "`STORAGE`"
    3.  `part-no `and` serial-no` have non-empty values. Valid format for these values needs to be explored.
    4.  `removable `is `true` for microSD and `false` for SSD.
    5.  `io-errors` has a non-negative integral value. It need not be present for microSD since it is a removable device.

# Power Supply Unit

This section describes the test plan for the power supply unit component.

## Path Summary

Power supply unit component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<psu>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<psu>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<psu>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<psu>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<psu>]/state/part-no</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<psu>]/state/serial-no</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: PSU information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<psu>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<psu>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<psu>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<psu>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<psu>]/state/part-no</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<psu>]/state/serial-no</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch `name, type, parent, location, part-no `and` serial-no `for each PSU present in the switch.
2.  Expect the following results for each PSU component:
    1.  `name` is "`psu`"
    2.  `type` is "`POWER_SUPPLY`"
    3.  `parent` is "`chassis`"
    4.  `part-no `and` serial-no` have non-empty values. Valid format for these values needs to be explored.
    5.  `location` is TBD

# Integrated Circuits

This section describes the test plan for integrated circuits components.

## Path Summary
Integrated circuits component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/config/name</td>
      <td>Set/Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/state/name</td>
      <td>Set/Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/config/fully-qualified-name</td>
      <td>Set/Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/state/fully-qualified-name</td>
      <td>Set/Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/integrated-circuit/config/node-id</td>
      <td>Set/Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/integrated-circuit/state/node-id</td>
      <td>Set/Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/integrated-circuit/state/counters/corrected-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/integrated-circuit/state/counters/errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<integrated-circuit>]/state/type</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: IC information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<integrated-circuit>]/state/parent</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/state/type</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch `parent`, `type, corrected-errors `and` errors` for the integrated circuit.
2.  Expect the following results:
    1.  `parent` is "`chassis`"
    2.  `type` is "`INTEGRATED_CIRCUIT`"

### Test 2: IC error information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<integrated-circuit>]/integrated-circuit/memory/state/corrected-parity-errors</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/integrated-circuit/memory/state/total-parity-errors</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch `corrected-parity-errors `and` total-parity-errors` for the integrated circuit.
2.  Expect the following results:
    1.  `corrected-parity-errors `and` total-parity-errors `have a non-negative integral value. Additionally, a threshold needs to be defined for the number of `corrected-parity-errors`. The test shall be marked as failed if:
        2.  `corrected-parity-errors `> threshold
        3.  `total-parity-errors `> `corrected-parity-errors `indicating that uncorrected errors have occurred in the integrated-circuit.

### Test 3: Set valid IC name

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<integrated-circuit>]/config/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/config/fully-qualified-name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/state/fully-qualified-name</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values for `name` and `fully-qualified-name.` Expect that the get operation succeeds and both state values are non-empty strings.
2.  Use gNMI set operation to configure the `name` of the integrated circuit as "`integrated_circuit0`".
3.  Use gNMI set operation to configure `fully-qualified-name` of integrated circuit (such as "`ju1u1m1b1s1i1.ibs40.net.google.com`").
4.  Use gNMI get operation to fetch the configured `name` and `fully-qualified-name` and verify that they match the values configured in steps 2 and 3.

This test assumes that a default config with `name` and `fully-qualified-name` fields has already been pushed into the switch before the test starts. If that is not the case then step 1 should be modified as:

-   Use gNMI get operation to fetch the state value of `/components/component[name=<integrated-circuit>]` subtree. Verify that the values returned for the subtree don't have any value for `name` and `fully-qualified-name` leaf nodes.

### Test 4: Set invalid IC name

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<integrated-circuit>]/config/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/state/name</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch `name` of integrated circuit.
2.  Use gNMI set operation to configure the name of the integrated circuit as "`integrated_circuit1`".
3.  Use gNMI get operation to fetch the configured `name`. Verify that it remains unchanged and matches the `name` in step 1.
4.  Use gNMI set operation to configure the name of the integrated circuit as "`invalid_name`".
5.  Use gNMI get operation to fetch the configured `name`. Verify that it remains unchanged and matches the `name` in step 1.

### Test 5: Set node-id

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<integrated-circuit>]/integrated-circuit/config/node-id</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/integrated-circuit/state/node-id</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI set operation to configure `node-id` of integrated circuit (such as `12345678`).
2.  Use gNMI get operation to fetch the configured `node-id` and verify that it matches the value configured in step 1.
3.  Connect with P4RT application on stream channel with the `node-id` configured in step 1.
4.  Verify that the connection succeeds.
5.  Connect with P4RT application on stream channel with a different `node-id`.
6.  Verify that the connection fails.

### Test 6: Persistence after reboot

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<integrated-circuit>]/config/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/config/fully-qualified-name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/state/fully-qualified-name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/integrated-circuit/config/node-id</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<integrated-circuit>]/integrated-circuit/state/node-id</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI set operation to configure of the `name, fully-qualified-name `and` node-id` of the integrated-circuit:
    1.  `name` is "`integrated_circuit0`".
    2.  `fully-qualified-name` is "`ju1u1m1b1s1i1.ibs40.net.google.com`". This is just an example and the value can randomized or configured differently for each test run.
    3.  `node-id` is `12345678`. This is just an example and the value can randomized or configured differently for each test run.
2.  Use gNMI get operation to fetch the state values for `name, fully-qualified-name `and` node-id` of the integrated-circuit.
3.  Expect that:
    1.  `name` is "`integrated_circuit0`".
    2.  `fully-qualified-name` is "`ju1u1m1b1s1i1.ibs40.net.google.com`".
    3.  `node-id` is `12345678`.
4.  Use gNOI `reboot` operation to reboot the switch.
5.  After the switch has successfully rebooted, use gNMI get operation to fetch the state values for `name, fully-qualified-name `and` node-id` of the integrated-circuit.
6.  Expect that these values match the state values fetched in step 3.
7.  Use gNMI get operation to fetch the *configured* values for `name, fully-qualified-name `and` node-id` of the integrated-circuit.
8.  Expect that these values match the configured values in step 1.

# Power Sequencer

This section describes the test plan for the power sequencer component.

## Path Summary

Power sequencer component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<power_sequencer>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/commanded-frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/commanded-output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/input-energy</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/input-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/input-power</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/input-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/manufacturer-status</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/output-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/all-status-vout</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/blackbox</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_sequencer>]/power-supply/state/blackbox-information</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Power sequencer power supply information
**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<power_sequencer>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/all-status-vout</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/blackbox</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/blackbox-information</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for each power sequencer in the switch.
2.  Expect the following values for each power sequencer:
    1.  `name` is `<power_sequence_name>`.
    2.  `parent` is "`chassis`".
    3.  `location` matches the PMBus Address of the power sequencer (expected to be fetched from the switch model in the test).
    4.  `type` is "`POWER_SUPPLY`".
    5.  `temperature ` is a non-negative integral value greater than a certain threshold.
    6.  `type is `"`POWER_SEQUENCER`"`.`
    7.  `commanded-frequency` is non-negative integral value.
    8.  `commanded-output-voltage` is non-negative integral value.
    9.  `frequency` is non-negative integral value.
    10.  `input-energy` is non-negative integral value.
    11.  `input-current` is non-negative integral value.
    12.  `input-voltage` is non-negative integral value.
    13.  `manufacturer-status` is `TBD`.
    14.  `output-current` is non-negative integral value.
    15.  `output-voltage` is non-negative integral value.
    16.  `all-status-vout` is non-negative integral value.
    17.  `blackbox` is `TBD`.
    18.  `blackbox-information` is `TBD`.
3.  Perform platform-specific validations for these values if applicable. However, this document does not specify any values for power sequencer component.

### Test 2: Sysfs Validation

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<power_sequencer>]/state/temperature/instant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/all-status-vout</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/blackbox</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_sequencer>]/power-supply/state/blackbox-information</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for each power sequencer in the switch.
2.  In order to validate that the above readings are correct, these readings need to be validated by logging into the switch and fetching them from sysfs. These readings might have changed from step 2 so the validation would require certain error margin (e.g  ±10%).

# Power Brick

This section describes the test plan for the power brick component.

## Path Summary

Power brick component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<power_brick>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/commanded-frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/commanded-output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/input-energy</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/input-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/input-power</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/input-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/manufacturer-status</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/output-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/mfr-blackbox-data</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_brick>]/power-supply/state/mfr-blackbox-offset</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Power brick power supply information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<power_brick>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/mfr-blackbox-data</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/mfr-blackbox-offset</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for each power brick in the switch.
2.  Expect the following values for each power brick:
    1.  `name` is `<power_brick_name>`.
    2.  `parent` is "`chassis`"
    3.  `location` matches the PMBus Address of the power brick (expected to be fetched from the switch model in the test).
    4.  `type` is "`POWER_SUPPLY`".
    5.  `temperature ` is an integral value greater than a certain threshold.
    6.  `type `is` `"`POWER_BRICK`"`.`
    7.  `commanded-frequency` is non-negative integral value.
    8.  `commanded-output-voltage` is non-negative integral value.
    9.  `frequency` is non-negative integral value.
    10.  `input-energy` is non-negative integral value.
    11.  `input-current` is non-negative integral value.
    12.  `input-voltage` is non-negative integral value.
    13.  `manufacturer-status` is `TBD`.
    14.  `output-current` is non-negative integral value.
    15.  `output-voltage` is non-negative integral value.
    16.  `mfr-blackbox-data` is `TBD`.
    17.  `mfr-blackbox-offset` is `TBD`.
3.  Perform platform-specific validations for these values if applicable. Rows 12 and 13 in this sheet are related to power brick component.

### Test 2: Sysfs Validation

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<power_brick>]/state/temperature/instant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/mfr-blackbox-data</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_brick>]/power-supply/state/mfr-blackbox-offset</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for each power brick in the switch.
2.  In order to validate that the above readings are correct, these readings need to be validated by logging into the switch and fetching them from sysfs. These readings might have changed from step 2 so the validation would require certain error margin (e.g  ±10%).

# Power Voltage Regulator

This section describes the test plan for the power voltage regulator component.

## Path Summary

Power voltage regulator component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/commanded-frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/commanded-output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/input-energy</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/input-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/input-power</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/input-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/manufacturer-status</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/output-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_voltage_regulator>]/power-supply/state/output-voltage</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Power voltage regulator power supply information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<power_voltage_regulator>]/state/name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/output-voltage</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for each voltage regulator in the switch.
2.  Expect the following values for each voltage regulator:
    1.  `name` is `<power_voltage_regulator_name>`.
    2.  `parent` is "`chassis`"
    3.  `location` matches the PMBus Address of the voltage regulator (expected to be fetched from the switch model in the test).
    4.  `type` is "`POWER_SUPPLY`".
    5.  `temperature ` is an integral value greater than a certain threshold.
    6.  `type` is "`POWER_VOLTAGE_REGULATOR`".
    7.  `commanded-output-voltage` is non-negative integral value.
    8.  `frequency` is non-negative integral value.
    9.  `input-voltage` is non-negative integral value.
    10.  `manufacturer-status` is `TBD`.
    11.  `output-current` is non-negative integral value.
    12.  `output-voltage` is non-negative integral value.
3.  Perform platform-specific validations for these values if applicable. Rows 3 to 11 in this sheet are related to power voltage regulator component.

### Test 2: Sysfs Validation

**Paths Verified:**

<table>
  <thead>
    <tr>
      <th><br>
/components/component[name=<power_voltage_regulator>]/state/temperature/instant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_voltage_regulator>]/power-supply/state/output-voltage</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for each voltage regulator in the switch.
2.  In order to validate that the above readings are correct, these readings need to be validated by logging into the switch and fetching them from sysfs. These readings might have changed from step 1 so the validation would require certain error margin (e.g  ±10%).

# Power Hotswap

This section describes the test plan for the power hotswap component.
## Path Summary

Power hotswap component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/location</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/temperature/instant</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/temperature/max</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/state/temperature/interval</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/commanded-frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/commanded-output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/frequency</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/input-energy</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/input-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/input-power</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/input-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/manufacturer-status</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/output-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/peak-input-power</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/peak-input-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/peak-output-current</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/peak-output-voltage</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<power_hotswap>]/power-supply/state/status-gpio</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Power hotswap power supply information

**Paths Verified:**

<table>
  <thead>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/name</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/location</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/temperature/instant</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/temperature/max</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/temperature/interval</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/status-gpio</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for power hotswap.
2.  Expect the following values:
    1.  `name` is `<power_hotswap_name>.`
    2.  `parent` is "`chassis`"
    3.  `location` matches the PMBus Address of the power hotswap (expected to be fetched from the switch model in the test).
    4.  `type` is "`POWER_SUPPLY`".
    5.  `temperature ` is an integral value greater than a certain threshold.
    6.  `max ` is an integral value less than a certain threshold.
    7.  `interval ` is an integral value greater that matches the system uptime. The system uptime can be fetched by either logging into the switch and running `uptime` command.
    8.  `type` is "`POWER_HOTSWAP`".
    9.  `commanded-frequency` is non-negative integral value.
    10.  `commanded-output-voltage` is non-negative integral value.
    11.  `frequency` is non-negative integral value.
    12.  `input-energy` is non-negative integral value.
    13.  `input-current` is non-negative integral value.
    14.  `input-voltage` is non-negative integral value.
    15.  `manufacturer-status` is `TBD`.
    16.  `output-current` is non-negative integral value.
    17.  `output-voltage` is non-negative integral value.
    18.  `peak-input-power` is non-negative integral value.
    19.  `peak-input-voltage` is non-negative integral value.
    20.  `peak-output-voltage` is non-negative integral value.
    21.  `status-gpio` is `TBD`.
3.  Perform platform-specific validations for these values if applicable. However, this document does not specify any values for power hotswap component.

### Test 2: Sysfs Validation

**Paths Verified:**

<table>
  <thead>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/temperature/instant</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/state/temperature/max</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/commanded-frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/commanded-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/frequency</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-energy</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/manufacturer-status</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-input-power</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-input-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-output-current</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/peak-output-voltage</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<power_hotswap>]/power-supply/state/status-gpio</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch the state values of the all the above paths for power hotswap.
2.  In order to validate that the above readings are correct, these readings need to be validated by logging into the switch and fetching them from sysfs. These readings might have changed from step 2 so the validation would require certain error margin (e.g  ±10%).

# Haven

This section describes the test plan for the haven security component.

## Path Summary

Haven security component consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<haven>]/state/name</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/state/type</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/state/parent</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/state/firmware-version</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/state/serial-no</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/hardware-security-module/state/secure-payload-enforced</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/hardware-security-module/state/payload-version</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<haven>]/hardware-security-module/state/payload-signature-type</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Haven information


<table>
  <thead>
    <tr>
      <th><br>
Paths Verified</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/components/component[name=<haven>]/state/name</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/state/type</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/state/parent</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/state/firmware-version</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/state/serial-no</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/hardware-security-module/state/secure-payload-enforced</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/hardware-security-module/state/payload-version</td>
    </tr>
    <tr>
      <td><br>
/components/component[name=<haven>]/hardware-security-module/state/payload-signature-type</td>
    </tr>
  </tbody>
</table>

1.  Use gNMI get operation to fetch `name, type, parent, firmware-version, serial-no, secure-payload-enforced, payload-version `and` payload-signature-type `for the haven component.
2.  Expect the following results (there should only be 1 haven component):
    1.  `name` is "`haven`".
    2.  `type` is "`HARDWARE_SECURITY_MODULE`".
    3.  `parent` is "`chassis`".
    4.  `firmware-version` is not empty.
    5.  `serial-no` is not empty.
    6.  `secure-payload-enforced` is `true`.
    7.  `payload-version` is not empty.
    8.  `payload-signature-type` is "`Invalid|Unsigned|Dev|Prod`".

# Mount Points

This section describes the test plan for the mount points.

## Path Summary

Mount points consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/system/mount-points/mount-point[name=<mount_point>]/state/available</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/system/mount-points/mount-point[name=<mount_point>]/state/size</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: Mount Points information

1.  Use gNMI get operation to fetch all mount points in the switch. Expect that:
    1.  The number of mount points returned are >= the required number of mount points. For Taygeta and Brixia, this number is 14.
2.  For each required mount point, verify that:
    1.  `mount_point `key is amongst the list of expected mount points`.`
    2.  `size` > `0`.
    3.  `available` <= `size`.

# PCIe Errors

This section describes the test plan for the PCIe errors.

## Path Summary

PCIe errors consists of the following gNMI paths:

<table>
  <thead>
    <tr>
      <th><strong>Path</strong></th>
      <th><strong>Type</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/total-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/undefined-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/data-link-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/surprise-down-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/poisoned-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/flow-control-protocol-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/completion-timeout-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/completion-abort-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/unexpected-completion-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/receiver-overflow-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/malformed-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/ecrc-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/unsupported-request-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/acs-violation-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/internal-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/blocked-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/atomic-op-blocked-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/fatal-errors/tlp-prefix-blocked-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/total-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/undefined-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/data-link-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/surprise-down-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/poisoned-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/flow-control-protocol-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/completion-timeout-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/completion-abort-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/unexpected-completion-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/receiver-overflow-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/malformed-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/ecrc-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/unsupported-request-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/acs-violation-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/internal-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/blocked-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/atomic-op-blocked-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/tlp-prefix-blocked-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/total-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/receiver-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/bad-tlp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/bad-dllp-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/relay-rollover-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/replay-timeout-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/advisory-non-fatal-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/internal-errors</td>
      <td>Get</td>
    </tr>
    <tr>
      <td>/components/component[name=<pcie-device>]/state/pcie/correctable-errors/hdr-log-overflow-errors</td>
      <td>Get</td>
    </tr>
  </tbody>
</table>

## Test Cases

### Test 1: PCIe information

1.  Use gNMI get operation to fetch state values of the above Openconfig paths for BCM chip and Google FPGA.
2.  Expect that:
    1.  All the above Openconfig paths are populated for both the PCIe devices.
    2.  `total-errors` <= sum of individual errors. However, `total-errors` != 0 if individual errors > 0 since at least a single error message must have  been received.
    3.  Fail the test if a fatal error counter is non-zero. This will help us report standalone testbeds that need repair.

### Test 2: Hardware PCIe error injection

This test injects hardware PCIe errors in the Broadcom chip by toggling it's reset pin. BCM chip toggling might produce either correctable or uncorrectable PCIe errors. The type of errors generated is non-deterministic. Therefore, the entire snapshot of PCIe error information needs to be taken before injecting errors and compared with the snapshot after injecting errors.

`/components/component[name=<pcie-device>]/state/pcie/fatal-errors/total-errors, /components/component[name=<pcie-device>]/state/pcie/non-fatal-errors/total-errors `and` /components/component[name=<pcie-device>]/state/pcie/correctable-errors/total-errors` paths represent the total number of **error messages** received by the root port. A single error message can consist of multiple type of errors of that type. For example, a single correctable error message might consist of 3 different correctable errors encountered by the PCIe device. Therefore, the sum of individual types of error counters might **not** be equal to the total-errors counter. This condition is taken into consideration in the verification step 4.

1.  Use gNMI get operation to fetch all PCIe error counters. (pre error injection counters)
2.  Inject hardware PCIe errors by toggling the Broadcom chip reset pin.  This requires SSHing into the switch.
3.  Use gNMI get operation to fetch all PCIe error counters. (post error injection counters)
4.  For `correctable-errors, non-fatal-errors `and` fatal-errors `subtree, perform the following verifications between pre and post error injection counters:
    1.  If an individual error counter has increased, `total-errors` counter should also increase.
    2.  If `total-errors` counter has increased, then at least one of the individual error counter should also increase.
    3.  `total-errors` counter cannot be incremented by a greater amount than the individual error counters.
    4.  `total-errors` counter of at least one subtree should increase i.e. ensure that at least one correctable/non-fatal/fatal error message was received.
5.  Repeat steps 2 to 4 a few times to inject more PCIe errors and perform validations over greater number of errors.
6.  For `correctable-errors, non-fatal-errors `and` fatal-errors subtree`, validate that error counters reported through gNMI match the error counters reported in sysfs.
7.  Reboot the switch to ensure that the error counters are reset.
