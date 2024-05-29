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
1.  Verify that the `name, parent,` `type sub-type `and` location` for the hardware components matches the following values:
    1.  CPU:
        1.  `name` is "`cpu_core_<index>`"
        1.  `parent` is "`chassis`"
        1.  `type` is "`CPU`"
        1.  `location` is "`cpu_core_0`"
    1.  Exhaust Gas: For each exhaust gas temperature sensor:
        1.  `name `is` `~~"`sensor<index>`"~~  "`exhaust_sensor<index>`"where `<index>` is a numeric value
        1.  `parent` is "`chassis`"
        1.  `type `is` `"`SENSOR`"
        1.  `sub-type` is "`EXHAUST_TEMPERATURE_SENSOR`"
        1.  `location` is "`exhaust_sensor<index>`"
    1.  Heatsink: For each heatsink temperature sensor:
        1.  `name `is` `"`heatsink_sensor<index>`" where `<index>` is a numeric value
        1.  `parent` is "`chassis`"
        1.  `type `is` `"`SENSOR`"
        1.  `sub-type` is "`HEAT_SINK_TEMPERATURE_SENSOR`"
        1.  `location` is "`heatsink_sensor<index>`"
    1.  Inlet: For each inlet temperature sensor:
        1.  `name `is` `"`inlet_sensor<index>`" where `<index>` is a numeric value
        1.  `parent` is "`chassis`"
        1.  `type `is` `"`SENSOR`"
        1.  `sub-type `is "`INLET_TEMPERATURE_SENSOR`"
        1.  `location` is "`inlet_sensor<index>`"
    1.  Dimm: For each dimm temperature sensor:
        1.  `name `is` `"`dimm_sensor<index>`" where `<index>` is a numeric value
        1.  `parent` is "`chassis`"
        1.  `type `is` `"`SENSOR`"
        1.  `sub-type` is "`DIMM_TEMPERATURE_SENSOR`"
        1.  `location` is "`dimm_sensor<index>`"

### Test 2: Fetch temperature information
