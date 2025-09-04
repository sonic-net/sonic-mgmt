# Optics Insertion and Removal Test Plan

## Scope

This test plan outlines a comprehensive framework for testing the optics insertion and removal(OIR) of CMIS compliant transceivers being onboarded to SONiC. It includes both physical OIR (where transceivers are physically inserted and removed) and simulated OIR (where OIR is simulated using on-device command or script). The goal is to automate all tests listed in this document.

**Optics Scope**:
The test plan includes various optics types, such as:

- Active Optical Cables (AOC)
- Active Electrical Cables (AEC)
- DR8 optics
- Direct Attach Cables (DAC)
- Short Range/Long Range (SR/LR) optics
- SONiC-supported breakout cables

**Optics Specifications**:
Tests will cover optics compliant with:

- CMIS
- C-CMIS
- SFF-8636
- SFF-8436
- SFF-8472

## Testbed Topology

Please refer to the [Testbed Topology](./transceiver_onboarding_test_plan.md#testbed-topology) section.

## Test Cases

**Pre-requisites for the Below Tests:**

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases) must be met.

2. `physical_oir_attributes.json` located in `ansible/files/transceiver/inventory` directory should be present to define the attributes for the physical OIR tests. The schema is defined in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases). Following attributes are applicable here:

| Attribute | Type | Default | Mandatory | Description |
|-----------|------|---------|------------|-------------|
| port_under_test | List | All | No | A list under `dut_specific.dut_name` containing the ports to be tested for physical OIR test.<br>This attribute must exist only under `dut_specific` field. | 
| physical_oir_timeout | Int | 30 | No | The timeout value in minutes to wait for the optics to be inserted/removed. |
| simultaneous_oir | Bool | False | No | A flag indicating whether to allow simultaneous OIR operations on multiple ports. |
| physical_oir_stress_iteration | Int | 5 | No | The number of iterations to stress test the physical OIR process. |
| monitor_kernel_errors | Bool | False | No | A flag indicating whether to monitor kernel errors during the test. |


3. `soft_oir_attributes.json` located in `ansible/files/transceiver/inventory` directory should be present to define the attributes for the soft OIR tests. The schema is defined in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases).

| Attribute | Type | Default | Mandatory | Description |
|-----------|------|---------|------------|-------------|
| port_under_test | List | All | No | A list under `dut_specific.dut_name` containing the ports to be tested for soft OIR test.<br>This attribute must exist only under `dut_specific` field. | 
| soft_oir_timeout | Int | 10 | No | The timeout value in seconds to wait for the soft OIR process to complete. |
| soft_oir_stress_iteration | Int | 5 | No | The number of iterations to stress test the soft OIR process. |
| monitor_kernel_errors | Bool | False | No | A flag indicating whether to monitor kernel errors during the test. |

#### 1.1 Optics Insertion and Removal Testing

This section outlines the test cases for validating the insertion and removal of optics in SONiC. The tests cover both physical and simulated OIR scenarios, ensuring that the system behaves correctly when optics are inserted or removed.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Optics removal validation| 1. Physically remove the optical module under test.| 1. Transceiver eeprom command should return "SFP EEPROM not detected" with exit code 0.<br>2. DOM values should not be present for the interface.<br>3. Interface should go oper down.<br>4.Other interfaces on the device should stay up.<br>5. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Optics insertion validation| 1. Insert the optical module under test.| 1. Transceiver eeprom command should return correct values with exit code 0.<br>2. Expected DOM values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen.<br>5. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 3 | Simultaneous Physical OIR | 1. Physically remove all optical modules under test simultaneously.<br>2. Physically insert all optical modules under test simultaneously.| 1. All the expected results from TC#1 for all ports under test.<br>2. All the expected results from TC#2 for all ports under test.|
| 4 | Simulated OIR test| 1. Perform the simulated OIR on the module under test.| 1. Transceiver eeprom command should return correct values with exit code 0.<br>2. Expected DOM values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen.<br>5. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 5 | Physical OIR stress test| 1. Perform the physical OIR process `physical_oir_stress_iteration` times in quick succession.| 1. All the expected results from TC#2 after last insertion.|
| 6 | Simulated OIR stress test| 1. Perform the simulated OIR process `soft_oir_stress_iteration` times.| 1. All the expected results from TC#4 after the last simulated OIR.|


#### CLI commands

Refer to [CLI commands](./transceiver_onboarding_test_plan.md#cli-commands) section for the CLI commands used in the above test cases.