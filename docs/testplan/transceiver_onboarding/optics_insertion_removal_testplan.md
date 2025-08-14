# CMIS CDB Firmware Upgrade Test Plan

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

1. A file `transceiver_dut_info.csv` (located in `ansible/files/transceiver_inventory` directory) should be present to describe the metadata of the transceiver connected to every port of each DUT. The format of the file is defined in [Transceiver DUT Information Format](./transceiver_onboarding_test_plan.md#1-tests-not-involving-traffic)

2. A file named `transceiver_common_attributes.csv` (located in the `ansible/files/transceiver_inventory` directory) must be present to define the common attributes for each transceiver, keyed by normalized vendor part number. The format of the file is defined in [Transceiver DUT Information Format](./transceiver_onboarding_test_plan.md#1-tests-not-involving-traffic)

3. A file (`sonic_{inv_name}_links.csv`) containing the connections of the ports should be present. This file is used to create the topology of the testbed which is required for minigraph generation.

    - `inv_name` - inventory file name that contains the definition of the target DUTs. For further details, please refer to the [Inventory File](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md#inventory-file)

**Attributes for  the below tests**

Following test attributes under `optics_insertion_removal` attribute category are applicable:

| Attribute | Type | Default | Mandatory | Description |
|-----------|------|---------|------------|-------------|
| port_under_test | Dict | None | Yes | A dictionary containing the device name as the key and list of ports to be tested as its value |
| firmware_versions | Dict | None | Yes | A dictionary containing the normalized transceiver product number as the key and list of firmware versions to be tested as its value |
| firmware_download_timeout_minutes | Dict | 30 | No | A nested dictionary containing platform type as the outer key and normalized product number as the inner key and timeout value in minutes as the integer value |
| restore_initial_firmwares | Bool | False | No | A flag indicating whether to restore the initial active and inactive firmware versions after testing is completed |
| firmware_download_stress_iterations | Int | 5 | No | The number of iterations to stress test the firmware download process |
| firmware_activation_stress_iterations | Int | 5 | No | The number of iterations to stress test the firmware activation process |
| firmware_download_abort_method | String | "sfputil_reset" | No | The method to abort the firmware download process. It can be one of the following strings: "ctrl_c", "sfputil_reset", "optic_reinsert" |
| firmware_download_abort_percentage | List | `[10, 50, 90]` | No | The percentage of download progress at which the firmware download should be aborted. | 


> Note: The test attributes HLD is in progress. The test attributes mentioned in this doc might change once the HLD is finalized.

#### 1.1 Optics Insertion and Removal Testing

**Prerequisites:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that cannot support CDB background mode.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped during firmware operations.
3. **Firmware requirements:**
   - The firmware version specified  by `firmware_versions` test attribute must be available.
   - All firmware versions must support the CDB protocol for proper testing.
4. **Module capabilities:** The module must support dual banks for firmware upgrade operations.
5. **Network connectivity:** The DUT must have network access to the firmware server specified in `cmis_cdb_firmware_base_url.csv` for downloading firmware binaries.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Optics removal validation| 1. Physically remove the optical module.| 1. Transceiver eeprom command should return "SFP EEPROM not detected" with exit code 0.<br>2. DOM values should not be present for the interface.<br>3. Interface should go oper down.<br>4.Other interfaces on the device should stay up.<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Optics insertion validation| 1. Insert the optical module.| 1. Transceiver eeprom command should return correct values with exit code 0.<br>2. Expected DOM values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen.<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 3 | Simulated OIR test| 1. Insert the optical module.| 1. Transceiver eeprom command should return correct values with exit code 0.<br>2. Expected DOM values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen.<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 4 | Physical OIR stress test| 1. Insert the optical module.| 1. Transceiver eeprom command should return correct values with exit code 0.<br>2. Expected DOM values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen.<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 5 | Simulated OIR stress test| 1. Insert the optical module.| 1. Transceiver eeprom command should return correct values with exit code 0.<br>2. Expected DOM values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen.<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |


#### CLI commands

**Note**

1. `<port>` in the below commands should be replaced with the logical port number i.e. EthernetXX

2. `<namespace>` in the below commands should be replaced with the asic of the port.

Issuing shutdown command for a port
```
sudo config interface -n '<namespace>' shutdown <port>
```

Issuing startup command for a port
```
sudo config interface -n '<namespace>' startup <port>
```

Check link status of a port
```
show interface status <port>
```

Enable/disable DOM monitoring for a port

**Note:** For breakout cables, always issue this command for the first subport within the breakout port group, irrespective of the specific subport currently in use.
```
config interface -n '<namespace>' transceiver dom <port> enable/disable

Verification
sonic-db-cli -n '<namespace>' CONFIG_DB hget "PORT|<port>" "dom_polling"

Expected o/p
For enable: "dom_polling" = "enabled" or "(nil)"
For disable: "dom_polling" = "disabled"
```

Restart `xcvrd`

```
docker exec pmon supervisorctl restart xcvrd
```

Get uptime of `xcvrd`

```
docker exec pmon supervisorctl status xcvrd | awk '{print $NF}'
```

Start/Stop `thermalctld` (if applicable)

```
docker exec pmon supervisorctl start thermalctld
OR
docker exec pmon supervisorctl stop thermalctld
```

CLI to get link flap count from redis-db

```
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "flap_count"
```

CLI to get link uptime/downtime from redis-db

```
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "last_up_time"
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "last_down_time"
```

Restart `pmon`

```
sudo systemctl restart pmon
```

Restart `swss`

```
sudo systemctl restart swss
```

Restart `syncd`

```
sudo systemctl restart syncd
```

sfputil reset

```
sudo sfputil reset <port>
```

Check if transceiver is present

```
sudo sfputil show presence -p <port>
```

Dump EEPROM of the transceiver

```
sudo sfputil show eeprom -p <port>
```

Check transceiver specific information through CLI relying on redis-db

```
show int transceiver info <port>
```

Check transceiver error-status through CLI relying on redis-db

```
show int transceiver error-status <port>
```

Check transceiver error-status through CLI relying on transceiver HW

```
show int transceiver error-status -hw <port>
```

Check FW version of the transceiver

```
sudo sfputil show fwversion <port>
```

Download firmware

```
sudo sfputil download <port> <fwfile>
```

Run firmware

```
sudo sfputil firmware run <port>
```

Commit firmware

```
sudo sfputil firmware commit <port>
```

Finding I2C errors from dmesg

```
dmesg -T -L -lerr
```
