# Transceiver Onboarding Test Plan

## Scope

This test plan outlines a comprehensive framework for ensuring feature parity for new transceivers being onboarded to SONiC. The goal is to automate all tests listed in this document, covering the following areas:

- **Link Behavior**: Test link behavior using shut/no shut commands and under process crash scenarios.
- **Transceiver Information Fields**: Verify transceiver specific fields (Vendor name, part number, serial number) via CLI commands, ensuring values match expectations.
- **Firmware**: Check firmware version readability and compliance with vendor-suggested values, using regex for version pattern matching.
- **DOM Data**: Ensure Digital Optical Monitoring (DOM) data is correctly read and within acceptable ranges.
- **Flags and Alerts**: Confirm no unexpected flags (e.g., Loss of Signal (LOS), Loss of Lock (LOL), DOM warnings) are set.
- **Firmware Management**: Test firmware upgrade and downgrade processes under various scenarios.
- **Remote Reseat**: Verify support for remote reseat functionality.

**Transceiver Specific Capabilities** (if available):

- Adjustments to frequency and tx power.
- Configuration of different Forward Error Correction (FEC) modes.
- For breakout cables, ensure specific lanes are correctly modified by shut/no shut or lane specific commands.

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

A total of 2 ports of a device with the onboarding transceiver should be connected with a cable. Each of these ports can be on the same device or different devices as well. In the case of a breakout cable, the expectation is to connect all sides of the cable to the DUT and test each port individually.

1. Topology with both ports connected on the same SONiC device (self loopback)

    ```text
    +-----------------+
    |           Port 1|<----+
    |                 |     | Loopback
    |    Device       |     | Connection
    |           Port 2|<----+
    |                 |
    +-----------------+
    ```

2. Topology with port connected on different SONiC devices

    ```text

    +-----------------+     +-----------------+
    |           Port 1|<--->|Port 1           |
    |                 |     |                 |
    |    Device 1     |     |     Device 2    |
    |                 |     |                 |
    |                 |     |                 |
    +-----------------+     +-----------------+
    ```

3. Topology with port connected between SONiC and a server using a Y-cable

    ```text
    +-----------------+       +-----------------+
    |                 |<----->|Port 1           |
    |           Port 1|       |     Server      |
    |    Device 1     |<----->|Port 2           |
    |                 |       |                 |
    |                 |       |                 |
    +-----------------+       +-----------------+
    ```

## Test Cases

### 1. Tests not involving traffic

These tests do not require traffic and are standalone, designed to run on a Device Under Test (DUT) with the transceiver plugged into 2 ports, connected by a cable.

**Breakout Cable Assumptions for the Below Tests:**

- All sides of the breakout cable should be connected to the DUT, and each port should be tested individually.
- For link toggling tests on a subport, it's crucial to ensure that the link status of neighboring subports (those belonging to the same breakout port group) remains unaffected.

**Pre-requisites for the Below Tests:**

1. A file "transceiver_static_info.yaml" should be present to describe the metadata of the transceiver. Following should be the format of the file

    ```yaml
    topology:
        <device_name>:
            <port_name>:
                active_firmware: <active_firmware_version>
                inactive_firmware: <inactive_firmware_version>
                cmis_rev: <cmis_revision>
                vendor_date: <vendor_date_code>
                vendor_name: <vendor_name>
                vendor_oui: <vendor_oui>
                vendor_pn: <part_number>
                vendor_rev: <revision_number>
                vendor_sn: <serial_number>
                dual_bank_support: <yes_or_no>
    ```

#### 1.1 Link related tests

The following tests aim to validate the link status and stability of transceivers under various conditions.

| Step | Goal | Expected Results |
|------|------|------------------|
| Issue CLI command to shutdown a port | Validate link status using CLI configuration | Ensure both local and remote sides are linked down |
| Issue CLI command to startup a port | Validate link status using CLI configuration | Ensure both local and remote sides are linked up, and both ports appear in the LLDP table. For CMIS-supported transceivers, verify the CMIS state machine initializes the port successfully on the first attempt |
| In a loop, issue startup/shutdown command 100 times | Stress test for link status validation | Ensure link status toggles to up/down appropriately with each startup/shutdown command. Verify ports appear in the LLDP table when the link is up |
| Restart `xcvrd` | Test link stability | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table |
| Induce I2C errors and restart `xcvrd` | Test link stability in case of `xcvrd` restart + I2C errors | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table |
| Restart `pmon` | Validate module re-initialization and link status post-process crash | Ensure `xcvrd` restarts and the expected port links up again, with port details visible in the LLDP table |
| Restart `swss` | Validate module re-initialization and link status post-process crash | Ensure `xcvrd` restarts and the expected port links up again, with port details visible in the LLDP table |
| Restart `syncd` | Validate module re-initialization and link status post-process crash | Ensure `xcvrd` restarts and the expected port links up again, with port details visible in the LLDP table |
| Perform a config reload | Test module re-initialization and link status | Ensure `xcvrd` restarts and the expected port links up again, with port details visible in the LLDP table |
| Execute a cold reboot | Validate module re-initialization and link status post-device reboot | Confirm the expected port links up again post-reboot, with port details visible in the LLDP table |
| Execute a warm reboot | Test link stability through the reboot process | Ensure `xcvrd` restarts and maintains link stability for the interested ports, with their presence confirmed in the LLDP table |

**Note:** For CMIS-supported transceivers, it's crucial to monitor the CMIS state machine's behavior closely, especially during initialization and reboot scenarios, to ensure compatibility and performance within the SONiC environment.

#### 1.2 sfputil Command Tests

The following tests aim to validate various functionalities of the transceiver using the `sfputil` command.

| Step | Goal | Expected Results |
|------|------|------------------|
| Reset the module followed by issuing shutdown and then startup command | Module reset validation | Ensure both local and remote sides are linked down after reset, and the local port is in low power mode. The shutdown and startup commands are later issued to re-initialize the port and bring the link up |
| Put module in low power mode followed by issuing shutdown and then startup command | Module low power mode validation | Ensure both local and remote sides are linked down after putting the module in low power mode. Ensure that the local port is in low power mode. The shutdown and startup commands are later issued to re-initialize the port and bring the link up |
| Verify if transceiver presence works with CLI | Module presence validation | Ensure module presence is detected |
| Verify EEPROM of the module using CLI | Module specific fields validation from EEPROM | Ensure module specific fields are matching with the values retrieved from "transceiver_static_info.yaml" file |
| Verify EEPROM DOM of the module using CLI when interface is in shutdown and no shutdown state | EEPROM DOM validation | Ensure the fields are in line with the expectation based on interface shutdown/no shutdown state |
| Verify EEPROM hexdump of the module using CLI | Module EEPROM hexdump validation | Ensure the output shows Lower Page (0h) and Upper Page (0h) for all 128 bytes on each page. Also, ensure that page 11h shows the Data Path state correctly |
| Verify firmware version of the module using CLI | Firmware version validation | Ensure the active and inactive firmware version is in line with the expectation |
| Verify different types of loopback | Module loopback validation | Ensure that the various supported types of loopback work on the module. The LLDP neighbor can also be used to verify the data path after enabling loopback |

#### 1.3 sfpshow Command Tests

The following tests aim to validate various functionalities of the transceiver using the `sfpshow` command.

| Step | Goal | Expected Results |
|------|------|------------------|
| Verify transceiver specific information through CLI | Validate CLI relying on redis-db | Ensure module specific fields match the values retrieved from "transceiver_static_info.yaml" file |
| Verify DOM data is read correctly and is within an acceptable range | Validate CLI relying on redis-db | Ensure DOM data is read correctly and falls within the acceptable range |
| Verify transceiver status when the interface is in shutdown and no shutdown state | Validate CLI relying on redis-db | Ensure the fields align with expectations based on the interface being in shutdown or no shutdown state |
| Verify transceiver error-status | Validate CLI relying on redis-db | Ensure the relevant port is in an "OK" state |
| Verify transceiver error-status with hardware verification | Validate CLI relying on module hardware | Ensure the relevant port is in an "OK" state |

#### 1.4 Firmware Related Tests

All the firmware related tests assume that the DOM monitoring is disabled for the corresponding port.

| Step | Goal | Expected Results |
|------|------|------------------|
| Download invalid firmware | Firmware download validation | Ensure that the active and inactive firmware versions do not change. Also, ensure no link flap is seen during this process. |
| Execute “reboot” or kill the process which is downloading the firmware | Firmware download validation | Ensure that the active and inactive firmware versions do not change. Also, ensure no link flap is seen during this process. |
| Download firmware which is valid | Firmware download validation | Look for a “Firmware download complete success” message to confirm if the firmware is downloaded successfully. Also, a return code of 0 will denote CLI executed successfully. The inactive firmware version should show the firmware which was downloaded, and also ensure no link flap is seen. |
| Execute module reset after firmware download | Firmware download validation | Ensure that the active and inactive firmware versions do not change. Ensure the link goes down after the module reset is performed, and then perform shutdown followed by startup to bring the link up. |
| Execute firmware run command | Firmware run validation | Look for a “Firmware run in mode=0 success” message to confirm if the firmware is successfully running. Also, a return code of 0 will denote CLI executed successfully. With the firmware version dump CLI, ensure the “Active Firmware” shows the new firmware version. |
| Execute firmware commit command | Firmware commit validation | Look for a “Firmware commit successful” message. Please do not proceed further if this message is not seen. Also, a return code of 0 will denote CLI executed successfully. With the firmware version dump CLI, ensure the “Committed Image” field is updated with the relevant bank. Also, ensure no link flap is seen during this process. |
| Execute module reset post firmware run | Firmware run validation | Ensure that the active and inactive firmware versions are the same as what was captured before initiating the firmware run. |

#### 1.5 Remote Reseat Testing

The following tests aim to validate the functionality of remote reseating of the transceiver module.

| Step | Goal | Expected Results |
|------|------|------------------|
| Issue CLI command to disable DOM monitoring | Remote reseat validation | Ensure that the DOM monitoring is disabled for the port |
| Issue CLI command to shutdown the port | Remote reseat validation | Ensure that the port is linked down |
| Reset the module | Module reset validation | Ensure port is in low power mode |
| Sleep for 5 seconds | Remote reseat validation | Dump transceiver EEPROM and ensure valid contents are seen |
| Put module in low power mode (if LPM supported) | Remote reseat validation | Ensure that the local port is in low power mode |
| Put module in high power mode (if LPM supported) | Remote reseat validation | Ensure that the local port is in high power mode |
| Issue CLI command to startup the port | Remote reseat validation | Ensure both local and remote sides are linked up and both ports are seen in the LLDP table. For CMIS supported transceivers, ensure the CMIS state machine initializes the port in the first attempt |
| Issue CLI command to enable DOM monitoring for the port | Remote reseat validation | Ensure that the DOM monitoring is enabled for the port |


#### CLI commands

Issuing shutdown command for a port
```
sudo config interface shutdown <port>
```

Issuing startup command for a port
```
sudo config interface startup <port>
```

Check link status of a port
```
show interface status <port>
```

show lldp table
```
show lldp table
```

Enable/disable DOM monitoring for a port

**Note:** For breakout cables, always issue this command for the first subport within the breakout port group, irrespective of the specific subport currently in use.
```
config interface transceiver dom <port> enable/disable

Verification
redis-cli -n 4 hget "PORT|<port>" "dom_polling"

Expected o/p
For enable: "dom_polling" = "enabled" or "(nil)"
For disable: "dom_polling" = "disabled"
```


Check if CMIS initialization is successful in 1st attempt
```
1. Ensure the o/p "CMIS: <port>: READY" is seen upon executing the below command
sudo cat /var/log/syslog | grep READY

2. To ensure CMIS initialization is successful in 1st attempt, execute the below command and ensure not o/p is seen
cat syslog | grep $lport | grep DP_ACTIVATION | grep -v retries=0
```

Restart xcvrd

```
docker exec pmon supervisorctl restart xcvrd
```

Ensure from syslogs that xcvrd has restarted (below command should return the o/p being searched for)

```
sudo cat /var/log/syslog | grep "SfpStateUpdateTask: Posted all port DOM/SFP info to DB"
```

Ensure from syslogs that no link flap was observed for any ports (below command should return no o/p)

```
sudo cat /var/log/syslog | grep updatePort
```

Restart pmon

```
sudo systemctl restart pmon
```

Restart swss

```
sudo systemctl restart swss
```

Restart syncd

```
sudo systemctl restart syncd
```

config reload

```
sudo config reload
```

Cold reboot

```
sudo reboot -f
```

Warm reboot

```
sudo warm-reboot
```

sfputil reset

```
CLI
sudo sfputil reset <port>
```

Check if the port is in low power mode

```
sudo sfputil show lpmode -p <port>
```

Put port in low power mode

```
sudo sfputil lpmode on <port>
```

Check lpmode status of a port

```
sudo sfputil show lpmode -p <port>
```

Check if transceiver is present

```
sudo sfputil show presence -p <port>
```

Dump EEPROM of the module

```
sudo sfputil show eeprom -p <port>
```

Dump EEPROM DOM information of the module and verify fields based on the below information

```
sudo sfputil show eeprom -d -p <port>

Verification
For a port in shutdown state, following fields need to be verified
Local port
TX<lane_id>Bias is 0mA
TX<lane_id>Power is 0dBm

Remote port
RX<lane_id>Power is -40dBm

For a port in no shutdown state, following fields need to be verified
Local port
TX<lane_id>Bias is non-zero
TX<lane_id>Power is non-zero

Remote port
RX<lane_id>Power is non-zero
```

Dump EEPROM hexdump of the module

```
sudo sfputil show eeprom-hexdump -p <port> -n <PAGE_NUM>
```

Loopback commands

```
sudo sfputil debug loopback <port> <loopback_type>
```

Check transceiver specific information through CLI relying on redis-db

```
show int transceiver info <port>
```

Check DOM data through CLI relying on redis-db

```
show int transceiver dom <port>
```

Check transceiver status through CLI relying on redis-db and verify fields based on the below information

```
show int transceiver status <port>

Verification
For a port in shutdown state, following fields need to be verified
Local port
"TX disable status on lane <lane_id>" is True
"Disabled TX channels" is set for the corresponding lanes
"Data path state indicator on host lane <lane_id>" is DataPathInitialized
"Tx output status on media lane <lane_id>" is False
"Tx loss of signal flag on host lane <lane_id>" is True
"Tx clock and data recovery loss of lock on host lane <lane_id>" is True
"CMIS State (SW):" is READY

Remote port
"Rx loss of signal flag on media lane <lane_id>" is True
"Rx output status on host lane <lane_id>" is False
"Rx clock and data recovery loss of lock on media lane <lane_id>" is True
"Rx power low warning flag on lane <lane_id> is set
"Rx power low alarm flag on lane <lane_id> is set"

For a port in no shutdown state, following fields need to be verified
Local port
"TX disable status on lane <lane_id>" is False
"Disabled TX channels" is set to 0 for the corresponding lanes
"Data path state indicator on host lane <lane_id>" is DataPathActivated
"Tx output status on media lane <lane_id>" is True
"Tx loss of signal flag on host lane <lane_id>" is False
"Tx clock and data recovery loss of lock on host lane <lane_id> is False
Verify all the fields containing warning/alarm flags are set to False
"CMIS State (SW):" is READY

Remote port
"Rx loss of signal flag on media lane <lane_id>" is False
"Rx output status on host lane <lane_id>" is True
"Rx clock and data recovery loss of lock on media lane <lane_id>" is False
Verify all the fields containing warning/alarm flags are set to False
```

Check transceiver error-status through CLI relying on redis-db

```
show int transceiver error-status <port>
```

Check transceiver error-status through CLI relying on module HW

```
show int transceiver error-status -hw <port>
```

Check FW version of the module

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
