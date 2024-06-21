# Transceiver Onboarding Test Plan

### Scope

The scope of this test plan is to layout a framework of tests to ensure feature parity of new transceivers being onboarded to SONiC. The test plan is planned to be automated.

The below features/properties of the transceiver are to be tested in this test plan.

- Verify link behavior with shut/no shut commands
- Verify link behavior with process crash scenarios
- Verify transceiver specific fields (such as Vendor name, part number and serial number) have expected value using CLI command.
- Ensure that the firmware version can be read and is one of the acceptable values suggested by vendor. The major, minor number and build version can be qualified by a regex match with a predefined pattern
- Verify DOM data is read correctly and is in acceptable range.
- Check if any unexpected flags (such as LOS, LOL, DOM related warnings) are not set
- Ensure firmware download, upgrade and downgrade works fine.
- Ensure that the transceiver supports remote reseat

These are some transceiver specific capabilities which should be tested if available.

- Verify that the transceiver is able to be configured to a different frequency and tx power
- Verify that the transceiver is able to be configured to a different FEC mode
- For breakout cable, ensure that only the specific lanes get affected upon issuing shut/no shut command.


### Testbed Setup

A total of 2 ports of a device with the onboarding transceiver should be connected with a cable. Each of these port can be on the same device or different devices as well.

## Test Cases

1. Tests not involving traffic

    These tests don't require traffic and are standalone tests which can run on a DUT which has the transceiver plugged in 2 ports and are connected with a cable.

    Breakout cable related assumption for the below tests
    - The expectation is to connect all sides of the cable to the DUT and test each port individually.
    - For tests related to link toggling for a subport, it is mandatory to ensure that the link status of the neighboring subports (subports belonging to the same breakout port group) is not affected.

    Pre-requisites for the below tests
    1. A file "transceiver_static_info.yaml" should be present to describe the metadata of the transceiver. Following should be the format of the file

        ```yaml
        topoplogy:
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
        ```

    1.1 Link related tests

    | Step | Goal | Expected results |
    |-|-|-|
    | Issue CLI command to shutdown a port | Link status validation with CLI config | Ensure both local and remote sides are linked down |
    | Issue CLI command to startup a port | Link status validation with CLI config | Ensure both local and remote sides are linked up and both ports are seen in LLDP table. For CMIS supported transceivers, ensure CMIS state machine initializes the port in the first attempt  |
    | In a loop, issue startup/shutdown command 100 times  | Stress test to validate link status with CLI config | Ensure link status is up/down when the relevant startup/shutdown command is issued. Also, ensure ports are seen in LLDP table if link is up |
    | Restart xcvrd | Link stability | Ensure xcvrd has restarted and link doesn't flap for the corresponding ports along with their presence in LLDP table |
    | Restart pmon | Module re-initialization and link up after process crash | Ensure xcvrd has restarted and the expected port links up again along with their presence in LLDP table |
    | Restart swss | Module re-initialization and link up after process crash | Ensure xcvrd has restarted and the expected port links up again along with their presence in LLDP table |
    | Restart syncd | Module re-initialization and link up after process crash | Ensure xcvrd has restarted and the expected port links up again along with their presence in LLDP table |
    | Config reload | Module re-initialization and link up | Ensure xcvrd has restarted and the expected port links up again along with their presence in LLDP table |
    | Cold reboot | Module re-initialization and link up after device reboot | Ensure the expected port links up again along with their presence in LLDP table |
    | Warm reboot | Link stability | Ensure xcvrd has restarted and link doesn't flap for the interested ports along with their presence in LLDP table |

    1.2 sfputil command tests
    | Step | Goal | Expected results |
    |-|-|-|
    | Reset the module followed by issuing shutdown and then startup command | Module reset validation | Ensure both local and remote sides are linked down after reset and the local port is in low power mode. The shutdown and startup commands are later issued to re-initialize the port and bring the link up |
    | Put module in low power mode followed by issuing shutdown and then startup command | Module low power mode validation | Ensure both local and remote sides are linked down after putting the module in low power mode. Ensure that the local port is in low power mode. The shutdown and startup commands are later issued to re-initialize the port and bring the link up |
    | Verify if transceiver presence works with CLI | Module presence validation | Ensure module presence is detected |
    | Verify EEPROM of the module using CLI | Module specific fields validation from EEPROM | Ensure module specific fields are matching with the values retrieved from "transceiver_static_info.yaml" file |
    | Verify EEPROM DOM of the module using CLI when interface is in shutdown and no shutdown state | EEPROM DOM validation | Ensure the fields are inline with the expectation based on interface shutdown/no shutdown state |
    | Verify EEPROM hexdump of the module using CLI | Module EEPROM hexdump validation | Ensure the o/p shows Lower Page (0h) and Upper Page (0h) for all 128 bytes on each page. Also ensure that page 11h shows the Data Path state correctly  |
    | Verify firmware version of the module using CLI | Firmware version validation | Ensure the active and inactive FW version is inline with the expectation |
    | Verify different types of loopback | Module loopback validation | Ensure that the various supported types of loopback work on the module. The LLDP neighbor can also be used to verify data path after enabling loopback |

    1.3 sfpshow command tests
    | Step | Goal | Expected results |
    |-|-|-|
    | Verify transceiver specific information through CLI | Validate CLI relying on redis-db | Ensure module specific fields are matching with the values retrieved from "transceiver_static_info.yaml" file |
    | Verify DOM data is read correctly and is in acceptable range | Validate CLI relying on redis-db | Ensure DOM data is read correctly and is in acceptable range |
    | Verify transceiver status when interface is in shutdown and no shutdown state | Validate CLI relying on redis-db | Ensure the fields are inline with the expectation based on interface shutdown/no shutdown state |
    | Verify transceiver error-status | Validate CLI relying on redis-db | Ensure relevant port is in "OK" state |
    | Verify transceiver error-status -hw | Validate CLI relying on module HW | Ensure relevant port is in "OK" state |

    1.4 Firmware related tests
    | Step | Goal | Expected results |
    |-|-|-|
    | Download invalid firmware | Firmware download validation | Ensure that the active and inactive FW versions do not change. Also, ensure no link flap is seen during this process |
    | Execute “reboot” or kill the process which is downloading the FW | Firmware download validation | Ensure that the active and inactive FW versions do not change. Also, ensure no link flap is seen during this process |
    | Download firmware which is valid | Firmware download validation | Look for “Firmware download complete success” message to confirm if the FW is downloaded successfully. Also, return code 0 will denote CLI executed successfully. The inactive firmware version should show the FW which was downloaded and also ensure no link flap is seen |
    | Execute module reset after firmware download | Firmware download validation | Ensure that the active and inactive FW versions do not change. Ensure link goes down after module reset is performed and then perform shutdown followed by startup to bring the link up |
    | Execute firmware run command | Firmware run validation | Look for “Firmware run in mode=1 success” message to confirm if the FW is successfully running. Also, return code 0 will denote CLI executed successfully. With the FW version dump CLI, ensure “Active Firmware” shows the new FW version |
    | Execute firmware commit command | Firmware commit validation | Look for “Firmware commit successful” message. Please do not proceed further if this message is not seen. Also, return code 0 will denote CLI executed successfully. With the FW version dump CLI, ensure “Committed Image” field is updated with the relevant bank. Also ensure no link flap is seen during this process |
    | Execute module reset post firmware run | Firmware run validation | Ensure that the active and inactive firmware version are same as to what was captured before initiating firmware run |

    1.5 Remote reseat testing
    | Step | Goal | Expected results |
    |-|-|-|
    | Issue CLI command to disable DOM monitoring | Remote reseat validation | Ensure that the DOM monitoring is disabled for the port |
    | Issue CLI command to shutdown the port | Remote reseat validation | Ensure that the port is linked down |
    | Reset the module | Module reset validation | Ensure port is in low power mode |
    | Sleep for 5 seconds | Remote reseat validation | Dump transceiver EEPROM and ensure valid contents are seen |
    | Put module in low power mode (if LPM supported) | Remote reseat validation | Ensure that the local port is in low power mode |
    | Put module in high power mode (if LPM supported) | Remote reseat validation | Ensure that the local port is in high power mode |
    | Issue CLI command to startup a port | Remote reseat validation | Ensure both local and remote sides are linked up and both ports are seen in LLDP table. For CMIS supported transceivers, ensure CMIS state machine initializes the port in the first attempt  |
    | Issue CLI command to enable DOM monitoring for the port | Remote reseat validation | Ensure that the DOM monitoring is enabled for the port |

### CLI commands

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
