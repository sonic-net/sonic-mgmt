# Support BMC Flows Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| Support BMC HLD | [https://github.com/sonic-net/SONiC/pull/2062]|

## Definitions/Abbreviation

| **Definitions/Abbreviation** | **Description** |
|-------------------|----------|
| SONiC | Software for Open Networking in the Cloud |
| BMC | Baseboard Management Controller  |
| RedFish | RESTful management protocol for BMC  |

## Overview

Baseboard Management Controller (BMC) is a specialized microcontroller that provide out-of-band remote monitoring and management capabilities for servers/switches. It operates independently of the switch's main CPU and operating system, allowing administrators to manage the switch even when it is powered off or unresponsive. BMC is a powerful tool that can be used to automate and simplify many tasks associated with managing switches. It can help to improve network efficiency, reliability, and security.

OpenBMC is an open-source project that provides a Linux-based firmware stack for BMC. It implements the Redfish standard, allowing for standardized and secure remote management of server hardware. OpenBMC serves as the software that runs on BMC hardware, utilizing the Redfish API to facilitate efficient hardware management.

Redfish is a standard for managing and interacting with hardware in a datacenter, designed to be simple, secure, and scalable. It works with BMC to provide a RESTful API for remote management of servers. Together, Redfish and BMC enable efficient and standardized hardware management.

In summary, NOS will deal with BMC through the redfish RESTful API.

## Scope

The test is to verify the common platform BMC api and SONiC command lines defined for BMC.

### Scale and Performance

No scale and performance test involved in this test plan.

### SONiC BMC Platform API

BMC API supported in this phase:

Get the BMC name
```
get_name()
```

Get the BMC presence
```
get_presence()
```

Get the BMC model
```
get_model()
```

Get the BMC serial number
```
get_serial()
```

Get the BMC revision
```
get_revision()
```

Get the BMC status
```
get_status()
```

Check if the BMC is replaceable
```
is_replaceable()
```

Get the BMC eeprom values
```
get_eeprom()
```

Get the BMC firmware version
```
get_version()
```

Reset the root password
```
reset_root_password()
```

Trigger the BMC dump
```
trigger_bmc_debug_log_dump()
```

Get the BMC dump
```
get_bmc_debug_log_dump(task_id, filename, path)
```

Install the BMC firmware
```
update_firmware(fw_image)
```

### SONiC BMC Command

show platform bmc summary
```
Manufacturer: NVIDIA
Model: P3809
PartNumber: 699-13809-1404-500
SerialNumber: 1581324710134
PowerState: On
FirmwareVersion: 88.0002.1252
```

show platform firmware status
```
Component    Version                    Description
-----------  -------------------------  ----------------------------------------
ONIE         2025.05-5.3.0017-9600-dev  ONIE - Open Network Install Environment
SSD          0202-000                   SSD - Solid-State Drive
BIOS         0ACLH004_02.02.010_9600    BIOS - Basic Input/Output System
CPLD1        CPLD000120_REV0900         CPLD - Complex Programmable Logic Device
CPLD2        CPLD000254_REV0600         CPLD - Complex Programmable Logic Device
CPLD3        CPLD000191_REV0102         CPLD - Complex Programmable Logic Device
BMC          88.0002.1252               BMC – Board Management Controller
```

show platform bmc eeprom
```
Manufacturer: NVIDIA
Model: P3809
PartNumber: 699-13809-1404-500
PowerState: On
SerialNumber: 1581324710134
```

config platform firmware install component BMC fw -y ${BMC_IMAGE}

### Supported Topology
The test will be supported on t0 and t1 topology.


## Test Cases

### Pre Test Preparation
1. Start platform api service in pmon docker for platform api test usage
2. Get the switch facts

### Test Case # 1 - Test getting BMC name
1. Get the BMC name by BMC platform api get_name()
2. Validate the value existence and value type is string
3. Validate the value is equal to the BMC name in switch facts

### Test Case # 2 - Test getting BMC presence
1. Get the BMC presence status by BMC platform api get_presence()
2. Validate the value existence and value type is bool
3. Validate the value is equal to the BMC presence in switch facts

### Test Case # 3 - Test getting BMC model
1. Get the BMC model by BMC platform api get_model()
2. Validate the value existence and value type is string
3. Validate the value is equal to the BMC model in switch facts

### Test Case # 4 - Test getting BMC serial number
1. Get the BMC serial number by BMC platform api get_serial()
2. Validate the value existence and value type is string
3. Validate the value is equal to the BMC serial number from command 'show platform bmc summary'

### Test Case # 5 - Test getting BMC revision
1. Get the BMC revision by BMC platform api get_revision()
2. Validate the value existence and value type is string
3. Validate the value is equal to 'N/A'

### Test Case # 6 - Test getting BMC status
1. Get the BMC status by BMC platform api get_status()
2. Validate the value existence and value type is bool
3. Validate the value is equal to bool True

### Test Case # 7 - Test getting BMC replaceable value
1. Get the BMC replaceable value by BMC platform api is_replaceable()
2. Validate the value existence and value type is bool
3. Validate the value is equal to bool False

### Test Case # 8 - Test getting BMC eeprom
1. Get the BMC eeprom value by BMC platform api get_eeprom()
2. Validate the value existence and correctness by command 'show platform bmc eeprom'

### Test Case # 9 - Test getting BMC version
1. Get the BMC eeprom value by BMC platform api get_version()
2. Validate the value existence and correctness

### Test Case # 10 - Test reseting BMC root password
1. Reset the BMC root password by BMC platform api reset_root_password
2. Validate the root password had been reset to the default password by login test using Redfish api
3. Change the root password to a new value by using Redfish api
4. Validate login password had been changed by login test using Redfish api
5. Reset the BMC root password by BMC platform api reset_root_password()
6. Validate the root password had been reset to the default password by login test using Redfish api

### Test Case # 11 - Test BMC dump
1. Trigger the BMC dump by BMC platform api trigger_bmc_debug_log_dump()
2. During waiting, check the dump process by BMC platform api get_bmc_debug_log_dump()
3. After BMC dump finished, validate the BMC dump file existence

### Test Case # 12 - Test BMC firmware update
1. Check and record the original BMC firmware version
2. Update the BMC firmware version by command
    'config platform firmware install chassis component BMC fw -y xxx' or
    'config platform firmware update chassis component BMC fw -y'
    depending on completeness_level:
        if the completeness_level is basic, only test one command type randomly
        if the completeness_level is others, test both command types
        in this case,the test test_bmc_firmware_update will be executed twice times
3. Wait after the installation done
4. Validate the BMC firmware had been updated to the destination version by command
    'show platform firmware status'
5. Recover the BMC firmware version to the original one by BMC platform api update_firmware(fw_image)
6. Wait after the installation done
7. Validate the BMC firmware had been restored to the original version by command
    'show platform firmware status'

### Test Case # 13 - Test BMC dump in techsupport
1. Run command 'show techsupport' to generate a switch dump
2. Wait until the dump generated
3. Extract the dump file and validate the BMC dump files existence
