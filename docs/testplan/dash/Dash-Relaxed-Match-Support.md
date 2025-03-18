# DASH Relaxed Match Support test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
  The feature Relaxed Match is to support dynamic change of VXLAN UDP port on the DPU.
  The configuration is made via swssconfig in the swss container, and it takes effect immediatly after the configuration is applied.
  The purpose of this test is to verify the functionality of dynamic VXLAN UDP port changing on DPU.

### Scope
The test is targeting on the vetification of functionality on a standalone DPU testbed.
The test has two parts:
- Part1: Integrate the functionality test into the existing dash vnet test(https://github.com/sonic-net/sonic-mgmt/blob/master/tests/dash/test_dash_vnet.py).
- Part2: Add a new test file for the negative test cases.

The configration is not persistent, it disappears after reload/reboot. So, the reload/reboot test is not in the scope.

### Testbed
The test will run on standalone DPU testbed.

### Setup configuration
Common tests configuration:
- Test will apply the basic DASH configration for vnet to vnet scenario

Common tests cleanup:
- Remove the vnet to vnet configration

Configuration example to change the port:
```
[​
    {​
        "SWITCH_TABLE:switch": { "vxlan_port": "12345" },​
        "OP": "SET"​
    }​
]​
```

## Test
## Part1 - Functionality test integrated to dash vnet test
### Test objective
Verify VXLAN udp port can be changed dynamically
### Test steps
* The validation of the VxLAN port is integrated to the dash vnet test.
* In each test case, randomly choose a UDP port from list ["default", 4789, 1024, 13330, random_port, 65535].
  * "default" means no vxlan port will be explicitly configured, the traffic will use the default port 4789.
  * 4789 means the default port 4789 will be explicitly configured.
  * 0 to 1023 are the well known ports, they are not tested to avoid unexpected issues.
  * The tested port range is from 1024 to 65535, the first 1024 and last 65535 are always in the list, and randomly add another port from the range.
  * 13330 is the vnet VXLAN_PORT which is used also in the VXLAN vnet test.
  * The port can also be specified by a pytest option.
* In each test case, after the dash configuration, change the VxLAN UDP dst port via swssconfig.
* Run the following traffic validations of the test case with the specified port.

## Part2 - Negative test
### Test case # 1 – Negative traffic validation
#### Test objective
Verify VXLAN udp port can be changed dynamically, and the traffic with the original port is dropped.
#### Test steps
* Configure basic dash vnet configuration.
* Send the traffic with default port 4789, check it is received.
* Change the port to 13330
* Send the traffic with default port 4789, check it is dropped.
* Send the traffic with default port 4789 and verify it can be received.
* Change the port back to 4789
* Send the traffic with port 4789, check it is received.
* Send the traffic with port 13330, check it is dropped.
* Restore the configuration

## TODO
The test is only for standalone DPU testbed. Need to align it to SmartSwitch DPU testbed after the test infra is ready.

## Open questions
