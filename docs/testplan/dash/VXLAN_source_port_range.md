# DASH VXLAN source port range test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
  The feature "VXLAN source port range" is to support entropy in the VxLAN UDP source port field on the smartsiwtch.
  A smartswitch DPU should use connection 5-tuple to calculate entropy, and fill it in the VxLAN UDP source port field.
  The entropy should be within the range of [5120, 5247](5120 with 7 bit mask).
  The configuration should be applied on the DPU via swssconfig in the swss container, and it takes effect immediatly after the configuration is applied.
  The purpose of this test is to verify the functionality of VXLAN source port range on smartswitch.


### Scope
The test is targeting on the verification of functionality on a smartswitch testbed.
The feature is tested along with the existing dash private link test, there will be no new dedicated test cases for this feature.
The configration is not persistent, it disappears after reload/reboot. So, the reload/reboot test is not in the scope.

### Testbed
The test will run on a smartswitch testbed with DPUs enabled.

### Setup configuration
Common tests configuration:
- Same as the dash priivate link test.

Common tests cleanup:
- Same as the dash priivate link test.

Configuration example to config the VxLAN UDP source port range:
```
[
    {
        "SWITCH_TABLE:switch": {
            "vxlan_sport": 5120,
            "vxlan_mask": 7
        },
        "OP": "SET"
    }
]
```

## Test
## Functionality test integrated to dash private link test
### Test objective
Verify VXLAN UDP source port range can be configured as user defined range on the smartswitch DPU, and the value of VxLAN UDP source port field in the PL inbound packet sent by DPU is in the range.
### Test steps
* The validation of the VxLAN port is integrated to the dash PL test tests/dash/test_dash_privatelink.py.
* For now there is only one test case in the PL test: test_privatelink_basic_transform.
* The UDP port range configuration(vxlan_sport=5120, vxlan_mask=7) is applied in the setup phase of the PL test module.
* Send the outbound and inbound PL traffic.
* Validate that the VxLAN UDP source port in the captured inbound packet is in the range of [5120, 5247]
* Restore the source port range config to the default by config reload on the DPU.


## TODO
The validation of the VxLAN UDP source port range can be integrated to all future dash test cases if needed.

## Open questions
