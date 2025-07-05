
# DASH ENI Based Forwarding test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
There are two possible NPU-DPU Traffic forwarding models.

1) VIP based model
    * Controller allocates VIP per DPU, which is advertised and visible from anywhere in the cloud infrastructure.
    * The host has the DPU VIP as the gateway address for its traffic.
    * Simple, decouples a DPU from switch.
    * Costly, since you need VIP per DPU.

2) ENI Based Forwarding
    * The host has the switch VIP as the gateway address for its traffic.
    * Cheaper, since only VIP per switch is needed (or even per a row of switches).
    * ENI placement can be directed even across smart switches.

Due to cost constraints, ENI Based Forwarding is the preferred approach.
Feature HLD: https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/eni-based-forwarding.md  


### Scope
There are [2 phases](https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/eni-based-forwarding.md?plain=1#L102-L115) for the ENI Based Forwarding feature.
Currently we are focusing on phase 1 only.

The full tests for ENI Based Forwarding feature should include three parts:
1. Migrate existing Private Link tests to use ENI Forwarding Approach. Until HaMgrd is available, test should write configuration to the DASH_ENI_FORWARD_TABLE.
2. Add individual test cases which verify forwarding to remote endpoint and also Tunnel Termination. This should not require HA availability.
3. HA test cases should work by just writing the expected configuration to DASH_ENI_FORWARD_TABLE. **This is not in the scope of this test plan.**

The configration in DASH_ENI_FORWARD_TABLE is not persistent, it disappears after reload/reboot. So, the reload/reboot test is not in the scope.

### Testbed
The test will run on a single dut Smartswitch light mode testbed.

### Setup configuration
Until HaMgrd is available, we can only write configuration to the DASH_ENI_FORWARD_TABLE.
DASH_ENI_FORWARD_TABLE schema: https://github.com/r12f/SONiC/blob/user/r12f/ha2/doc/smart-switch/high-availability/smart-switch-ha-detailed-design.md#2321-dash_eni_forward_table

Common tests configuration:
- Test will be based on the basic private link configuration.
- Need apply the configuration for DPU_TABLE, VIP_TABLE, VXLAN_TUNNEL, VNET in config_db according to the dash PL config.

Common tests cleanup:
- Remove the basic private link configuration.
- Remove the configuration for DPU_TABLE, VIP_TABLE, VXLAN_TUNNEL, VNET in config_db.

We need apply the config for DPU_TABLE, VIP_TABLE, VXLAN_TUNNEL and VNET into NPU config_db.
Example:
```
{
    "DPU_TABLE": {
        "1": {
            "type": "local",
            "state": "up",
            "pa_ipv4": "10.0.0.75",
            "npu_ipv4": "10.1.0.32"
        },
        "2": {
              "type": "cluster",
              "state": "up",
              "pa_ipv4": "10.0.0.79",
              "npu_ipv4": "10.1.0.32"
        }
    },
    "VIP_TABLE": {
       "10.2.0.1/32" : {}
    },
    "VXLAN_TUNNEL": {
        "tunnel1": {
            "src_ip": "<Loopback of NPU>"
        }
    },
    "VNET": {
        "Vnet1000": {
            "vxlan_tunnel": "tunnel1",
            "vni": "1000"
        }
    }
}
```

In a full functional HA testbed, the hamgrd should generate the entry in DASH_ENI_FORWARD_TABLE based on the above configuration. And this will be covered in the HA test.
In this test, we are not going to deploy and test the full HA fuctionality, so we still need to apply the DASH_ENI_FORWARD_TABLE via swssconfig to the APPL_DB.
Example:
```
[
    {
        "DASH_ENI_FORWARD_TABLE:Vnet1000:F4:93:9F:EF:C4:7E":
        {
            "vdpu_ids": "1,2",
            "primary_vdpu": "1",
            "outbound_vni": "1000",
            "outbound_eni_mac_lookup": ""
        },
        "OP": "SET"
    }
]
```
The outbound_vni is optional, it indicates the outbound VNI used by this ENI if it's different from the one in VNET. Each ENI can have its own VNI, such as ExpressRoute Gateway Bypass case. If it's not assigned, this is the vni in the VNET.
This field will be paramterized in the test by a pytest fixture, for the testcase uses this fixture, the outbound_vni will be tested both explicitly and implicitly. By default, we don't configure this field.
This fixture will be used only in test case #1(test_privatelink_basic_transform migrate to ENI based fowarding) to save test run time.

The outbound_eni_mac_lookup is used to decide whether we lookup the src mac or dst mac for ENI. Currenly the feature using this is not available yet. The validation for this field is not in the scope of this test plan. It can be removed from the config.


## Test
### Test case # 1 – test_privatelink_basic_transform migrate to ENI based fowarding
#### Test objective
This is the basic test for PL inbound and outbound packets validation. Migrate this test case to ENI based fowarding.
#### Test steps
* Update the APPLIANCE_VIP to the NPU VIP.
* Update the outer IP dst of the inbound/outbound sent packets to the NPU VIP.
* The tested ENI should be active(local DPU is primary).
* Add a step to check the ACL rules, there should be an flag to enable this check. It's enabled by default.
  * Check the ACL rules for the tested ENI are generated: totally 4 rules - 2 (inbound and outbound) * 2 (with/without Tunnel Termination).
  * Check the ACL rules are correct.
* Keep the other steps unchanged.
* Remove the configuration in DASH_ENI_FORWARD_TABLE.
* Check the ACL rules are removed, if the ACL check is enabled.

### Test case # 2 – test_privatelink_standby_eni_encap
#### Test objective
This is to validate when the PL packets land on NPU which has the tested ENI as standby ENI, the packets should be double encaped and sent to the NPU-NPU tunnel.
#### Test steps
* Apply the configuration for DASH_ENI_FORWARD_TABLE according to the migrated dash PL config.
* The tested ENI should be standby(cluster DPU is primary).
* Send inbound/outbound packets with dst IP of NPU VIP
* Check the packet is sent out through the tunnel.
* Check the received packets has double encaped vxlan header and the src mac/ip are the dut's and the dst mac is the nexthop's and dst ip is the "npu_ipv4" address of the primary DPU in DPU_TABLE.
* Check the inner inbound/outbound packets are not changed.
* Remove the configuration in DASH_ENI_FORWARD_TABLE.

### Test case # 3 – test_privatelink_tunnel_termination
#### Test objective
This is to validate when the double encaped PL packets land on NPU, the tunnel is terminated, and packets are decaped and sent to the local nexthop(DPU).
#### Test steps
* Apply the configuration for DASH_ENI_FORWARD_TABLE according to the migrated dash PL config.
* The tested ENI should be active(local DPU is primary).
* Send double encaped inbound/outbound packets to the NPU.
* The dst IP of the original PL outer header should be NPU VIP.
* The dst mac/ip of the out most vxlan header should be the dut.
* Check no double encaped vxlan packet is sent out by the dut and received by the ptf.
* Check the inbound/outbound packets are fowarded by the dpu and can be received by ptf.
* Check the received packets are as expected after PL transform.
* Change The tested ENI to be standby(cluster DPU is primary).
* Repeat the steps for active ENI, exactly the same results are expected.
* Remove the configuration in DASH_ENI_FORWARD_TABLE.

## TODO


## Open questions
