
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
The ENI based forwarding model is only supported in the FNIC scenario.
Feature HLD: https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/eni-based-forwarding.md  


### Scope
There are [2 phases](https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/eni-based-forwarding.md?plain=1#L102-L115) for the ENI Based Forwarding feature.
Currently we are focusing on phase 1 only.

In current stage, the test for ENI Based Forwarding feature will be a switch only test, the DPUs will not be involved.
This test will cover 4 use cases:
1. ENI is active on the dut, packet is fowarded to a local DPU.
2. ENI is standby on the dut, packet is fowarded to a remote DPU.
3. Packet lands on a NPU which doesn't host the corresponding ENI.
4. Tunnel termination.

The configration in DASH_ENI_FORWARD_TABLE is not persistent, it disappears after reload/reboot. So, the reload/reboot test is not in the scope.

### Testbed
The test will run on a single dut Smartswitch light mode testbed.

### Setup configuration
Until HaMgrd is available, we can only write configuration to the DASH_ENI_FORWARD_TABLE.
DASH_ENI_FORWARD_TABLE schema: [https://github.com/r12f/SONiC/blob/user/r12f/ha2/doc/smart-switch/high-availability/smart-switch-ha-detailed-design.md#2321-dash_eni_forward_table](https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/smart-switch-ha-detailed-design.md#2321-dash_eni_forward_table)

Common tests configuration:
- Apply the common config in config_db, including configrations in DEVICE_METADATA, VIP_TABLE, FEATURE, DPU, REMOTE_DPU, VDPU, DASH_HA_GLOBAL_CONFIG tables.
- Apply the config in DASH_ENI_FORWARD_TABLE to the appl_db via swssconfig.

Common tests cleanup:
- Remove the common configrations both in config_db and appl_db.

We need apply the config for DEVICE_METADATA, VIP_TABLE, FEATURE, DPU, REMOTE_DPU, VDPU, DASH_HA_GLOBAL_CONFIG into NPU config_db.
Example:
```
{
    "DEVICE_METADATA": {
        "localhost": {
            "cluster": "t1-smartswitch-01"
        }
    },
    "VIP_TABLE" : {
        "10.1.0.5" : {}
    },
    "FEATURE": {
        "dash-ha" : {
            "auto_restart": "disabled",
            "delayed": "False",
            "has_global_scope": "False",
            "has_per_asic_scope": "False",
            "has_per_dpu_scope": "True",
            "high_mem_alert": "disabled",
            "state": "disabled",
            "support_syslog_rate_limit": "true"
        }
    },
    "DPU": {
        "dpu0": {
            "dpu_id": "0",
            "gnmi_port": "50051",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.1",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.0.202.1",
            "local_nexthop_ip": "18.0.202.1",
            "state": "up",
            "swbus_port": "23606",
            "vdpu_id": "vdpu1_0",
            "vip_ipv4": "10.1.0.5"
        },
        "dpu1": {
            "dpu_id": "1",
            "gnmi_port": "50051",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.2",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.1.202.1",
            "local_nexthop_ip": "18.1.202.1",
            "state": "up",
            "swbus_port": "23607",
            "vdpu_id": "vdpu1_1",
            "vip_ipv4": "10.1.0.5"
        },
        "dpu2": {
            "dpu_id": "2",
            "gnmi_port": "50051",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.3",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.2.202.1",
            "local_nexthop_ip": "18.2.202.1",
            "state": "up",
            "swbus_port": "23608",
            "vdpu_id": "vdpu1_2",
            "vip_ipv4": "10.1.0.5"
        },
        "dpu3": {
            "dpu_id": "3",
            "gnmi_port": "50051",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.4",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.3.202.1",
            "local_nexthop_ip": "18.3.202.1",
            "state": "up",
            "swbus_port": "23609",
            "vdpu_id": "vdpu1_3",
            "vip_ipv4": "10.1.0.5"
        }
    },
    "REMOTE_DPU": {
        "dpu4": {
            "dpu_id": "0",
            "npu_ipv4": "10.1.0.32",
            "pa_ipv4": "18.0.202.1",
            "swbus_port": "23606",
            "type": "cluster"
        },
        "dpu5": {
            "dpu_id": "1",
            "npu_ipv4": "10.1.0.32",
            "pa_ipv4": "18.1.202.1",
            "swbus_port": "23607",
            "type": "cluster"
        },
        "dpu6": {
            "dpu_id": "2",
            "npu_ipv4": "10.1.0.32",
            "pa_ipv4": "18.2.202.1",
            "swbus_port": "23608",
            "type": "cluster"
        },
        "dpu7": {
            "dpu_id": "3",
            "npu_ipv4": "10.1.0.32",
            "pa_ipv4": "18.3.202.1",
            "swbus_port": "23609",
            "type": "cluster"
        }
    },
    "VDPU": {
        "vdpu0_0": {
            "main_dpu_ids": "dpu0"
        },
        "vdpu0_1": {
            "main_dpu_ids": "dpu1"
        },
        "vdpu0_2": {
            "main_dpu_ids": "dpu2"
        },
        "vdpu0_3": {
            "main_dpu_ids": "dpu3"
        },
        "vdpu1_0": {
            "main_dpu_ids": "dpu4"
        },
        "vdpu1_1": {
            "main_dpu_ids": "dpu5"
        },
        "vdpu1_2": {
            "main_dpu_ids": "dpu6"
        },
        "vdpu1_3": {
            "main_dpu_ids": "dpu7"
        }
    },
    "DASH_HA_GLOBAL_CONFIG": {
        "GLOBAL": {
            "dp_channel_dst_port": "7000",
            "dp_channel_probe_fail_threshold": "5",
            "dp_channel_probe_interval_ms": "500",
            "dp_channel_src_port_max": "7010",
            "dp_channel_src_port_min": "7001",
            "dpu_bfd_probe_interval_in_ms": "1000",
            "dpu_bfd_probe_multiplier": "3",
            "vnet_name": "Vnet_55"
        }
    }
}
```

In a full functional HA testbed, the hamgrd should generate the entry in DASH_ENI_FORWARD_TABLE based on the above configuration. And this will be covered in the HA test.
In this test, we are not going to deploy and test the full HA fuctionality, so we still need to apply the DASH_ENI_FORWARD_TABLE via swssconfig to the APPL_DB.
Two ENIs are configured, for ENI1 the primary_vdpu is a local DPU, for ENI2 the primary_vdpu is a remote DPU.
Example:
```
[
    {
        "DASH_ENI_FORWARD_TABLE:Vnet1000:F4:93:9F:EF:C4:7F":
        {
            "vdpu_ids": "vdpu0_0,vdpu1_0",
            "primary_vdpu": "vdpu0_0",
        },
        "OP": "SET"
    },
    {
        "DASH_ENI_FORWARD_TABLE:Vnet1000:F4:93:9F:EF:C4:80":
        {
            "vdpu_ids": "vdpu0_1,vdpu1_1",
            "primary_vdpu": "vdpu1_1",
        },
        "OP": "SET"
    }
]
```

## Test
### Test case # 1 – test_eni_fowarding_local_dpu
#### Test objective
This is to test for when the ENI is active on dut, the packet is forwarded to the local DPU.
#### Test steps
* Common config for config_db and appl_db is already applied by a module scope fixture common_setup_teardown.
* In the common_setup_teardown fixture, check the ACL rules are created:
  * Check the ACL rules for the tested ENIs are generated: for each ENI there should be 2 rules - 1 for redirect, 1 for tunnel termination.
  * Check the ACL rules are correct.
* Craft a VxLAN packet for the ENI1, which is active on the dut. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Configure a static route for the local DPU PA address(due to the config in DPU table, not the real address of the DPU), the nexthop should be a front panel port. In this case we can capture the packet in ptf without involve the DPU in the test.
* Send the packet to the DUT.
* Check the packet can be received by the ptf.
* Check the ACL rules are removed after the common config is removed in common_setup_teardown.

### Test case # 2 – test_eni_fowarding_remote_dpu
#### Test objective
This is to test for when the ENI is standby on dut, the packet is forwarded to the remote DPU through the VxLAN tunnel.
#### Test steps
* Common config for config_db and appl_db is already applied by a module scope fixture common_setup_teardown.
* In the common_setup_teardown fixture, check the ACL rules are created:
  * Check the ACL rules for the tested ENIs are generated: for each ENI there should be 2 rules - 1 for redirect, 1 for tunnel termination.
  * Check the ACL rules are correct.
* Craft a VxLAN packet for the ENI2, which is standby on the dut. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Send inbound/outbound packets with dst IP of NPU VIP
* Send the packet to the DUT.
* Check the packet can be received by the ptf.
* Check the ACL rules are removed after the common config is removed in common_setup_teardown.

### Test case # 3 – test_tunnel_termination
#### Test objective
This is to validate when the double encaped packet lands on NPU, the tunnel is terminated, and packets are decaped and sent to the local nexthop(DPU).
#### Test steps
* Common config for config_db and appl_db is already applied by a module scope fixture common_setup_teardown.
* * In the common_setup_teardown fixture, check the ACL rules are created:
  * Check the ACL rules for the tested ENIs are generated: for each ENI there should be 2 rules - 1 for redirect, 1 for tunnel termination.
  * Check the ACL rules are correct.
* Craft a double VXLAN encaped packet which is the packet redirected from a NPU in which the ENI is standby.
* Configure a static route for the local DPU PA address(due to the config in DPU table, not the real address of the DPU), the nexthop should be a front panel port. In this case we can capture the packet in ptf without involve the DPU in the test.
* Send the packet to the dut.
* Check the packet can be received by the ptf, and there is only one VxLAN header.
* Check the ACL rules are removed after the common config is removed in common_setup_teardown.

## TODO


## Open questions
