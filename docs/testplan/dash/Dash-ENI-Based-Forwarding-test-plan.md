
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
This test will cover 6 use cases:
1. ENI is active on the dut, packet is redirected to the local DPU.
2. ENI is standby on the dut, packet is redirected to the remote DPU.
3. The tunnel route is updated, the packet of the standby ENI can be redirected to the new tunnel interface.
4. Packet lands on a NPU which doesn't host the corresponding ENI, packet is redirected to the remote DPU.
5. Packet is redirected correctly after the ENI state is change from active to standby and vice versa.
6. Tunnel termination, double encapsulated packet is decapsulated and redirected to the local DPU.

No real DPU is involved in the test, the local DPU is simulated by a local front panel interface by using the peer IP as the DPU dataplane IP in the configuration.

The configration in DASH_ENI_FORWARD_TABLE is not persistent, it disappears after reload/reboot. So, the reload/reboot test is not in the scope.

### Testbed
The test will run on a single dut Smartswitch light mode testbed.

### Setup configuration
Until HaMgrd is available, we can only write configuration to the DASH_ENI_FORWARD_TABLE.
DASH_ENI_FORWARD_TABLE schema: https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/smart-switch-ha-detailed-design.md#2321-dash_eni_forward_table

Common tests configuration:
- Apply the common config in config_db, including configrations in DEVICE_METADATA, VIP_TABLE, FEATURE, DPU, REMOTE_DPU, VDPU, DASH_HA_GLOBAL_CONFIG tables.
- Apply the config in DASH_ENI_FORWARD_TABLE to the appl_db via swssconfig.

Common tests cleanup:
- Common config reload to retore the configurations after the the full test completes. 

We need apply the config for DEVICE_METADATA, VIP_TABLE, DPU, REMOTE_DPU, VDPU, VXLAN_TUNNEL, VNET, PORTCHANNEL_INTERFACE into NPU config_db.
CONFIG_DB Example:
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
    "DPU": {
        "dpu0": {
            "dpu_id": "0",
            "gnmi_port": "50052",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.1",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.0.202.1",
            "local_nexthop_ip": "18.0.202.1",
            "state": "up",
            "vdpu_id": "vdpu0_0",
            "vip_ipv4": "10.1.0.5"
        },
        "dpu1": {
            "dpu_id": "1",
            "gnmi_port": "50052",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.2",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "10.0.0.101",
            "local_nexthop_ip": "10.0.0.101",
            "state": "up",
            "vdpu_id": "vdpu0_1",
            "vip_ipv4": "10.1.0.5"
        },
        "dpu2": {
            "dpu_id": "2",
            "gnmi_port": "50052",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.3",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.2.202.1",
            "local_nexthop_ip": "18.2.202.1",
            "state": "up",
            "vdpu_id": "vdpu0_2",
            "vip_ipv4": "10.1.0.5"
        },
        "dpu3": {
            "dpu_id": "3",
            "gnmi_port": "50052",
            "local_port": "8080",
            "midplane_ipv4": "169.254.200.4",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": "18.3.202.1",
            "local_nexthop_ip": "18.3.202.1",
            "state": "up",
            "vdpu_id": "vdpu0_3",
            "vip_ipv4": "10.1.0.5"
        }
    },
    "REMOTE_DPU": {
        "dpu4": {
            "dpu_id": "4",
            "npu_ipv4": "100.100.100.1",
            "pa_ipv4": "18.0.202.1",
            "type": "cluster"
        },
        "dpu5": {
            "dpu_id": "5",
            "npu_ipv4": "100.100.100.1",
            "pa_ipv4": "18.1.202.1",
            "type": "cluster"
        },
        "dpu6": {
            "dpu_id": "6",
            "npu_ipv4": "100.100.100.1",
            "pa_ipv4": "18.2.202.1",
            "type": "cluster"
        },
        "dpu7": {
            "dpu_id": "7",
            "npu_ipv4": "100.100.100.1",
            "pa_ipv4": "18.3.202.1",
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
    "VXLAN_TUNNEL": {
        "tunnel_v4": {
            "src_ip": "10.1.0.32"
        }
    },
    "VNET": {
        "Vnet1000": {
            "vxlan_tunnel": "tunnel_v4",
            "vni": "1000",
            "peer_list": ""
        }
    },
    "PORTCHANNEL_INTERFACE" : {
        "PortChannel102" : {
            "vnet_name" : "Vnet1000"
        }
    }
}
```

In a full functional HA testbed, the hamgrd should generate the entry in DASH_ENI_FORWARD_TABLE based on the above config_DB configurations. This flow will be covered in the HA test.
In the ENI based forwarding test, we are not going to deploy and test the full HA fuctionality, so we still need to apply the DASH_ENI_FORWARD_TABLE via swssconfig to the APPL_DB.
Three ENIs are configured: for ENI1, the primary_vdpu is a local DPU; for ENI2 the primary_vdpu is a remote DPU; for ENI3, which is the "non-existing" ENI, both vdpus are remote DPUs.
APPL_DB Example:
```
[
    {
        "DASH_ENI_FORWARD_TABLE:Vnet1000:F4:93:9F:EF:C4:7F":
        {
            "vdpu_ids": "vdpu0_1,vdpu1_1",
            "primary_vdpu": "vdpu0_1"
        },
        "OP": "SET"
    },
    {
        "DASH_ENI_FORWARD_TABLE:Vnet1000:F4:93:9F:EF:C4:80":
        {
            "vdpu_ids": "vdpu0_1,vdpu1_1",
            "primary_vdpu": "vdpu1_1"
        },
        "OP": "SET"
    },
    {
        "DASH_ENI_FORWARD_TABLE:Vnet1000:F4:93:9F:EF:C4:81":
        {
            "vdpu_ids": "vdpu1_2,vdpu1_3",
            "primary_vdpu": "vdpu1_2"
        },
        "OP": "SET"
    }
]
```

## Test
### Commen setup and teardown
#### Test steps
* There will be a module level fixture common_setup_teardown to configure the CONFIG_DB, APPL_DB and a tunnel route(a static route to the tunnel peer loopback IP). A front panel interface peer IP is used as the mocked local DPU dataplane IP to revceive the packets which are redirected the local DPU.
* There will a ACL check after all the configurations are applied:
  * Check the ACL rules for the tested ENIs are generated. There should be 2 rules for the hosted ENI, one is for redirection, the other is for tunnel termination. There should be only 1 redirection rule for the "non-existing" ENI, no tunnel termination rule.
  * Check the key/value in the ACL rules are correct.
  * Any failrue in the ACL check is raised as an assertion.
* This fixture will do a config reload in the module teardown.

### Test case # 1 – test_eni_based_forwarding_active_eni
#### Test objective
This is to test that when the ENI is active on the dut, the packet of the ENI is redirected to the local DPU.
#### Test steps
* Craft a VxLAN packet for the ENI, which is active on the dut. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Send the packet to the dut.
* Check the packet can be received by the ptf through the mocked local DPU interface, and there is no addtional encapsulation on the packet.

### Test case # 2 – test_eni_based_forwarding_standby_eni
#### Test objective
This is to test that when the ENI is standby on the dut, the packet of the ENI is redirected to the remote DPU through the VxLAN tunnel interface.
#### Test steps
* Craft a VxLAN packet for the ENI, which is standby on the dut. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Send the packet to the DUT.
* Check the packet can be received by the ptf through the tunnel interface, and the packet is encapsulated with an additional tunnel VxLAN header.

### Test case # 3 – test_eni_based_forwarding_tunnel_route_update
#### Test objective
This is to test that when the tunnel route is updated, the packet of the standby ENI can be redirected to the new egress tunnel interface.
#### Test steps
* Reconfigure the route of the tunnel peer to use another nexthop. Keep all the other configrations unchanged.
* Craft a VxLAN packet for the ENI, which is standby on the dut. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Send the packet to the DUT.
* Check the packet can be received by the ptf through the new egress tunnel interface, and the packet is encapsulated with an additional tunnel VxLAN header.
* Restore the tunnel route.

### Test case # 4 – test_eni_based_forwarding_non_existing_eni
#### Test objective
This is to test that when the ENI is not hosted in the dut, the packet of the ENI is redirected to the to the tunnel interface.
#### Test steps
* Craft a VxLAN packet for the ENI, which is not hosted in the dut. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Send the packet to the DUT.
* Check the packet can be received by the ptf through the tunnel interface, and the packet is encapsulated with an additional tunnel VxLAN header.

### Test case # 5 – test_eni_based_forwarding_eni_state_change
#### Test objective
This is to test that when the ENI state changes, the ACL rules are and the redirect bahaviors are updated accordingly.
#### Test steps
* Change the active ENI to standby and vice versa.
* Craft a VxLAN packet for the original standby ENI, which is active now. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Send the packet to the DUT.
* Check the packet can be received by the ptf through the mocked local DPU interface, and there is no addtional encapsulation on the packet.
* Craft a VxLAN packet for the original active ENI, which is standby now. The outer DIP should be the VIP, inner DMAC should be the ENI MAC.
* Check the packet can be received by the ptf through the tunnel interface, and the packet is encapsulated with an additional tunnel VxLAN header.
* Restore the ENI states.

### Test case # 6 – test_eni_based_forwarding_tunnel_termination
#### Test objective
This is to test that when the double encapsulated packet lands on the dut, the tunnel is terminated, and packet is decapsulated and sent to the local DPU.
Regardless of the ENI is active or standby on the dut, the packet will not be sent out again through the tunnel.
#### Test steps
* Randomly generate a valid UDP port as the tunnel VxLAN dst port and configure it into APPL_DB via swssconfig. 
* Craft a double VxLAN encapsulated packet of the active ENI, the outmost VxLAN UDP dst port is the randome generated one.
* Send the packet to the dut.
* Check the packet can be received by the ptf through the mocked local DPU interface, and the outmost VxLAN header is decapsulated.
* Craft a double VxLAN encapsulated packet of the stadnby ENI, the outmost VxLAN UDP dst port is the randome generated one.
* Send the packet to the dut
* Check the packet can be received by the ptf through the mocked local DPU interface, and the outmost VxLAN header is decapsulated.
* Restore the VxLAN UDP dst port to the default 4789.

## TODO


## Open questions
