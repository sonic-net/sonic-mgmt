# PFC Storm with Shared Headroom Test Plan

## Motivation

This test covers the scenrio when a PFC Watchdog is applied on a port which already has it's occupancy crossed into shared headroom. 

The test checks if any PFC Frames are sent to the peer link from the DUT port. 

**Note:** 
+ This test case is only intended for Mellanox Platforms
+ This test case requires an RPC image
+ Shared Headroom has to be enabled on the device.

## Test Plan
+ Verify if the shared headroom is enabled
+ Make sure buffer occupancy crosses into the shared headroom region
   - Achieve buffer congestion by closing the dut tx port using `sai_thrift_port_tx_disable` API: https://github.com/Azure/sonic-mgmt/blob/master/tests/saitests/switch.py#L624.
   - Send pkts from the PTF docker which are destined to egress out of the dut tx port.
   - Make sure to send atleast num_pkts_pfs_frame + private_headroom pkts pkts
   - num_pkts_pfs_frame: num of pkts required to be sent in order to trigger a PFC frame from the DUT. More on this here: https://github.com/Azure/sonic-mgmt/blob/master/tests/qos/files/mellanox/qos_param_generator.py
   - private_headroom_pkts is specific to mellanox which is in the order of a few pkts.
   - Check the PFC Rx Counters to see verify if the occupancy has indeed crossed into 
    
+ Trigger a PFC storm directed towards the DUT port
+ PFC Watchdog is triggered
+ After PFC WD is restored, drain the Ingress buffers to drop the occupancy under Xon
  - Achieve this by re-opening dut tx port using `sai_thrift_port_tx_enable` API.
  - This'll drain the  buffers and the occupancy falls below Xon.
+ Check the Tx PFC Counters on the DUT source port which was stormed after the packets are drained. They shouldn't be incremented as the occupancy has fallen below Xon