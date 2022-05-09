# QoS remapping for tunnel traffic test plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Test case group for packet encapsulation](#test-case-group-for-packet-encapsulation)
  - [Test case group for packet decapsulation](#test-case-group-for-packet-decapsulation)

## Overview

The purpose is to test the functionality of QoS remapping of tunnel traffic.

## Scope

The test is targeting a running SONiC system with fully functioning configuration.
Purpose of the test is to verify a SONiC switch system correctly performs QoS remapping for tunnel traffic.

## Testbed

Supported topologies: dual-tor testbed

## Setup configuration

No setup pre-configuration is required, test will configure and return testbed to the initial state.

## Test cases
The test suite is categorized into two groups. 

## Test case group for packet encapsulation
### Setup of DUT switch
1. Randomly select a ToR for testing, say `upper_tor`
2. Randomly select a server (say ip `192.168.0.2`) facing interface on the selected ToR in step 1 (`upper_tor`), and toggle the mux status to `standby` in order to do packet encapsulation
3. Startup `garp_service` on ptf to populate arp for servers
### Test cases
#### Test case 1 - Verify DSCP re-writing
##### Test steps
1. Generate packet with various `DSCP` values (listed below), `target_ip = 192.168.0.2`, `src_ip = 1.1.1.1`
2. Send the packets to `upper_tor` via a portchannel
3. Verify the packets are encaped, and bounced back to T1
4. Verify the `DSCP` value of bounced back packet is as expected.

The expected DSCP values is as below


|DSCP| Expected DSCP after encap|TC to verify|
| ---- | ---- | --- |
|8|8|0|
|0|0|1|
|33|33|2|
|3|2|3|
|4|6|4|
|5|46|5|
|7|48|7|

#### Test case 2 - Verify traffic is egressed at expected queue
##### Test steps
1. Generate `100` packets with various `DSCP` values (listed below), `target_ip = 192.168.0.2`, `src_ip = 1.1.1.1`
2. Clear `queuecounter` with CLI `sonic-clear queuecounters`
3. Send the packets to `upper_tor` via a portchannel
4. Verify the packets are encaped, and bounced back to T1
5. Verify the bounced back traffic is egressed at expected queue with CLI `show queue counter`. The packet counter for expected queue is supposed to be larger or equal to `100`.

The expected DSCP to queue mapping is as below

|DSCP| Expected outgoing queue|TC to verify|
| ---- | ---- | --- |
|8|0|0|
|0|1|1|
|33|1|2|
|3|2|3|
|4|6|4|
|5|5|5|
|7|7|7|


## Test case group for packet decapsulation
### Setup of DUT switch
1. Swap `syncd` docker with `syncd-rpc` as `saithrift` call is required to do the validation
2. Randomly select a ToR for testing, say `upper_tor`, and the unselected ToR would be `lower_tor`
3. Randomly select a server (say ip `192.168.0.2`) facing interface on the selected ToR in step 1 (`upper_tor`), and toggle the mux status to `standby` in order to do packet encapsulation. server `192.168.0.2` would be active on `lower_tor`
4. Startup `garp_service` on ptf to populate arp for servers

### Test cases

#### Test case 1 - Verify packets enter expected PG on lower_tor
##### Test steps
1. Generate `100` packets with `DSCP = 3/4`, `target_ip = 192.168.0.2`, `src_ip = 1.1.1.1`
2. Send the `100` packets to `upper_tor` via a portchannel, and the encapped packets will be bounced to `lower_tor` via `T1`
3. Verify the encapped packets is ingressed to the expected PG on `lower_tor` by sai_thrift api sai_thrift_read_pg_counters. (`DSCP 3 -> PG 2, DSCP 4 -> PG 6`)

#### Test case 2 - Verify packets egressed to server at expected queue
##### Test steps
1. Generate `100` packets with `DSCP = 3/4`, `target_ip = 192.168.0.2`, `src_ip = 1.1.1.1`
2. Send the `100` packets to `upper_tor` via a portchannel
3. Verify the packets are bounced back to `lower_tor`, and the outlayer DSCP value is as expected (3->2, 4->6)
4. Verify the decapped packets is egressed to server at expected queue with CLI `show queue counter`. The packet counter for expected queue is supposed to be larger or equal to `100`. (`DSCP 3 -> Queue 3, DSCP 4 -> Queue 4`)

#### Test case 3 - Verify PFC frame generation at expected queue
##### Test steps
1. Disable egress for T1 facing port on `lower_tor` with sai_thrift api `sai_thrift_port_tx_disable`
2. Generate packet with `DSCP = 3/4`, `target_ip = 192.168.0.2`, `src_ip = 1.1.1.1`. 
3. Send the packet to `upper_tor` via a portchannel, and the traffic is bounced back to T1. The number of transmitted packets is determined by the lossless profile to ensure the pg is filled.
4. Send the packet one more time, and verify `lower_tor` will generate PFC pause frame on expected queue with sai_thrift api `sai_thrift_read_port_counters` (`DSCP 3 -> PFC 2,  DSCP 4 -> PFC 6`).


