# DASH eni counter test plan

* [Overview](#Overview)
   * [HLD](#HLD)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
The purpose is to verify that Sonic can get the correct eni debug counters.
By sending dash private link packet make the relevant counter change, and then check the change is expected as the expectation by reading counter db via the redis-cli command.


### HLD
- https://github.com/sonic-net/sonic-swss/pull/3266

### Scope
The test is targeting a running SONIC system with a dash private link configuration. The purpose of the test is verify the following eni counters can be get correclty from the low layer.  
   - SAI_ENI_STAT_OUTBOUND_RX_PACKETS
   - SAI_ENI_STAT_OUTBOUND_RX_BYTES
   - SAI_ENI_STAT_RX_PACKETS
   - SAI_ENI_STAT_RX_BYTES
   - SAI_ENI_STAT_INBOUND_RX_BYTES
   - SAI_ENI_STAT_INBOUND_RX_PACKETS
   - SAI_ENI_STAT_OUTBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS
   - SAI_ENI_STAT_OUTBOUND_CA_PA_ENTRY_MISS_DROP_PACKETS
   - SAI_ENI_STAT_INBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS
   - SAI_ENI_STAT_FLOW_CREATED
   - SAI_ENI_STAT_FLOW_DELETED
   - SAI_ENI_STAT_FLOW_AGED

### Testbed
The test will run on all DASH testbeds.

### Setup configuration
No setup pre-configuration is required, the test will configure and clean up all the configuration.

Common tests configuration:
- Test will configure basic IPs and routes on NPU and DPU
- Test will configure private link dash config
- Test will enalbe eni counter and set polling interval to 1 second for it

Common tests cleanup:
- Resotre eni counter config
- Remove the private link dash config
- Remove the basic IP and route config on NPU and DPU

## Test

## Test cases

### Test case # 1 – test_outbound_pkt_pass_eni_counter
#### Test objective
Verify outbound eni counter for normal flow
#### Test steps
* Get the eni_counter_before_sending_pkt before sending the dash pkt
* Send a outbound pkt, and the pkt pass the pipeline successfully
* Get the eni_counter_after_sending_pkt after sending the dash pkt
* Check the following counter change as follows by comparing eni_counter_before_sending_pkt with eni_counter_after_sending_pkt
  * SAI_ENI_STAT_FLOW_CREATED:  +1
  * SAI_ENI_STAT_OUTBOUND_RX_BYTES:  +len(packet)*packet_number
  * SAI_ENI_STAT_OUTBOUND_RX_PACKETS: +packet_number
  * SAI_ENI_STAT_RX_PACKETS: +packet_number
  * SAI_ENI_STAT_RX_BYTES: +len(packet)*packet_number
  * SAI_ENI_STAT_FLOW_AGED: +1
* Parameterize the tests with inner_packet_type(udp, tcp) and outer_encap(vxlan, gre)

### Test case # 2 – test_outbound_pkt_miss_routing_entry_drop_counter
#### Test objective
Verify SAI_ENI_STAT_OUTBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS
#### Test steps
* Get the eni_counter_before_sending_pkt before sending the dash pkt
* Send one outbound pkt with inner dst dip which cannot match the dash route
* Get the eni_counter_after_sending_pkt after sending the dash pkt
* Check the following counter change as follows by comparing eni_counter_before_sending_pkt with eni_counter_after_sending_pkt
  * SAI_ENI_STAT_OUTBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS: +1
* Parameterize the tests with inner_packet_type(udp, tcp) and outer_encap(vxlan, gre)

### Test case # 3 – test_outbound_pkt_ca_pa_entry_miss_drop_counter
#### Test objective
Verify SAI_ENI_STAT_OUTBOUND_CA_PA_ENTRY_MISS_DROP_PACKETS
#### Test steps
* Get the eni_counter_before_sending_pkt before sending the dash pkt
* Send a outbound pkt that matches to routing but no ca_to_pa exist for the vnet ID
* Get the eni_counter_after_sending_pkt after sending the dash pkt
* Check the following counter change as follows by comparing eni_counter_before_sending_pkt with eni_counter_after_sending_pkt
  * SAI_ENI_STAT_OUTBOUND_CA_PA_ENTRY_MISS_DROP_PACKETS: +1
* Parameterize the tests with inner_packet_type(udp, tcp) and outer_encap(vxlan, gre)

### Test case # 4 – test_eni_flow_deleted_counter
#### Test objective
Verify SAI_ENI_STAT_FLOW_DELETED
#### Test steps
* Send 1 pass TCP SYN packet
* Get the eni_counter_before_sending_pkt before sending the dash pkt
* Send 1 pass RST packet
* Get the eni_counter_after_sending_pkt before sending the dash pkt
* Check the following counter change as follows by comparing eni_counter_before_sending_pkt with eni_counter_after_sending_pkt
  * SAI_ENI_STAT_FLOW_DELETED increase by 1
* Parameterize the tests with outer_encap(vxlan, gre)

### Test case # 4 – test_inbound_pkt_eni_counter
#### Test objective
Verify inbound eni counters
#### Test steps
* Get the eni_counter_before_sending_pkt before sending the dash pkt
* Send a outbound pkt and a inbound pkt
* Get the eni_counter_after_sending_pkt after sending the dash pkt
* Check the following counter change as follows by comparing eni_counter_before_sending_pkt with eni_counter_after_sending_pkt
  * SAI_ENI_STAT_FLOW_CREATED: +1
  *  SAI_ENI_STAT_INBOUND_RX_BYTES: +len(inbound_packet)*packet_number
  *  SAI_ENI_STAT_INBOUND_RX_PACKETS: +packet_number
  *  SAI_ENI_STAT_RX_PACKETS: +packet_number*2
  *  SAI_ENI_STAT_RX_BYTES: +len(inbound_packet)*packet_number + len(outbound_packet)*packet_number
  *  SAI_ENI_STAT_FLOW_AGED: +1
* Send a inbound pkt without inbound route
* Get the eni_counter_after_sending_pkt after sending the inbound pkt
* Check the following counter change as follows by comparing eni_counter_before_sending_pkt with eni_counter_after_sending_pkt
  * SAI_ENI_STAT_INBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS: +packet_number
* Parameterize the tests with inner_packet_type(udp, tcp) and outer_encap(vxlan, gre)

## TODO

## Open questions
