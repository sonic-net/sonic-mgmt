SONiC DASH Fastpath ICMP Redirect Test Plan

## Overview

The purpose of this test plan is to verify that a TCP session switches to Fastpath based on an ICMP redirect message from the MUX device.  For phase 1, we are verifying Fastpath functionality for Private Link TCP sessions.

## Fastpath ICMP Flow Redirection

Fastpath is a feature that switches traffic from using VIP-to-VIP connectivity (which involves transiting SLB MUXes) to using a direct path between VMs (direct PA-to-PA path).  
Please refer to the Fastpath HLD:  
[Fastpath ICMP Flow Redirection HLD](https://github.com/sonic-net/DASH/blob/main/documentation/load-bal-service/fast-path-icmp-flow-redirection.md)

## Testbed

The test will run on all DASH testbeds.

## Setup Configuration

No pre-configuration is required. The test will configure and clean up all configuration.

### Common Test Configuration

- Configure underlay for NPU and DPU.  
- Configure DASH Private Link configuration.

### Common Test Cleanup

- Delete DASH Private Link configuration.  
- Remove the basic IP and route configuration on NPU and DPU.

## Traffic Profile

- **TCP Flow 1:** DPU receives an ICMP redirect from the MUX, followed by the SYN-ACK packet.
- **TCP Flow 2:** DPU receives a TCP SYN-ACK packet first, followed by an ICMP redirect from the MUX
- **TCP Flow 3:** DPU does not receive any ICMP redirect from the MUX.

## Test Cases

---

### Test Case 1  PL FNIC TCP Session Fastpath Transition

**Test Objective**  
Verify Fastpath transition of a Private Link FNIC TCP session.

**Test Steps**

1. Send initial TCP SYN packets for all three flows as per the traffic profile.  
2. Verify the outbound expected packets are received properly.  
3. For Flow 1, send a Fastpath ICMP redirect packet to the DPU and then send a TCP SYN+ACK packet.  
4. For Flow 2, send a TCP SYN+ACK packet and then send a Fastpath ICMP redirect packet to the DPU.  
5. For Flow 3, send a TCP SYN+ACK packet.  
6. Verify all received TCP SYN+ACK packets.  
7. For Flow 1, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
8. For Flow 2, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
9. For Flow 3, send outbound data payload and verify the received packet outer DIP (no Fastpath redirection).  
10. Send TCP FIN+ACK and properly close all three TCP sessions.

---

### Test Case 2  PL Redirect TCP Session Fastpath Transition

**Test Objective**  
Verify Fastpath transition of a Private Link Redirect TCP session.

**Test Steps**

1. Send initial TCP SYN packets for all three flows as per the traffic profile.  
2. Verify the outbound expected packets are received properly.  
3. For Flow 1, send a Fastpath ICMP redirect packet to the DPU and then send a TCP SYN+ACK packet.  
4. For Flow 2, send a TCP SYN+ACK packet and then send a Fastpath ICMP redirect packet to the DPU.  
5. For Flow 3, send a TCP SYN+ACK packet.  
6. Verify all received TCP SYN+ACK packets.  
7. For Flow 1, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
8. For Flow 2, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
9. For Flow 3, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (Redirect PORTMAP-range backend IP).  
10. Send TCP FIN+ACK and properly close all three TCP sessions.

---

### Test Case 3  PL FNIC + NSG TCP Session Fastpath Transition

**Test Objective**  
Verify Fastpath transition of a Private Link FNIC + NSG TCP session.

**Test Steps**

1. Send initial TCP SYN packets for all three flows as per the traffic profile.  
2. Verify the outbound expected packets are received properly.  
3. For Flow 1, send a Fastpath ICMP redirect packet to the DPU and then send a TCP SYN+ACK packet.  
4. For Flow 2, send a TCP SYN+ACK packet and then send a Fastpath ICMP redirect packet to the DPU.  
5. For Flow 3, send a TCP SYN+ACK packet.  
6. For Flow 1, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
   Since the flow is transitioned to Fastpath, verify that the received packet has only one outer encapsulation (PL NVGRE encapsulation).  
7. For Flow 2, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
   Since the flow is transitioned to Fastpath, verify that the received packet has only one outer encapsulation (PL NVGRE encapsulation).  
8. For Flow 3, send outbound data payload and verify that the received packet outer DIP is the expected IP.  
   This flow is not redirected to Fastpath, so the received packet should have two outer encapsulations (NSG encapsulation + PL NVGRE encapsulation).  
9. Send TCP FIN+ACK and properly close all three TCP sessions.

---

### Test Case 4  PL Redirect+ NSG TCP Session Fastpath Transition

**Test Objective**  
Verify Fastpath transition of a Private Link Redirect + NSG TCP session.

**Test Steps**

1. Send initial TCP SYN packets for all three flows as per the traffic profile.  
2. Verify the outbound expected packets are received properly.  
3. For Flow 1, send a Fastpath ICMP redirect packet to the DPU and then send a TCP SYN+ACK packet.  
4. For Flow 2, send a TCP SYN+ACK packet and then send a Fastpath ICMP redirect packet to the DPU.  
5. For Flow 3, send a TCP SYN+ACK packet.  
6. Verify all received TCP SYN+ACK packets.  
7. For Flow 1, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
   Since the flow is transitioned to Fastpath, verify that the received packet has only one outer encapsulation (PL NVGRE encapsulation).  
8. For Flow 2, send outbound data payload and verify that the received packet outer DIP is the expected Fastpath IP (ICMP-redirected IP).  
   Since the flow is transitioned to Fastpath, verify that the received packet has only one outer encapsulation (PL NVGRE encapsulation).  
9. For Flow 3, send outbound data payload and verify that the received packet outer DIP is the expected IP (Redirect PORTMAP-range backend IP).  
   This flow is not redirected to Fastpath, so the received packet should have two outer encapsulations (NSG encapsulation + PL NVGRE encapsulation).  
10. Send TCP FIN+ACK and properly close all three TCP sessions.

---

### Test Case 5: Invalid ICMP Redirect Packet Handling

**Test Objective**  
Verify that invalid ICMP Redirect packets are properly dropped.

**Test Steps**
1. Send initial TCP SYN packets for all three flows as defined in the traffic profile.  
2. Verify that the expected outbound packets are received correctly.  
3. For Flow 1, send an invalid Fastpath ICMP Redirect packet to the DPU, then send a TCP SYN+ACK packet.  
4. For Flow 2, send a TCP SYN+ACK packet, then send an invalid Fastpath ICMP Redirect packet to the DPU.  
5. Verify that all invalid ICMP Redirect packets are dropped and that existing flows are not affected.  
6. For Flow 3, send a TCP SYN+ACK packet.  
7. Verify that all received TCP SYN+ACK packets are processed properly.
8. Send TCP FIN+ACK packets to properly close all three TCP sessions.


---


## TODO

Additional test coverage will be added for future use cases.
SAI counter validation will be added after it is implemented.

## Document References

- [Private Link Service HLD](https://github.com/sonic-net/DASH/blob/main/documentation/private-link-service/private-link-service.md)  
- [Private Link Redirect HLD](https://github.com/sonic-net/DASH/blob/main/documentation/private-link-service/private-link-redirect-map.md)  
- [Fastpath ICMP Flow Redirection HLD](https://github.com/sonic-net/DASH/blob/main/documentation/load-bal-service/fast-path-icmp-flow-redirection.md)

