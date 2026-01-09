# SONiC RoCEv2 Test Plan

## Test Topology 1 – Functional test with single DUT

- Basic single-DUT functional topology.
- Tester connects four ports(rank 0,1,2,3) to the DUT at a common Ethernet speed (for example 800GE, 400GE, 200GE, or 100GE).
- Used for RoCEv2 functional and congestion-control scenarios.

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

## Test Topology 2 – Functional and performance test with Clos fabric

- Two leaf switches and one spine switch forming a two-tier leaf/spine Clos fabric.
- Downlink and uplink use the same link speed.
- Used for test cases that require multiple DUTs, such as hashing and load balancing.

<p float="left">
  <img src="Img/RoCEv2_Topology_2.png" width="350"  hspace="200"/>
</p>

---

## Test Case 1 – Basic dataplane traffic testing without congestion

### Objective

- Validate basic functionality for RoCEv2/RDMA AI traffic using:
  - Priority Flow Control (PFC)
  - ECN marking on the switch
  - CNP/ACK behavior on the endpoints
- Applicable roles: T0, T1, T2.

### Topology

- Uses Test Topology 1 (single DUT with four connected test ports).

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

### Test Steps

1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking.  
2. Configure 1:1 test traffic between rank 0-2 & 1-3, 1 rank (endpoint) per port.  
3. Configure constant rate test traffic (RoCEv2 AI traffic) for 2 lossless and 4 lossy queues: 6 QPs per rank pair. 
- DSCP value 0-5 on rank0 q1-6
- DSCP value 0-5 on rank1 q1-6
- DSCP for ACK/NAK/CNP value 48 
- 4K IB MTU, 1MB message size (256 packets in burst per message) 
- ECN-CE bit value 00 
4. Run lossless and lossy traffic for 3 minutes and verify the statistics.


### Expected Results

1.  In step 4, both lossless and lossy traffic should flow fine without any loss.
- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- No ECN-CE CNP Tx/Rx on the tester. 
- No PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 6, matching tester ACK counter. 
- ECN-CE should NOT be observed on queue 3 or 4, matching tester ECN-CE counter. 
- CNP should NOT be observed on queue 6, matching tester CNP counter. 
- Note Avg/Max latency and it should be within DUT spec. 
2.	Successful test result indicates that DUT forward RoCEv2 AI traffic and control signaling as expected.

## Test Case 2 – Congestion Control with PFC for AI Traffic 

### Objective

- Validate basic congestion control for RoCEv2/RDMA AI traffic using:
  - Priority Flow Control (PFC)
  - ECN marking on the switch
  - CNP/ACK behavior on the endpoints
- Applicable roles: T0, T1, T2.

### Topology

- Uses Test Topology 1 (single DUT with four connected test ports).

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

### Test Steps

1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking. 
2. Configure 2:1 in-cast test traffic between rank 0-3 & 1-3, 1 rank (endpoint) per port.   
3. Configure stateful RoCEv2 traffic to transmit 4GB data traffic for 1 lossless queue: 1QP per rank pair. 
- DSCP for data traffic value 3 
- DSCP for ACK/NAK value 3 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- 55% rate per Tx port 
- ECN-CE bit value 00 
4. Run traffic and validate statistics. 
5. Configure stateful RoCEv2 traffic to transmit 4GB data traffic each for 2 lossless queues: 1 QP per rank pair. 
- DSCP value 3 on rank0 
- DSCP value 4 on rank1 
- DSCP for ACK/NAK value 3 on rank0 
- DSCP for ACK/NAK value 4 on rank1 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- 55% rate per Tx port 
- ECN-CE bit value 00 
6. Run traffic and validate statistics. 
7. Configure stateful RoCEv2 traffic to transmit 4GB data traffic each for 2 lossless queues: 1 QP per rank pair. 
- DSCP value 3 on rank0 
- DSCP value 4 on rank1 
- DSCP for ACK/NAK value 3 on rank0 
- DSCP for ACK/NAK value 4 on rank1 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) on rank0 
- 4K IB MTU, 4KB message size (WRITE only message) on rank1 
- 55% rate per Tx port 
- ECN-CE bit value 00 
8. Run traffic and validate statistics. 
9.	Increase number of endpoint per port to 4K for testing T2

### Expected Results
1. In step 4, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- No ECN-CE CNP Tx/Rx on the tester. 
- PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 3, matching tester ACK counter. 
- ECN-CE should NOT be observed on queue 3, matching tester ECN-CE counter. 
- CNP should NOT be observed on queue 6, matching tester CNP counter. 
- Note Avg/Max latency and it should be within DUT spec. 

2. In step 6 and 8, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- No ECN-CE CNP Tx/Rx on the tester. 
- PFC should be observed on queue 3, matching tester PFC counter for rank0. 
- PFC should be observed on queue 4, matching tester PFC counter for rank1. 
- ACK should be observed on queue 3, matching tester ACK counter for rank0. 
- ACK should be observed on queue 4, matching tester ACK counter for rank1. 
- ECN-CE should NOT be observed on queue 3, matching tester ECN-CE counter. 
- CNP should NOT be observed on queue 6, matching tester CNP counter. 
- Note Avg/Max latency and it should be within DUT spec. 

3. Successful test results indicate that DUT forward RoCEv2 AI traffic and control signaling as expected. PFC congestion control functions as expected.  


## Test Case 3 – Congestion Control with DCQCN for AI Traffic 

### Objective

- Validate basic congestion control for RoCEv2/RDMA AI traffic using:
  - Priority Flow Control (PFC)
  - ECN marking on the switch
  - CNP/ACK behavior on the endpoints
- Applicable roles: T0, T1, T2.

### Topology

- Uses Test Topology 1 (single DUT with four connected test ports).

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

### Test Steps
1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking. 
2. Configure 2:1 in-cast test traffic between rank 0-3 & 1-3, 1 rank (endpoint) per port.   
3. Configure stateful RoCEv2 traffic to transmit 4GB data traffic for 1 lossless queue: 1QP per rank pair. 

- DSCP for data traffic value 3 
- DSCP for ACK/NAK value 3 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- 55% rate per Tx port 
- ECN-CE bit value 01/10 
- Run traffic and validate statistics. 

4. Configure stateful RoCEv2 traffic to transmit 4GB data traffic each for 2 lossless queues: 1 QP per rank pair. 

- DSCP for data value 3 on rank0 
- DSCP for data value 4 on rank1 
- DSCP for ACK/NAK value 3 on rank0 
- DSCP for ACK/NAK value 4 on rank1 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- 55% rate per Tx port 
- ECN-CE bit value 01/10 
5. Run traffic and validate statistics. 
6. Set ECN-CE bit value 11 
7. Run traffic and validate statistics. 
8. Increase endpoint per port to 4K for testing T2 

### Expected Result:  

1. In step 4, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 3, matching tester ACK counter. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Avg/Max latency and it should be within DUT spec. 

2. In step 6, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter for rank0. 
- Few or no PFC should be observed on queue 4, matching tester PFC counter for rank1. 
- ACK should be observed on queue 3, matching tester ACK counter for rank0. 
- ACK should be observed on queue 4, matching tester ACK counter for rank1. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter for rank0. 
- ECN-CE should be observed on queue 4, matching tester ECN-CE counter for rank1. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Avg/Max latency and it should be within DUT spec. 

3. In step 8, all messages should be completed successfully. 

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter for rank0. 
- Few or no PFC should be observed on queue 4, matching tester PFC counter for rank1. 
- ACK should be observed on queue 3, matching tester ACK counter for rank0. 
- ACK should be observed on queue 4, matching tester ACK counter for rank1. 
- All data packets marked with ECN-CE should be observed on queue 3 or 4, matching tester ECN-CE counter. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Avg/Max latency and it should be within DUT spec. 

4. Successful test results indicate that DUT forward RoCEv2 AI traffic and control signaling as expected. DCQCN congestion control functions as expected. 


## Test Case 4 – Congestion Control with PFC and ECN/CNP for Storage Traffic

### Objective

- Validate basic congestion control for RoCEv2/RDMA storage traffic using PFC and ECN/CNP.
- Applicable roles: T0, T1, T2.

### Topology

- Uses Test Topology 1.

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

### Test Steps
1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking. 
2. Configure tester for 2:1 in-cast between rank 0-3 & 1-3, 1 rank (endpoint) per port.   
3. Configure constant rate test traffic (RoCEv2 storage traffic) for 1 lossless queue: 1QP per rank pair 

- DSCP for data traffic value 3 
- DSCP for ACK/NAK value 3 
- DSCP for CNP value 48 
- 4K IB MTU, 1MB message size (256 packets in burst per message) 
- 55% rate per Tx port 
- ECN-CE bit value 01/10 
4. Disable DCQCN, run traffic for 3 minutes and validate statistics. 
5. Enable DCQCN, run traffic for 3 minutes and validate statistics. 
6. Configure constant rate test traffic (RoCEv2 storage traffic) for 2 lossless queues: 1 QPs per rank pair 

- DSCP value 3 on rank0 
- DSCP value 4 on rank1 
- 4K IB MTU, 1MB message size (256 packets in burst per message) 
- 55% rate per Tx port 
- ECN-CE bit value 01/10 
7. Disable DCQCN, run traffic for 3 minutes and validate statistics 
8. Enable DCQCN, run traffic for 3 minutes and validate statistics. 
9. Increase endpoint per port to 4K for testing T2 

### Expected Result:  

1. In step 4, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 3, matching tester ACK counter. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Bandwidth during traffic run and it should be within DUT spec. 
- Note Avg/Max latency and it should be within DUT spec. 

2. In step 5, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 3, matching tester ACK counter. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Bandwidth during traffic run and it should be within DUT spec. 
- Note Avg/Max latency and it should be within DUT spec. 

3. In step 7, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- PFC should be observed on queue 3, matching tester PFC counter for rank0. 
- PFC should be observed on queue 4, matching tester PFC counter for rank1. 
- ACK should be observed on queue 3, matching tester ACK counter for rank0. 
- ACK should be observed on queue 4, matching tester ACK counter for rank1. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter for rank0. 
- ECN-CE should be observed on queue 4, matching tester ECN-CE counter for rank1. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Bandwidth during traffic run and it should be within DUT spec. 
- Note Avg/Max latency and it should be within DUT spec. 

4. In step 8, all messages should be completed successfully.  

- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter for rank0. 
- Few or no PFC should be observed on queue 4, matching tester PFC counter for rank1. 
- ACK should be observed on queue 3, matching tester ACK counter for rank0. 
- ACK should be observed on queue 4, matching tester ACK counter for rank1. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter for rank0. 
- ECN-CE should be observed on queue 4, matching tester ECN-CE counter for rank1. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Bandwidth during traffic run and it should be within DUT spec. 
- Note Avg/Max latency and it should be within DUT spec. 

4. Successful test result indicates that DUT forward RoCEv2 storage traffic and control signaling as expected. PFC and ECN/CNP congestion signaling and congestion control function as expected.  

 ## Test Case 5 – PFC propagation

### Objective

- Validate basic PFC propagation for RoCEv2/RDMA AI/storage traffic.
- Applicable roles: T0, T1, T2.

### Topology

- Uses Test Topology 1.

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

### Test Steps

1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking. 
2. Configure tester for point-to-point traffic between rank 0-2 and 1-3, 1 rank (endpoint) per port.   
3. Configure constant rate test traffic (RoCEv2 storage traffic) for 2 lossless queues:  
- DSCP value 3 on rank0 
- DSCP value 4 on rank1 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- 100% rate per Tx port 
- ECN-CE bit value 00 
4. Run traffic for 10 seconds and validate statistics. 
5. Configure PFC generation on rank 2 and 3 for 90% available bandwidth. 
6. Run traffic for 30 seconds and validate statistics. 
7. Increase endpoint per port to 4K for testing T2 

### Expected Result:  

1. In step 4, all messages should be completed successfully.  
- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- No PFC should be observed on queue 3, matching tester PFC counter. 
- No PFC should be observed on queue 4, matching tester PFC counter. 
2. In step 6, all messages should be completed successfully.  
- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- PFC should be observed on queue 3, matching tester PFC counter. 
- PFC should be observed on queue 4, matching tester PFC counter. 
3. Successful test results indicate that DUT forward RoCEv2 AI traffic and PFC generated by tester as expected. 


## Test Case 6 – QP Fairness with DCQCN

### Objective

- Validate fairness between QPs under congestion controled with DCQCN.

### Topology

- Can use Test Topology 1 or 2; single-DUT topology is sufficient for illustration.

<p float="left">
  <img src="Img/RoCEv2_Topology_1.png" width="350"  hspace="200"/>
</p>

### Test Steps
1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking. 
2. Configure 2:1 in-cast test traffic between rank 0-3 & 1-3, 1 rank (endpoint) per port.   
3. Configure stateful RoCEv2 traffic to transmit constant rate data traffic for 1 lossless queue: 1QP per rank pair. 
- DSCP for data traffic value 3 
- DSCP for ACK/NAK value 3 
- DSCP for CNP value 48 
- 4K IB MTU, 1MB message size (256 packets in burst per message) 
- 100% rate per Tx port 
- ECN-CE bit value 01/10 
4. Run traffic for 3 minutes and validate statistics. 
5. Configure stateful RoCEv2 traffic to transmit constant rate data traffic 2 lossless queues: 1 QP per rank pair. 
- DSCP for data value 3 on rank0 
- DSCP for data value 4 on rank1 
- DSCP for ACK/NAK value 3 on rank0 
- DSCP for ACK/NAK value 4 on rank1 
- DSCP for CNP value 48 
- 4K IB MTU, 1MB message size (256 packets in burst per message) 
- 100% rate per Tx port 
- ECN-CE bit value 01/10 
6. Run traffic for 3 minutes and validate statistics. 
7. Configure n:1 in-cast test traffic to check QP fairness further.   

### Expected Result:  

1. In step 4, all messages should be completed successfully. 
- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 3, matching tester ACK counter. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Bandwidth during traffic run and Tx Rate of rank0 and rank1 should be fair, with a deviation less than 30%. 
2. In step 6, all messages should be completed successfully. 
- No loss should be observed on the tester.  
- No NAK and sequence error on the tester. 
- Few or no PFC should be observed on queue 3, matching tester PFC counter for rank0. 
- Few or no PFC should be observed on queue 4, matching tester PFC counter for rank1. 
- ACK should be observed on queue 3, matching tester ACK counter for rank0. 
- ACK should be observed on queue 4, matching tester ACK counter for rank1. 
- ECN-CE should be observed on queue 3, matching tester ECN-CE counter for rank0. 
- ECN-CE should be observed on queue 4, matching tester ECN-CE counter for rank1. 
- CNP should be observed on queue 6, matching tester CNP counter. 
- Note Bandwidth during traffic run and Tx Rate of rank0 and rank1 should be fair, with a deviation less than 30%. 

## Test Case 7 – Hashing and Load Balancing

### Objective

- Validate the DUT’s load-balancing and hashing behavior for distributing RoCEv2 traffic across multiple upstream links.
- Focus on avoiding congestion while preserving flow ordering.
- Applies primarily to T0 and T1; for T2 it may apply mainly to uplinks.

### Topology

- Uses Test Topology 2 (leaf–spine Clos).

<p float="left">
  <img src="Img/RoCEv2_Topology_2.png" width="350"  hspace="200"/>
</p>

### Test Steps

1.	Configure DUT with lossless queues 3 mapping to DSCP value 3. 
2.	Configure continuous test traffic: 4K IB MTU,1MB message size, 
3.	One rank pair from 0-4, 1 QP per rank pair, check leaf 1 egress.
4.	Increase to X QPs per rank pair, check leaf 1 egress.
5.	Two rank pairs from 0-4 and 1-5, 1 QP per rank pair, check leaf 1 egress
6.	Enable staggered transmit on tester side, check leaf 1 egress.
7.	Increase to X QPs per rank pair, check leaf 1 egress.
8.	Four rank pairs from 0-4,1-5, 2-6, 3-7, 1 QP per rank pair, check leaf 1 egress
9.	Enable staggered transmit on tester side, check leaf 1 egress.
10.	Increase to X QPs per rank pair, check leaf 1 egress.

### Expected Results

1.	In step 3, expect traffic on 1 egress port, no congestion.
2.	In step 4, expect traffic on 1 or more egress port, no congestion.
3.	In step 5, expect traffic on 1 egress port, 2-1 incast congestion. 
4.	In step 6, expect traffic on 2 egress ports, no congestion
5.	In step 7, expect traffic on 2 or more egress port, no congestion. 
6.	In step 8, expect traffic on 1 egress ports, 4-1 incast congestion
7.	In step 9, expect traffic on 2 or more egress ports, no congestion.
8.	In step 10, expect traffic on 2 or more egress ports, no congestion 

### Notes

1.	Hashing algorithm maybe different for different HW if different switch chip is used. The hashing algorithm is typically secret sauce of switch chip.
2.	Most of switch chip has dynamic hashing based on traffic load. In this case, the start time of various flows will impact hashing result.
3.	This kind of p2p test reflects pipeline parallelism and expert parallelism in real AI world training and inferencing. It is a good reference of hash behavior of DUT. 

## Test Case 8 – Packet Spray

### Objective

- Validate load balancing using packet spray such that traffic is efficiently distributed across all available links, while maintaining acceptable out-of-order characteristics.

### Topology

- Uses Test Topology 2.

<p float="left">
  <img src="Img/RoCEv2_Topology_2.png" width="350"  hspace="200"/>
</p>

### Test Steps
1. Configure DUT with lossless queues 3 mapping to DSCP value 3.  
2. Configure 4GB all-to-all test traffic between 8 ranks. 
- DSCP for data traffic value 3 
- DSCP for ACK/NAK value 3 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- ECN-CE bit value 01/10 
3. Enable Out-of-order support on tester. 
4. Run traffic and validate statistics. 

### Expected Result: 
1. In step 4, all messages should be completed successfully.  
- No loss or NAK should be observed on the tester.  
- No NAK and sequence error on the tester. 
- No PFC should be observed on queue 3, matching tester PFC counter. 
- ACK should be observed on queue 3, matching tester ACK counter. 
- No ECN-CE should be observed on queue 3, matching tester ECN-CE counter. 
- No CNP should be observed on queue 6, matching tester CNP counter. 
- Packet count should be evenly distributed on egress ports. 
- Note Avg/Max latency and it should be within DUT spec. 


## Test Case 9 – QoS Profile Prioritizing Lossless Traffic

### Objective

- Validate that the DUT prioritizes RoCEv2 lossless traffic and guarantees bandwidth in the presence of competing best-effort traffic.
- Particularly relevant for T2 with mixed lossless and lossy traffic.

### Topology

- Uses Test Topology 2, with one egress link intentionally brought down per leaf to create contention.

<p float="left">
  <img src="Img/RoCEv2_Topology_2_link_failover.png" width="350"  hspace="200"/>
</p>

### Test Steps

1.	Configure DUT with lossless queues 3 mapping to DSCP 26, lossy queue 0 mapped to DSCP 0
2.	RoCEv2 test traffic: 4K IB MTU,1MB message size, DSCP 26, enable PFC and DCQCN. 
3.	Create 3 background traffic flows between port pair 0-4, 1-5, 2-6. Start 3 traffic flows one after the other. Set traffic to 100% and start traffic. Check leaf 1 egress
4.	Create RoCEv2 traffic with one rank pair from 3-7, 1 QP per rank pair, check leaf 1 egress.
5.	Increase RoCEv2 traffic to X (eg. 16) QPs per rank pair, check leaf 1 egress.
6.	Stop RoCEv2 traffic and check leaf 1 egress.

### Expected Results

1.	In step 3, expect traffic of each ingress port is hashing to 1 egress port. No congestion and loss.
2.	In step 4, expect RoCEv2 traffic is forwarded without loss. Expect loss in one background traffic flow which hash collision with RoCEv2 traffic
3.	In step 5, expect loss in 1 or more background traffic flows 
4.	In step 6, expect background traffic recovery and no further loss are seen. 

### Notes
1.	Need to experiment to validate expected result.
2.	Set traffic rate as % of line rate which is applicable to different link speeds (Riff’s comment: Make traffic rate as input parameter to adapt to different test topology)


## Test Case 10 – Failover and Recovery

### Objective

- Validate that RoCEv2 traffic continues without loss during link failover and recovery in a Clos fabric.

### Topology

- Uses Test Topology 2.

<p float="left">
  <img src="Img/RoCEv2_Topology_2_single_link_failover.png" width="350"  hspace="200"/>
</p>

### Test Steps

1.	Configure DUT with lossless queues 3 mapping to DSCP value 26. 
2.	Configure test traffic between left and right leaf: 0-4, 1-5, 2-6, 4K IB MTU,1MB message size, 
3.	Start traffic and check tester statistics
4.	Bring down 1 egress link on leaf 1 which has traffic on it, check tester ports statistics 
5.	Bring up the down egress link on leaf 1, check tester ports statistics 

### Expected Results

1.	In step 3, traffic is forward across available egress link on leaf 1. No loss is expected.
2.	In step 4, traffic should be failover to the next available egress link on leaf 1. No loss is expected.
3.	In step 5, expect traffic to move back to original link if resilient ECMP is enabled/supported, or expect traffic to stay if resilient ECMP is disabled/not-supported.


## Test Case 11 – Control Plane Timeout Retransmission Mitigation

### Objective

- Validate control plane timeout due to PFC mitigated by setting higher or other priority queue. This test applies to T0/T1/T2. 

### Topology

- Uses Test Topology 2.

<p float="left">
  <img src="Img/RoCEv2_Topology_2.png" width="350"  hspace="200"/>
</p>

### Test Steps

1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4, queue 6 mapping to DSCP 48, enable PFC and ECN-marking.   
2. Configure 4:1 in-cast test traffic between rank 0-4, 1-4, 2-4 & 3-4 and 1:4 broadcast test traffic between rank 4-0, 4-1, 4-2, 4-3, 1 rank (endpoint) per port.  
- DSCP for data traffic value 3 
- DSCP for ACK/NAK value 3 
- DSCP for CNP value 48 
- 4K IB MTU, 128KB message size (32 packets in burst per message) 
- ECN-CE bit value 00 
3. Run traffic for 60 seconds and validate statistics.  
4. Configure constant rate test traffic for incast with dscp3, set ACK/NACK dscp7.  
5. Configure constant rate test traffic for broadcast with dscp3, set ACK/NACK dscp7.  
6. Run traffic for 60 seconds and validate statistics. 
7. Configure constant rate test traffic for broadcast with dscp4, set ACK/NACK dscp4.  
8. Run traffic for 60 seconds and validate statistics. 

### Expected Result:  

1. In step 5, messages completions suffered ACK-timeout retransmission under PFC-pause-induced latency or failed after retransmission with ACK loss. 
2. In step 8, all messages should be completed without retransmission. ACK timeout retransmission is mitigated by a higher queue. 
3. In step 10, all messages should be completed without retransmission. ACK timeout retransmission is mitigated by another lossless queue. 
