## Overview

In traditional packet loss handling, when a lossy queue exceeds its buffer threshold, packets are silently dropped without notifying the destination host. While packet recovery can occur via fast retransmission or timeout-based retransmission, the latter method introduces significant latency, degrading application performance.

Packet Trimming is an enhancement mechanism designed to optimize network performance during congestion conditions. Instead of dropping packets, it will trim packets to a configured size and try sending them on a different queue (usually a higher-priority queue) to deliver packet drop notifications to the end host. The end host can then quickly send a retransmission request for the trimmed packet to the source device. This speeds up retransmissions and reduces network latency.

### Scope

The test cases included in this document aim to verify the following:
1. Packet trimming counters for lossy egress queues on SONiC switches are accurate. This will be verified by comparing the counter values with the number of trimmed packets received on the Keysight RX port.
2. Rate of trimmed packets received on the Keysight RX port is as expected. This expected rate depends on the rate of packets received per second from Keysight TX ports, rate-limit imposed on the SONiC TX port (or the line rate of the SONiC TX port if there is no imposed rate-limit), and DWRR weights for different queues.

### Testbed

```
+-------------+      +--------------+      +-------------+
|             |------|              |      |             |
| Keysight TX |------|   SONiC DUT  |------| Keysight RX |
|             |------|              |      |             |
|             |------|              |      |             |
+-------------+      +--------------+      +-------------+
```
Keysight ports are connected via SONiC switch as shown in the illustration above.

The Keysight device is connected to 5 ports of the SONiC DUT (4 ports for TX and 1 port for RX).

## Packet Trimming on SONiC

To configure packet trimming on the SONiC DUT, use the following command:

<code>config switch-trimming global --size {s} --dscp {d} --queue {q}</code>

In the above command, `s` is the size of packets after trimming (in bytes), `d` is the DSCP value assigned to trimmed packets, and `q` is the egress queue number used to send out trimmed packets.

**Note:** In our tests, we set trimmed packet size to 256.

You also need to enable packet trimming for the buffer profile associated with the egress queue:

<code>config mmu -p {buffer_profile_name} -t on</code>

To see buffer profiles configured on the DUT, you can use the following command:

<code>show mmu</code>

Queue-level counters must be enabled prior to running tests:

<code>counterpoll queue enable</code>

The default update interval for queue counters is 10 seconds. It is recommended that you set this interval to a small value (e.g., 1 second) so that the counter is updated frequently:

<code>counterpoll queue interval 1000</code>

The following command will display the number of dropped and trimmed packets per queue for every queue of every port:

<code>show queue counters --all</code>

Queue-level counters can be reset using the following command:

<code>sonic-clear queuecounters</code>

The counters should be reset before each test.


### Creating Congestion on SONiC Egress Queues

In order to test the Packet Trimming feature, we need to create congestion on the SONiC egress queue so that the queue becomes full and the switch starts trimming packets that would be otherwise dropped. For unicast (1-to-1) test cases, we need to rate-limit the egress queue to create congestion (since we assume that all ports have the same speed). For incast test cases (2-to-1 or 4-to-1), congestion should happen without any extra effort. However, in some incast tests we will rate-limit the egress queue so that trimmed packets are not dropped by the DUT due to congestion.

We can rate-limit a queue by using a scheduler. First, we need to find the scheduler that is used for a particular queue. For example, to
find the scheduler for `Ethernet100|6`, we can use the following command:

<code>sonic-db-cli CONFIG_DB HGET "QUEUE|Ethernet100|6" "scheduler"</code>

Then, we can limit the rate of packets that can be added to the egress queue per second as follows (assuming that the above command returned `scheduler.0`):

<code>sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.0" "pir" "100" "meter_type" "packets"</code>

The above command will limit the rate of packets allowed into `Ethernet100|6` to 100 packets per second.

**Note:** If no scheduler is configured for the test egress queue (e.g., `Ethernet100|6`), then we can define one and associate it with the queue using the following commands:

<code>sonic-db-cli CONFIG_DB HSET "SCHEDULER|test_scheduler" "type" "DWRR" "weight" "15" "pir" "100" "meter_type" "packets"</code>

<code>sonic-db-cli CONFIG_DB HSET "QUEUE|Ethernet100|6" "scheduler" "test_scheduler"</code>

## Setup Configuration

### DUT Configuration
•	Enable queue-level counters on the SONiC DUT.

•	Enable packet trimming on the DUT and set the trimmed packet size to 256.

### Keysight Configuration
•	All Keysight ports should have the same bandwidth capacity.

•	Test specific configurations are mentioned in respective test cases.

## Test Cases (Validating Packet Trimming Counters)

### Test Objective

These tests aim to verify that the DUT’s packet trimming counters for egress queues are accurate.

### Test Parameters
Here are the parameters used to generate different test cases:

1. The number of SONiC RX ports: Can be 1 (unicast), 2, or 4 (incast).
2. All SONiC test ports belong to the same memory module or they belong to different memory modules.
3. Randomly-picked lossy egress queue $i$. All ingress test traffic to the DUT will be mapped to this queue. The index of this queue must be different from the queue index that trimmed packets will be sent to (configured using the `config switch-trimming global` command).
4. Using IPv4 or IPv6 packets in tests.
5. Whether rate-limiting is applied to queue $i$ or not.
6. Using a single or multiple DSCP values for test packets. All of these DSCP values must map to the index of queue $i$.

Each test case has been created by selecting a value for each of the above parameters.

### Test Assumptions
These assumptions apply to all test cases:
1. The size of each test packet is 1KB.
2. Each test packet has a correct DSCP value so that the DUT will send it to the selected egress queue $i$. The correct DSCP value can be obtained by looking at `DSCP_TO_TC_MAP` and `TC_TO_QUEUE_MAP` tables in `CONFIG DB`.

### Test Case #1

#### Parameters Used
1. Unicast traffic (1-to-1)
2. All test ports in the same memory module.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. Rate-limit of 10 million packets per second (PPS) imposed on queue $i$.
6. Using a single DSCP value for all test packets.

#### Test Configuration

- On SONiC DUT configure the following:
  1. Rate-limit egress flow for queue $i$ to 10 million PPS in order to create congestion.

- Configure following traffic items on the Keysight device(s):
  1. Test data traffic: A traffic item from the Keysight TX port to the Keysight RX port. The PPS rate from the Keysight TX port should be greater that 10 million to create congestion.

#### Test Steps

1. Clear all queue counters on the SONiC DUT.
2. Start sending the test packets and wait until the egress queue $i$ is full.
4. Start packet capturing on the Keysight RX port.
5. Stop sending test packets after 10 seconds.
6. Wait until both queues for trimmed packets and test packets are empty.
6. Stop packet capturing on the Keysight RX port.
7. Verify the following:
   * The number of trimmed packets received on the Keysight RX port is equal to the trim counter for queue $i$. 

### Test Case #2

#### Parameters Used
1. Unicast traffic (1-to-1)
2. Test ports in different memory modules.
3. Randomly-selected lossy queue $i$.
4. Using IPv6 packets for test.
5. Rate-limit of 10 million packets per second (PPS) imposed on queue $i$.
6. Using a single DSCP value for all test packets.

#### Test Configuration

Same as Test Case #1.

#### Test Steps

Same as Test Case #1.

### Test Case #3

#### Parameters Used
1. Incast traffic (2-to-1)
2. All test ports in the same memory module.
3. Randomly-selected lossy queue $i$.
4. Using IPv6 packets for test.
5. Rate-limit of 10 million packets per second (PPS) imposed on queue $i$.
6. Using a single DSCP value for all test packets.

#### Test Configuration

- On SONiC DUT configure the following:
  1. Rate-limit egress flow for queue $i$ to 10 million PPS in order to create congestion.

- Configure following traffic items on the Keysight device(s):
  1. Test data traffic: A traffic item from the Keysight TX port to the Keysight RX port.

#### Test Steps

Same as Test Case #1.

### Test Case #4

#### Parameters Used
1. Incast traffic (2-to-1)
2. Test ports in different memory modules.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. Rate-limit of 10 million packets per second (PPS) imposed on queue $i$.
6. Using 2 different DSCP values for test packets. Packets sent to the same SONiC RX port have the same DSCP value.

#### Test Configuration

Same as Test Case #3.

#### Test Steps

Same as Test Case #1.

### Test Case #5

#### Parameters Used
1. Incast traffic (4-to-1)
2. All test ports in the same memory module.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. Rate-limit of 10 million packets per second (PPS) imposed on queue $i$.
6. Using a single DSCP value for all test packets.

#### Test Configuration

Same as Test Case #3.

#### Test Steps

Same as Test Case #1.

### Test Case #6

#### Parameters Used
1. Incast traffic (4-to-1)
2. Test ports in different memory modules.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. Rate-limit of 10 million packets per second (PPS) imposed on queue $i$.
6. Using 4 different DSCP values for test packets. Packets sent to the same SONiC RX port have the same DSCP value.

#### Test Configuration

Same as Test Case #3.

#### Test Steps

Same as Test Case #1.

### Test Case #7

#### Parameters Used
1. Incast traffic (4-to-1)
2. All test ports in the same memory module.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. No rate-limit imposed on queue $i$.
6. Using a single DSCP value for all test packets.

#### Test Configuration

- Configure following traffic items on the Keysight device(s):
  1. Test data traffic: A traffic item from the Keysight TX port to the Keysight RX port.

#### Test Steps

1. Clear all queue counters on the SONiC DUT.
2. Start sending the test packets and wait until the egress queue $i$ is full.
4. Start packet capturing on the Keysight RX port.
5. Stop sending test packets after 10 seconds.
6. Wait until both queues for trimmed packets and test packets are empty.
6. Stop packet capturing on the Keysight RX port.
7. Verify the following:
   * The number of trimmed packets received on the Keysight RX port is equal to the trim counter for queue $i$ minus the drop counter for the trimmed packet queue.

### Test Case #8

#### Parameters Used
1. Incast traffic (4-to-1)
2. Test ports in different memory modules.
3. Randomly-selected lossy queue $i$.
4. Using IPv6 packets for test.
5. No rate-limit imposed on queue $i$.
6. Using 4 different DSCP values for test packets. Packets sent to the same SONiC RX port have the same DSCP value.

#### Test Configuration

Same as Test Case #7.

#### Test Steps

Same as Test Case #7.

## Test Cases (Verifying the Rate of Trimmed Packets Received)

### Test Objective

These tests aim to verify that the rate of trimmed packets received on the Keysight RX port is as expected.

### Test Parameters
Here are the parameters used to generate different test cases:

1. The number of SONiC RX ports: Can be 2 or 4 (incast).
2. All SONiC test ports belong to the same memory module or they belong to different memory modules.
3. Randomly-picked lossy egress queue $i$. All ingress test traffic to the DUT will be mapped to this queue. The index of this queue must be different from the queue index that trimmed packets will be sent to (configured using the `config switch-trimming global` command).
4. Using IPv4 or IPv6 packets in tests.
5. Using a single or multiple DSCP values for test packets. All of these DSCP values must map to the index of queue $i$.

Each test case has been created by selecting a value for each of the above parameters.

### Test Assumptions
These assumptions apply to all test cases:
1. The size of each test packet is 1KB.
2. Each test packet has a correct DSCP value so that the DUT will send it to the selected egress queue $i$. The correct DSCP value can be obtained by looking at `DSCP_TO_TC_MAP` and `TC_TO_QUEUE_MAP` tables in `CONFIG DB`.

### Test Case #9

#### Parameters Used
1. Incast traffic (2-to-1)
2. All test ports in the same memory module.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. Using a single DSCP value for all test packets.

#### Test Configuration

- Configure following traffic items on the Keysight device(s):
  1. Test data traffic: A traffic item from the Keysight TX port to the Keysight RX port.

#### Test Steps

1. Clear all queue counters on the SONiC DUT.
2. Start sending the test packets and wait until both the egress queue $i$ and the queue for trimmed packets are full.
3. Start packet capturing on the Keysight RX port.
4. Stop sending test packets after 10 seconds.
5. Stop packet capturing on the Keysight RX port.
6. Verify the following:
   * The rate of trimmed packets received on the Keysight RX port is proportional to the DWRR weight assinged to the trimmed packet queue.

### Test Case #10

#### Parameters Used
1. Incast traffic (2-to-1)
2. Test ports in different memory modules.
3. Randomly-selected lossy queue $i$.
4. Using IPv4 packets for test.
5. Using 2 different DSCP values for test packets. Packets sent to the same SONiC RX port have the same DSCP value.

#### Test Configuration

Same as Test Case #9.

#### Test Steps

Same as Test Case #9.

### Test Case #11

#### Parameters Used
1. Incast traffic (4-to-1)
2. All test ports in the same memory module.
3. Randomly-selected lossy queue $i$.
4. Using IPv6 packets for test.
5. Using a single DSCP value for all test packets.

#### Test Configuration

Same as Test Case #9.

#### Test Steps

Same as Test Case #9.

### Test Case #12

#### Parameters Used
1. Incast traffic (4-to-1)
2. Test ports in different memory modules.
3. Randomly-selected lossy queue $i$.
4. Using IPv6 packets for test.
5. Using 4 different DSCP values for test packets. Packets sent to the same SONiC RX port have the same DSCP value.

#### Test Configuration

Same as Test Case #9.

#### Test Steps

Same as Test Case #9.
