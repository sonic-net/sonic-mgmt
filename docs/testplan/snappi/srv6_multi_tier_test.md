# SONiC Switch SRv6 Dataplane Performance Test -- Multi-tier Setup

- [Test Objective](#test-objective)
- [Test Setup](#test-setup)
- [Test Parameters](#test-parameters)
- [Test Steps](#test-steps)
- [Metrics to Collect](#metrics-to-collect)

## Test Objective

This test aims to assess the data-plane performance of the SRv6 forwarding function of SONiC switches in a typical multi-tier network.

## Test Setup

### Network Topology Setup

- The test is designed to be run againts a Network Under Test (NUT) with topology `nut-2tiers`.
- There should be at least two Tier-0 switches each of which is connected to a Traffic Generator via full duplex links and they should be connected to a common Tier-1 switch.
- The switches should have as many parallel links as possible between each other and the traffic generators in order to maximize the bandwidth utilization of the switches.

### Network Configuration

The switches should have SRv6 and route configurations as follows:
- Each switch should have a sufficient number of SRv6 SIDs(uN) configured so that its neighbors in a different tier can control which link to send a packet when doing SRv6 forwarding.
- Assuming that every switch at Tier-0 has 16 uplinks and 16 downlinks in the NUT, then every switch should have at least 16 SRv6 SIDs. If using locator block fcbb:bbbb::, the SIDs can be configured as follows:
    - For T0 device indexed by i, the SRv6 SIDs can be configured as follows: fcbb:bbbb:hex(i)01::/48 ~ fcbb:bbbb:hex(i)10::/48
    - If there are M T0 devices, the SRv6 SIDs of the T1 device can be configured as follows: fcbb:bbbb:hex(16M + 1)01::/48 ~ fcbb:bbbb:hex(16M + 1)10::/48
    - The traffic generator corresponding to i-th T0 device can have SRv6 SIDs as follows: fcbb:bbbb:hex(i)11::/48 ~ fcbb:bbbb:hex(i)20::/48
- Each switch should have a static route entry configured for each SRv6 SID that its neighbors have. For the example above, every T0 device should have 32 static routes (16 upward + 16 downward). The T1 device should have 16 x M static routes.

### Traffic Generation Configuration

The traffic generators should be configured to send traffic as follows:
- We should split the ports of the traffic generators into two groups (e.g. first half vs last half) so that two groups have equal bandwidth/capacity.
- Each port of the traffic generators should mutually exclusively communicate with a single port in the other group.
- Every pair of ports should communicate using a SRv6 path (by specifying SRv6 SID list in IPv6 header) that does not share any link with any other pair of ports so that the network is congestion free by design.

For a NUT which have M T0 devices with M traffic generators that has N ports, the SRv6 paths used by each traffic generator port can be calculated as follows:
- The ports of the i-th (0 <= i < M/2) traffic generator (in the first group) can use SRv6 paths:
    - fcbb:bbbb:hex(i)01:hex(16M)01:hex(M/2 + i)01:hex(M/2 + i)hex(N + 1)::
    - fcbb:bbbb:hex(i)02:hex(16M)02:hex(M/2 + i)02:hex(M/2 + i)hex(N + 2)::
    - ...
    - fcbb:bbbb:hex(i)10:hex(16M)hex(N):hex(M/2 + i)10:hex(M/2 + i)hex(2N)::
- The ports of the i-th (M/2 <= i < M) traffic generator (in the second group) can use SRv6 paths:
    - fcbb:bbbb:hex(i)01:hex(16M)01:hex(i - M/2)01:hex(i - M/2)hex(N + 1)::
    - fcbb:bbbb:hex(i)02:hex(16M)02:hex(i - M/2)02:hex(i - M/2)hex(N + 2)::
    - ...
    - fcbb:bbbb:hex(i)10:hex(16M)hex(N):hex(i - M/2)10:hex(i - M/2)hex(2N)::

### Metrics Monitoring

The test should perform the following metrics monitoring:
- Collects key metrics listed in [Metrics to Collect](#metrics-to-collect) periodically from switches during the test.
- Measure the throughput of the traffic on the receiver side.
- Measure the latency of every packet received and log the data.


### Traffic Pattern

The traffic patterns that we want to test includes:
- 100% packets sized at 128 bytes
- 100% packets sized at 256 bytes
- 100% packets sized at 4K bytes
- 1% packets sized at 128 bytes, a random percent (< 90%) of packets sized at 256 bytes and all the other packets sized at 4K bytes.

## Test Parameters

- `test_duration`: The duration of the test in minutes, which supports 1min, 5min, 15mins, 60mins, 1day and 2days.
- `packet_size`: The size of the packets in bytes to be sent in the traffic, which supports 128, 256, 4096 and mix.
- `traffic_rate`: The rate of the traffic to be sent, which supports 10%, 25%, 50%, 75% and 100% of the line rate.
- `collect_interval`: The interval between two metrics collection operations on the switch.

## Test Steps

1. For each combination of test parameters, start the traffic generator to generate traffic according the parameters provided.
2. Start the monitoring thread to collect metrics from all SONiC devices in the testbed.
3. Wait until the test to be completed.
4. Stop the traffic generator.

## Metrics to collect

During this test, we are going to collect the following metrics from the SONiC devices in the testbed:

### Interface Metrics

The `show interface counters` is used on the switch to retrieve interface metrics. The following labels are expected to be provided:

| User Interface Label          | Label Key in DB | Example Value |
|-------------------------------|-----------------|---------------|
| `METRIC_LABEL_DEVICE_ID`      | device.id       | switch-A      |
| `METRIC_LABEL_DEVICE_PORT_ID` | device.port.id  | Ethernet8     |

| User Interface Metric Name    | Metric Name in DB | Example Value  |
|-------------------------------|-------------------|----------------|
| `METRIC_NAME_PORT_STATE`      | port.state        | OPER_STATUS.UP |
| `METRIC_NAME_PORT_RX_BPS`     | port.rx.bps       | 26.38          |
| `METRIC_NAME_PORT_RX_UTIL`    | port.rx.util      | 0.00           |
| `METRIC_NAME_PORT_RX_OK`      | port.rx.ok        | 5190           |
| `METRIC_NAME_PORT_RX_ERR`     | port.rx.err       | 0              |
| `METRIC_NAME_PORT_RX_DROP`    | port.rx.drop      | 248            |
| `METRIC_NAME_PORT_RX_OVERRUN` | port.rx.overrun   | 0              |
| `METRIC_NAME_PORT_TX_BPS`     | port.tx.bps       | 9.76           |
| `METRIC_NAME_PORT_TX_UTIL`    | port.tx.util      | 0.00           |
| `METRIC_NAME_PORT_TX_OK`      | port.tx.ok        | 4896           |
| `METRIC_NAME_PORT_TX_ERR`     | port.tx.err       | 0              |
| `METRIC_NAME_PORT_TX_DROP`    | port.tx.drop      | 10             |
| `METRIC_NAME_PORT_TX_OVERRUN` | port.tx.overrun   | 0              |

### Queue Metrics

The `show queue watermark unicast` or  `show queue watermark multicast` is used on the switch to retrieve queue metrics. The following labels are expected to be provided:

| User Interface Label             | Label Key in DB   | Example Value |
|----------------------------------|-------------------|---------------|
| `METRIC_LABEL_DEVICE_ID`         | device.id         | switch-A      |
| `METRIC_LABEL_DEVICE_PORT_ID`    | device.port.id    | Ethernet8     |
| `METRIC_LABEL_DEVICE_QUEUE_ID`   | device.queue.id   | MC1           |
| `METRIC_LABEL_DEVICE_QUEUE_CAST` | device.queue.cast | multicast     |

| User Interface Metric Name          | Metric Name in DB     | Example Value |
|-------------------------------------|-----------------------|---------------|
| `METRIC_NAME_QUEUE_WATERMARK_BYTES` | queue.watermark.bytes | 7620          |

### SRv6 MY_SID Metrics

The `show srv6 stat` command is used on the switch to retrieve the packets and bytes counter for every SRv6 MY_SID entry configured on the device. The following labels are expected to be provided:

| User Interface Label              | Label Key in DB  | Example Value   |
|-----------------------------------|------------------|-----------------|
| `METRIC_LABEL_DEVICE_ID`          | device.id        | switch-A        |
| `METRIC_LABEL_DEVICE_SRV6_MY_SID` | device.srv6_my_sid | fcbb:bbbb:1::/48 |

| User Interface Metric Name             | Metric Name in DB               | Example Value       |
|----------------------------------------|---------------------------------|---------------------|
| `METRIC_NAME_SRV6_MY_SID_BYTES`        | srv6_my_sid.bytes               | 10000               |
| `METRIC_NAME_SRV6_MY_SID_PACKETS`      | srv6_my_sid.packets             | 2                   |