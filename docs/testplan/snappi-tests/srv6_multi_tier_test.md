# SONiC Switch SRv6 Dataplane Performance Test -- Multi-tier Setup

- [Test Objective](#test-objective)
- [Test Setup](#test-setup)
- [Test Steps](#test-steps)

## Test Objective

This test aims to assess the data-plane performance of the SRv6 forwarding function of SONiC switches in a typical multi-tier network.

## Test Setup

The test is designed to be run in a network under test that at least has two tiers.

### Network Topology Setup

- There are at least two Tier-0 switches each of which is connected to a Traffic Generator via full duplex links.
- The switches should have as many parallel links as possible between each other and the traffic generators in order to maximize the bandwidth utilization of the switches.

### Network Configuration

The switches should have SRv6 and route configurations as follows:
- Each switch should have a sufficient number of SRv6 SIDs(uN) configured so that its neighbors in a different tier can control which link to send a packet when doing SRv6 forwarding.
- Each switch should have a static route entry configured for each SRv6 SID that its neighbors have.

### Traffic Generation Configuration

The traffic generators should be configured to send traffic as follows:
- We should split the ports of the traffic generators into two groups so that two groups have equal bandwidth/capacity.
- Each port of the traffic generators should mutually exclusively communicate with a single port in the other group.
- Every pair of ports should communicate using a SRv6 path (by specifying SRv6 SID list in IPv6 header) that does not share any link with any other pair of ports so that the network is congestion free by design.

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

1. Pick a traffic pattern and start the traffic generator to generate traffic according the parameters provided.
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

### PSU Metrics

The `show platform psu` command is used on the switch to retrieve PSU metrics. The following labels are expected to be provided:

| User Interface Label             | Label Key in DB   | Example Value   |
|----------------------------------|-------------------|-----------------|
| `METRIC_LABEL_DEVICE_ID`         | device.id         | switch-A        |
| `METRIC_LABEL_DEVICE_PSU_ID`     | device.psu.id     | PSU 1           |
| `METRIC_LABEL_DEVICE_PSU_MODEL`  | device.psu.model  | PWR-ABCD        |
| `METRIC_LABEL_DEVICE_PSU_SERIAL` | device.psu.serial | 1Z011010112349Q |
| `METRIC_LABEL_DEVICE_PSU_HW_REV` | device.psu.hw_rev | 02.00           |

| User Interface Metric Name | Metric Name in DB | Example Value   |
|----------------------------|-------------------|-----------------|
| `METRIC_NAME_PSU_VOLTAGE`  | psu.voltage       | 12.09           |
| `METRIC_NAME_PSU_CURRENT`  | psu.current       | 18.38           |
| `METRIC_NAME_PSU_POWER`    | psu.power         | 222.00          |
| `METRIC_NAME_PSU_STATUS`   | psu.status        | PSU_STATUS.OK   |
| `METRIC_NAME_PSU_LED`      | psu.led           | LED_STATE.GREEN |

### Sensor Temperature Metrics

The `show platform temperature` command is used on the switch to retrieve sensor temperatuer metrics. Among the outputs, the "CPU temp sensor" and "Switch Card temp sensor" are of particular interest. The following labels are expected to be provided:

| User Interface Label            | Label Key in DB  | Example Value   |
|---------------------------------|------------------|-----------------|
| `METRIC_LABEL_DEVICE_ID`        | device.id        | switch-A        |
| `METRIC_LABEL_DEVICE_SENSOR_ID` | device.sensor.id | Cpu temp sensor |

| User Interface Metric Name             | Metric Name in DB        | Example Value       |
|----------------------------------------|--------------------------|---------------------|
| `METRIC_NAME_TEMPERATURE_READING`      | temperature.reading      | 29.5                |
| `METRIC_NAME_TEMPERATURE_HIGH_TH`      | temperature.high_th      | 95                  |
| `METRIC_NAME_TEMPERATURE_LOW_TH`       | temperature.low_th       | 0                   |
| `METRIC_NAME_TEMPERATURE_CRIT_HIGH_TH` | temperature.crit_high_th | 115                 |
| `METRIC_NAME_TEMPERATURE_CRIT_LOW_TH`  | temperature.crit_low_th  | -5                  |
| `METRIC_NAME_TEMPERATURE_WARNING`      | temperature.warning      | WARNING_STATUS.TRUE |

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