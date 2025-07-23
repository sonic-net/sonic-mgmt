# SONiC Switch SRv6 Dataplane Performance Test

- [Test Objective](#test-objective)
- [Test Setup](#test-setup)
- [Test Parameters](#test-parameters)
- [Test Steps](#test-steps)
- [Metrics to Collect](#metrics-to-collect)

## Test Objective

This test aims to assess the data-plane performance of the SRv6 forwarding function of a SONiC switch.

## Test Setup

### Network Topology Setup

The test is designed to be topology-aganostic.
The recommded topology to use includes:
1. nut-2tiers
2. Snake topo as shown in ![Snake Topology](./assets/snake_topo.png)

### Network Configuration

The DUT should have SRv6 and route configurations as follows:
- Every Device Under Test(DUT) should be configured with a number of SRv6 SIDs up to the maximum number of parallel links between DUT and the neighbors. If using fcbb:bbbb:: as the locator block, the SRv6 SIDs of a switch with I as device index in the topo and Q as the number of maximum parallel links can be configured to be fcbb:bbbb:hex(I << 8 + 1)::/48 ~ fcbb:bbbb:hex(I << 8 + Q)::/48.
- Every Traffic Generator(TG) should also be configured a number of SRv6 SIDs each of which corresponds to a link between the traffic generator and the DUT. If using fcbb:bbbb:: as the locator block, the SRv6 SIDs of a traffic generator with I as device index in N ports can be as fcbb:bbbb:hex(I << 8 + 1)::/48 ~ fcbb:bbbb:hex(I << 8 + N)::/48.
- The DUT should have a static route entry configured for each SRv6 SID that its neighbors (including both DUTs and TGs) have.

### Traffic Generation Configuration

The traffic generators should be configured to send traffic with SRv6 SIDs in IPv6 header and optionally Segment Routing Header.
The exact way of configuring the SRv6 SIDs in the header depends on the topology and the traffic path the users want to test.

We give two examples for nut2tiers topology and snake topology here:

#### SRv6 SIDs configuration for `nut-2tiers` Topology

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

#### SRv6 SIDs configuration for Snake Topology
For a port of the traffic generator indexed by i (1 <= i <= N), the packet sent by the traffic generator should have SRv6 SID list in IPv6 header (and potentially Segment Routing Header) as follows:
- fcbb:bbbb:i00:i:hex(N + i):hex(2N + i)...hex(MN + i):hex(N+i)00::, note: hex(N+i)00 refers to the SRv6 SID of the receiving traffic generator.

To maximize the stress on the DUT, the i-th port of the traffic generators on the other side of the topology should send packets to the DUT with SRv6 SID list as follows:
- fcbb:bbbb:hex(N+i)00:hex(MN + i):hex((M-1)N + i):...:i:i00::, note: this is essentially the reverse of the SID list used by the other side.

### Metrics Monitoring

The test should perform the following metrics monitoring:
- Collects all metrics listed in [Switch Capability Test](./switch_capacity_test.md) periodically from switches during the test.
- Collects additional metrics listed in [Metrics to Collect](#metrics-to-collect) periodically from switches during the test.
- Measure the throughput of the traffic on the receiver side.
- Measure the latency of every packet received and log the data.


## Test Parameters

- `test_duration`: The duration of the test in minutes, which supports 1min, 5min, 15mins, 60mins, 1day and 2days.
- `packet_size`: The size of the packets in bytes to be sent in the traffic, which supports 128, 256, 4096, and mix of packet size (In the mix, the 128 packet size should always only occupy 1% of the traffic).
- `collect_interval`: The interval between two metrics collection operations on the switch.

## Test Steps

1. For each combination of test parameters, start the traffic generator to generate traffic according to the parameters provided.
2. Start the monitoring thread to collect metrics from all SONiC devices in the testbed.
3. Wait until the test to be completed.
4. Stop the traffic generator.

## Metrics to collect

During this test, we are going to collect the following metrics from the SONiC device in the testbed:

### SRv6 MY_SID Metrics

The `show srv6 stat` command is used on the switch to retrieve the packets and bytes counter for every SRv6 MY_SID entry configured on the device. The following labels are expected to be provided:

| Metrics Label                     | Label Key in DB  | Example Value   |     Description   |
|-----------------------------------|------------------|-----------------|-------------------|
| `METRIC_LABEL_DEVICE_ID`          | device.id        | switch-A        | Switch Identifier |
| `METRIC_LABEL_DEVICE_SRV6_MY_SID` | device.srv6.my_sid | fcbb:bbbb:1::/48 | IP Prefix of the SRv6 SID entry |

| User Interface Metric Name             | Metric Name in DB               | Example Value       |
|----------------------------------------|---------------------------------|---------------------|
| `METRIC_NAME_SRV6_MY_SID_BYTES`        | srv6.my_sid.rx.bytes               | 10000               |
| `METRIC_NAME_SRV6_MY_SID_PACKETS`      | srv6.my_sid.rx.packets             | 2                   |