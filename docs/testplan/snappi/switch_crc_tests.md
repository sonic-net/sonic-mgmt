# Snappi-based CRC Error Handling Test

1. [1. Test Objective](#1-test-objective)  
2. [2. Test Setup](#2-test-setup)  
   1. [2.1. Test port and traffic setup](#21-test-port-and-traffic-setup)  
   2. [2.2. DUT configuration](#22-dut-configuration)  
   3. [2.3. Metrics monitoring](#23-metrics-monitoring)  
3. [3. Test parameters](#3-test-parameters)  
4. [4. Test Steps](#4-test-steps)  
   1. [4.1. Category 1: Line-rate CRC-error drop](#41-category-1-line-rate-crc-error-drop)  
   2. [4.2. Category 2: CRC-error isolation from good traffic](#42-category-2-crc-error-isolation-from-good-traffic)  
      1. [4.2.1. Many-to-1 in-cast](#421-many-to-1-in-cast)  
      2. [4.2.2. 1-to-1 parallel links](#422-1-to-1-parallel-links)  
      3. [4.2.3. Mixed-traffic on a single port](#423-mixed-traffic-on-a-single-port)  
5. [5. Metrics to collect](#5-metrics-to-collect)  
   1. [5.1. Interface Metrics](#51-interface-metrics)  
   2. [5.2. Traffic Generator Metrics](#52-traffic-generator-metrics)  

## 1. Test Objective

Validate that a SONiC switch:

- Drops **100%** of Ethernet frames with CRC errors on ingress at line rate.  
- Forwards **100%** of valid frames unaffected, even when CRC-errored frames arrive simultaneously.

## 2. Test Setup

Reuses the existing Snappi-based pytest framework in the sonic-mgmt repo.

### 2.1. Test port and traffic setup

- **Traffic Generator (TG):** Snappi-capable (e.g. IXIA/Keysight).  
- **DUT ports:** One-to-one mapping to TG ports, identical speed.  
- **Flows:**  
  - **Good-CRC**: default FCS.  
  - **Bad-CRC**: FCS set to `0x00000000` or a random incorrect value.  

### 2.2. DUT configuration

- Place all test ports in a single L2 VLAN (untagged) or assign IPs/routes for IPv4/IPv6 as needed.  
- Ensure interfaces are up and forwarding is enabled.  
- Verify connectivity: `show vlan brief` or `show ip route`.

### 2.3. Metrics monitoring

- A background thread polls DUT interface counters (`show interface counters` or telemetry) periodically during traffic.

## 3. Test parameters

| Parameter        | Description                                         | Example Values                |
|——————|——————————————————|-——————————|
| `packet_size`    | Ethernet frame length                               | 64, 128, 512, 1518 bytes      |
| `crc_error_type` | FCS corruption mode                                 | `zero`, `random`             |
| `tx_port_count`  | Number of concurrent ingress TG ports               | 1, 2, 4                       |
| `ip_version`     | L2 only, IPv4, or IPv6                              | `L2`, `IPv4`, `IPv6`          |
| `test_duration`  | Traffic transmission time                           | 60 seconds                    |

## 4. Test Steps

### 4.1. Category 1: Line-rate CRC-error drop

1. Parameterize test for each combination of `packet_size` and `crc_error_type`.  
2. Build a Snappi flow on one TG port: ingress → egress, FCS corrupted.  
3. Start the metrics-monitoring thread.  
4. Transmit at **100% line rate** for `test_duration`.  
5. Stop traffic; join monitoring thread.  
6. Retrieve stats:  
   - TG Rx on egress port should be **0 frames**.  
   - DUT ingress CRC-error counter Δ must equal the Tx frame count.  
7. **Validation:** Pass if all bad-CRC frames are dropped (egress Rx = 0).

### 4.2. Category 2: CRC-error isolation from good traffic

#### 4.2.1. Many-to-1 in-cast

1. Configure `tx_port_count` TG ingress ports sending to one TG egress port.  
2. Assign flows:  
   - Ports 1…M send **bad-CRC** at line rate.  
   - Remaining ports send **good-CRC** at ≤ (line rate ÷ M) to avoid congestion.  
3. Start monitoring thread.  
4. Start all flows concurrently.  
5. Stop traffic; join monitoring thread.  
6. Retrieve stats:  
   - Egress Rx = sum of good-CRC Tx frames.  
   - Bad-CRC Rx = 0.  
   - DUT ingress CRC-error Δ matches bad-CRC Tx.  
7. **Validation:** Good-CRC traffic sees 0% loss; bad-CRC traffic is fully dropped.

#### 4.2.2. 1-to-1 parallel links

1. Map two TG→DUT port pairs: Pair A (bad-CRC), Pair B (good-CRC).  
2. Configure flows:  
   - Pair A: **only bad-CRC** at line rate.  
   - Pair B: **only good-CRC** at line rate.  
3. Start monitoring thread.  
4. Start both flows simultaneously.  
5. Stop traffic; join monitoring thread.  
6. Retrieve stats:  
   - Pair B egress Rx = Tx (no loss).  
   - Pair A egress Rx = 0.  
   - DUT CRC-error Δ on Pair A ingress = Tx_A.  
7. **Validation:** Bad-CRC drops are isolated; good-CRC throughput unaffected.

#### 4.2.3. Mixed-traffic on a single port

1. Build two Snappi flows on one TG→DUT port:  
   - **Flow-G**: good-CRC at 50% line rate.  
   - **Flow-B**: bad-CRC at 50% line rate.  
2. Start monitoring thread.  
3. Start both flows interleaved.  
4. Stop traffic; join monitoring thread.  
5. Retrieve stats:  
   - Egress Rx_G = Tx_G.  
   - Egress Rx_B = 0.  
   - DUT ingress CRC-error Δ = Tx_B.  
6. **Validation:** Good and bad frames co-exist without head-of-line blocking; good-CRC sees 0% loss.

## 5. Metrics to collect

### 5.1. Interface Metrics

| Label                   | DB Key               | Notes                               |
|-————————|-———————|-————————————|
| `METRIC_LABEL_PORT_ID`  | device.port.id       | e.g. Ethernet4                      |
| `port.rx.crc_errors`    | port.rx.crc_errors   | Number of bad-CRC frames detected   |
| `port.rx.drop`          | port.rx.drop         | Should match CRC error count       |
| `port.tx.ok`            | port.tx.ok           | Number of good frames sent         |
| `port.tx.drop`          | port.tx.drop         | 0 for good-CRC flows               |

### 5.2. Traffic Generator Metrics

| Flow Name         | Metric            | Expectation                           |
|-——————|-——————|—————————————|
| `bad_flow_<p>`    | flow.tx.frames    | > 0 (line rate)                       |
|                   | flow.rx.frames    | 0                                     |
| `good_flow_<p>`   | flow.tx.frames    | > 0                                   |
|                   | flow.rx.frames    | = flow.tx.frames (no loss)            |