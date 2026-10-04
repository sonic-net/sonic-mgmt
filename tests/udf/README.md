# Simple Traffic Test - sonic-mgmt Framework

This directory contains a minimal example of sending packets to a DUT using the sonic-mgmt framework.

## Files

- `test_simple_traffic.py` - Basic packet sending examples

## Prerequisites

1. **sonic-mgmt container** running
2. **Testbed configured** (testbed.yaml)
3. **DUT accessible** via SSH
4. **PTF host** running and connected to DUT

## Running the Test

### 1. Enter sonic-mgmt container

```bash
cd ~/sonic-mgmt
docker exec -it sonic-mgmt bash
```

### 2. Run the simple traffic test

```bash
cd /data/sonic-mgmt/tests

# Run just the send test (no verification)
pytest udf/test_simple_traffic.py::test_send_simple_tcp_packet \
    --inventory=../ansible/lab \
    --host-pattern=YOUR_DUT_NAME \
    --testbed=YOUR_TESTBED_NAME \
    --testbed_file=../ansible/testbed.yaml \
    -v -s

# Run send and verify test
pytest udf/test_simple_traffic.py::test_send_and_verify_packet \
    --inventory=../ansible/lab \
    --host-pattern=YOUR_DUT_NAME \
    --testbed=YOUR_TESTBED_NAME \
    --testbed_file=../ansible/testbed.yaml \
    -v -s
```

### 3. Example with real values

```bash
# If your testbed is named "vms-kvm-t0" and DUT is "sonic-switch"
pytest udf/test_simple_traffic.py::test_send_simple_tcp_packet \
    --inventory=../ansible/lab \
    --host-pattern=sonic-switch \
    --testbed=vms-kvm-t0 \
    --testbed_file=../ansible/testbed.yaml \
    -v -s
```

## What Each Test Does

### `test_send_simple_tcp_packet`
- Sends a single TCP packet to DUT
- Does NOT verify reception (minimal example)
- Shows how to:
  - Get DUT information
  - Build a packet
  - Send it via PTF

### `test_send_and_verify_packet`
- Sends a packet AND verifies it's received
- Shows how to:
  - Create expected packet masks
  - Verify packet forwarding
  - Handle packet transformations (TTL decrement, MAC rewrite)

## Understanding the Code

### Key Components

1. **Fixtures Used:**
   - `duthosts` - Access to DUT(s)
   - `rand_one_dut_hostname` - Random DUT selection
   - `ptfadapter` - PTF packet operations
   - `tbinfo` - Testbed information

2. **Getting Router MAC:**
   ```python
   router_mac = duthost.facts["router_mac"]
   ```

3. **Building a Packet:**
   ```python
   pkt = testutils.simple_tcp_packet(
       eth_dst=router_mac,
       eth_src="00:11:22:33:44:55",
       ip_src="10.0.0.1",
       ip_dst="10.0.0.2",
       ip_ttl=64,
       tcp_sport=1234,
       tcp_dport=80,
       pktlen=100
   )
   ```

4. **Sending a Packet:**
   ```python
   ptfadapter.dataplane.flush()  # Clear any old packets
   testutils.send(ptfadapter, ptf_src_port, pkt, count=1)
   ```

5. **Verifying a Packet:**
   ```python
   testutils.verify_packet(ptfadapter, expected_pkt, ptf_dst_port, timeout=5)
   ```

## Customizing the Packet

### Send UDP instead of TCP:
```python
pkt = testutils.simple_udp_packet(
    eth_dst=router_mac,
    ip_src="10.0.0.1",
    ip_dst="10.0.0.2",
    udp_sport=1234,
    udp_dport=5678
)
```

### Send ICMP:
```python
pkt = testutils.simple_icmp_packet(
    eth_dst=router_mac,
    ip_src="10.0.0.1",
    ip_dst="10.0.0.2"
)
```

### Add custom payload:
```python
pkt = testutils.simple_tcp_packet(
    eth_dst=router_mac,
    ip_src="10.0.0.1",
    ip_dst="10.0.0.2"
)
pkt = pkt / scapy.Raw(load=b"\xAB\xCD\xEF")  # Add custom bytes
```

### Build completely custom packet:
```python
pkt = scapy.Ether(dst=router_mac, src="00:11:22:33:44:55")
pkt = pkt / scapy.IP(src="10.0.0.1", dst="10.0.0.2")
pkt = pkt / scapy.TCP(sport=1234, dport=80)
pkt = pkt / scapy.Raw(load=b"Custom payload")
```

## Verifying Packets Reach the DUT

There are **multiple ways** to verify if packets are reaching the DUT:

### Method 1: PTF Packet Verification (Recommended)

Check if packet is received back on PTF ports:

```python
# Example from test_simple_traffic.py::test_send_and_verify_packet
import ptf.testutils as testutils
from ptf.mask import Mask

# Send packet
testutils.send(ptfadapter, src_port, pkt, count=1)

# Verify packet received on specific port
testutils.verify_packet(ptfadapter, expected_pkt, dst_port, timeout=5)

# OR verify packet on ANY of multiple ports
testutils.verify_packet_any_port(ptfadapter, expected_pkt, ports=[1,2,3], timeout=5)
```

Run: `pytest udf/test_simple_traffic.py::test_send_and_verify_packet -v -s`

### Method 2: Polling for Any Packet

Check if ANY packet arrives (useful for debugging):

```python
# Example from test_minimal.py::test_verify_loopback
result = testutils.dp_poll(ptfadapter, device_number=0, timeout=2)

if isinstance(result, ptfadapter.dataplane.PollSuccess):
    print(f"Packet received on port {result.port}")
    print(f"Packet data: {result.packet.hex()}")
else:
    print("No packet received")
```

Run: `pytest udf/test_minimal.py::test_verify_loopback -v -s`

### Method 3: DUT Interface Counters (Most Reliable)

Check DUT interface counters before/after sending:

```python
# Example from test_minimal.py::test_verify_on_dut_with_counters

# Get counters BEFORE
result_before = duthost.shell("show interfaces counters -i Ethernet0")

# Send packets
testutils.send(ptfadapter, ptf_port, pkt, count=10)

# Get counters AFTER
result_after = duthost.shell("show interfaces counters -i Ethernet0")

# Compare RX_OK counters
```

Run: `pytest udf/test_minimal.py::test_verify_on_dut_with_counters -v -s`

### Method 4: Manual Verification via SSH

SSH directly to DUT during test:

```bash
# In one terminal: Run the test
pytest udf/test_minimal.py::test_minimal_send_packet -v -s

# In another terminal: SSH to DUT and monitor
ssh admin@<dut-ip>
show interfaces counters      # Check RX counters
show interfaces status         # Check port status
show ip route                  # Check routing table

# Or use tcpdump on DUT (if available)
sudo tcpdump -i Ethernet0 -n -v
```

### Method 5: PTF tcpdump

Capture packets on PTF host directly:

```bash
# SSH to PTF host
docker exec -it <ptf-container> bash

# Run tcpdump on specific interface
tcpdump -i eth0 -n -v -X

# Or save to file for analysis
tcpdump -i eth0 -w /tmp/capture.pcap
```

### Method 6: Check Logs

Check if packet processing is logged:

```python
# In your test
duthost.shell("show logging | grep -i <some-identifier>")

# Or check syslog
duthost.shell("tail -f /var/log/syslog")
```

## Verification Summary Table

| Method | Use Case | Pros | Cons |
|--------|----------|------|------|
| **PTF verify_packet()** | Verify forwarding | Precise, automated | Needs routing setup |
| **PTF dp_poll()** | Debug packet arrival | Simple, fast | No verification logic |
| **DUT Counters** | Confirm RX on DUT | Most reliable | Needs counter parsing |
| **Manual SSH** | Deep debugging | Full control | Manual, slow |
| **PTF tcpdump** | Low-level capture | See raw packets | Requires PTF access |
| **DUT Logs** | Troubleshooting | Detailed info | May not show all packets |

## Troubleshooting

### Test skips with "No PTF ports available"
- Check your testbed.yaml has correct topology
- Verify PTF host is running: `docker ps | grep ptf`

### Packet not received
- **Check DUT routing**: `show ip route`
- **Verify port is up**: `show interface status`
- **Check counters**: `show interfaces counters -i Ethernet0`
- **Verify PTF interfaces**: `docker exec -it <ptf> ifconfig`

### Permission errors
- Make sure you're in the sonic-mgmt container
- Check ansible inventory has correct credentials

### Packet verification fails but counters increase
- Packet is reaching DUT but not being forwarded
- Check routing, ARP, next-hop configuration
- Packet might be dropped (check drop counters)

## Next Steps

Once this works, you can:
1. Add UDF configuration to DUT
2. Craft packets with UDF fields
3. Verify UDF extraction with ACL rules
4. Check hash behavior with UDF

See `test_udf_basic.py` (to be created) for UDF-specific examples.
