# sFlow Dropped Packet Notification (MOD) Test Plan

## Table of Contents

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup Configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Test Case 1: Verify sFlow Drop Monitor Configuration](#test-case-1-verify-sflow-drop-monitor-configuration)
  - [Test Case 2: Verify Drop Monitor Enable/Disable](#test-case-2-verify-drop-monitor-enabledisable)
  - [Test Case 3: Verify Drop Monitor Limit Configuration](#test-case-3-verify-drop-monitor-limit-configuration)
  - [Test Case 4: Verify Dropped Packet Notification Generation - ACL Drop](#test-case-4-verify-dropped-packet-notification-generation---acl-drop)
  - [Test Case 5: Verify Dropped Packet Notification Generation - TTL Exceeded](#test-case-5-verify-dropped-packet-notification-generation---ttl-exceeded)
  - [Test Case 6: Verify Dropped Packet Notification Generation - L3 Routing Miss](#test-case-6-verify-dropped-packet-notification-generation---l3-routing-miss)
  - [Test Case 7: Verify Dropped Packet Notification Generation - MTU Exceeded](#test-case-7-verify-dropped-packet-notification-generation---mtu-exceeded)
  - [Test Case 8: Verify Dropped Packet Notification Generation - Ingress VLAN Filter](#test-case-8-verify-dropped-packet-notification-generation---ingress-vlan-filter)
  - [Test Case 9: Verify Dropped Packet Notification Generation - Buffer/Tail Drop](#test-case-9-verify-dropped-packet-notification-generation---buffertail-drop)
  - [Test Case 10: Verify Drop Monitor Rate Limiting](#test-case-10-verify-drop-monitor-rate-limiting)
  - [Test Case 11: Verify Drop Notification with sFlow Counter Polling](#test-case-11-verify-drop-notification-with-sflow-counter-polling)
  - [Test Case 12: Verify Drop Notification with Packet Sampling](#test-case-12-verify-drop-notification-with-packet-sampling)
  - [Test Case 13: Verify Drop Monitor After Config Reload](#test-case-13-verify-drop-monitor-after-config-reload)
  - [Test Case 14: Verify Drop Monitor After Service Restart](#test-case-14-verify-drop-monitor-after-service-restart)
  - [Test Case 15: Verify Multiple Drop Reasons Simultaneously](#test-case-15-verify-multiple-drop-reasons-simultaneously)
  - [Test Case 16: Verify Drop Notification Sequence Numbers](#test-case-16-verify-drop-notification-sequence-numbers)
  - [Test Case 17: Verify sFlow Drop Extension in Datagram](#test-case-17-verify-sflow-drop-extension-in-datagram)
  - [Test Case 18: Verify Drop Monitor Configuration Persistence](#test-case-18-verify-drop-monitor-configuration-persistence)
  - [Test Case 19: Verify Drop Monitor with Multiple Collectors](#test-case-19-verify-drop-monitor-with-multiple-collectors)
  - [Test Case 20: Verify CLI Show Commands for Drop Monitor](#test-case-20-verify-cli-show-commands-for-drop-monitor)
- [Related DUT CLI Commands](#related-dut-cli-commands)

---

## Overview

### Scope

This test plan covers the sFlow Dropped Packet Notification feature (also known as Mirror-on-Drop or MOD) in SONiC. The feature extends existing sFlow functionality to export information about packets dropped by the network device, enabling real-time visibility into drop events.

The sFlow dropped packet notification mechanism uses the standard sFlow version 5 protocol extension defined in [sFlow Dropped Packet Notification Structures](https://sflow.org/sflow_drops.txt). When a packet is dropped by the switch, the ASIC traps the dropped packet to the CPU along with drop reason metadata. The hsflowd daemon processes these notifications and exports them to configured sFlow collectors using the `discarded_packet` record format.

Key components tested:
- CONFIG_DB schema for drop monitor configuration (`SFLOW|global` table)
- sFlowOrch TAM (Telemetry and Monitoring) integration
- SAI TAM API for Mirror-on-Drop functionality
- hsflowd mod_sonic integration for drop notifications
- sFlow datagram generation with drop extension
- CLI commands for drop monitor management

### Testbed

The test requires the following testbed configuration:

```
+----------------+                              +----------------+
|                |         DUT Ports            |                |
|   PTF Host     |<---------------------------->|     DUT        |
|  (Traffic Gen) |                              |   (SONiC)      |
+----------------+                              +----------------+
       |                                              |
       |                                              |
       v                                              v
+----------------+                              +----------------+
| sFlow Collector|<-------- Management ---------|   CONFIG_DB    |
|  (sflowtool)   |          Network             |   APPL_DB      |
+----------------+                              +----------------+
```

**Requirements:**
- T0 or T1 topology
- PTF container with scapy for traffic generation
- sFlow collector (sflowtool or equivalent) accessible via management network
- Platform supporting SAI TAM MOD (Mirror-on-Drop) functionality

**Supported topologies:**
- t0
- t0-64
- t0-116
- t1
- t1-lag

---

## Setup Configuration

### Prerequisites

1. **Enable sFlow globally:**
   ```bash
   config sflow enable
   ```

2. **Configure sFlow collector:**
   ```bash
   config sflow collector add <collector_name> <collector_ip> [--port <udp_port>]
   ```

3. **Enable drop monitoring:**
   ```bash
   config sflow drop-monitor enable
   ```

4. **Configure drop monitor limit (optional):**
   ```bash
   config sflow drop-monitor-limit <packets_per_second>
   ```

### CONFIG_DB Schema

The drop monitor feature adds the following fields to the `SFLOW|global` table:

```json
{
  "SFLOW|global": {
    "admin_state": "up",
    "polling_interval": "20",
    "agent_id": "default",
    "drop_monitor_limit": "500",
    "sample_direction": "rx"
  },
  "SFLOW_COLLECTOR|<collector_name>": {
    "collector_ip": "<ip_address>",
    "collector_port": "6343",
    "collector_vrf": "default"
  },
  "SFLOW_DROP_SESSION|global": {
    "admin_state": "up",
    "drop_monitor_limit": "500"
  }
}
```

### APPL_DB Schema

```json
{
  "SFLOW_DROP_SESSION_TABLE:global": {
    "admin_state": "up",
    "drop_monitor_limit": "500"
  }
}
```

### sFlow Drop Reasons (per sFlow specification)

| Code | Drop Reason | Description |
|------|-------------|-------------|
| 256 | unknown | Unknown drop reason |
| 257 | ttl_exceeded | TTL value is too small |
| 258 | acl | ACL drop (ingress/egress flow action) |
| 259 | no_buffer_space | Tail drop due to buffer exhaustion |
| 260 | red | Random Early Detection drop |
| 261 | traffic_shaping | Traffic shaping/policing drop |
| 262 | pkt_too_big | MTU value exceeded |
| 265 | ingress_vlan_filter | Ingress VLAN filter drop |
| 269 | blackhole_route | Blackhole route drop |
| 279 | unresolved_neigh | Unresolved neighbor drop |

---

## Test Cases

### Test Case 1: Verify sFlow Drop Monitor Configuration

**Test Objective:** Verify that sFlow drop monitor can be configured via CLI and is reflected in CONFIG_DB and APPL_DB.

**Test Steps:**
1. Enable sFlow globally
2. Configure sFlow collector
3. Enable drop monitor via CLI: `config sflow drop-monitor enable`
4. Verify CONFIG_DB entry:
   ```bash
   redis-cli -n 4 hgetall "SFLOW_DROP_SESSION|global"
   ```
5. Verify APPL_DB entry:
   ```bash
   redis-cli -n 0 hgetall "SFLOW_DROP_SESSION_TABLE:global"
   ```
6. Verify drop monitor status via show command:
   ```bash
   show sflow
   ```

**Expected Results:**
- CONFIG_DB contains `SFLOW_DROP_SESSION|global` with `admin_state: up`
- APPL_DB contains `SFLOW_DROP_SESSION_TABLE:global` with `admin_state: up`
- Show command displays drop monitor as enabled

---

### Test Case 2: Verify Drop Monitor Enable/Disable

**Test Objective:** Verify that drop monitor can be enabled and disabled dynamically.

**Test Steps:**
1. Enable sFlow and configure collector
2. Enable drop monitor: `config sflow drop-monitor enable`
3. Verify drop monitor is enabled in CONFIG_DB
4. Disable drop monitor: `config sflow drop-monitor disable`
5. Verify drop monitor is disabled in CONFIG_DB
6. Verify APPL_DB reflects the disabled state
7. Re-enable drop monitor
8. Verify functionality is restored

**Expected Results:**
- Drop monitor state changes are reflected in both CONFIG_DB and APPL_DB
- State transitions occur without errors
- hsflowd service remains stable during state changes

---

### Test Case 3: Verify Drop Monitor Limit Configuration

**Test Objective:** Verify that drop monitor rate limit can be configured.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure drop monitor limit: `config sflow drop-monitor-limit 100`
3. Verify limit in CONFIG_DB:
   ```bash
   redis-cli -n 4 hget "SFLOW_DROP_SESSION|global" "drop_monitor_limit"
   ```
4. Configure different limit values: 10, 500, 1000
5. Verify each configuration is applied correctly
6. Test invalid limit values (0, negative, exceeding max)

**Expected Results:**
- Valid limit values are accepted and stored in CONFIG_DB
- Invalid limit values are rejected with appropriate error message
- Default limit is applied when not explicitly configured (default: 500 pps)

---

### Test Case 4: Verify Dropped Packet Notification Generation - ACL Drop

**Test Objective:** Verify that packets dropped by ACL rules generate sFlow drop notifications.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure ACL rule to drop traffic:
   ```bash
   config acl add table DROP_TEST L3 -s ingress
   config acl rule add DROP_TEST RULE1 -p DROP --src-ip 10.10.10.0/24
   config acl update full /path/to/acl.json
   ```
3. Start sFlow collector capture (sflowtool)
4. Send traffic from PTF matching ACL drop rule:
   ```python
   pkt = Ether(dst=dut_mac)/IP(src="10.10.10.5", dst="20.20.20.5")/TCP()
   sendp(pkt, iface=ptf_interface, count=100)
   ```
5. Capture and analyze sFlow datagrams at collector
6. Verify drop notification contains:
   - `discarded_packet` record type (format=5)
   - Drop reason code 258 (acl)
   - Packet header information
   - Input interface index

**Expected Results:**
- sFlow collector receives `discarded_packet` records
- Drop reason is correctly identified as ACL (258)
- Packet header and interface information are accurate
- Drop notification count correlates with sent packet count (subject to rate limit)

---

### Test Case 5: Verify Dropped Packet Notification Generation - TTL Exceeded

**Test Objective:** Verify that packets dropped due to TTL expiration generate sFlow drop notifications.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Start sFlow collector capture
3. Send packets with TTL=1 from PTF:
   ```python
   pkt = Ether(dst=dut_mac)/IP(src="10.10.10.5", dst="20.20.20.5", ttl=1)/ICMP()
   sendp(pkt, iface=ptf_interface, count=50)
   ```
4. Analyze sFlow datagrams at collector

**Expected Results:**
- sFlow collector receives `discarded_packet` records
- Drop reason is correctly identified as TTL exceeded (257)
- Packet header shows TTL=1

---

### Test Case 6: Verify Dropped Packet Notification Generation - L3 Routing Miss

**Test Objective:** Verify that packets dropped due to L3 routing miss (no route) generate sFlow drop notifications.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Ensure destination IP has no route in routing table
3. Start sFlow collector capture
4. Send traffic to unknown destination:
   ```python
   pkt = Ether(dst=dut_mac)/IP(src="10.10.10.5", dst="192.168.255.1")/UDP()
   sendp(pkt, iface=ptf_interface, count=50)
   ```
5. Analyze sFlow datagrams at collector

**Expected Results:**
- sFlow collector receives `discarded_packet` records
- Drop reason is correctly identified as blackhole_route (269) or unknown_l3 (285)
- Packet header contains the unreachable destination IP

---

### Test Case 7: Verify Dropped Packet Notification Generation - MTU Exceeded

**Test Objective:** Verify that packets dropped due to MTU exceeded generate sFlow drop notifications.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure interface with small MTU:
   ```bash
   config interface mtu Ethernet0 1500
   ```
3. Start sFlow collector capture
4. Send oversized packet with DF bit set:
   ```python
   pkt = Ether(dst=dut_mac)/IP(src="10.10.10.5", dst="20.20.20.5", flags="DF")/Raw(load="X"*2000)
   sendp(pkt, iface=ptf_interface, count=10)
   ```
5. Analyze sFlow datagrams at collector

**Expected Results:**
- sFlow collector receives `discarded_packet` records
- Drop reason is correctly identified as pkt_too_big (262)

---

### Test Case 8: Verify Dropped Packet Notification Generation - Ingress VLAN Filter

**Test Objective:** Verify that packets dropped due to VLAN membership generate sFlow drop notifications.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure VLAN on interface
3. Start sFlow collector capture
4. Send traffic with incorrect VLAN tag:
   ```python
   pkt = Ether(dst=dut_mac)/Dot1Q(vlan=999)/IP(src="10.10.10.5", dst="20.20.20.5")/TCP()
   sendp(pkt, iface=ptf_interface, count=50)
   ```
5. Analyze sFlow datagrams at collector

**Expected Results:**
- sFlow collector receives `discarded_packet` records
- Drop reason is correctly identified as ingress_vlan_filter (265) or vlan_tag_mismatch (264)

---

### Test Case 9: Verify Dropped Packet Notification Generation - Buffer/Tail Drop

**Test Objective:** Verify that packets dropped due to buffer exhaustion generate sFlow drop notifications.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Start sFlow collector capture
3. Generate traffic burst to cause congestion:
   ```python
   # Send traffic at line rate to congest egress port
   pkt = Ether(dst=dut_mac)/IP(src="10.10.10.5", dst="20.20.20.5")/UDP()/Raw(load="X"*1400)
   sendp(pkt, iface=ptf_interface, count=100000, inter=0.0001)
   ```
4. Verify tail drop occurs by checking interface counters
5. Analyze sFlow datagrams at collector

**Expected Results:**
- sFlow collector receives `discarded_packet` records
- Drop reason is correctly identified as no_buffer_space (259)
- Interface drop counters increase

---

### Test Case 10: Verify Drop Monitor Rate Limiting

**Test Objective:** Verify that drop notifications are rate limited according to configuration.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure drop monitor limit to 10 pps:
   ```bash
   config sflow drop-monitor-limit 10
   ```
3. Start sFlow collector capture with timestamps
4. Generate 1000 dropped packets within 1 second (ACL drop)
5. Count received `discarded_packet` records over time
6. Increase limit to 100 pps and repeat

**Expected Results:**
- With limit=10, approximately 10 drop notifications per second
- With limit=100, approximately 100 drop notifications per second
- Rate limiting is enforced by the system

---

### Test Case 11: Verify Drop Notification with sFlow Counter Polling

**Test Objective:** Verify that drop notifications work correctly alongside counter polling.

**Test Steps:**
1. Enable sFlow with polling interval: `config sflow polling-interval 20`
2. Enable drop monitor
3. Start sFlow collector capture
4. Generate dropped traffic
5. Wait for at least 2 polling intervals
6. Verify both counter samples and drop notifications are received

**Expected Results:**
- sFlow collector receives both counter samples and `discarded_packet` records
- Counter samples include interface discard counters
- Both mechanisms operate independently and correctly

---

### Test Case 12: Verify Drop Notification with Packet Sampling

**Test Objective:** Verify that drop notifications work correctly alongside packet sampling.

**Test Steps:**
1. Enable sFlow with packet sampling on interface
2. Enable drop monitor
3. Start sFlow collector capture
4. Generate mixed traffic: normal forwarded packets and dropped packets
5. Analyze sFlow datagrams

**Expected Results:**
- sFlow collector receives flow_sample records for forwarded traffic
- sFlow collector receives `discarded_packet` records for dropped traffic
- Both mechanisms operate independently
- Dropped packets are not double-counted (no flow_sample for dropped packets)

---

### Test Case 13: Verify Drop Monitor After Config Reload

**Test Objective:** Verify that drop monitor configuration persists across config reload.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure drop monitor limit
3. Save configuration: `config save`
4. Reload configuration: `config reload -y`
5. Verify drop monitor state and limit are preserved
6. Verify drop notifications are generated correctly

**Expected Results:**
- Drop monitor configuration persists after config reload
- Drop notifications continue to work after reload

---

### Test Case 14: Verify Drop Monitor After Service Restart

**Test Objective:** Verify that drop monitor recovers after hsflowd service restart.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Verify drop notifications are working
3. Restart sflow container: `sudo systemctl restart sflow`
4. Wait for service to stabilize
5. Verify drop notifications resume

**Expected Results:**
- hsflowd service restarts successfully
- Drop monitor functionality recovers after restart
- No persistent errors in logs

---

### Test Case 15: Verify Multiple Drop Reasons Simultaneously

**Test Objective:** Verify that different drop reasons can be reported simultaneously.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure multiple drop scenarios:
   - ACL drop rule
   - Ensure routing miss for certain destinations
3. Start sFlow collector capture
4. Generate traffic triggering different drop reasons simultaneously
5. Analyze sFlow datagrams

**Expected Results:**
- sFlow collector receives `discarded_packet` records with different drop reasons
- Each drop reason is correctly identified
- Drop statistics are accurate for each reason

---

### Test Case 16: Verify Drop Notification Sequence Numbers

**Test Objective:** Verify that drop notification sequence numbers increment correctly.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Start sFlow collector capture
3. Generate dropped packets in controlled manner
4. Extract sequence numbers from `discarded_packet` records
5. Verify sequence numbers are monotonically increasing

**Expected Results:**
- Sequence numbers start from expected value
- Sequence numbers increment by 1 for each notification
- No gaps in sequence numbers (within rate limit)

---

### Test Case 17: Verify sFlow Drop Extension in Datagram

**Test Objective:** Verify that sFlow datagrams contain correct drop extension data.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Start packet capture on collector (tcpdump/wireshark)
3. Generate dropped packets
4. Decode sFlow datagrams and verify structure:
   - Enterprise = 0 (standard sFlow)
   - Format = 5 (discarded_packet)
   - Sequence number field
   - Source ID (data source)
   - Drops counter
   - Input interface index
   - Output interface index (0 for ingress drops)
   - Drop reason code
   - Flow records (packet header)

**Expected Results:**
- sFlow datagram structure matches specification
- All fields contain valid values
- Drop reason code matches expected value

---

### Test Case 18: Verify Drop Monitor Configuration Persistence

**Test Objective:** Verify that drop monitor configuration survives warm/cold reboot.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure drop monitor limit
3. Save configuration
4. Perform warm reboot: `sudo warm-reboot`
5. Verify configuration after warm reboot
6. Perform cold reboot: `sudo reboot`
7. Verify configuration after cold reboot

**Expected Results:**
- Drop monitor configuration persists across warm reboot
- Drop monitor configuration persists across cold reboot
- Drop notifications work correctly after reboots

---

### Test Case 19: Verify Drop Monitor with Multiple Collectors

**Test Objective:** Verify that drop notifications are sent to multiple collectors.

**Test Steps:**
1. Enable sFlow with multiple collectors:
   ```bash
   config sflow collector add collector1 10.0.0.100
   config sflow collector add collector2 10.0.0.101
   ```
2. Enable drop monitor
3. Start capture on both collectors
4. Generate dropped packets
5. Verify both collectors receive drop notifications

**Expected Results:**
- Both collectors receive `discarded_packet` records
- Drop notification content is identical on both collectors
- Sequence numbers are consistent

---

### Test Case 20: Verify CLI Show Commands for Drop Monitor

**Test Objective:** Verify that CLI show commands display drop monitor information correctly.

**Test Steps:**
1. Enable sFlow and drop monitor
2. Configure drop monitor limit
3. Execute show commands:
   ```bash
   show sflow
   show sflow interface
   ```
4. Verify output includes drop monitor status and configuration

**Expected Results:**
- `show sflow` displays:
  - Drop monitor admin state (up/down)
  - Drop monitor limit
- Output format is consistent and readable

**Expected Output Format:**
```
sFlow Global Information:
  sFlow Admin State:          up
  sFlow Polling Interval:     20
  sFlow Sample Direction:     rx
  sFlow AgentID:              default
  sFlow Drop Monitor:         up
  sFlow Drop Monitor Limit:   500

  2 Collectors configured:
    Name: collector1          IP addr: 10.0.0.100    UDP port: 6343
    Name: collector2          IP addr: 10.0.0.101    UDP port: 6343
```

---

## Related DUT CLI Commands

### Configuration Commands

```bash
# Enable/Disable sFlow globally
config sflow enable
config sflow disable

# Configure sFlow collector
config sflow collector add <name> <ip> [--port <port>] [--vrf <vrf>]
config sflow collector del <name>

# Configure sFlow agent ID
config sflow agent-id add <interface>
config sflow agent-id del

# Configure polling interval
config sflow polling-interval <seconds>

# Configure sample direction
config sflow sample-direction <rx|tx|both>

# Enable/Disable drop monitor
config sflow drop-monitor enable
config sflow drop-monitor disable

# Configure drop monitor limit
config sflow drop-monitor-limit <packets_per_second>

# Interface-level sFlow configuration
config sflow interface enable <interface>
config sflow interface disable <interface>
config sflow interface sample-rate <interface> <rate>
```

### Show Commands

```bash
# Display sFlow global configuration
show sflow

# Display sFlow interface configuration
show sflow interface
```

### Debug Commands

```bash
# Check sFlow container status
docker ps | grep sflow

# Check hsflowd logs
docker exec -it sflow cat /var/log/hsflowd.log

# Check CONFIG_DB entries
redis-cli -n 4 keys "SFLOW*"
redis-cli -n 4 hgetall "SFLOW|global"
redis-cli -n 4 hgetall "SFLOW_DROP_SESSION|global"

# Check APPL_DB entries
redis-cli -n 0 keys "SFLOW*"
redis-cli -n 0 hgetall "SFLOW_DROP_SESSION_TABLE:global"

# Check SAI TAM objects (platform specific)
# Verify TAM objects are created for MOD functionality
```

---

## References

1. [HLD: Dropped Packet Notification (MOD) Support - PR #1786](https://github.com/sonic-net/SONiC/pull/1786)
2. [sFlow Dropped Packet Notification Structures](https://sflow.org/sflow_drops.txt)
3. [SAI TAM MOD Localhost Proposal](https://github.com/opencomputeproject/SAI/blob/master/doc/TAM/SAI-Proposal-TAM-MOD-Localhost.md)
4. [sFlow Version 5 Specification](https://sflow.org/sflow_version_5.txt)
5. [SONiC sFlow HLD](https://github.com/sonic-net/SONiC/blob/master/doc/sflow/sflow_hld.md)
6. [Linux Devlink Trap Documentation](https://www.kernel.org/doc/html/latest/networking/devlink/devlink-trap.html)

---

## Appendix: sFlow Drop Reason Codes

The following drop reason codes are supported (based on sflow_drops.txt specification):

| Code | Name | Description |
|------|------|-------------|
| 0 | net_unreachable | Network unreachable |
| 1 | host_unreachable | Host unreachable |
| 2 | protocol_unreachable | Protocol unreachable |
| 3 | port_unreachable | Port unreachable |
| 4 | frag_needed | Fragmentation needed |
| 6 | dst_net_unknown | Destination network unknown (LPM miss) |
| 256 | unknown | Unknown drop reason |
| 257 | ttl_exceeded | TTL value is too small |
| 258 | acl | ACL drop |
| 259 | no_buffer_space | Tail drop |
| 260 | red | Random Early Detection drop |
| 261 | traffic_shaping | Traffic shaping drop |
| 262 | pkt_too_big | MTU exceeded |
| 263 | src_mac_is_multicast | Source MAC is multicast |
| 264 | vlan_tag_mismatch | VLAN tag mismatch |
| 265 | ingress_vlan_filter | Ingress VLAN filter |
| 266 | ingress_spanning_tree_filter | STP filter |
| 269 | blackhole_route | Blackhole route |
| 275 | ip_header_corrupted | IP header corrupted |
| 279 | unresolved_neigh | Unresolved neighbor |
| 284 | unknown_l2 | Unknown L2 drop |
| 285 | unknown_l3 | Unknown L3 drop |
| 287 | unknown_buffer | Unknown buffer drop |
| 301 | egress_vlan_filter | Egress VLAN filter |

---

## Test Automation

### Test File Location

```
sonic-mgmt/tests/sflow/test_sflow_drop_notification.py
```

### Pytest Markers

```python
@pytest.mark.topology('t0', 't0-64', 't0-116', 't1', 't1-lag')
```

### Required Fixtures

- `duthost`: DUT host fixture
- `ptfhost`: PTF host fixture
- `ptfadapter`: PTF adapter for packet sending
- `sflow_collector`: Custom fixture for sFlow collector management

### Sample Test Implementation

```python
import pytest
import logging
from tests.common.helpers.sflow_helper import SflowCollector

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def setup_sflow_drop_monitor(duthost, sflow_collector):
    """Setup sFlow with drop monitoring enabled"""
    # Enable sFlow
    duthost.shell("config sflow enable")
    
    # Add collector
    duthost.shell(f"config sflow collector add test_collector {sflow_collector.ip}")
    
    # Enable drop monitor
    duthost.shell("config sflow drop-monitor enable")
    
    yield
    
    # Cleanup
    duthost.shell("config sflow drop-monitor disable")
    duthost.shell("config sflow collector del test_collector")
    duthost.shell("config sflow disable")


class TestSflowDropNotification:
    
    def test_drop_monitor_config(self, duthost, setup_sflow_drop_monitor):
        """Test Case 1: Verify drop monitor configuration"""
        # Verify CONFIG_DB
        result = duthost.shell("redis-cli -n 4 hget 'SFLOW_DROP_SESSION|global' admin_state")
        assert result['stdout'].strip() == 'up'
        
        # Verify APPL_DB
        result = duthost.shell("redis-cli -n 0 hget 'SFLOW_DROP_SESSION_TABLE:global' admin_state")
        assert result['stdout'].strip() == 'up'
    
    def test_acl_drop_notification(self, duthost, ptfadapter, setup_sflow_drop_monitor, sflow_collector):
        """Test Case 4: Verify ACL drop generates notification"""
        # Configure ACL drop rule
        acl_config = {...}  # ACL configuration
        duthost.copy(content=json.dumps(acl_config), dest="/tmp/acl.json")
        duthost.shell("config acl update full /tmp/acl.json")
        
        # Start collector capture
        sflow_collector.start_capture()
        
        # Send traffic matching ACL
        pkt = testutils.simple_tcp_packet(
            eth_dst=duthost.facts['router_mac'],
            ip_src="10.10.10.5",
            ip_dst="20.20.20.5"
        )
        ptfadapter.dataplane.send(ptf_port, str(pkt))
        
        # Wait and verify
        time.sleep(2)
        drops = sflow_collector.get_drop_notifications()
        
        assert len(drops) > 0, "No drop notifications received"
        assert drops[0]['reason'] == 258, "Drop reason should be ACL (258)"
```

---

*Document Version: 1.0*
*Last Updated: December 2025*
*Author: SONiC Community*
