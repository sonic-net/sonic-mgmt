This document describes how to test if the switch reacts to IEEE 802.3x pause frames, a.k.a., global pause frames.  

## Background
Different from priority-based flow control (PFC), global pause frames can prevent a switch port from sending any data in a time interval. The global pause frame (Figure 1 in https://www.cisco.com/c/en/us/products/collateral/switches/nexus-7000-series-switches/white_paper_c11-542809.html) has a pause duration field. The pause duration is a 2-byte value that expresses time as a number of quanta, where each quanta represents the time needed to transmit 512 bits at the current network speed. For example, the value of 65535 at a 40 Gbps link means 65535 * 512bits / 40Gbps = 838.84 microseconds. Therefore, to fully block a switch port, we need to generate global pause frames fast enough. For example, to block a 40G link, we need to generate a global pause frame with 65535 quantas in every 838.84 microseconds. A pause duration of zero quanta has the special meaning of unpausing a switch port. 

By default, the SONiC switch only enables PFC at two priorities: 3 and 4. It should not react to global pause frames.

## Testbed Setup
The testbed consists of two IXIA ports and a SONiC device under test (DUT) as follows. Both IXIA ports should have the same bandwidth capacity. To reduce the configuration complexity, we recommond configuring the switch as a Top of Rack (ToR) / Tier 0 (T0) switch and binding two switch interfaces to the Vlan. 

```
                     _________
                    |         |
IXIA tx port ------ |   DUT   |------ IXIA rx port
                    |_________|
```
In addition, [PFC watchdog](https://github.com/Azure/SONiC/wiki/PFC-Watchdog-Design) must be disabled at the SONiC DUT. Otherwise, the DUT will trigger PFC watchdog to drop packets when it detects a queue that has been paused by a very long time. The command to disable PFC watchdog is <code>sudo pfcwd stop</code>.

## Experiment Steps
In this experiment, we need to create two traffic items:

- Test data traffic: Data packets sent from the IXIA tx port to the IXIA rx port at all the priorities (0 to 7). Since we include all the 8 priorities, we can mark packets with all the DSCP values (0 - 63). The traffic demand should be 100% of the line rate. 

- Global pause storm: Persistent global pause frames from the IXIA rx port to the IXIA tx port. The inter-frame transmission interval should be smaller than per-frame pause duration. 
  
This experiment needs the following five steps:

- Start the global pause storm. 
  
- After a fixed duration (e.g., 1 second), start test data traffic. 

- After a fixed duration (e.g., 5 seconds), stop test data traffic. 
  
- Check if the IXIA rx port receives all the sent frames of test data traffic. Check if the throughput of test data traffic is close to link capacity.
  
- Stop global pause storm




