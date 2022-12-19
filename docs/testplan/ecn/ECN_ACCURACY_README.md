This document describes how to test if RED/ECN marks packets at the egress (a.k.a., dequeue ECN).

## Background
[Explicit Congestion Notification (ECN)](https://en.wikipedia.org/wiki/Explicit_Congestion_Notification) allows end-to-end notification of network congestion without dropping packets. ECN is an optional feature that may be used between two ECN-enabled endpoints when the underlying network infrastructure also supports it.

Conventionally, TCP/IP networks signal congestion by dropping packets. When ECN is successfully negotiated, an ECN-aware router may set a mark in the IP header instead of dropping a packet in order to signal impending congestion. The receiver of the packet echoes the congestion indication to the sender, which reduces its transmission rate as if it detected a dropped packet.

Commodity switches typically use [Random Early Detection (RED)](https://en.wikipedia.org/wiki/Random_early_detection) algorithm to perform ECN marking. RED algorithm has at least three parameters: the minimum threshold *Kmin*, the maximum threshold *Kmax*, and the maximum marking (or dropping) probability *Pmax*. When the instantaneous queue length is smaller than the minimum marking threshold, the marking probability is 0%. When the instantneous queue length is larger than the maixmum marking threshold, the marking probability is 100%. Otherwise, the marking probability varies is *(queue_length - Kmin) / (Kmax - Kmin) * Pmax*.

Commodity switches can run RED at ingress (enqueue packet to the switch buffer) or egress (dequeue packet from the switch buffer). Compared to ingress RED/ECN, egress RED/ECN can achieve lower feedback delay. 

## RED/ECN on SONiC
On SONiC, you can use <code>ecnconfig</code> to check and modify RED/ECN configuration.

To check current RED/ECN configuration:

<code>$ ecnconfig -l</code>

Note that we only care about parameters for green.

To check if ECN is enabled at queue 3:

<code>$ ecnconfig -q 3</code>

To enable ECN at queue 3:

<code>$ ecnconfig -q 3 on</code>

To set Kmin:

<code>$ ecnconfig -p [profile_name] -gmin [Kmin in byte]</code>

To set Kmax:

<code>$ ecnconfig -p [profile_name] -gmax [Kmax in byte]</code>

To set Pmax:

<code>$ ecnconfig -p [profile_name] -gdrop [Kmin in byte]</code>

## Testbed Setup
The testbed consists of two IXIA ports and a SONiC device under test (DUT) as follows. Both IXIA ports should have the same bandwidth capacity. To reduce the configuration complexity, we recommond configuring the switch as a Top of Rack (ToR) / Tier 0 (T0) switch and binding two switch interfaces to the Vlan. 

```
                     _________
                    |         |
IXIA tx port ------ |   DUT   |------ IXIA rx port
                    |_________|
```
In addition, [PFC watchdog](https://github.com/Azure/SONiC/wiki/PFC-Watchdog-Design) must be disabled at the SONiC DUT. Otherwise, the DUT will trigger PFC watchdog to drop packets when it detects persistent PFC pause storms. The command to disable PFC watchdog is <code>sudo pfcwd stop</code>.

## Experiment Steps
In this experiment, we need to create two traffic items:

- Test data traffic: A *fixed number* of data packets sent from the IXIA tx port to the IXIA rx port at a lossless priorities (e.g., e.g., 3 or 4). Note that the packets should be marked with the correct DSCP value (e.g., DSCP 3 for priority 3).  

- PFC pause storm: Persistent PFC pause frames from the IXIA rx port to the IXIA tx port. The priorities of PFC pause frames should be same as those of test data traffic. And the inter-frame transmission interval should be smaller than per-frame pause duration. 
  
This experiment repeats the following steps for each lossless priority:

- Configure the minimum ECN marking threshold, the maximum ECN marking threshold, and the maximum marking probability of the priority *i* to *Kmin* KB, *Kmax* KB and *Pmax*, respectively. Our recommended values are 500, 2000, and 5%. 

- Start packet capturing at the receiver.
  
- The receiver sends persistent PFC pause frames (PFC storm) to block the priority *i* of DUT.

- The sender sends *Kmax* + 10 1KB data packets to the receiver. The packets should be mapped to priority *i* on the DUT. Note that the DUT should have enough buffer to hold all these packets. 

- The receiver stops PFC storm and captures data packets sent by the sender.

- Repeat the steps 2-5 for at least 200 times 

- If RED/ECN marks packets at the egress, the queue length associated with the data packet *i* (*i* = 1, 2, …  *Kmax* + 10) is *Kmax* + 10 – *i* KB. Given the RED settings *Kmin*, *Kmax* and *Pmax*, we should be able to calculate the theoretical ECN marking probability for every data packet. For example, the queue lengths associated with the first 10 data packets are larger than *Kmax* KB, which indicates 100% ECN marking probability. Since we run this experiment for at least 200 times, we can also get actual ECN marking fraction for every data packet. Please draw a figure to show the theoretical ECN marking probability and the actual ECN marking fraction versus queue length.     