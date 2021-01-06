This document describes how to test the basic functionalities of of PFC watchdog. 

## Background
PFC watchdog is designed to detect and mitigate PFC storm received for each port. PFC pause frames is used in lossless Ethernet to pause the link partner from sending packets. Such back-pressure mechanism could propagate to the whole network and cause the network stop forwarding traffic. PFC watchdog is to detect *abnormal* back-pressure caused by receiving excessive PFC pause frames, and mitigate such situation by disable PFC caused pause temporarily. 

On SONiC, PFC watchdog is enabled at lossless priorities (e.g., 3 and 4) by default. PFC watchdog has three function blocks, i.e. detection, mitigation and restoration. You can find more details [here](https://github.com/Azure/SONiC/wiki/PFC-Watchdog).  

### PFC storm detection
The PFC storm detection is for a switch to detect a lossless queue is receiving PFC storm from its link partner and the queue is in a paused state over *T0* amount of time. Even when the queue is empty, as soon as the duration for a queue in paused state exceeds T0 amount of time, the watchdog should detect such storm. T0 is called *PFC storm detection time*. 

### PFC storm mitigation
Once PFC storm is detected on a queue, the watchdog can then have two actions, drop and forward at per queue level. When drop action is selected, following actions need to be implemented.

* All existing packets in the output queue are discarded
* All subsequent packets destine to the output queue are discarded
* All subsequent packets received by the corresponding priority group of this queue are discarded including the pause frames received. As a result, the switch should not generate any pause frame to its neighbor due to congestion of this output queue.

When forward action is selected, following actions need to be implemented.

* The queue no longer honor the PFC frames received. All packets destined to the queue are forwarded as well as those packets that were in the queue.

The default action is drop.

### PFC storm restoration
The watchdog should continue count the PFC frames received on the queue. If there is no PFC frame received over *T1* period. Then, re-enable the PFC on the queue and stop dropping packets if the previous mitigation was drop. T1 is called *PFC storm restoration time*. 

### PFC watchdog implementation
PFC watchdog polls the states of each lossless queue every *T2* period. T2 is called polling interval. To reduce CPU overhead, T2 is typically of hundreds of milliseconds. 

## PFC watchdog commands on SONiC
To get PFC watchdog configuraton:

<code>$ pfcwd show config</code>

To get PFC watchdog statistics:

<code>$ pfcwd show stats</code>

To start PFC watchdog using default parameters and action

<code>$ sudo pfcwd start_default</code>

To start PFC watchdog using specific time values and drop action on all the ports

<code>$ sudo pfcwd start --action drop ports all detection-time [detection time in ms] --restoration-time [restoration time in ms]</code>

To stop PFC watchdog

<code>$ sudo pfcwd stop</code>

Note that there is no way to clear PFC watchdog statistics unless we reload config database or minigraph. 

The testbed consists of two IXIA ports and a SONiC device under test (DUT) as follows. All the IXIA ports should have the same bandwidth capacity. To reduce the configuration complexity, we recommond configuring the switch as a Top of Rack (ToR) / Tier 0 (T0) switch and binding three switch interfaces to the Vlan. PFC watchdog must be enabled at the DUT.

```
                        _________
                       |         |
IXIA port 1 ------ et1 |   DUT   | et2------ IXIA port 2
                       |_________|

```

## Experiment Steps
In this experiment, we need to create three traffic items:

- Data traffic 1: Data packets from IXIA port 1 to IXIA port 2. The traffic demand is 100% line rate. The trafffic is mapped to the lossless priority i (e.g., 3 or 4) at the switch. To this end, packets should be marked with the correct DSCP value (e.g., DSCP 3 for priority 3).
  
- Data traffic 2: Data packets from IXIA port 1 to IXIA port 2. The traffic demand is 100% line rate. The trafffic is *also* mapped to the lossless priority i (e.g., 3 or 4) at the switch. To this end, packets should be marked with the correct DSCP value (e.g., DSCP 3 for priority 3). *Data traffic 2 and 1 have different time durations and start delays.* 

- PFC pause storm: Persistent PFC pause frames from the IXIA port 2 to et2 of DUT having same priority (e.g., 3) as data traffic. To fully block the switch queue, the inter-frame transmission interval should be smaller than per-frame pause duration.

This experiment needs the following steps. We need to repeat these steps for each lossless priority individually and all the lossless priorities simultaneously. Let’s use $T_{detect}$, $T_{restore}$, and $T_{poll}$ to denote the detection time, restoration time, and polling interval of PFC watchdog.  

This experiment needs the following steps. We need to repeat these steps for each lossless priority individually and all the lossless priorities simultaneously. We should try two PFC storm durations: one is larger than $T_{detect} + T_{poll}$ (trigger PFC watchdog) and the other one is smaller than $T_{detect}$ (not trigger PFC watchdog)

- At time 0, start PFC pause storm. PFC pause storm lasts for $T_{storm}$. 
   
- At time $T_{restore}/2$, start data traffic 1. The duration of data traffic 1 is also $T_{storm}$.

- At time $T_{storm}$, stop PFC pause storm.
  
- At time $T_{restore}/2 + T_{storm}$, stop data traffic 1.
  
- At time $T_{restore} + T_{poll} + T_{storm}$, start data traffic 2. Its duration is 1 second. 
 
-	At time $T_{restore} + T_{poll} + T_{storm}$ + 1 second, stop data traffic 2. 

After the above steps, we should check the following items:

- When $T_{storm}$ is larger than $T_{detect}$ + $T_{poll}$:
  - PFC watchdog is triggered on the corresponding lossless priority of et2.
  - All the packets of traffic 1 are dropped.
  - All the packets of traffic 2 are received. The throughput of traffic 2 is close to 100% of line rate.

- When $T_{storm}$ is smaller than $T_{detect}$:
  - PFC watchdog is NOT triggered at interface et2.
  - All the packets of traffic 1 are received.
  - All the packets of traffic 2 are received. The throughput of traffic 2 is close to 100% of line rate.


