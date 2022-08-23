This document describes how to test PFC watchdog in a 3-node topology with 2 senders and 2 receivers.

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

The testbed consists of three IXIA ports and a SONiC device under test (DUT) as follows. All the IXIA ports should have the same bandwidth capacity. To reduce the configuration complexity, we recommond configuring the switch as a Top of Rack (ToR) / Tier 0 (T0) switch and binding three switch interfaces to the Vlan. PFC watchdog must be enabled at the DUT.

```
                        __________
                       |          |
IXIA port 1 ------ et1 |   DUT    |
                       |          | et3 ------ IXIA port 3
IXIA port 2 ------ et2 |          |
                       |__________|

```

## Experiment Steps
In this experiment, we need to create three types traffic items:

- Test data traffic: IXIA port 1 sends bi-directional traffic to port 2 and 3 at a lossless priority (e.g., 3).

- Background data traffic: IXIA port 1 sends bi-directional traffic to port 2 and 3 at all the lossy priorities.

- PFC pause storm: Persistent PFC pause frames from the IXIA port 2 to et2 of DUT having same priority (e.g., 3) as test data traffic. To fully block the switch queue, the inter-frame transmission interval should be smaller than per-frame pause duration.

The duration of test data traffic and background data traffic is $T_{data}$. The duration of PFC pause storm is $T_{storm}$. Let’s use $T_{detect}$ and $T_{poll}$ to denote the detection time, and polling interval of PFC watchdog.

We start all the traffic items at time 0, wait for all the traffic items to finish, and then check the following items:

- When $T_{storm}$ is larger than $T_{detect}$ + $T_{poll}$:
  - PFC watchdog is triggered on the corresponding lossless priority of et2.
  - Test data traffic between port 1 and 2 experience packet losses.
  - All the other data traffic items are not impacted.

- When $T_{storm}$ is smaller than $T_{detect}$:
  - PFC watchdog is NOT triggered at interface et2.
  - Test data traffic from port 1 to port 2 is delayed. Its throughput is lower than the demand. But it should have no packet drops.
  - All the other data traffic items are not impacted.
