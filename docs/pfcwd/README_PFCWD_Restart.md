
This document describes test methodology to verify that restarting PFC watchdog on a particular port does not affect the watchdog behavior on that port.
Background

## Background

PFC watchdog is designed to detect and mitigate PFC storm received for each port. PFC pause frames is used in lossless Ethernet to pause the link partner from sending packets. Such back-pressure mechanism could propagate to the whole network and cause the network stop forwarding traffic. PFC watchdog is to detect _abnormal_ back-pressure caused by receiving excessive PFC pause frames, and mitigate such situation by disable PFC caused pause temporarily.

On SONiC, PFC watchdog is enabled at lossless priorities (e.g., 3 and 4) by default. PFC watchdog has three function blocks, i.e. detection, mitigation and restoration. You can find more details [here](https://github.com/Azure/SONiC/wiki/PFC-Watchdog).

### PFC storm detection

The PFC storm detection is for a switch to detect a lossless queue is receiving PFC storm from its link partner and the queue is in a paused state over _T0_ amount of time. Even when the queue is empty, as soon as the duration for a queue in paused state exceeds T0 amount of time, the watchdog should detect such storm. T0 is called _PFC storm detection time_.

### PFC storm mitigation

Once PFC storm is detected on a queue, the watchdog can then have two actions, drop and forward at per queue level. When drop action is selected, following actions need to be implemented.

* All existing packets in the output queue are discarded
* All subsequent packets destine to the output queue are discarded
* All subsequent packets received by the corresponding priority group of this queue are discarded including the pause frames received. As a result, the switch should not generate any pause frame to its neighbor due to congestion of this output queue.

When forward action is selected, following actions need to be implemented.

* The queue no longer honor the PFC frames received. All packets destined to the queue are forwarded as well as those packets that were in the queue.

### PFC storm restoration

The watchdog should continue count the PFC frames received on the queue. If there is no PFC frame received over T1 period. Then, re-enable the PFC on the queue and stop dropping packets if the previous mitigation was drop. T1 is called _PFC storm restoration time_.

### PFC watchdog implementation

PFC watchdog polls the states of each lossless queue every T2 period. T2 is called _polling interval_. To reduce CPU overhead, T2 is typically of hundreds of milliseconds.

## PFC watchdog commands on SONiC

To get PFC watchdog configuration:

<code> $ pfcwd show config</code>

To get PFC watchdog statistics:

<code>$ pfcwd show stats</code>

To start PFC watchdog

<code>$ sudo pfcwd start --action drop ports all detection-time [detection time in ms] --restoration-time [restoration time in ms]</code>

To stop PF C watchdog

<code>$ sudo pfcwd stop</code>

## Testbed Setup

The testbed consists of two Keysight ports and a SONiC device under test (DUT) as follows. All the KEYSIGHT ports should have the same bandwidth capacity.

``` 
                            _________
                           |         |
KEYSIGHT port 1 ------- et1|   DUT   |et2------ KEYSIGHT port 2
                           |_________|
                               et3
                                |
                                |
                        KEYSIGHT port 3
                        
```

## Experiment Steps

1. Execute the test “PFCWD_Basic_All-to-all” test for only one priority (e.g., 3)
2. Verify that the test should pass.
3. Stop PFCWD on et3
4. Start PFCWD on et3
5. Execute the test “PFCWD_Basic_All-to-all” for only one priority (e.g., 4)
6. Verify that the test should pass.
