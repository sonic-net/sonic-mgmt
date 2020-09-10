# 1. PFCWD test plan


| Rev |     Date       |       Author         | Change Description               |
|:---:|:---------------|:---------------------|:-----------------------------------|
| 0.1 |        Sep-09-2020     | Wei Bai, Microsoft<br>                           Suvendu Mozumdar, Keysight     | Initial version of test plan                 |
|



## 1.1. Overview

PFC watchdog is designed to detect and mitigate PFC storm received for each port. PFC pause frames are used in lossless Ethernet to pause the link partner from sending packets. Such back-pressure mechanism could propagate to the whole network and cause the network stop forwarding traffic. PFC watchdog is to detect abnormal back-pressure caused by receiving excessive PFC pause frames, and mitigate such situation by disabling PFC caused pause temporarily.

On SONiC, PFC watchdog is enabled at lossless priorities (e.g., 3 and 4) by default. PFC watchdog has three function blocks, i.e. detection, mitigation and restoration. More details can be found [here](https://github.com/Azure/SONiC/wiki/PFC-Watchdog).

### PFC Storm Detection
The PFC storm detection is for a switch to detect a lossless queue is receiving PFC storm from its link partner and the queue is in a paused state over T0 amount of time. Even when the queue is empty, as soon as the duration for a queue in paused state exceeds T0 amount of time, the watchdog should detect such storm. T0 is a port level parameter. The detection needs to enable/disable at per port level. Such detection mechanism is only available for lossless queue. By default, the detection mechanism is disabled. T0 should be on the scale of hundred milliseconds.

### PFC Storm Mitigation
Once PFC storm is detected on a queue, the watchdog can then have two actions, drop or forward at per queue level. When drop action is selected, following actions need to be implemented:

* All existing packets in the output queue are discarded.
* All subsequent packets destined to the output queue are discarded.
* All subsequent packets received by the corresponding priority group of this queue are discarded including the pause frames received. As a result, the switch should not generate any pause frame to its neighbor due to congestion of this output queue.
  
When forward action is selected, following actions need to be implemented:

* The queue no longer honors the PFC frames received. All packets destined to the queue are forwarded along with those packets that were in the queue.

### PFC Storm Restoration

The watchdog should continue count the PFC frames received on the queue. If there is no PFC frame received over T1 period. Then, re-enable the PFC on the queue and stop dropping packets if the previous mitigation was drop. T1 is port level parameter. T1 should be on the scale of hundred milliseconds.

### 1.1.1. Scope

The test cases depicted in this document aim to do functional testing of ECN behavior of SONiC DUT (Device Under Test) as per RED (Random Early Detection) algorithm.

### 1.1.2. Testbed

```
+-----------------+           +--------------+           +-----------------+       
| Keysight Port 1 |------ et1 |   SONiC DUT  | et2 ------| Keysight Port 2 | 
+-----------------+           +--------------+           +-----------------+ 
                                   et3
                                    |
                                    |
                                    |
                            +-----------------+
                            | Keysight Port 3 |
                            +-----------------+

                                 Topology 1
```


## 1.2. Setup configuration

### 1.2.1. DUT Configuration
•	PFC watchdog must be enabled in the DUT.


### 1.2.2. Keysight configuration
•	All Keysight ports should have the same bandwidth capacity.

•	Test specific configurations are mentioned in respective test cases.

## 1.3. Test Cases

### 1.3.1. Test Case #1 - PFCWD two senders two receivers

#### 1.3.1.1. Test Objective

This test aims to verify how PFC watchdog can handle PFC storms in a topology with two senders and two receivers.

#### 1.3.1.2. Test Topology

Refer to Topology 1 for the test topology.

#### 1.3.1.3. Test Configuration

- On SONiC DUT configure the following:
  1. Enable watchdog with default storm detection time (400ms) and restoration time (2sec).
  2. Configure a single lossless priority value Pi (0 <= i <= 7).
  3. To minimize configuration complexity, it is recommended that the SONiC DUT be configured as either Top of Rack (ToR) or Tier 0 (T0) switch with three VLAN interfaces.

- Configure following traffic items on the Keysight device:
  1. Traffic 1<->2 : Bi-directional traffic between Keysight port 1 and port 2, with DSCP value mapped to lossless priority Pi configured in the DUT. Traffic Tx rate should be configured as 50% of line rate.
  2. Traffic 2<->3 : Bi-directional traffic between Keysight port 2 and port 3, with DSCP value mapped to lossless priority Pi configured in the DUT. Traffic Tx rate should be configured as 50% of line rate.
  3. PFC PAUSE storm: Persistent PFC pause frames from Keysight
        port 3 to et3 of DUT. Priority of the PFC pause
        frames should be same as that configured in DUT and the
        inter-frame transmission interval should be lesser than
        per-frame pause duration.

#### 1.3.1.4. Test Steps

Refer to the time diagram below to understand the work flow of the test case:

![](image/PFCWD_2rcvrs_2senders_test_workflow.PNG)

1. At time $T_{startTraffic}$ , start all the bi-directional lossless traffic items.
2. At time $T_{startPause}$ , start PFC pause storm.
3. At time $T_{stopPause}$ , stop PFC pause storm. ($T_{stopPause} - T_{startPause}$) should be larger than PFC storm detection time to trigger PFC watchdog.
4. At time $T_{stopTraffic}$, stop lossless traffic items. Note that ($T_{stopTraffic} - T_{stopPause}$) should be larger than PFC storm restoration time to re-enable PFC.
5. Verify the following:
   * PFC watchdog is triggered on the corresponding lossless priorities at DUT interface et3. 
   * 'Traffic 1<->2' must not experience any packet loss in both directions. Its throughput should be close to 50% of the line rate.
   * For 'Traffic 2<->3', between $T_{startPause}$ and $T_{stopPause}$, there should be almost 100% packet loss in both directions. 
   * After $T_{stopPause}$, the traffic throughput should gradually increase and become 50% of line rate in both directions. 
   * There should not be any traffic loss after PFC storm restoration time has elapsed.
   * Keysight Port 1 and Keysight Port 2 must not receive any PFC pause packets during the test (either by DUT counters or packet capture at Keysight port 1/2).

6. Repeat the test for other lossless priorities.