### Testbed

```
+-------------+      +--------------+      +-------------+       
| Keysight TX |------|   SONiC DUT  |------| Keysight RX | 
+-------------+      +--------------+      +-------------+ 

Keysight ports are connected via SONiC switch as shown in the illustration above.
```

### Test Case #4 - PFC Watchdog behavior on MMU change

#### Test Objective

This test aims to verify changes in MMU settings of the DUT do not impact the current state of PFCWD and its functionality.

#### Test Configuration

- On SONiC DUT configure the following:
  1. Enable watchdog with default storm detection time (400ms) and restoration time (2sec).
  2. Configure lossless priority Pi (0 <= i <= 7).
  3. To configure alpha value following commands are used:
        
        * Get the profiles configured in the DUT:
        *_$mmuconfig -l_*
        
        * Configure alpha value
  
            *_$sudo mmuconfig -p [profile_name] -a [alpha_value]_*

- Configure following traffic items on the Keysight device:
  1. Data traffic 1: Data packets from KEYSIGHT Tx port to KEYSIGHT Rx port. To cause congestion at port 2, the traffic demand should be 100% line rate. To map traffic to lossless priorities at the switch, we should mark packets with the correct DSCP value (e.g., DSCP 3 for priority 3). 
  2. Data traffic 2: Data packets from KEYSIGHT Tx port to KEYSIGHT Rx port. To cause congestion at port 2, the traffic demand should be 100% line rate. To map traffic to lossless priorities at the switch, we should mark packets with the correct DSCP value (e.g., DSCP 3 for priority 3). Data traffic 2 will start after data traffic 1.
  3. PFC pause storm: Persistent PFC pause frames from the KEYSIGHT Rx port to et2 of DUT having same priority (e.g., priority 3) as data traffic. The PFC frames should be able to pause the above lossless traffic. And the inter-frame transmission interval should be smaller than per-frame pause duration.

Configure Alpha (threshold) value 
    
*_sudo mmuconfig -p [profile_name] -a [alpha_value]_*

•	See all 

*_mmuconfig -l_*

#### Test Steps
Let’s use **_T<sub>detect</sub>_**, **_T<sub>restore</sub>_**, and **_T<sub>poll</sub>_** to denote the detection time, restoration time, and polling interval of PFC watchdog in sec. 

1. At time 0, start PFC PAUSE storm for **_T<sub>storm</sub>_** duration.
2. At time **_T<sub>restore</sub>_**/2, start data traffic 1. The duration of data traffic 1 is also **_T<sub>storm</sub>_**.
3. At time **_T<sub>restore</sub>_**/2 + **_T<sub>storm</sub>_**/2, change alpha.
4. At time **_T<sub>storm</sub>_**, stop PFC pause storm.
5. At time **_T<sub>restore</sub>_**/2 + **_T<sub>storm</sub>_**, stop data traffic 1.
6. At time **_T<sub>storm</sub>_** + **_T<sub>poll</sub>_** + **_T<sub>restore</sub>_**, start data traffic 2 for 5sec.
7. At time **_T<sub>storm</sub>_** + **_T<sub>poll</sub>_** + **_T<sub>restore</sub>_** + 5sec, stop data traffic 2.
8. Verify the following:
   *    If **_T<sub>storm</sub>_** > (**_T<sub>detect</sub>_** + **_T<sub>poll</sub>_**)
        *    PFC watchdog is triggered on the corresponding lossless priorities at interface et2.
        *    All the packets of data traffic 1 are dropped.
        *    All the packets of data traffic 2 are received. The throughput of traffic 2 is close to 100% of line rate.
   *    If **_T<sub>storm</sub>_** < **_T<sub>detect</sub>_**
        *    PFC watchdog is NOT triggered on the corresponding lossless priorities at interface et2.
        *    All the packets of data traffic 1 are received.
        *    All the packets of data traffic 2 are received. The throughput of traffic 2 is close to 100% of line rate.