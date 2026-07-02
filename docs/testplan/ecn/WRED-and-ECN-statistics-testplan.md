ECN WRED statistics verification

 <span id="_Toc205800613" class="anchor"><span id="_Toc463421032" class="anchor"><span id="_Toc463514628" class="anchor"></span></span></span>**Related documents**
 | Document name     | Link     |
 |-------------------|----------|
 | ECN and WRED statistics HLD | [Link](https://github.com/sonic-net/SONiC/blob/ebcd2a4a987f1d6027cd57677dc6806b8a9adcdb/doc/qos/ECN_and_WRED_statistics_HLD.md#cli-changes) |




 ## **Overview**

 This testplan aims to verify the  WRED and ECN statistics feature in SONiC.

 The purpose is to test the functionality of WRED and ECN statistics on the SONIC switch DUT . The test assumes all necessary configuration, including WRED and ECN profile , data path forwarding .

 ### **Scope**

 The test is targeting to verify WRED and ECN statistics in a PTF setup by simulating a congestion in the egress queue.
 ### **Scale / Performance**

 Not applicable
 ### **Related DUT CLI commands**
 ----------------------------



 | **Command**                                                      | **Comment** |
 |------------------------------------------------------------------|-------------|
 | **Configuration commands**                                       |
 | counterpoll wred-queue enable/disable                            |  Enable/Disable the queue level counters           |
 | counterpoll wred-port enable/disable                             |  Enable/Disable the port level counters           |
 | counterpoll wred-queue interval &lt;value&gt;                    |  Set polling interval for queue level counters           |
 | counterpoll wred-port interval &lt;value&gt;                     |  Set polling interval for port level counters          |
 | **Show commands**                                                |
 | show queue wredcounters [interface-name]                         |  Display the statistics on the console            |
 | show interfaces counters detailed Ethernet&lt;&gt;               |  Display the statistics on the console           |
 | sonic-clear queue wredcounters                                   |  Statistics are cleared on user request            |
 | sonic-clear counters                                             |  Statistics are cleared on user request           |
 | counterpoll show                                                 |  Display the status of the counters           |
 ### **Setup configuration**
 -------------------
 PTF setup: T0, T1
 ### **Related DUT configuration files**
 -----------------------------------
       "WRED_PROFILE": {
          "AZURE_LOSSY": {
             "ecn": "ecn_all",
             "green_drop_probability": "100",
             "green_max_threshold": "2240000",
             "green_min_threshold": "1120000",
             "red_drop_probability": "100",
             "red_max_threshold": "1344000",
             "red_min_threshold": "672000",
             "wred_green_enable": "true",
             "wred_red_enable": "true",
             "wred_yellow_enable": "true",
             "yellow_drop_probability": "100",
             "yellow_max_threshold": "1792000",
             "yellow_min_threshold": "896000"
         }
      }
     "QUEUE": {
         "Ethernet252|0": {
             "wred_profile": "[WRED_PROFILE|AZURE_LOSSY]"
         }
     }
 ### **Related SAI APIs and Attributes**
 -------------------------------
 Following SAI statistics will get tested:

 SAI_PORT_STAT_GREEN_WRED_DROPPED_PACKETS <br>
 SAI_PORT_STAT_YELLOW_WRED_DROPPED_PACKETS <br>
 SAI_PORT_STAT_RED_WRED_DROPPED_PACKETS <br>
 SAI_PORT_STAT_WRED_DROPPED_PACKETS <br>
 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS <br>
 SAI_QUEUE_STAT_WRED_ECN_MARKED_BYTES <br>

 <span id="_Toc463421033" class="anchor"></span>
 ## **Test methodology**

 1. Apply WRED/ECN Profile to the queue  .

 2. Query STATE_DB using REDIS CLI to find out if platform supports WRED/ECN  .

 3. On supported platform:

    Enable/Disable WRED at queue level using config:<br>
        counterpoll wred-queue enable/disable<br>
    Enable/Disable WRED at interface level using config:
        counterpoll wred-port enable/disable<br>

 4. on egress port  set   attribute SAI_PORT_ATTR_PKT_TX_ENABLE = false . <br>
    ( It will build up the traffic in egress queue thereby congestion gets simulated and DUT reacts with WRED/ECN if configured )

 5. Reset counters using the CLI:<br>
        sonic-clear queue wredcounters

 6. Send TCP/UDP traffic switched/routed to the egress interface which is in tx disable state .

 7. on egress port  set   attribute SAI_PORT_ATTR_PKT_TX_ENABLE = true . <br>

 8. on supported platform:<br>
      Verify WRED/ECN counters at queue level using the  new CLI:<br>
        show queue wredcounters Ethernet&lt;&gt;

      Verify WRED statistics at port level using the enhanced CLI:<br>
        show interfaces counters detailed Ethernet&lt;&gt;




 Test cases
 ----------
 WRED/ECN statistics verification on supported platform

 Terminology:<br>
    WRED=0/1 refers WRED disabled/enabled on queue <br>
    ECN=0/1 refers ECN disabled/enabled queue <br>
    CODE POINT refers to ECN CODE POINT in the IP header <br>
 | <div style="width:250px">Testcase</div> | <div style="width:300px">Test expectation </div>                                               | <div style="width:500px">Test Steps</div> |
 | --------------------------------------- | -----------------------------------------------------------------------------------------------| ----------------------------------------- |
 | WRED=0 ECN=0 CODE POINT=XX              | Tail Drop and hence no WRED/ECN counter increments                                                                 | 1. Query STATE_DB for WRED/ECN support on the platform <br> 2. tx disable egress port  <br>    3. Send TCP/UDP traffic. <br> 4. tx enable egress port <br> 5. Verify WRED/ECN packet counter and Byte counter <br>        |
 | WRED=1 ECN=0 CODE POINT=XX              | If WRED Algorithm determines pkt is drop eligible then increment WRED counters. ECN counters should not increment . | 1. Query STATE_DB for WRED/ECN support on the platform <br> 2. tx disable egress port  <br>    3. Send TCP/UDP traffic. <br> 4. tx enable egress port <br> 5. Verify WRED/ECN packet counter and Byte counter <br>  |
 | WRED=1 ECN=1 CODE POINT=00              | If WRED Algorithm determines pkt is drop eligible then increment WRED counters. ECN counters should not increment . | 1. Query STATE_DB for WRED/ECN support on the platform <br> 2. tx disable egress port  <br>    3. Send TCP/UDP traffic. <br> 4. tx enable egress port <br> 5. Verify WRED/ECN packet counter and Byte counter <br> |
 | WRED=1 ECN=1 CODE POINT=01              | If WRED Algorithm determines pkt is drop eligible then increment ECN counters. WRED counters should not increment . | 1. Query STATE_DB for WRED/ECN support on the platform <br> 2. tx disable  egress port  <br>    3. Send TCP/UDP traffic. <br> 4. tx enable egress port <br> 5. Verify WRED/ECN packet counter and Byte counter <br> |
 | WRED=1 ECN=1 CODE POINT=10              | If WRED Algorithm determines pkt is drop eligible then increment ECN counters. WRED counters should not increment . | 1. Query STATE_DB for WRED/ECN support on the platform <br> 2. tx disable  egress port  <br>    3. Send TCP/UDP traffic. <br> 4. tx enable egress port <br> 5. Verify WRED/ECN packet counter and Byte counter <br> |
 | WRED=1 ECN=1 CODE POINT=11              | If WRED Algorithm determines pkt is drop eligible then increment ECN counters. WRED counters should not increment . | 1. Query STATE_DB for WRED/ECN support on the platform <br> 2. tx disable egress port  <br>    3. Send TCP/UDP traffic. <br> 4. tx enable egress port <br> 5. Verify WRED/ECN packet counter and Byte counter <br> |

 CLI sample output
 ----------

 #### CLI output on a WRED and ECN queue statistics supported platform

 ```
 sonic-dut:~# show queue wredcounters Ethernet16
       Port    TxQ    WredDrp/pkts    WredDrp/bytes  EcnMarked/pkts EcnMarked/bytes
 ----------  -----  --------------  ---------------  -------------- ---------------
 Ethernet16    UC0               0                0               0               0
 Ethernet16    UC1               1              120               0               0
 Ethernet16    UC2               0                0               0               0
 Ethernet16    UC3               0                0               0               0
 Ethernet16    UC4               0                0               0               0
 Ethernet16    UC5               0                0               0               0
 Ethernet16    UC6               0                0               0               0
 Ethernet16    UC7               0                0               0               0
 ```
 #### CLI output on a platform which supports WRED drop statistics and does not support ECN statistics
 ```
 sonic-dut:~# show queue wredcounters Ethernet16
       Port    TxQ    WredDrp/pkts    WredDrp/bytes
 ----------  -----  --------------  ---------------
 Ethernet16    UC0               0                0
 Ethernet16    UC1               1              120
 Ethernet16    UC2               0                0
 Ethernet16    UC3               0                0
 Ethernet16    UC4               0                0
 Ethernet16    UC5               0                0
 Ethernet16    UC6               0                0
 Ethernet16    UC7               0                0
 ```
 #### CLI output on a platform which supports ECN statistics and does not support WRED statistics
 ```
 sonic-dut:~# show queue wredcounters Ethernet16
      Port    TxQ  EcnMarked/pkts  EcnMarked/bytes
 ----------  -----  --------------  ---------------
 Ethernet16    UC0               0                0
 Ethernet16    UC1               1              120
 Ethernet16    UC2               0                0
 Ethernet16    UC3               0                0
 Ethernet16    UC4               0                0
 Ethernet16    UC5               0                0
 Ethernet16    UC6               0                0
 Ethernet16    UC7               0                0
 ```
 #### show interface counters CLI output on a WRED drop statistics supported platform
 ```
 root@sonic-dut:~# show interfaces counters detailed Ethernet8
 Packets Received 64 Octets..................... 0
 Packets Received 65-127 Octets................. 2
 Packets Received 128-255 Octets................ 0
 Packets Received 256-511 Octets................ 0
 Packets Received 512-1023 Octets............... 0
 Packets Received 1024-1518 Octets.............. 0
 Packets Received 1519-2047 Octets.............. 0
 Packets Received 2048-4095 Octets.............. 0
 Packets Received 4096-9216 Octets.............. 0
 Packets Received 9217-16383 Octets............. 0
 Total Packets Received Without Errors.......... 2
 Unicast Packets Received....................... 0
 Multicast Packets Received..................... 2
 Broadcast Packets Received..................... 0
 Jabbers Received............................... N/A
 Fragments Received............................. N/A
 Undersize Received............................. 0
 Overruns Received.............................. 0
 Packets Transmitted 64 Octets.................. 32,893
 Packets Transmitted 65-127 Octets.............. 16,449
 Packets Transmitted 128-255 Octets............. 3
 Packets Transmitted 256-511 Octets............. 2,387
 Packets Transmitted 512-1023 Octets............ 0
 Packets Transmitted 1024-1518 Octets........... 0
 Packets Transmitted 1519-2047 Octets........... 0
 Packets Transmitted 2048-4095 Octets........... 0
 Packets Transmitted 4096-9216 Octets........... 0
 Packets Transmitted 9217-16383 Octets.......... 0
 Total Packets Transmitted Successfully......... 51,732
 Unicast Packets Transmitted.................... 0
 Multicast Packets Transmitted.................. 18,840
 Broadcast Packets Transmitted.................. 32,892
 Time Since Counters Last Cleared............... None
 WRED Green Dropped Packets..................... 1
 WRED Yellow Dropped Packets.................... 3
 WRED RED Dropped Packets....................... 10
 WRED Total Dropped Packets..................... 14
 ```

 #### show interface counters CLI output on a platform which does not support WRED drop statistics
 ```
 root@sonic-dut:~# show interfaces counters detailed Ethernet8
 Packets Received 64 Octets..................... 0
 Packets Received 65-127 Octets................. 2
 Packets Received 128-255 Octets................ 0
 Packets Received 256-511 Octets................ 0
 Packets Received 512-1023 Octets............... 0
 Packets Received 1024-1518 Octets.............. 0
 Packets Received 1519-2047 Octets.............. 0
 Packets Received 2048-4095 Octets.............. 0
 Packets Received 4096-9216 Octets.............. 0
 Packets Received 9217-16383 Octets............. 0
 Total Packets Received Without Errors.......... 2
 Unicast Packets Received....................... 0
 Multicast Packets Received..................... 2
 Broadcast Packets Received..................... 0
 Jabbers Received............................... N/A
 Fragments Received............................. N/A
 Undersize Received............................. 0
 Overruns Received.............................. 0
 Packets Transmitted 64 Octets.................. 32,893
 Packets Transmitted 65-127 Octets.............. 16,449
 Packets Transmitted 128-255 Octets............. 3
 Packets Transmitted 256-511 Octets............. 2,387
 Packets Transmitted 512-1023 Octets............ 0
 Packets Transmitted 1024-1518 Octets........... 0
 Packets Transmitted 1519-2047 Octets........... 0
 Packets Transmitted 2048-4095 Octets........... 0
 Packets Transmitted 4096-9216 Octets........... 0
 Packets Transmitted 9217-16383 Octets.......... 0
 Total Packets Transmitted Successfully......... 51,732
 Unicast Packets Transmitted.................... 0
 Multicast Packets Transmitted.................. 18,840
 Broadcast Packets Transmitted.................. 32,892
 Time Since Counters Last Cleared............... None
 ```
