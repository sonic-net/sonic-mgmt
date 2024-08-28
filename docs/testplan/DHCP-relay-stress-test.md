# DHCP Relay Stress Test Plan
- [Overview](#overview)
- [Scope](#scope)
- [Scale / Performance](#scale--performance)
- [Related DUT CLI commands](#related-dut-cli-commands)
- [Test structure](#test-structure)
  - [Configuration](#configuration)
  - [Test cases](#test-cases)
    - [Test case](#test-case)



## Overview

The purpose is to test the DHCP relay service can survive the max load that we lift to CPU.

### Scope
---------

CoPP is to limit the rate of traffic sent to CPU, and then generating packets above this maximum rate, the test is to ensure the DHCP relay service can handle the maximum load without failure.

### Scale / Performance
-------------------
1. Verfy DHCP Container Status.
2. CPU should remain within acceptable range, indicating the DUT is not overwhelmed.
3. Check whether the function is still normal.
4. No errors in the logs related to DHCP or CoPP.

### Related **DUT** CLI commands
----------------------------


| **Command**                                                      | **Comment** |
|------------------------------------------------------------------|-------------|
| docker ps \| grep dhcp          | check the status of DHCP container            |
| show processes cpu --verbose \| grep dhcp \| awk '{print $9}'  | check the resource utilisation   |
| docker exec dhcp_relay supervisorctl status \| grep dhcp \| awk '{print $2}' | verify the status of processes in dhcp are running |
| loganalyzer    | check no error keywords related to DHCP and CoPP |

## Test structure 
===============

### Configuration
-------------------

1) def setup_copp_policy(): define a CoPP policy on the test device, and limit DHCP traffic to a maximum rate 600.
2) def client_send_discover(): simulate client sending DHCPDISCOVER message from different source MAC by broadcast. Duration: 120s. e.g. PTF will send 10,000 packets per second.
3) def server_send_offer(): simulate the server sending DHCPOFFER message to the client. At a rate up to 600 packets per second with a tolerance of 10%.
4) def client_send_request(): simulate client sending DHCPREQUEST message from different source MAC or through different interface.
5) def server_send_ack(): simulate the server sending DHCPACK message to the client under the same conditions (up tp 600 packets per second with a tolerance of 10%).
6) def verify_dhcp_container_alive(): verify the DHCP container is still alive.
7) def verify_cpu_utilisation(): verify the %cpu is within an acceptable range, the acceptable range will be adjusted after checking the device.
8) def verify_supervisor_process_running(): verify the status of processes managed by Supervisor is normal.
9) def verify_relay_packet_count_with_delay(): check DHCP relay packet count within a reasonable delay time range. Note that the packet count for DHCP offer and ack messages is around 72,000 packets (600 packets per second with 2 minutes) with a tolerance of 10%, and the packet count for DHCP discover and request messages should be 1,200,000 packets (10,000 packets per second for 120 seconds).
10) No errors in the logs related to DHCP or CoPP, just using loganalyzer.

Test cases
----------

### Test case 

Test objective: To test the DHCP relay service can survive the max load that we lift to CPU.

Test steps:
1) Configure CoPP policy
2) Clients broadcast a discover message
3) The DHCP server sends a offer message to client
4) Clients broadcast a request message
5) The DHCP server sends a offer message

| **\#** | **Test Description** | **Expected Result** |
|--------|----------------------|---------------------|
| a.     | verify_dhcp_container_alive() | Ensure the DHCP container is running by using the command ```docker ps \| grep dhcp```. |
| b.     | verify_cpu_utilisation() | Verify the cpu is less than the maximum allowed CPU usage percentage. |
| c.     | verify_supervisor_process_running()| Verify that all DHCP-related processes are running normally.|
| d.     | verify_relay_packet_count_with_delay() | The function checks the packet count for DHCP messages within a reasonable delay. |
| e.     | loganaylzer                  | Ensure there are no errors in the logs.     |
