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
3) def client_send_request(): simulate client sending DHCPREQUEST message from different source MAC or through different interface.
4) def verify_dhcp_container_alive(): verify the DHCP container is still alive.
5) def verify_cpu_utilisation(): verify the %cpu is within an acceptable range, the acceptable range will be adjusted after checking the device.
6) def verify_supervisor_process_running(): verify the status of processes managed by Supervisor is normal.
7) No errors in the logs related to DHCP or CoPP, just using loganalyzer.

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
| d.     | loganaylzer                  | Ensure there are no errors in the logs.     |
