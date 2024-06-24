# DHCP Relay Pressure Testplan

#SONiC Test Plan




<span id="_Toc205800613" class="anchor"><span id="_Toc463421032" class="anchor"><span id="_Toc463514628" class="anchor"></span></span></span>**Related documents**

|                   |          |
|-------------------|----------|
| **Document Name** | **Link** |
|                   |          |
|                   |          |
|                   |          |




## Overview

The purpose is to test the DHCP relay service can survive the max load that we lift to CPU.

### Scope
---------

CoPP is to limit the rate of traffic sent to CPU, and then generating at this maximum rate, the test is to ensure the DHCP relay service can handle the maximum load without failure.

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
| docker exec dhcp_relay supervisorctl status \| grep dhcp | verify the status of processes in dhcp are running |
| loganalyzer    | check no error keywords related to DHCP and CoPP |

###Related DUT configuration files
-----------------------------------

&lt;&lt; Place here configuration files that should be used for the test itself. Refer to DUT configuration only &gt;&gt;

&lt;&lt; If no configuration files required for this feature, please keep the table but add N/A &gt;&gt;

## Test structure 
===============

### Setup configuration
-------------------

1) def setup_copp_policy(): define a CoPP policy on the test device, and limit DHCP traffic to a maximum rate 600.
2) def client_send_discover(): simulate client sending DHCPDISCOVER message by broadcast. Duration: 120s.
3) def client_send_request(): simulate client sending DHCPREQUEST message from different source MAC or through different interface.
5) def verify_dhcp_container_alive(): verify the DHCP container is still alive.
```
  cmd = "docker ps | grep dhcp"
  output = duthost.shell(cmd)
  return "dhcp" in output
```
7) def verify_cpu_utilisation(): verify the %cpu is within an acceptable range, the acceptable range need to adjust after checking the device.
```
  cmd = "show processes cpu --verbose | grep dhcp | awk '{print $9}'"
  output = duthost.shell(cmd)
  cpu_usage = float(output.strip())
  return cpu_usage < CPU_USAGE_THRESHOLD_UNDER_PRESSURE
```
9) def verify_supervisor_process_running(): verify the status of processes managed by Supervisor is normal.
```
  cmd = "docker exec dhcp_relay supervisorctl status | grep dhcp | awk '{print $2}'"
  output = duthost.shell(cmd)
  processes_status = output['stdout'].splitlines()
  return all(status == 'RUNNING' for status in processes_status)
```
11) No errors in the logs related to DHCP or CoPP, just using loganalyzer.

###Configuration scripts
---------------------

&lt;&lt; Place here configuration scripts to be using for the test. Not only DUT but also for the entire system configuration &gt;&gt;

Test cases
----------

### Test case 

Test objective

test the DHCP relay service can survive the max load that we lift to CPU.

Test description

1) configure CoPP policy
2) disable the upper layer service
3) send DHCP packets
4) 

| **\#** | **Test Description** | **Expected Result** |
|--------|----------------------|---------------------|
| 1.     | verify_dhcp_container_alive() | we can grep dhcp by using command: docker ps |
| 2.     | verify_cpu_utilisation() | verify the cpu is within an acceptable range |
| 3.     | verify_logs_no_error() | verify no error in logs |
| 4.     |                      |                     |
