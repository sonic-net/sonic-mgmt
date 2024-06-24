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
| docker exec dhcp_relay supervisorctl status \| grep dhcp | verify the status of processes in dhcp are running |
| loganalyzer    | check no error keywords related to DHCP and CoPP |

## Test structure 
===============

### Configuration
-------------------

1) def setup_copp_policy(): define a CoPP policy on the test device, and limit DHCP traffic to a maximum rate 600.
2) def client_send_discover(): simulate client sending DHCPDISCOVER message by broadcast. Duration: 120s. e.g. PTF will send 1,000 packets per second.
```
duration = 120
while time.time() - start_time < duration:
  for i in range(SOURCE_MACS_TOTAL_NUMBER): # e.g. SOURCE_MACS_TOTAL_NUMBER = 1000
    src_mac = "00:10:00:00:%02x:%02x" % (i//256, i%256)
    dhcp_discover = self.create_dhcp_discover_packet(BROADCAST_MAC, src_mac) # BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    start_time = time.time()
    testutils.send_packet(self, self.client_port_index, dhcp_discover)
```
3) def client_send_request(): simulate client sending DHCPREQUEST message from different source MAC or through different interface.
4) def verify_dhcp_container_alive(): verify the DHCP container is still alive.
```
  cmd = "docker ps | grep dhcp"
  output = duthost.shell(cmd)
  return "dhcp" in output
```
5) def verify_cpu_utilisation(): verify the %cpu is within an acceptable range, the acceptable range will be adjusted after checking the device.
```
  cmd = "show processes cpu --verbose | grep dhcp | awk '{print $9}'"
  output = duthost.shell(cmd)
  cpu_usage = float(output.strip())
  return cpu_usage < CPU_USAGE_THRESHOLD_UNDER_PRESSURE # Maximum allowed CPU usage percentage under pressure
```
6) def verify_supervisor_process_running(): verify the status of processes managed by Supervisor is normal.
```
  cmd = "docker exec dhcp_relay supervisorctl status | grep dhcp | awk '{print $2}'"
  output = duthost.shell(cmd)
  processes_status = output['stdout'].splitlines()
  return all(status == 'RUNNING' for status in processes_status)
```
7) No errors in the logs related to DHCP or CoPP, just using loganalyzer.

Test cases
----------

### Test case 

Test objective

test the DHCP relay service can survive the max load that we lift to CPU.

Test description

1) configure CoPP policy
2) clients broadcast a discover message
3) the DHCP server sends a offer message to client
4) clients broadcast a request message
5) the DHCP server sends a offer message

| **\#** | **Test Description** | **Expected Result** |
|--------|----------------------|---------------------|
| 1.     | verify_dhcp_container_alive() | we can grep dhcp by using command: docker ps |
| 2.     | verify_cpu_utilisation() | verify the cpu is within an acceptable range |
| 3.     | verify_supervisor_process_running()| verify DHCP related processes are running |
| 4.     | loganaylzer                  |  no error                   |
