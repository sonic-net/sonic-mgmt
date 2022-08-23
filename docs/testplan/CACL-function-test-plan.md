# Control Plane Access List Function Test Plan
- [Overview](#overview)
- [Test Procedure](#test-procedure)

## Overview
This test aims to ensure that a configured Control Plane Access List (CACL) is able to DROP incoming packets from specified incoming IP addresses using a variety of protocols such as SSH, SNMP, and NTP.   

## Test Procedure

1. Test that SNMP works initially, before CACL configuration
2. Send NTP request initially, before CACL configuration
3. Copy CACL config shell file to DUT and run file
    - Once the CACL is configured, it stays active for 2 mintues before being automatically removed
4. Have localhost wait for the SSH port on the DUT to be stopped. Test will fail if the port doesn't stop
    - This confirms that the CACL has been configured
5. Check that the SSH port is up expecting a `False` result
6. Send SNMP request expecting no response from the DUT
7. Send NTP request expecting an exception
8. Have localhost wait for CACL to be removed
9. Delete config file from the dut
10. Send SNMP request and ensure that a response is sent
11. Send NTP request and expect no exception