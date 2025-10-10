# PTF-based Test Plan for Static SRv6 functionalities

Since several functionalities were added in SONiC to support the deployment of static SRv6 network(refer to [HLD](https://github.com/sonic-net/SONiC/blob/master/doc/srv6/srv6_static_config_hld.md)), we propose to add test cases that will help in verify the correctness of those SRv6 functionalities.
These test cases falls into two categories, data-plane focused and control-plane focused.
In the control-plane test cases, we mainly verify that the configuration from CONFIG_DB will be programmed into APPL_DB correctly.
For the data-plane test cases, we first set up test cases that verify the basic forwarding and decapsulation functionalities of the device.
Then, there are additional test cases that verify the aforementioned SRv6 functions and their interaction with other system components under certain scenarios.

## Overview of SRv6 protocol

Segment Routing IPv6 (SRv6) is a next-generation IP bearer protocol that combines Segment Routing (SR) and IPv6.
Utilizing existing IPv6 forwarding technology, SRv6 implements network programming through flexible IPv6 extension
headers. SRv6 reduces the number of required protocol types, offers great extensibility and programmability,
and meets the diversified requirements of more new services.


## Revision

| Rev |     Date    |           Author             | Change Description                |
|:---:|:-----------:|:----------------------------:|-----------------------------------|
| 0.1 | March 2025  | Changrong Wu / Abhishek Dosi | Initial Draft                     |
| 0.2 | Apr 2025    | Chuan Wu                     | Add the comprehensive test case and techsupport test case |
| 0.3 | Oct 2025    | Baorong Liu                  | Add test case for uA |

## Test Plan

### Table 1: Abbreviations

| ****Term**** | ****Meaning**** |
| -------- | ----------------------------------------- |
| SRv6 | Segment Routing IPv6  |
| SID  | Segment Identifier  |
| SRH  | Segment Routing Header  |
| uSID | Micro Segment |
| uN   | SRv6 instantiation of a prefix SID |
| uA   | SRv6 adjacency SID, END.X with Next |
| USD | Ultimate Segment Decapsulation |

### Scope
The test is to verify the functions in SRv6 phase I and II.

### Scale
Max number of MY_SID entries is 10, it would be covered in this test plan.

### Control-plane Test
#### uN Config
- Setup a SRv6 locator and a uN SID configuration in CONFIG_DB.
- Verify that the corresponding configuration appears in FRR configuration.
- Verify that the APPL_DB is programmed correctly according to the configuration.

#### uA Config
- Setup a SRv6 locator and a uA SID configuration in CONFIG_DB.
- Verify that the corresponding configuration appears in FRR configuration.
- Verify that the APPL_DB is programmed correctly according to the configuration.

#### uDT46 Config
- Setup a SRv6 locator, a DT46 SID and a VRF configuration in CONFIG_DB.
- Verify that the corresponding configuration appears in FRR configuration.
- Verify that the APPL_DB is programmed correctly according to the configuration.

### Data-plane Test

#### Comprehensive Test for SRv6 dataplane uN function
1. Configure SRV6_MY_SIDS with uN action at the same time for different SIDs <br>
  a. Configure all of the SRV6_MY_SIDS as __pipe__ mode <br>
2. Validate correct SRv6 CRM resource items had been used
3. Clear srv6 counter <br>
4. Send IPv6 packets from downstream to upstream neighbors <br>
  a. Including IPv6 packets with reduced SRH(no SRH header) for uN action <br>
  b. Including IPv6 packets with 1 uSID container in SRH for uN action <br>
  c. Including IPv6 packets with 2 uSID container in SRH for uN action <br>
  d. Including IPinIPv6 packets with reduced SRH(no SRH header) and uSID container in SRH for USD flavor<br>
  e. Including IPv6inIPv6 packets with reduced SRH(no SRH header) and uSID container in SRH for USD flavor <br>
5. All types of IPv6 packets should be handled correctly <br>
  a. For uN action, DIP shift/ uSID container copy to DIP/ segment left decrement should happen <br>
  b. For uN action USD flavor, IP tunnel decap should happen <br>
  c. For each SID, the SRv6 counter for packet number and size should be updated correctly
6. Randomly choose one action from cold reboot/config reload and do it
7. Resend the all types of IPv6 packets
8. All types of IPv6 packets should be handled correctly <br>
  a. For uN action, DIP shift/ uSID container copy to DIP/ segment left decrement should happen <br>
  b. For uN action USD flavor, IP tunnel decap should happen <br>
  c. For each SID, the SRv6 counter for packet number and size should be updated correctly
9. Remove all the configured SRV6_MY_SIDS <br>
10. Check all the SRv6 CRM resource had been released <br>

#### Test SRv6 uN forwarding function and control-plane integrity after configuration reload
- Set up SRv6 configuration and relevant static-route configuration in CONFIG_DB
- Verify the DUT’s uN forwarding functions by running the traffic test
- Perform a config reload and verify that APPL_DB gets reprogrammed
- Verify the DUT’s uN forwarding functions by running the traffic test again

#### Test SRv6 uN forwarding function and control-plane integrity after BGP container restart
- Set up SRv6 uN configuration and relevant static-route configuration in CONFIG_DB
- Verify the DUT’s uN forwarding functions by running the traffic test
- Restart the BGP systemd service and verify that APPL_DB gets reprogrammed
- Verify the DUT’s uN forwarding functions by running the traffic test again

#### Test SRv6 uN forwarding function and control-plane integrity after reboot
- Set up SRv6 uN configuration and relevant static-route configuration in CONFIG_DB
- Verify the DUT’s uN forwarding functions by running the traffic test
- Reboot the DUT and verifies that APPL_DB gets reprogrammed
- Verify the DUT’s uN forwarding functions by running the traffic test again

#### Test SRv6 uN forwarding on downstream neighbors on T0 devices
- Set up SRv6 uN configuration and down-stream neighbor static-route configuration in CONFIG_DB
- Verify that ARP entries for down-stream neighbors are created on DUTs
- Inject packets with a uSID pointing to the down stream neighbor from PTF
- Verify that SRv6 packets are received on down-stream ports of PTF container

#### Test SRv6 No-op and blackholing route
- Set up SRv6 uN configuration and relevant static-route configuration in CONFIG_DB
- Inject packets with a uSID that does not match the uSID of DUT from PTF
- Verify that the SRv6 packets are not received on any PTF ports

#### Verify SRv6 configuration in techsupport
1. Configure SRV6_MY_SIDS with uN action at the same time for different SIDs <br>
  a. Configure all of the SRV6_MY_SIDS as __pipe__ mode <br>
2. Collect techsupport dump files
3. SRv6 related configuration should be revealed in dump files

#### Test for SRv6 dataplane basic uA function
1. Configure SRV6_MY_SIDS with uA action <br>
  a. Configure SRV6_MY_SIDS as __pipe__ mode <br>
2. Send IPv6 packets from downstream to upstream neighbors <br>
  a. Including IPv6 packets with reduced SRH(no SRH header) for uA action <br>
  b. For uA action, DIP shift/ uSID container copy to DIP/ segment left decrement should happen <br>
  c. For uA action, the packet should be forwarded thru the assigned interface <br>
3. Remove all the configured SRV6_MY_SIDS <br>

#### Test for SRv6 dataplane uSID with uN action plus uSID with uA action
1. Configure one SRV6_MY_SIDS with uN action and one SRV6_MY_SIDS with uA action (same locator) <br>
  a. Configure SRV6_MY_SIDS as __pipe__ mode <br>
2. Send IPv6 packets from downstream to upstream neighbors <br>
  a. Including IPv6 packets with reduced SRH(no SRH header) for uN and uA action <br>
  b. For uN action, DIP shift/ uSID container copy to DIP/ segment left decrement should happen <br>
  d. For uA action, DIP shift/ uSID container copy to DIP/ segment left decrement should happen <br>
  e. For uA action, the packet should be forwarded thru the assigned interface <br>
3. Remove all the configured SRV6_MY_SIDS <br>

#### Test SRv6 uA forwarding function and control-plane integrity after configuration reload
- Set up SRv6 configuration and relevant static-route configuration in CONFIG_DB
- Verify the DUT’s uA forwarding functions by running the traffic test
- Perform a config reload and verify that APPL_DB gets reprogrammed
- Verify the DUT’s uA forwarding functions by running the traffic test again

#### Test SRv6 uA forwarding function and control-plane integrity after BGP container restart
- Set up SRv6 uA configuration and relevant static-route configuration in CONFIG_DB
- Verify the DUT’s uA forwarding functions by running the traffic test
- Restart the BGP systemd service and verify that APPL_DB gets reprogrammed
- Verify the DUT’s uA forwarding functions by running the traffic test again

#### Test SRv6 uA forwarding function and control-plane integrity after reboot
- Set up SRv6 uA configuration and relevant static-route configuration in CONFIG_DB
- Verify the DUT’s uA forwarding functions by running the traffic test
- Reboot the DUT and verifies that APPL_DB gets reprogrammed
- Verify the DUT’s uA forwarding functions by running the traffic test again
