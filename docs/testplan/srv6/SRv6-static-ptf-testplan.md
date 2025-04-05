# PTF-based Test Plan for Static SRv6 functionalities

Since several functionalities were added in SONiC to support the deployment of static SRv6 network(refer to [HLD](https://github.com/sonic-net/SONiC/blob/master/doc/srv6/srv6_static_config_hld.md)), we propose to add test cases that will help in verify the correctness of those SRv6 functionalities.
These test cases falls into two categories, data-plane focused and control-plane focused.
In the control-plane test cases, we mainly verify that the configuration from CONFIG_DB will be programmed into APPL_DB correctly.
For the data-plane test cases, we first set up test cases that verify the basic forwarding and decapsulation functionalities of the device.
Then, there are additional test cases that verify the aforementioned SRv6 functions and their interaction with other system components under certain scenarios.



## Revision

| Rev |     Date    |           Author             | Change Description                |
|:---:|:-----------:|:----------------------------:|-----------------------------------|
| 0.1 | March 2025  | Changrong Wu / Abhishek Dosi | Initial Draft                     |

## Test Plan


### Control-plane Test
#### uN Config
- Setup a SRv6 locator and a uN SID configuration in CONFIG_DB.
- Verify that the corresponding configuration appears in FRR configuration.
- Verify that the APPL_DB is programmed correctly according to the configuration.

#### uDT46 Config
- Setup a SRv6 locator, a DT46 SID and a VRF configuration in CONFIG_DB.
- Verify that the corresponding configuration appears in FRR configuration.
- Verify that the APPL_DB is programmed correctly according to the configuration.

### Data-plane Test

#### Test SRv6 uN forwarding function
- Set up SRv6 uN configuration and relevant static-route configuration in CONFIG_DB
- Inject packets with two uSIDs from PTF container
- Verify that the DUT removes the first uSID in destination address and forwards packet back to PTF based on IPv6 static-route

#### Test SRv6 uN USD decapsulation function
- Set up SRv6 uN configuration and relevant static-route configuration in CONFIG_DB
- Inject packets with one uSID from PTF container
- Verify that the DUT removes the SRH and forwards packet back to PTF with the expected inner header.

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
