# DASH Private Link Redirect Test Plan
- [Overview](#overview)
	- [Scope](#scope)
	- [Testbed](#testbed)
	- [Setup Configuration](#setup-configuration)
- [Test Cases](#test-cases)
- [Open Questions](#open-questions)

## Overview
Private Link redirect map leverages the identical SDN transformation as defined in the standard private link implementation. The only difference is that the IP address used in underlay routing and 4to6 action will be specified by a port-based service mapping for a specified port range, different IP or destination port can be used for crafting the packet. The same is applied to PL-NSG also, when PL NSG is enabled, the extra encap for tunneling the packet to NSG will still be added on top the original PL encap. And the return packet will be exactly the same as the regular case without PL NSG.



### Scope
The test is targeting the verification of the private link redirect functionality on DPU in a smartswitch.
New test script and testcases are added to verify the packet is sdn tranformed as expected and packets/counters are verified.

### Testbed
The test will run on a smartswitch testbed with DPUs enabled.

### Setup Configuration
- **Common Setup:**
	- Dash private link FNIC configs along with PL redirect configs for TCs 1 to 10.
	- Dash private link & PL-NSG configs along with PL redirect configs for TCs 11 to 20.

		- **PL redirect configs:**
		    - ##### DASH_OUTBOUND_PORT_MAP_TABLE
                ```
                DASH_OUTBOUND_PORT_MAP_TABLE:{{map_id}}
                "guid": {{string}}
                ---------------------------------------
                key = DASH_OUTBOUND_PORT_MAP_TABLE:map_id:port_range ; ID of the port map
                ; field = value
                guid = (OPTIONAL) GUID of the port mapping.
                ```

            - ##### DASH_OUTBOUND_PORT_MAP_RANGE_TABLE

                ```
                DASH_OUTBOUND_PORT_MAP_RANGE_TABLE:{{map_id}}:{{port_range}}
                "action": {{map_action}},
                "backend_ip": {{ip_address}},
                "backend_port_base": {{int}}
                ---------------------------------------
                key = DASH_OUTBOUND_PORT_MAP_TABLE:map_id:port_range ; parent port map ID from DASH_OUTBOUND_PORT_MAP_TABLE, and the range of ports for this mapping instance with the format `{{start port}}-{{end port}}`
                ; field = value
                action = action to take when packet matches this port range. Must be one of ["SKIP_MAPPING", "MAP_PRIVATE_LINK_SERVICE"]
                backend_ip = the IP of the Private Link service backend. Used for overlay dst IP 4to6 transformation and underlay dst IP
                backend_port_base = the first port of the translated port range
                ```
- **Common cleanup:**
	- Remove configs after execution of all test cases
## Test Cases

### Test Case #1: TCP DST Port is below the map table range
-  **Objectives:** Verify that a TCP packet with a destination port below the configured port map range, is forwarded as normal private link packet with out any pl redirect modifations of dst port or underlay ip.
-  **Setup:**
	- Create port map table.
	- Create Redirect port map table with, action : 2 (MAP_PRIVATE_LINK_SERVICE), port range : 8001-9000, backend ip : 60.60.60.1 & port base 42001.
	- Update the ENI table on DPU with the created PL Redirect map table and push the ENI config to DPU.
	- Send TCP packet with dst port below the map table range (eg: 8000).
-  **Validation:**
	- Check that the packet is forwarded as normal private link packet with out any pl redirect modifations of dst port or underlay ip.
-  **Tear down:**
	- Remove configs after execution of all test cases

### Test Case #2: TCP DST Port is above the map table range
-  **Objectives:** Verify that a TCP packet with a destination port above the configured port map range, is forwarded as normal private link packet with out any pl redirect modifations of dst port or underlay ip.
-  **Setup:**
	- Create port map table.
	- Create Redirect port map table with, action : 2 (MAP_PRIVATE_LINK_SERVICE), port range : 8001-9000, backend ip : 60.60.60.1 & port base 42001.
	- Update the RNI table on DPU with the created PL Redirect map table and push the ENI config to DPU.
	- Send TCP packet with dst port above the map table range (eg: 9001).
-  **Validation:**
	- Check that the packet is forwarded as normal private link packet with out any pl redirect modifations of dst port or underlay ip.
-  **Tear down:**
	- Remove configs after execution of all test cases


### Test Case #3: TCP DST Port falls with in map table range and is same as the start port
-  **Objectives:** Verify that a TCP packet with a destination port with in map table range and is equal to start port, then the packet is pl redirect sdn modified and forwarded with expected port and underlay ip.
-  **Setup:**
	- Create port map table.
	- Create Redirect port map table with, action : 2 (MAP_PRIVATE_LINK_SERVICE), port range : 8001-9000, backend ip : 60.60.60.1 & port base 42001.
	- Update the RNI table on DPU with the created PL Redirect map table and push the ENI config to DPU.
	- Send TCP packet with dst port is within the map table range and is the start port (eg: 8001).
-  **Validation:**
	- Check that the packet is forwarded as expected private link packet with pl redirect modifications of dst port (50002) and underlay ip (60.60.60.1).
-  **Tear down:**
	- Remove configs at the end of execution of all test cases


### Test Case #4: TCP DST Port falls with in map table range and is same as the end port
-  **Objectives:** Verify that a TCP packet with a destination port with in map table range and is equal to end port, then the packet is pl redirect sdn modified and forwarded with expected port and underlay ip.
-  **Setup:**
	- Create port map table.
	- Create Redirect port map table with, action : 2 (MAP_PRIVATE_LINK_SERVICE), port range : 8001-9000, backend ip : 60.60.60.1 & port base 42001.
	- Update the RNI table on DPU with the created PL Redirect map table and push the ENI config to DPU.
	- Send TCP packet with dst port is within the map table range and is the end port (eg: 9000).
-  **Validation:**
	- Check that the packet is forwarded as expected private link packet with pl redirect modifications of dst port (51001) and underlay ip (60.60.60.1).
-  **Tear down:**
	- Remove configs at the end of execution of all test cases


### Test Case #5: TCP DST Port falls with in map table range and is any value with in the range
-  **Objectives:** Verify that a TCP packet with a destination port with in map table range and is with in the range, then the packet is pl redirect sdn modified and forwarded with expected port and underlay ip.
-  **Setup:**
	- Create port map table.
	- Create Redirect port map table with, action : 2 (MAP_PRIVATE_LINK_SERVICE), port range : 8001-9000, backend ip : 60.60.60.1 & port base 42001.
	- Update the ENI table on DPU with the created PL Redirect map table and push the ENI config to DPU.
	- Send TCP packet with dst port is within the map table range and is any value within the range (eg: 8500).
-  **Validation:**
	- Check that the packet is forwarded as expected private link packet with pl redirect modifications of dst port (50501) and underlay ip (60.60.60.1).
-  **Tear down:**
	- Remove configs at the end of execution of all test cases

### Test Case #6 to #10:  With UDP Packet
- Repeat the TC 1 to TC 5, but with UDP Packet
- Instead of removing and adding the PL Redirect configs after each test, config once before all tests, Update if needed in test cases and remove after all tests.

### Test Case #11 to #20: TCP & UDP Packets with PL-NSG Enabled
- Repeat the TC 1 to TC 10, but with the PL-NSG configs.
- Config PL-NS with PL Redirect once before all tests and remove after all tests.
- Verify the extra outer Vxlan header is also added as expected in all the test cases.

### Test Case #21: PL Redirect with Map action as SKIP_MAPPING
- Coverage to be added when supported

### Test Case #22: PL Redirect with Map Update/modify port base and verify with TCP, UPD with and without PL-NSG
- Coverage to be added when the config 'Update' is supported

### Test Case #23: PL Redirect with Map Update/modify port range and verify with TCP, UPD  with and without PL-NSG
- Coverage to be added when the config 'Update' is supported

### Test Case #24: PL Redirect with Map Update/modify backen ip and verify with TCP, UPD  with and without PL-NSG
- Coverage to be added when the config 'Update' is supported

### Test Case #26: Verify PL Redirect Counters.
- Coverage to be added when Counters are supported

## Document References

- [Private Link Service HLD](https://github.com/sonic-net/DASH/blob/main/documentation/private-link-service/private-link-service.md)
- [Private Link Redirect HLD](https://github.com/sonic-net/DASH/blob/main/documentation/private-link-service/private-link-redirect-map.md)

## Open Questions
