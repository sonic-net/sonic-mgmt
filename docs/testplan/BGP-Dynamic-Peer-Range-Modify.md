# BGP Dynamic Peer Range Modification Testplan
- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Sample Configurations](#sample-configurations)
- [Test cases](#test-cases)

## Overview
The goal of this test is to validate that the modification of subnet size for dynamic BGP neighbors is supported via bgpcfgd. The ip_range field in the config DB schema stores the subnet from which BGP connections are accepted.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test for BGP expected behavior when ip_range is modified for dynamic BGP neighbors. The IP range can be modified by adding a new IP range, deleting an IP range, increasing/decreasing the size of existing range. 

### Testbed
The test could run on t0 testbed in virtual switch environment.

### Sample Configurations
To create a dynamic BGP neighbor:
```json
{
   "BGP_PEER_RANGE": {
      "BGPSLBPassive": {
         "ip_range": [
            "10.0.0.56/30"
         ],
         "peer_asn": "64600",
         "src_address": "10.0.0.56",
         "name": "BGPSLBPassive"
      }
   }
}
```

To modify the ip range from previous configuration:
```json
{
   "BGP_PEER_RANGE": {
      "BGPSLBPassive": {
         "ip_range": [
            "10.0.0.56/31"
         ],
         "peer_asn": "64600",
         "src_address": "10.0.0.56",
         "name": "BGPSLBPassive"
      }
   }
}
```

To add a new IP range to previous configuration:
```json
{
   "BGP_PEER_RANGE": {
      "BGPSLBPassive": {
         "ip_range": [
            "10.0.0.56/31","10.0.0.60/31"
         ],
         "peer_asn": "64600",
         "src_address": "10.0.0.56",
         "name": "BGPSLBPassive"
      }
   }
}
```

To remove the previously added ip range:
```json
{
   "BGP_PEER_RANGE": {
      "BGPSLBPassive": {
         "ip_range": [
            "10.0.0.56/31"
         ],
         "peer_asn": "64600",
         "src_address": "10.0.0.56",
         "name": "BGPSLBPassive"
      }
   }
}
```
### Related DUT CLI commands

| Goal | Command |
| -------- | ------- |
| To view summarized neighbor information | show ip bgp summary |
| To parse config using sonic-cfggen | sonic-cfggen -j /etc/sonic/config_db.json --write-to-db |
| To delete a dynamic peer | redis-cli -n 4 DEL "BGP_PEER_RANGE|<vnet name>|<peer name>" |

### Testcases

| Step | Goal | Expected results |
| -------- | ------- | ------- |
|Configure a dynamic peer group in BGP_PEER_RANGE section |Validate initial setup|Should see peers from configured range come up|
|Modify the subnet size of dynamic neighbors and run sonic-cfggen for it to take effect |Validate Modifying subnet size |Peers from the previous subnet range will flap. Peers from the modified subnet range should come up. Static peers should not flap.|
|Add a new IP range and run sonic-cfggen for it to take effect |Validate Adding IP range|Peer from new IP range should come up. Peers from existing IP range should not flap and stay up.Static peers should not flap.|
|Delete the IP range configured in previous step and run sonic-cfggen for it to take effect |Validate Deleting IP range|Peer from removed IP range should be removed. Peers from existing IP range should not flap. Static peers should not flap|
|Perform deletion/addition of an ip range 20 times |Stress testing|Peers from the ip range should go down on deletion and come back up on addition. No core dumps generated. Static peers should not flap. Peers from other dynamic ranges should not flap.|
|Delete the entire dynamic peer group |Validate Deleting dynamic peer|All the peers from the dynamic peer group should be removed. Static peers should not flap|
|Perform deletion/addition of the entire dynamic peer group 20 times |Stress testing|Peers from the dynamic peer group should go down on deletion and come back up on addition. No core dumps generated. Static peers should not flap|

