# **Introducing new ACL Table Type L3V4V6**

## **L3V4V6 ACL Table Test Plan**

## **Overview**

This test plan covers the required testcases for newly introduced ACL Table type - L3V4V6

### **Scope**
---------

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to cover test cases for functional testing of ACL Table type L4V4V6 on SONiC system, making sure that traffic flows correctly, according to the V4 & V6 ACL Rules configuration.



### **Related **DUT** CLI commands**
----------------------------


| **Command**                                                      | **Comment** |
|------------------------------------------------------------------|-------------|
| **Configuration commands**                                       |
|config acl add table <table_name> L3V4V6<br> acl-loader update full <File_Name> |             |
| **Show commands**                                                |
|  show acl table <table_name><br> aclshow -a |

### **Related DUT configuration files**
-----------------------------------

Example ACL rules in config_db for ACL Table type L3V4V6

```
{
    "ACL_TABLE": {
        "DATAACL": {
            "policy_desc": "L3V4V6 DATAACL",
            "ports": [
                "Ethernet100",
                "Ethernet104",
                "Ethernet92",
                "Ethernet96",
                "Ethernet28"
            ],
            "type": "L3V4V6",
            "stage": "ingress"
        }
    }
        "ACL_RULE": {
            "DATAACL|RULE_1": {
                "PRIORITY": "100",
                "SRC_IP": "10.0.0.10/32",
                "IP_TYPE": "IPV4",
                "PACKET_ACTION": "FORWARD"
            },
            "DATAACL|RULE_2": {
                "PRIORITY": "100",
                "IP_TYPE": "IPV4",
                "DST_IP": "20.0.0.10/32",
                "PACKET_ACTION": "DROP"
            },
            "DATAACL|RULE_3": {
                "PRIORITY": "100",
                "IP_TYPE": "IPV6",
                "SRC_IPV6": "2010:0:1:0::1/128",
                "PACKET_ACTION": "DROP"
            },
            "DATAACL|RULE_4": {
                "PRIORITY": "100",
                "IP_TYPE": "IPV6",
                "DST_IPV6": "2011:0:1:0::1/128",
                "PACKET_ACTION": "FORWARD"
            }
        }
    }

}
```
### **Related SAI APIs**
----------------

NA

<span id="_Toc463421033" class="anchor"></span>

## **Test structure**

### **Setup configuration**
----------------------------

The test will run on the t0 testbed:

![testbed-t0.png](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t0.png?raw=true)


### **Configuration scripts**
---------------------
* Before starting the test, Acl capability of STATE_DB will be checked. If the platform does not support L3V4V6 ACL Table Type, then further testing will be skipped.
* Creating below given ACL Table will have the specified ACL Match Fields <br>

| ACL Table Type                   | ACL table stage: ingress | ACL table stage: egress |
| ------------------------------ | ------------------------ | ----------------------- |
| L3V4V6 | MATCH_SRC_IP<br>MATCH_DST_IP<br>MATCH_SRC_IPV6<br>MATCH_DST_IPV6<br>MATCH_OUTER_VLAN_ID<br>MATCH_L4_SRC_PORT<br>MATCH_L4_DST_PORT<br>MATCH_ETHER_TYPE<br>MATCH_IP_PROTOCOL<br>MATCH_TCP_FLAGS<br>MATCH_ACL_IP_TYPE<br>MATCH_ICMP_TYPE<br>MATCH_ICMP_CODE<br>MATCH_ICMPV6_TYPE<br>MATCH_ICMPV6_CODE<br>MATCH_IPV6_NEXT_HEADER|MATCH_SRC_IP<br>MATCH_DST_IP<br>MATCH_SRC_IPV6<br>MATCH_DST_IPV6<br>MATCH_OUTER_VLAN_ID<br>MATCH_L4_SRC_PORT<br>MATCH_L4_DST_PORT<br>MATCH_ETHER_TYPE<br>MATCH_IP_PROTOCOL<br>MATCH_TCP_FLAGS<br>MATCH_ACL_IP_TYPE<br>MATCH_ICMP_TYPE<br>MATCH_ICMP_CODE<br>MATCH_ICMPV6_TYPE<br>MATCH_ICMPV6_CODE<br>MATCH_IPV6_NEXT_HEADER|

### **Test cases**

### **Test case \#1**

Test objective

* To verify IPv4 match fields for upstream neighbors, downstream hosts in both Ingress & Egress stages of L3V4V6 ACL TABLE

Test description


| **\#** | **Test Description** | **Expected Result** |
|--------|----------------------|---------------------|
| 1.     |  Create ACL table of type L3V4V6 | ACL Table should be created                    |
| 2.     | Configure ACL Rules for all the supported match fields for IPv4| Configuration should be successful                     |
| 3.     | Associate the table to upstream neighbors in Ingress & Egress stages| Config should be successful|
| 4.     | Send traffic to verify appropriate IPv4 match fields| Traffic should be matched against the respective ACL Rules|
| 5.     | Send traffic not matching the appropriate IPv4 match fields  | Traffic should not be matched against the respective ACL Rules|
| 6.     | Associate the table to downstream hosts in Ingress & Egress stages| Config should be successful|
| 7.     | Send traffic to verify appropriate IPv4 match fields| Traffic should be matched against the respective ACL Rules|
| 8.     | Send traffic not matching the appropriate IPv4 match fields  | Traffic should not be matched against the respective ACL Rules|
| 9.     | Verify "aclshow" and ensure counters are reflected correctly | Counters should be incremented only for matched traffic|
| 10.     | Verify "show acl table <table_name> and ensure table_type is displaying as L3V4V6 | Counters should be incremented only for matched traffic|
| 11.     | Save the config, do reload and verify traffic again | No deviation from the above expected results should be observed |
| 12.     | Flap the ACL associated ports and verify traffic again | No deviation from the above expected results should be observed |


### **Test case \#2**

Test objective

* To verify IPv6 match fields for upstream neighbors, downstream hosts in both Ingress & Egress stages of L3V4V6 ACL TABLE

Test description

| **\#** | **Test Description** | **Expected Result** |
|--------|----------------------|---------------------|
| 1.     |  Create ACL table of type L3V4V6 | ACL Table should be created                    |
| 2.     | Configure ACL Rules for all the supported match fields for IPv6| Configuration should be successful                     |
| 3.     | Associate the table to upstream neighbors in Ingress & Egress stages| Config should be successful|
| 4.     | Send traffic to verify appropriate IPV6 match fields| Traffic should be matched against the respective ACL Rules|
| 5.     | Send traffic not matching the appropriate IPV6 match fields | Traffic should not be matched against the respective ACL Rules|
| 6.     | Associate the table to downstream hosts in Ingress & Egress stages| Config should be successful|
| 7.     | Send traffic to verify appropriate IPV6 match fields| Traffic should be matched against the respective ACL Rules|
| 8.     | Send traffic not matching the appropriate IPV6 match fields  | Traffic should not be matched against the respective ACL Rules|
| 9.     | Verify "aclshow" and ensure counters are reflected correctly | Counters should be incremented only for matched traffic|
| 10.     | Verify "show acl table <table_name> and ensure table_type is displaying as L3V4V6 | Counters should be incremented only for matched traffic|
| 11.     | Save the config, do reload and verify traffic again | No deviation from the above expected results should be observed |
| 12.     | Flap the ACL associated ports and verify traffic again | No deviation from the above expected results should be observed |

### **Test case \#3**

Test objective

* To verify both IPv4 & IPv6 match fields in L3V4V6 ACL TABLE

Test description


| **\#** | **Test Description** | **Expected Result** |
|--------|----------------------|---------------------|
| 1.     |  Create ACL table of type L3V4V6 | ACL Table should be created                    |
| 2.     | Configure ACL Rules for all the supported match fields for IPv4 & IPv6| Configuration should be successful                     |
| 3.     | Associate the table to upstream neighbors in Ingress & Egress stages| Config should be successful|
| 4.     | Send traffic to verify appropriate IPv4 & IPv6 match fields| Traffic should be matched against the respective ACL Rules|
| 5.     | Send traffic not matching the appropriate IPv4 & IPv6  match fields | Traffic should not be matched against the respective ACL Rules|
| 6.     | Associate the table to downstream hosts in Ingress & Egress stages| Config should be successful|
| 7.     | Send traffic to verify appropriate IPv4 & IPv6 match fields| Traffic should be matched against the respective ACL Rules|
| 8.     | Send traffic not matching the appropriate IPv4 & IPv6 match fields | Traffic should not be matched against the respective ACL Rules|
| 9.     | Verify "aclshow" and ensure counters are reflected correctly | Counters should be incremented only for matched traffic|
| 10.     | Verify "show acl table <table_name> and ensure table_type is displaying as L3V4V6 | Counters should be incremented only for matched traffic|
| 11.     | Save the config, do reload and verify traffic again | No deviation from the above expected results should be observed |
| 12.     | Flap the ACL associated ports and verify traffic again | No deviation from the above expected results should be observed |
