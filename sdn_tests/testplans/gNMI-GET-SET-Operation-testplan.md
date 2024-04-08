# [DRAFT, UNDER DEVELOPMENT]

# **Overview**

This document aims to outline the approach for testing the functionality of different gNMI GET/SET operations supported by the gNMI protocol as part of GPINs OpenConfig end-to-end testing.

With SONiC as the network operating system (NOS) for GPINS, gNMI is responsible for monitoring, streaming telemetry, and configuration management.  Broadcom’s Unified Management Framework (UMF) provides gNMI streaming telemetry based on the standard OpenConfig model. More details on gNMI for GPINs can be found here. \
 \
From the gNMI specification, the gNMI client can invoke a GET,  and/or SET request. The SET operations can be further categorized into UPDATE, REPLACE, and DELETE operations.


# **Test Setup**

In the test setup of Figure 1, a test client initializes a gNMI client that connects to the gNMI server running on a single switch under test (SUT).  This connection uses the `bond0` management interface.  

<img width="408" alt="Screenshot 2024-04-03 at 3 34 30 PM" src="https://github.com/saiilla/sonic-mgmt/assets/165318278/44d26d2b-b82d-4851-a534-2d93da867939">


Figure 1: gNMI end to end test setup.


# **E2E Test Cases**

All the payload values will be randomized in the test cases instead of hard-coded values. For example EthernetX will be used as an interface name instead of Ethernet0 and EthernetX can be taken out from the list of interfaces supported by the DUT during the execution.

The SFE will always use gNMI SET replace/update/delete operation for modifying/removing the value in the switch and gNMI GET for fetching the values.


## SET operation


<table>
  <tr>
   <td style="background-color: #b7b7b7"><p style="text-align: right">
<strong>Case </strong></p>

   </td>
   <td style="background-color: #b7b7b7"><strong>SET update</strong>
   </td>
   <td style="background-color: #b7b7b7"><strong>SET replace</strong>
   </td>
   <td style="background-color: #b7b7b7"><strong>SET delete</strong>
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Unpopulated leaf</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Unpopulated leaf with no payload</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Populated leaf with  no payload</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Populated leaf</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid data for a leaf</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">N/A
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid leaf path </p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Read only leaf</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Unpopulated subtree</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Populated subtree</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid data for a subtree</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Read only subtree</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid subtree path </p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Multiple payload</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Root level operation</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success*
   </td>
  </tr>
</table>


To validate any of the following SET operations and its correctness of the data, the client will invoke a gNMI get operation for corresponding nodes and cache the result before invoking a set operation. The cached values will be adjusted based on the set request payload. Once the set operation is successful the client will invoke another get operation and validate the response against the expected response. The below example shows the operations in sequential order


```
cached_response = gNMI get for the interface/interface[name=EthernetX]/ 
gNMI set for the interface/interface[name=EthernetX]/config/mtu
expected_response = Update the MTU value for both config/state leafs in the cached response
response = gNMI get for the interface/interface[name=EthernetX]/ 
Validate the response against the expected_response
```


The GPINS gNMI server only supports encoding as proto and json and doesn’t not support any other encoding. The SET only accepts the payload as JSON values today.

## Test

### Update Expectation

The expectation is for the gNMI server to process the valid update request and populate the leaf nodes with the values specified in the request payload and return the valid response to the client. If the leaf nodes are not present in the payload then the server should not populate them with the default values and leave those leaf values as-is(not modify them).

### Test 1: Send a valid Update request for an existing leaf

Condition to test:

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```

Validation:
  - gNMI Set RPC responds without error and all the fields in the response matches the expectation.
  - interfaces/interface/[name=EthernetX]/config/description matches the payload value ("Test_config").
  - Verify that other fields for the EthernetX subtree is not updated

### Test 2: Send a valid Update request for an non-existing leaf

Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } } encoding: JSON
payload: {   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {  
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             }, 
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      }, 
                      "index" : 0,
                      "openconfig-if-ip:ipv4" : {  
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  },
                                  "ip" : "<IP_ADD>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  },
                                  "ip" : "<IP_ADD>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
 }
```

Validation:
  - Verify that the Leaf should be created and proper response received. In this case the loopback interfaces should be created in the configuration.

### Test 3: Send an Update request with 2 valid updates
Condition to test: send update request with 2 valid update payloads
```
path: { origin: "openconfig" elem: { name:"interfaces" } }

payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {   
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             },  
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {   
                      "config" : {
                         "index" : 0
                      },  
                      "index" : 0, 
                      "openconfig-if-ip:ipv4" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  }, 
                                  "ip" : "<IP_ADD>"
                               }, 
                               {  
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  }, 
                                  "ip" : "<IP_ADD>"
                               }  
                            ]     
                         }     
                      }     
                   }     
                ]     
             }     
          }     
       ]     
    },    
    "openconfig-interfaces:interfaces" : {
       "interface" : [ 
          {   
             "config" : { 
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             },
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      },
                      "index" : 0,
                      "openconfig-if-ip:ipv6" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  },
                                  "ip" : "<IP_ADD>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  },
                                  "ip" : "<IP_ADD>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
}
```
Validation: 
  - Verify that the Leaf should be created and proper response received. In this case the loopback interfaces should be along with both IPV4 and IPV6 addresses.

### Test 4: Negative test cases - Interface description for the platform subtree

Condition to test: Send interface description for the platform subtree  
```
path: { origin: "openconfig" elem: { name:"platform" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```

Validation: 
  - SET response should contain a failure message, also verifies none of the other path’s values are changed for the platform subtree

### Test 4: Negative test cases - Send invalid path

Condition to test: Send invalid path
```
path: { origin: "openconfig" elem: { name:"xyz" } }

Payload: {"openconfig-interfaces:description":"Test_config"}

```

Validation: 
  - SET response should contain a failure message, also verifies none of the other paths values are changed and there shouldn’t be any values populated for xyz path

### Replace Expectation

The expectation is for the gNMI server to process the valid replace request and populate the leaf nodes with the values specified in the request payload and return the valid response to the client. If the leaf nodes are not present in the payload then the server should populate them with the default values.

### Test 1: Send a Replace request for a branch in a default state to mutate a single leaf

Condition to test: replace request for a single leaf

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_config"}

```

Validation: 
  - Verify that the interfaces/interface/[name=EthernetX]/config/description is properly replaced and proper response is returned without any errors.

### Test 2: Send a Replace request to mutate few leafs in a branch that has other modified values

Condition to test: replace request for multiple leafs
```
path: { origin: "openconfig" elem: { name:"interfaces" } }
payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {  
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             }, 
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      }, 
                      "index" : 0,
                      "openconfig-if-ip:ipv4" : {  
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  },
                                  "ip" : "<IP_ADD>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  },
                                  "ip" : "<IP_ADD>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
 }

```

Validation: 
  - Verify that the Leaf should be created and proper response received. In this case the loopback interfaces should be created in the configuration and all the unset values for this interface should be set to default values ( example: mtu )

### Test 3: Send an Replace request with 2 valid updates

Condition to test: send update request with 2 valid update payloads

```
path: { origin: "openconfig" elem: { name:"interfaces" } }
Payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {   
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "LoopbackX"
             },  
             "name" : "LoopbackX",
             "subinterfaces" : {
                "subinterface" : [
                   {   
                      "config" : {
                         "index" : 0
                      },  
                      "index" : 0, 
                      "openconfig-if-ip:ipv4" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  }, 
                                  "ip" : "<IP_ADD>"
                               }, 
                               {  
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : XX
                                  }, 
                                  "ip" : "<IP_ADD>"
                               }  
                            ]     
                         }     
                      }     
                   }     
                ]     
             }     
          }     
       ]     
    },    
    "openconfig-interfaces:interfaces" : {
       "interface" : [ 
          {   
             "config" : { 
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "LoopbackX"
             },
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      },
                      "index" : 0,
                      "openconfig-if-ip:ipv6" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADD>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADD>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
}
```
Validation: 
  - Verify that the Leaf should be created and proper response received. In this case the loopback interfaces should be along with both IPV4 and IPV6 addresses.

### Test 4: Negative test cases - Send a request with 1 valid and 1 invalid Replace operations

Condition to test: replace request with 1 valid and 1 invalid request 
```
path: { origin: "openconfig" elem: { name:"interfaces" } }
payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {  
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopbackx"
             }, 
             "name" : "Loopbackx",
             "mtu"  : "<MTU>"
             }
          }
       ]
    }
 }
```

Validation: 
  - The SET request should be rejected and SET response should contain a failure message, also verifies none of the other paths values are changed.

### Test 5: Negative test cases - Interface description for the platform subtree 
Condition to test: Send interface description for the platform subtree 
```
path: { origin: "openconfig" elem: { name:"platform" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```
Validation: 
  - SET response should contain a failure message, also verifies none of the other path’s values are changed for the platform subtree

### Test 6: Negative test cases - Send invalid path
 Condition to test: Send invalid path
```
path: { origin: "openconfig" elem: { name:"xyz" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```
Validation: 
  - SET response should contain a failure message, also verifies none of the other paths values are changed and there shouldn’t be any values populated for xyz path.

### Delete Expectation
The expectation is for the gNMI server to process the valid delete request and remove those nodes from the system. The server should send a valid response to the client once the request has been processed successfully. 

### Test 1: Send a valid delete request for an existing leaf 

Condition to test: Send a delete request for an existing interface

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }
```

Validation: 
  - Verify that the interfaces/interface/[name=EthernetX] is properly removed from the config and a valid response is returned to the client.

### Test 2: Send an delete request for a non-existing leaf

Condition to test: Send a delete request for an invalid interface

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetY" } }
```

Validation: 
   - Verify that the delete request has failed and respond with an appropriate error message.

### Test 3: Send an delete request with 2 valid delete messages

Condition to test: Send delete request with 2 messages

```
path: { origin: "openconfig" elem: { name:"interfaces" } }
payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {   
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             },  
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {   
                      "config" : {
                         "index" : 0
                      },  
                      "index" : 0, 
                      "openconfig-if-ip:ipv4" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : xx
                                  }, 
                                  "ip" : "<IP_ADD>"
                               }, 
                               {  
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : xx
                                  }, 
                                  "ip" : "<IP_ADD>"
                               }  
                            ]     
                         }     
                      }     
                   }     
                ]     
             }     
          }     
       ]     
    },    
    "openconfig-interfaces:interfaces" : {
       "interface" : [ 
          {   
             "config" : { 
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             },
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      },
                      "index" : 0,
                      "openconfig-if-ip:ipv6" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADD>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADD>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADD>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
}
```

Validation: 
  - Verify that the Leaf should be deleted and proper response received. In this case the loopback interfaces should be along with both IPV4 and IPV6 addresses.

### SET operation 

### Mixed type operations Expectation

A valid request containing a delete, a replace and an update operation, the server must follow the processing order specified in gNMI specification and handle the request without any errors. The server should send a valid response to the client once the request has been processed successfully.

### Test 1: Send a valid delete, replace and update request for an existing subtree

Condition to test: Send a delete for an interface, replace for other interfaces followed by an update request.
```
path: { origin: "openconfig" elem: { name:"interfaces" } }
payload:
```

Validation: 
  - Verify that the specified interface has been deleted(not present in the response ) and other specified interfaces have been replaced(present in the response) with the updated leaf values.

### Test 2: Send a valid delete and update request for an existing subtree 

Condition to test: Send a delete for an interface followed by an update request
```
path: { origin: "openconfig" elem: { name:"interfaces" } }

```
Validation: 
  - Verify that the specified interface has been deleted(not present in the response ) and other specified interfaces attributes have been updated.

### Test 3: Send a valid delete and invalid update request for an existing subtree

Condition to test: Send a delete for an interface followed by an update request
```
path: { origin: "openconfig" elem: { name:"interfaces" } }

```

Validation: 
  - Verify the SET response contains an error message related to the invalid update message in the SET request.

### Test 4: Send a valid replace request at the root level

Condition to test: Send a replace request at the root level

```
path: { origin: "openconfig" elem: { name:"/" } }
payload:
```

Validation: 
  - Verify that the specified payload has been replaced and no other subtrees (openconfig/system/ or openconfig/qos ) are not populated in the response.

### Test 5: Send a valid set request without any path 

Condition to test: Send a valid request with empty path list

Validation: 
  - Verify that there are no errors returned by the server and it has been processed by the server and a valid response has been sent to the client, also verifies that none of the paths are changed.

### Test 6: Master arbitration: Send a valid set request from two clients 

Condition to test: Create two gNMI clients with two different connection IDs. Send the setRequest from both client

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_config"}

```

Validation: 
   - Verify that gNMI Set RPC responds without error and all the fields in the response matches the expectation.
   - Verify that interfaces/interface/[name=EthernetX]/config/description matches the payload value ("Test_config").
   - Verify that the second client set request has been rejected by the gNMI server due to master arbitration feature.

### GET operation

#### Expectation
The GET response should contain the value of the request nodes. The expectation is for the gNMI server to process the valid get request and should send a valid response containing the values of the request nodes. Only the PROTO and JSON encodings are currently supported in the GPINS.

#### Challenges
For end-to-end tests, we cannot be sure of what config nodes are set in the system beforehand and hence cannot determine what paths to validate against. The GET request can be issued after a SET request and validate the values that have been used in the SET request.

### Test cases
This test can extend an existing config push and subsequent GET request path test to validate the following test cases.

### Test 1: At the subtree level
Condition to test: 
```
path: {
origin: "openconfig" elem: { name:"interfaces" }
elem: { name:"interface" key: { key: "name" value: "EthernetX" } }
} 
```

Validation: 
  - Verify that the interfaces/interface/[name=EthernetX]/* are returned.

### Test 2: At the module level
Condition to test:
```
path: {
origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface"}
}
```

Validation: 
  - Verify that the interfaces/interface/[name=<*>]/* are returned.

### Test 2: Valid encoding
Condition to test: Issue a GET request with proto encoding 
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface"} } encoding: PROTO
```

Verify that the interfaces/interface/[name=<*>]/* are returned with PROTO format.

### Test 3: At the root level
Condition to test:
```
path:{
 origin: "openconfig" elem: { name:"/" }
 }
```

Validation: 
  - Verify that the interfaces/interface/[name=<*>]/* are returned.

### Test 4: Invalid data
Verify that appropriate error message returned when requesting an GET request for an invalid path
Condition to test: Config type with state/operational subtree
```
path: {
origin: "openconfig" elem: { name:"interfaces" }
elem: { name:"interface" key: { key: "name" value: "EthernetY" }
}
```

Validation: should return response with an error.

### Test 5: Invalid path
Verify that appropriate error message returned when requesting an GET request for an invalid path
Condition to test: Config type with state/operational subtree
```
path: { origin: "openconfig" elem: { name:"xye" } }
```

Validation: should return response with an error.

### Test 6: Invalid encoding
Condition to test: Issue a GET request with ASCII encoding 
```
path: {
origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface"} }
encoding: ASCII
```

Validation: Verify that the response returned with an error.
