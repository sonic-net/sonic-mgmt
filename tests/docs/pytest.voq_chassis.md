# SONiC Mgmt Test Framework for SONiC Dis-aggregated Chassis
# High Level Document

Table of Contents

  - [Revision](#revision)

  - [About this Manual](#about-this-manual)

  - [Scope](#scope)

  - [1 Requirements](#1-requirements)
  
  - [2 Approach](#2-approach)
    - [2.1 Ansible modules](#21-ansible-modules)
    - [2.2 Parameterizing dut_index and asic_index](#22-parameterizing-dut_index-and-asic_index)
    - [2.3 duthosts](#23-duthosts)
  - [3 Testbed](#3-testbed)
  - [4 Orchestration](#4-Orchestration)
    - [4.1 Ansible inventory](#41-ansible-inventory)   
    - [4.2 connection graph](#42-connection-graph)
    - [4.3 testbed.csv](#43-testbedcsv)
    - [4.4 topology file](#44-topology-file)
  - [5 Test case changes](#5-test-case-changes)
    - [5.1 parameterizing dut_index](#51-parameterizing-dut_index)
    - [5.2 duthosts](#52-duthosts)
  - [6 Acknowledgement](#6-acknowlegement)
   
###### Revision
| Rev |     Date    |       Author                                                                       | Change Description                |
|:---:|:-----------:|:----------------------------------------------------------------------------------:|-----------------------------------|
| 1.0 | 11/10/2020  | Nokia Sonic Team                                                                   | Initial  version                  |


# About this Manual
This document describes the design details for testing SONiC Chassis by extending the existing sonic-mgmt test framework.  

# Scope
A SONiC Chassis typically has multiple line cards and supervisor card. Today, there is no 'single point of mgmt' for a SONiC Chassis. In a dis-aggregated model, each linecard
and supervisor card has its own management IP address, that can be controlled/configured independently. 

The existing sonic-mgmt test framework has well defined test methodologies for testing of SONiC pizza boxes (a single mgmt. IP). 
The scope of this document is to enhance the framework to test SONiC Chassis with multiple mgmt. IP addresses, while still utilizing the existing test methodologies. 

The end goal is to be able to run the existing Open Community tests in sonic-mgmt repository against a SONiC Chassis with minimal changes to test cases itself.

# 1 Requirements
The sonic-mgmt test framework enhancements for testing on SONiC VOQ shall support the following
- backward compatability - Any enhancement should not break testing of pizza box, while allowing for testing of SONiC Chassis.

 - Test case changes - The enhancements should allow for incremental changes to existing test cases to support testing of SONiC Chassis and pizza boxes. If a test is enhanced to work with SONiC Chassis, it should still be able to test a SONiC pizza box.

# 2 Approach
In order to test SONiC chassis, the following issues had to be resolved:
- The SONiC chassis as a collection of linecards. Each linecard has its own mgmt. IP. 
- The front-panel linecards could be multi-asic (have multiple SONiC instances). 
- Need to distinguish between front-panel linecards and supervisor cards

The solution is to improve the current sonic-mgmt test infrastructure to support multi-DUT and multi-ASIC systems. Then, a SONiC chassis can be viewed as a collection of DUT's, each with either a single or multiple asics. This includes the 'supervisor' card as well. 

There was support added for multi-DUT for [Spytest](https://github.com/Azure/sonic-mgmt/pull/1848). This approach was extended with the following enhancements that facilitate the testing of SONiC chassis.

## 2.1 Ansible modules
The OC pytest tests in sonic-mgmt use ansible modules for querying for parsing data from the DUT. 

The ansible modules that are applicable to be run in different namespaces have been enhanced to support such functionaliy. Currently, the following modules support running them on different namespaces:
- bgp_facts - added 'instance_id' as an optional module param.
- config_facts - added 'namespace' as an opitonal module param.

If the optional namespace/ASIC specific module params are not specified, then they default to returning the output from the global namespace.

Other modules will be enhanced as needed during adaption of the tests to SONiC chassis.

## 2.2 Parameterizing the test case 
PR's
- [[Multi asic]: parameterize enum_asic_index and enum_dut_index](https://github.com/Azure/sonic-mgmt/pull/2245)

With this approch we use pytest parameterization to repeat a test against each of the DUTs and all asics (namespaces). If 'enum_asic_index' and 'enum_dut_index' are used as arguements to the test, then it would get repeated on each asic and each DUT. The 'enum_dut_index' is derived from the number of DUTs specified in testbed.csv and 'enum_asic_index' is derived from 'num_asics' defined in the inventory for each of the DUT.

Sample inventory file:
<pre>
node1:
   ansible_host: 10.1.1.100
   ansible_hostv6: fec0::ffff:afa:7
   <b>num_asics: 6</b>
</pre>

The test case modified to take 'enum_dut_index' and 'enum_asic_index' as an argument:
```
def test_bgp_facts(duthosts, enum_dut_index, enum_asic_index):
  duthost = duthosts[enum_dut_index]
  bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)
```

The infrastructure has been extended to support below fixtures for parameterizing test cases as well:
- enum_dut_index
- enum_dut_hostname
- enum_asic_index
- enum_frontend_asic_index
- enum_dut_portname
- enum_dut_portname_oper_up
- enum_dut_portname_admin_up
- enum_dut_portchannel
- enum_dut_portchannel_oper_up
- enum_dut_portchannel_admin_up
- enum_dut_feature
    
## 2.3 duthosts
PR's
- [Add proposal for multi-DUT and multi-ASIC testing support](https://github.com/Azure/sonic-mgmt/pull/2347)
- [Implementation of multi-DUT and multi-ASIC as per PR 2347](https://github.com/Azure/sonic-mgmt/pull/2417)

In this approach, we have introduced 
- 'MultiAsicSonicHost' class to represent a 'SonicHost' that can have one or more ASICs. Each linecard of the SONiC chassis is an instance of 'MultiAsicSonicHost'. 
- 'DutHosts' class that is a collection of 'MultiAsicSonicHost'. It has 3 important attributes:
 - nodes: list of all the 'MultiAsicSonicHost' DUT's in the testbed.
 - frontend_nodes: subset of nodes that have frontpanel ports.
 - supervisor_nodes: subset of nodes that are supervisor cards.
Other node types can be added as needed.

A SONiC chassis is an instance of 'DutHosts', with its 'nodes' having an instance of 'MultiAsicSonicHost' representing each linecards and supervisor card; 'frontend-nodes' being list of linecards, and 'supervisor_nodes' having the supervisor card(s). You can call ansible modules on the duthosts. The result would be a dictionary keyed by each nodes hostname, and value being the list of results for each asic. For example,

```
{ 'node1' : [ asic0_result_node1, asic1_result_node1 .... ], 'node2': [ asic0_result_node1, asic1_result_node2, ....] }
```

The format of the return value is the same for all the following scenarios:
- single asic pizza box
- multi-asic pizza box
- single-asic multi-duts - For example, a SONiC chassis with single-asic linecards
- multi-asic multi-duts - For example, a SONiC chassis with multi-asic linecards

'duthosts' fixture returns an instance of 'DutHosts'.

The test case can take 'duthosts' as an arguement
```
def test_bgp_facts(duthosts):
  bgp_facts = duthosts.frontend_nodes.bgp_facts(asic_index='all')
```

# 3 Testbed

The testbed consists of SONiC chassis, where each linecard with frontpanel ports is connected to 'leaf' fanout switch.

We use the **same testbed server** for all the linecards. So, all the VMs that are connecting to a SONiC chassis are running on the same testbed server.

We use a **single PTF container** for all the linecards in the SONiC chassis.

# 4 Orchestration

Lets consider a chassis with 2 linecards (node1, node2) and a single supervisor card (supervisor1).

# 4.1 Ansible inventory

We define each linecard of a SONiC chassis in the inventory file as a single AnsibleHost. The only change required is that for the linecards, you would add 'num_asics' field, and for supervisor card you would specify the 'type' field as 'supervisor'

```
sonic:
  hosts:
    node1:
      ansible_host: 10.10.10.1
      num_asics: 1
    node2:
      ansible_host: 10.10.10.2
      num_asics: 1
    supervisor1:
      ansible_host: 10.10.10.3
      type: supervisor
      num_asics: 1
```

# 4.2 connection graph

In the connection graph, you would define each linecard (including supervisor card) and all the links between the linecards of the SONiC chassis and the fanout switch(es).

```
node1,Ethernet0,fanout1,Ethernet0,100000,100,Access
node1,Ethernet1,fanout1,Ethernet4,100000,101,Access
.
.
node2,Ethernet0,fanout2,Ethernet0,100000,100,Access
.
.
```

# 4.3 testbed.csv

In testbed.csv, you define the SONiC chassis as a list of duts

<pre>
# conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,comment
chassis1-t1,vms_5,t1-chassis,docker-ptf,ptf_vms_6,10.250.5.188/24,,server_5,VM0500,<b>[node1;node2;supervisor1]</b>, OC tests for chassis1

</pre>

# 4.4 topology file

We use the multi-dut approach in defining the topology file, where the VM offsets have the format '<dut_index>.<dut_port>@<ptf_index>'. This format was introduced to support [Dual Tor](https://github.com/Azure/sonic-mgmt/pull/2333).  

```
topology:
  VMs:
    VM0100:
      vlans:
        - "0.0@0"
      vm_offset: 0
    VM0101:
      vlans:
        - "0.1@1"
      vm_offset: 1
    .
    .
    VM0132:
      vlans:
        - "1.0@32"
      vm_offset: 32
    VM0133:
      vlans:
        - "1.1@33"
      vm_offset: 33
    .
    .
```

# 5 Test case changes

We have outline two approaches above of how to adapt existing tests to be able to run on SONiC chassis 
- parameterizing the test case
- duthosts

Whether you we use the parameterizing approach, or duthosts approach depends upon the test case, where one approach might be easier to adapt the test case for a SONiC chassis. For example, 
- platform tests might be easier to modify using the parameterizing approach,
- tests like test_dip_sip if extended to test traffic across multiple asics (same or different linecards) and using ptf's would make sense to run with 'duthosts' approach.

Below, we take the example test_bgp_facts modified with both approaches as an example.

## 5.1 parameterizing the test case

- Modify definition to replace 'duthost' with 'duthosts', and include the dut parameter fixtures like 'enum_dut_hostname' and 'enum_asic_index'.
- Get duthost based on enum_dut_hostname from duthosts
- Call ansible modules 'bgp_facts' and config_facts' using the namespace arguements. 

<pre>
def test_bgp_facts(<b>duthosts, enum_dut_hostname, enum_asic_index</b>):
    """compare the bgp facts between observed states and target state"""
    <b>
    duthost = duthosts[enum_dut_hostname]
    # Check if the duthost is a supervisor card, and if so, skip it.
    if duthost.is_supervisor_node():
        pytest.skip("bgp_facts not valid on supervisor card '%s'" % enum_dut_hostname)
    </b>
    bgp_facts = duthost.bgp_facts(<b>instance_id=enum_asic_index</b>)['ansible_facts']
    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    config_facts = duthost.config_facts(host=duthost.hostname, source="running", <b>namespace=namespace</b>)['ansible_facts']
    
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        # Verify locat ASNs in bgp sessions
        assert v['local AS'] == int(config_facts['DEVICE_METADATA']['localhost']['bgp_asn'].decode("utf-8"))

    for k, v in config_facts['BGP_NEIGHBOR'].items():
        # Compare the bgp neighbors name with config db bgp neigbhors name
        assert v['name'] == bgp_facts['bgp_neighbors'][k]['description']
        # Compare the bgp neighbors ASN with config db
        assert int(v['asn'].decode("utf-8")) == bgp_facts['bgp_neighbors'][k]['remote AS']
</pre>


## 5.2 duthosts

- Modify definition to replace 'duthost' with 'duthosts'
- call 'bgp_facts' and 'config_facts' on duthosts.frontend_nodes.
- iterate through the returned dictionary for each frontend node in duthosts.

<pre>
def test_bgp_facts(<b>duthosts</b>):
    """compare the bgp facts between observed states and target state"""
    <b>bgp_facts = duthosts.frontend_nodes.bgp_facts(asic_index='all')
    config_facts = duthosts.frontend_nodes.config_facts(asic_index='all', source="persistent")
    
    for a_node, node_bgp_facts in bgp_facts.items():
        for asic_index in range(len(node_bgp_facts)):</b>
            asic_bgp_facts = node_bgp_facts[asic_index]['ansible_facts']
            for k, v in asic_bgp_facts['bgp_neighbors'].items():
                # Verify bgp sessions are established
                assert v['state'] == 'established'
                # Verify locat ASNs in bgp sessions
                assert v['local AS'] == int(config_facts[a_node][asic_index]['ansible_facts']['DEVICE_METADATA']['localhost']['bgp_asn'].decode("utf-8"))
                #assert v['local AS'] == mg_facts['minigraph_bgp_asn']
            for k, v in config_facts[a_node][asic_index]['ansible_facts']['BGP_NEIGHBOR'].items():
                # Compare the bgp neighbors name with config db bgp neigbhors name
                assert v['name'] == asic_bgp_facts['bgp_neighbors'][k]['description']
                # Compare the bgp neighbors ASN with config db
                assert int(v['asn'].decode("utf-8")) == asic_bgp_facts['bgp_neighbors'][k]['remote AS']

</pre>

A few PR's have already been pushed to change test cases/fixtures to be multi-dut aware.  Some examples:
- [[multi-dut] Make test_posttest and test_pretest multi-dut ready](https://github.com/Azure/sonic-mgmt/pull/2475)
- [[multi-DUT] making test_interfaces multi-DUT ready](https://github.com/Azure/sonic-mgmt/pull/2471)
- [[multi-dut] making test_show_features multi-dut ready](https://github.com/Azure/sonic-mgmt/pull/2470)
- [[multi-dut] - sanity checks for multi-duts](https://github.com/Azure/sonic-mgmt/pull/2478)

If you search 'multi-dut' in the PR's on sonic-mgmt github, you will be able to see more examples of tests already modified.

# 6 Acknowlegement

This is a work based on inputs from multiple discussions with many people. Special thanks to [Arvindsrinivasan Lakshminarasimhan](https://github.com/arlakshm) and [Xin Wang](https://github.com/wangxin). The parameterizing of dut_index and asic_index idea was from Arvindsrinivasan. Xin provided valueable input to the multi-DUT and multi-ASIC support. Nokia prototyped and refined the solutions as a proof of concept for chassis.
