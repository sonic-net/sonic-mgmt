# Guidelines for designing a customized ansible module to support multi-ASIC

PR https://github.com/Azure/SONiC/pull/644 introduced the HLD to support multi ASIC. In the future, multi DUT or Chassis will be supported by SONiC as well. Some of the customized ansible modules need to be updated to support testing of the upcoming new architectures. This document tries to propose some guidelines for designing customized ansible modules that need to deal with multi-ASIC. The idea is to have a clean and easy to use interface for calling these ansible modules in scripts testing multi DUT and multi ASIC system. Meanwhile, the ansible modules need to maintain backward compatibility for single DUT and single ASIC testing.

## Guidelines

* The module must take optional argument for specifying ASIC index.
* The module must not take argument for specifying the number of ASICs the host has. Instead the module must figure out by itself whether the current host supports multi ASIC and how many ASICs it has.
* When ASIC index is supplied, return a single result. Do not return a list of results.
* When ASIC index is not supplied, the module should find out whether multiple ASICs is supported by the current host.
  * If the host supports multiple ASICs, then the module should find out the number of ASICs, do its job for each of the ASICs and return the results in a list. Each item in the list is the result of one ASIC.
  * If the host does not support multiple ASICs, return a single result. Do not return a list of results. This is for backward compatibility.

## Possible interfaces for calling the modules

This section tries to add some dummy examples for how to call the multi ASCI aware ansible modules in test scripts. Assume:
* module `foo` is a multi ASIC aware customized ansible module
* fixture `duthost` is an instance representing single host with single ASIC
* fixture `duthost_multi_asic` is an instance representing single host with multi ASIC
* fixture `duthosts` is an instance representing a testbed with multi DUTs or a Chassis. The `duthosts` have attributes like:
  * `duthosts.nodes`: A list of all the hosts in the testbed.
  * `duthosts.frontend_nodes`: A list of all the frontend hosts in the testbed.

### Call the module for single host supports single ASIC

```
duthost.foo()  # No behavior change, for backward compatibility
```

### Call the module for single host supports multi ASICs

```
duthost_multi_asic.foo()  # Run `foo` for each of the asic. return results in a list

duthost_multi_asic.foo(asic_index=0)  # Run `foo` for asic_index=0

duthost_multi_asic.foo(asic_index=1)  # Run `foo` for asic_index=0
```

### Call the module for multiple hosts support single ASIC

```
# Run `foo` for each of the frontend node. Return results in a dict: {'node1': foo_result, 'node2': foo_result}
duthosts.frontend_nodes.foo()
```

### Call the module for multiple hosts support multiple ASICs

```
# Run `foo` for each of the frontend node and each of the ASIC. Return results in a dict like:
#     {'node1': [asic0_foo_result, asic1_foo_result], 'node2': [asic0_foo_result, asic1_foo_result]}
duthosts.frontend_nodes.foo()

# Run `foo` for asic_index=0 for each of the frontend node. Return results in a dict like:
#     {'node1': asic0_foo_result, 'node2': asic0_foo_result}
duthosts.frontend_nodes.foo(asic_index=0)

```

## How to detect a multi ASIC system

According to https://github.com/Azure/SONiC/pull/644, multi ASIC system should have file `/usr/share/sonic/device/<platform>/asic.conf`:

Sample asic.conf:
```
NUM_ASIC=3
DEV_ID_ASIC_0=03:00.0
DEV_ID_ASIC_1=06:00.0
DEV_ID_ASIC_2=11:00.0
```
Ansible module can check existence of this file to tell the current host is a multi ASIC system or single ASIC system.
