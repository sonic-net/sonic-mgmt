# Improve the test infrastructure to support multi-DUT and multi-ASIC systems

## Background

PR https://github.com/Azure/SONiC/pull/644 introduced the HLD to support multi ASIC. In the future, multi DUT or Chassis will be supported by SONiC as well. The test infrastructure and some of the customized ansible modules need to be updated to support testing of the upcoming new architectures. This document tries to propose how to improve the current test infrastructure to support multi-DUT and multi-ASIC systems. The target is to ensure that the existing test scripts are not broken and we can update the tests in incremental way.

## Current Status

In current infrastructure, we use class `SonicHost` to represent a single SONiC system.

Fixture `duthost` is an instance of `SonicHost`. Fixture `duthosts` is a list of `SonicHost` instances initialized according to the list of DUT host names defined in `testbed.csv` for current testbed.

This `SonicHost` class provides interface for calling any ansible module on the SONiC device under test using format like `duthost.<module_name>(*args, **kwargs)`. Please refer to the implementation of methods [`__getattr__` in `AnsibleHostBase`](https://github.com/Azure/sonic-mgmt/blob/857cfb2bbed741057e830a1a20b48d2364f65cc3/tests/common/devices.py#L58) for more details. `AnsibleHostBase` is the base class of `SonicHost`.

## Requirements

To support multi-DUT and multi-ASIC testing, the `duthosts` and `duthost` fixture need to be updated. The target is that in test scripts we can use these fixtures to perform operations for
* all DUTs
* specific type of DUTs
* specific DUT
* all ASICs
* specific ASIC
* combinations of the above scenarios

Meanwhile, we need to ensure backward compatibility for scenarios including:
* single DUT, single ASIC
* Multiple single-ASIC DUTs

The test scripts should be able to use interfaces like below to perform operations on DUTs and ASICs
```python
duthost.foo()
duthost.foo(asic_index=1)
duthost.asics[1].foo()      # Equivalent to the line above
duthost.foo(asic_inex="all")

[asic.foo() for asic in duthost.asics]

duthosts.foo()
duthosts.foo(asic_index=1)
duthosts.foo(asic_index="all")

[node.foo() for node in duthosts]

duthosts.nodes.foo()                 # Equivalent to: duthosts.foo()
duthosts.nodes.foo(asic_index=1)     # Equivalent to: duthosts.foo(asic_index=1)
duthosts.nodes.foo(asic_index="all") # Equivalent to: duthosts.foo(asic_index="all")

[node.foo() for node in duthosts.nodes]

duthosts[1].foo()
duthosts[1].foo(asic_index=1)
duthosts[1].asics[1].foo()        # Equivalent to the line above
duthosts[1].foo(asic_index="all")

duthosts["node1"].foo()
duthosts["node1"].foo(asic_index=1)
duthosts["node1"].asics[1].foo()        # Equivalent to the line above
duthosts["node1"].foo(asic_index="all")

duthosts.nodes[1].foo()                 # Equivalent to: duthosts[1].foo()
duthosts.nodes[1].foo(asic_index=1)     # Equivalent to: duthosts[1].foo(asic_index=1)
duthosts.nodes[1].asics[1].foo()        # Equivalent to: duthosts[1].asics[1].foo()
duthosts.nodes[1].foo(asic_index="all") # Equivalent to: duthosts[1].foo(asic_index="all")

duthosts.nodes["node1"].foo()                 # Equivalent to: duthosts["node1"].foo()
duthosts.nodes["node1"].foo(asic_index=1)     # Equivalent to: duthosts["node1"].foo(asic_index=1)
duthosts.nodes["node1"].asics[1].foo()        # Equivalent to: duthosts["node1"].asics[1].foo()
duthosts.nodes["node1"].foo(asic_index="all") # Equivalent to: duthosts["node1"].foo(asic_index="all")

duthosts.frontend_nodes.foo()
duthosts.frontend_nodes.foo(asic_index=1)
duthosts.frontend_nodes.foo(asic_index="all")

[node.foo() for node in duthosts.frontend_nodes]

duthosts.frontend_nodes[1].foo()
duthosts.frontend_nodes[1].foo(asic_index=1)
duthosts.frontend_nodes[1].asics[1].foo()  # Equivalent to the line above
duthosts.frontend_nodes[1].foo(asic_index="all")

duthosts.frontend_nodes["node1"].foo()
duthosts.frontend_nodes["node1"].foo(asic_index=1)
duthosts.frontend_nodes["node1"].asics[1].foo()  # Equivalent to the line above
duthosts.frontend_nodes["node1"].foo(asic_index="all")

duthosts.supervisor_nodes.bar()
duthosts.supervisor_nodes[0].bar()
duthosts.supervisor_nodes["supervisor0"].bar()
```

In the above examples:
* `duthost.asics` should be a list of objects. Each object represents an ASIC in the DUT. `duthost.asics` represents all the ASIC instances in the DUT.
* `duthosts.nodes` should be a list of objects. Each object represents a DUT host in the multi-DUT system.
* `duthosts.frontend_nodes` should be a subset of `duthosts.nodes`. Each object represent a frontend DUT host in multi-DUT system.
* `duthosts.supervisor_nodes` should be a subset of `duthosts.nodes`. Each node represents a supervisor DUT host in multi-DUT system.
* The `duthosts` should can be extended with other attributes to represent other specific type of nodes. For example `duthosts.supervisor_nodes`.


### Backward compatibility
```python
duthost.foo()
```
The `duthost` fixture should support running operations on single DUT just like before. Call like `duthost.foo()` should be applicable for both single-ASIC and multi-ASIC DUT. For single-ASIC DUT, everything should be the same as before.

### Multi-ASIC related operations
```python
duthost.foo(asic_index=1)
duthost.asics[1].foo()      # Equivalent to the line above
duthost.foo(asic_inex="all")
[node.foo() for node in duthosts.nodes]
```
For multi-ASIC related operations on DUT host, the function or ansible module call should accept optional `asic_index` argument.
* No `asic_index`, perform operation just on the host (or default namespace). For example, just run command `"show ip bgp summary"`.
* `asic_index` is a number, perform operation for the specific ASIC. For example, run command `"show ip bgp summary -n asic1"`.
* `asic_index` is `"all"`, perform operation for each of the ASIC. For example, run commands: `"show ip bgp summary -n asic0"`, `"show ip bgp summary -n asic1"`, ...
  * In case the DUT is a single ASIC pizza box, just perform the operation for on the host (or default namespace) and return the single result in a list.
* Alternatively, code like `duthost.asics[1].foo()` should be equivalent to `duthost.foo(asic_index=1)`. In this case, argument `asic_index` is not required.

The enhancement should support iterating through the `duthost.asics` list to perform operations on each ASIC instance.
```python
[node.foo() for node in duthosts.nodes]
```

### Multi-DUT related operations
```python
duthosts.foo()
duthosts.nodes.foo()           # Equivalent to: duthosts.foo()
duthosts.frontend_nodes.foo()
```
The `duthosts` fixture should support operations on all nodes or specific type of nodes in multi-DUT system.

### Combine Multi-DUT and Multi-ASIC related operations
```python
duthosts.foo(asic_index=1)
duthosts.foo(asic_index="all")

duthosts.nodes.foo(asic_index=1)     # Equivalent to: duthosts.foo(asic_index=1)
duthosts.nodes.foo(asic_index="all") # Equivalent to: duthosts.foo(asic_index="all")

duthosts.frontend_nodes.foo(asic_index=1)
duthosts.frontend_nodes.foo(asic_index="all")
```
If argument `asic_index` is specified, the operation should be performed for specific ASIC instance on all nodes or some type of nodes.
If `asic_index="all"`, then the operation should be performed for each ASIC instance on all nodes or some type of nodes.

### Iteration support
```python
[node.foo() for node in duthosts]
[node.foo() for node in duthosts.nodes]
[node.foo() for node in duthosts.frontend_nodes]
```
The `duthosts` fixture itself should supports iteration. Of course iterating through `duthosts.nodes` or `duthosts.frontend_nodes` should be supported as well.

### Indexing support
```python
duthosts[1]
duthosts["node1"]
duthosts.nodes[1]
duthosts.nodes["node1"]
duthosts.frontend_nodes[1]
duthosts.frontend_nodes["node1"]
```
The `duthosts` should support indexing operations like returning specific duthost by index number or node's hostname.

### Flexible combinations
With support of all the capabilities, it would be very flexible for the test scripts to run operations on any DUT or ASIC.
```python
duthosts.frontend_nodes["node1"].foo(asic_index=1)
```

## Proposed changes

To support all of the above requirements, we need to:
* add some new classes
* update the fixtures `duthosts` and `duthost`
* update some customized ansible modules that need to deal with ASIC/namespace

### Add new `MultiDutSonicHost` and `SonicAsic` classes to support multi-ASIC

Prototype of the new classes:
```python
class SonicAsic(object):

    def __init__(self, sonichost, asic_index):
        self.sonichost = sonichost
        self.asic_index = asic_index

    # Wrapper for ASIC/namespace aware modules
    def foo(self, arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value2"):
        # Delegate the actual ansible module call to sonichost
        return self.sonichost.foo(arg1, arg2, kwarg1=kwarg1, kwarg2=kwarg2, asic_index=self.asic_index)

    def bar(self, arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value2"):
        # The ASIC/namespace aware modules may have special requirement of specifying ASIC/namespace.
        # The method may need to call other modules or methods to do the job.
        return self.sonichost.bar1(arg1, arg2, kwarg1=kwarg1, kwarg2=kwarg2, namespace="asic{}".format(self.asic_index))


class MultiAsicSonicHost(object):

    def __init__(self, ansible_adhoc, hostname):
        self.sonichost = SonicHost(ansible_adhoc, hostname)
        self.asics = [SonicAsic(self.sonichost, asic_index) for asic_index in range(self.sonichost.facts["num_asic"])]

    def _run_on_asics(self, *module_args, **complex_args):
        if "asic_index" not in complex_args:
            # Default ASIC/namespace
            return getattr(self.sonichost, self.attr)(*module_args, **complex_args)
        else:
            asic_index = complex_args.pop("asic_index")
            if type(asic_index) == int:
                # Specific ASIC/namespace
                return getattr(self.asics[asic_index], self.attr)(*module_args, **complex_args)
            elif type(asic_index) == str and asic_index.lower() == "all":
                # All ASICs/namespaces
                if self.sonichost.facts["num_asic"] == 1:
                    return [getattr(self.sonichost, self.attr)(*module_args, **complex_args)]
                return [getattr(asic, self.attr)(*module_args, **complex_args) for asic in self.asics]
            else:
                raise ValueError("Argument 'asic_index' must be an int or string 'all'.")

    def __getattr__(self, attr):
        self.attr = attr
        sonic_asic_attr = getattr(SonicAsic, attr, None)
        if not attr.startswith("_") and sonic_asic_attr and callable(sonic_asic_attr):
            return self._run_on_asics
        else:
            return getattr(self.sonichost, attr)  # For backward compatibility
```

The `MultiAsicSonicHost` class needs to have two attributes:
* `sonichost`: a `SonicHost` instance. This object is for interacting with the SONiC host through pytest_ansible.
* `asics`: a list of `SonicAsic` instances.

The `SonicAsic` class needs to implement methods for ASIC/namespace related operations. The purpose is to hide the complexity of handling ASIC/namespace specific details. Then the test scripts do not have to worry about which argument to be passed to the ASIC/namespace aware modules. For example, the argument name required by different ansible modules may be like `instance_id`, `asic_id`, `asic_index`, `namespace`, etc. Some operations may need to run commands with special syntax on SONiC host. These kinds of complexity should be handled by the methods of the `SonicAsic` class.

The `SonicAsic` class needs to have a reference to the SonicHost instance. Then in its methods, it can use this instance to interact with the SonicHost.

In python, the special `__getattr__` method is called when getting an attribute that the object does not have. When we try to get an undefined attribute from the `MultiAsicSonicHost` instance, method `MultiAsicSonicHost.__getattr__` will be called. In `MultiAsicSonicHost.__getattr__`, the code firstly check if the attribute is a method of the `SonicAsic` class:
* If not, just get the attribute from `self.sonichost` and return it. The returned attribute of `self.sonichost` may be an ordinary attribute, a method or the callable function for running ansible module. No matter what it is, the operation is delegated to `SonicHost`. If the returned attribute is a function for running ansible module, this will eventually run an ordinary ansible module on the SONiC host. This is for backward compatibility. Consequently after the `duthost` fixture is replaced with an instance of `MultiAsicSonicHost`, the existing test scripts do not need to be updated for calling ASIC/namespace unaware ansible modules.
* If the attribute is a method of `SonicAsic`, then the code will return callable `MultiAsicSonicHost._run_on_acis`. The callable will be called with positional and keyword arguments. Method `_run_on_asics` firstly check if argument `asic_index` is in the keyword arguments.
  * If not, the code will just try to get the attribute from sonichost, run it with the arguments and return the result: `return getattr(self.sonichost, self.attr)(*module_args, **complex_args)`. The ansible module is executed for default ASIC/namespace in this case.
  * If `asic_index` is in the keyword arguments and is an integer, the code will try to call the method of `SonicAsic` on the ASIC instance specified by `asic_index` and return the result: `return getattr(self.asics[asic_index], self.attr)(*module_args, **complex_args)`.
  * If `asic_index` is string and equals to `"all"`, then check if the DUT is a single ASIC pizza box:
    * In case the DUT is a single ASIC pizza box (self.sonichost.facts["num_asic"]==1), just get the attribute from sonichost, run it with the arguments and return the result in a list: `return [getattr(self.sonichost, self.attr)(*module_args, **complex_args)]`
    * Otherwise the DUT is a multi-ASIC system, run the method of `SonicAsic` on each of the ASICs and return the results in a list: `return [getattr(asic, self.attr)(*module_args, **complex_args) for asic in self.asics]`.

When run a method of `SonicAsic`, eventually `SonicAsic` needs to run some ansible modules on the SONiC host to perform ASIC/namespace related operations.

### Add new `DutHosts` class to support multi-DUT

To support multi-DUT, we need to add a new class `DutHosts` to represent all the DUTs in a testbed.
```python
class DutHosts(object):

    class _Nodes(list):

        # Delegate the call to each of the nodes, return the results in a dict.
        def _run_on_nodes(self, *module_args, **complex_args):
            return {node.hostname: getattr(node, self.attr)(*module_args, **complex_args) for node in self}

        # To support calling ansible modules on list of nodes.
        def __getattr__(self, attr):
            self.attr = attr
            return self._run_on_nodes

    def __init__(self, ansible_adhoc, tbinfo):
        self.nodes = self._Nodes([MultiAsicSonicHost(ansible_adhoc, hostname) for hostname in tbinfo["duts"]])
        self.frontend_nodes = self._Nodes([node for node in self.nodes if self._is_frontend_node(node)])
        self.supervisor_nodes = self._Nodes([node for node in self.nodes if self._is_supervisor_node(node)])

    # To support operations like duthosts[0] and duthost['sonic1_hostname']
    def __getitem__(self, index):
        if type(index) == int:
            return self.nodes[index]
        elif type(index) == str:
            for node in self.nodes:
                if node.hostname == index:
                    return node
            else:
                raise KeyError("No node has hostname '{}'".format(index))
        else:
            raise IndexError("Bad index '{}'".format(index))

    # To support iteration
    def __iter__(self):
        self._node_index = 0
        return self

    # To support iteration
    def __next__(self):
        if self._node_index < len(self.nodes):
            node = self.nodes[self._node_index]
            self._node_index += 1
            return node
        else:
            raise StopIteration

    def _is_frontend_node(self, node):
        # Return True if `node` is a frontend node, otherwise return False
        pass

    def _is_supervisor_node(self, node):
        # Return True if `node` is a supervisor node, otherwise return False
        pass

    # To support calling ansible modules directly on instance of DutHosts
    def __getattr__(self, attr):
        return getattr(self.nodes, attr)
```

The `DutHosts` class has 3 important attributes:
* `nodes`: `self.nodes = self._Nodes([MultiAsicSonicHost(ansible_adhoc, hostname) for hostname in tbinfo["duts"]])`
* `frontend_nodes`: `self.frontend_nodes = self._Nodes([node for node in self.nodes if self._is_frontend_node(node)])`
* `supervisor_nodes`: `self.frontend_nodes = self._Nodes([node for node in self.nodes if self._is_frontend_node(node)])`

The `nodes` attribute is a list of `MultiAsicSonicHost` instances for all the SONiC nodes (or cards for chassis) in the multi-DUT testbed. The `frontend_nodes` is a subset of `nodes`. It holds list of `MultiAsicSonicHost` instances for frontend nodes (or line cards for chassis). The `supervisor_nodes` is another subset of `nodes`. It holds list of `MultiAsicSonicHost` instances for supervisor nodes (or supervisor card for chassis). The class can be enhanced in the future to have list for other type of nodes.

The various nodes lists are instance of embedded class `_Nodes` which is a subclass of python `list`. The `_Nodes` class is extended with capability to run ansible module on each of the nodes in the list and return the results in a node hostname keyed dictionary.

The `DutHosts` class also need to implement below methods to support iteration and get one of the node by index or hostname:
* `__iter__`
* `__next__`
* `__getitem__`

The idea is to ensure that scripts using the existing `duthosts` fixture will not be affected. Please refer to the next section for more details of fixtures `duthosts` and `duthost`.

### Update the `duthosts` fixture

Most existing test scripts depend on the `duthost` or `duthosts` fixture. The current `duthost` fixture is an instance of `SonicHost`. The `duthosts` fixture is simply a list of `SonicHost` instances.

The current `duthosts` fixture:
```python
@pytest.fixture(name="duthosts", scope="session")
def fixture_duthosts(ansible_adhoc, tbinfo):
    return [SonicHost(ansible_adhoc, dut) for dut in tbinfo["duts"]]
```

To support multi-DUT better, the `duthosts` fixture need to be updated to hold a `DutHosts` instance
```python
@pytest.fixture(scope="session")
def duthosts(ansible_adhoc, tbinfo):
    return DutHosts(ansible_adhoc, tbinfo)
```

Because the `DutHosts` class has `__getitem__`, `__iter__` and `__next__` implemented, the existing scripts using fixture `duthosts` will not be affected. The scripts still can iterate through `duthosts` to operate on each DUT host.

Another thing is that the new `duthosts` fixture is a list (kind of) of `MultiAsicSonicHost` instances, not `SonicHost` instances. The new `MultiAsicSonicHost` will just delegate all non-ASIC/namespace related calls to `SonicHost`. The calls include:
* ordinary ansible modules
* methods of `SonicHost`
Because of the backward compatibility design of `MultiAsicSonicHost` class, scripts using `duthosts` fixture do not need update.

The `duthost` fixture is just to return one item from the `duthosts` list according to `dut_index` found in pytest `session` object. If `dut_index` is not found, return the first item from the `duthosts` list. After the `duthosts` fixture is updated, the `duthost` fixture will get an item from the new `duthosts` list. Implementation of the `duthost` fixture do not need update. Scripts using `duthost` fixture will have access to a `MultiAsicSonicHost` instance. Again, because `MultiAsicSonicHost` is backward compatible, the existing test scripts won't be affected.

## Requirements for the ASIC/namespace aware ansible modules

To support multi-ASIC SONiC testing, some of the customized ansible modules need to be updated to support ASIC/namespace. Based on the design of `MultiAsicSonicHost` and `SonicAsic`, the ASIC/namespace aware modules must follow below requirements:
* The module must take optional argument for specifying ASIC index or namespace.
* When ASIC index or namespace is specified, return the the `ansible_facts` of the specified ASIC/namespace.
* When ASIC index is not specified, return the `ansible_facts` for the default ASIC/namespace, do not return `ansible_facts` for ASIC 0.

Why not return a list of results for all ASICs when ASIC index or namespace is not specified? There are two reasons:
* Ansible requires that the returned `ansible_facts` must be a dictionary. It cannot be a list.
* For multi-ASIC SONiC, there is default namespace. It makes more sense to return result of the default namespace. The object holding the list of ASICs can take care of getting results for all ASICs.
* Just return result of the default ASIC/namespace can maintain backward compatibility for single ASIC SONiC device.

Why not return result for ASIC0 when ASIC/namespace is not specified?
* For multi-ASIC SONiC, the default namespace is not equivalent to namespace of ASIC 0.

There is no strict require of argument name for specifying ASIC index or namespace. The argument name can be like: `instance_id`, `asic_index`, `namespace_id`,etc. Which argument to be use should be taken care of by methods in `SonicAsic` class.

## Using the new infrastructure supporting multi-DUT and multi-ASIC in test scripts

With the new infrastructure changes, it would be flexible and straight forward to call ansible modules or methods of the classes on DUT nodes or ASICs. Because calling methods of classes is straight forward, we will explain more about calling ansible modules.

### Run ordinary ansible module on single DUT
```python
duthost.xyz(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2')   # => ordinary_result
```
Run `xyz` on duthost. Same as before.

### Run ASIC/namespace aware ansible module on single DUT for default ASIC/namespace
```python
duthost.foo(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2')   # => default_namespace_result
```
Run `foo` on duthost. Same as before. Because argument `asic_index` is not specified, the module will be executed for the default ASIC/namespace.

### Run ASIC/namespace aware ansible module on single DUT for specific ASIC/namespace
```python
duthost.foo(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2', asic_index=1)  # => asic1_result
```
Run `foo` on duthost for ASIC 1.

### Run ASIC/namespace aware ansible module on single DUT for all ASIC/namespace
```python
duthost.foo(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2', asic_index="all")  # => [asic0_result, asic1_result, ...]
```
Run `foo` on duthost for all ASICs/namespaces.

Returned result is like: [asic0_result, asic1_result, ...]

### Run ordinary ansible module on all nodes

```python
duthosts.xyz(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2')        # => {node1: ordinary_result, node2: ordinary_result , ...}
duthosts.nodes.xyz(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2')  # => {node1: ordinary_result, node2: ordinary_result , ...}
```
The sample code will run module `xyz` on all nodes.

Returned result is like: {node1: ordinary_result, node2: ordinary_result , ...}

### Run ordinary ansible module on specific type of nodes
```python
duthosts.frontend_nodes.xyz(arg1, arg2, kwarg1='sample_value1', kwarg2='sample_value2')  # => {node1: ordinary_result, node2: ordinary_result , ...}
```
Similar as above, the difference that `xyz` is executed on just the frontend_nodes.

Returned result is like: {node1: ordinary_result, node2: ordinary_result , ...}

### Run ASIC/namespace aware ansible module on nodes for default ASIC/namespace
```python
duthosts.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1")  # => {node1: default_namespace_result, node2: default_namespace_result, ...}
duthosts.frontend_nodes.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1")  # => {node1: default_namespace_result, node2: default_namespace_result, ...}
```
The sample code is to run ansible module `foo` on all nodes or specific type of nodes. Because argument `asic_index` is not specified, the module will be executed for the default ASIC/namespace.

Note: Generally, ASIC/namespace aware ansible modules should not be applicable for supervisor node. Here the sample is just to demonstrate capability of the new test infrastructure.

Returned result is like: {node1: default_namespace_result, node2: default_namespace_result, ...}

### Run ASIC/namespace aware ansible module on nodes for specific ASIC/namespace
```python
duthosts.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index=1)  # => {node1: asic1_result, node2: asic1_result, ...}
duthosts.frontend_nodes.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index=1)  # => {node1: asic1_result, node2: asic1_result, ...}
```
The sample code is to run ansible module `foo` on all nodes or specific type of nodes. Because `asic_index` is specified, the module will be executed for specific ASIC/namespace.

Returned result is like: {node1: asic1_result, node2: asic1_result, ...}

### Run ASIC/namespace aware ansible module on nodes for all ASIC/namespaces
```python
duthosts.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index="all") # => {node1: [asic0_result, asic1_result, ...], node2: [asic0_result, asic1_result, ...], ...}
duthosts.frontend_nodes.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index="all")  # => {node1: [asic0_result, asic1_result, ...], node2: [asic0_result, asic1_result, ...], ...}
```
The sample code is to run ansible module `foo` for all ASICs/namespaces on all nodes or specific type of nodes. Because `asic_index` is `"all"`, the module will be executed for all ASICs/namespaces.

Returned result is like: {node1: [asic0_result, asic1_result, ...], node2: [asic0_result, asic1_result, ...], ...}

### Run ASIC/namespace aware ansible module on specific node for specific ASIC/namespace
```python
duthosts.nodes['node1'].foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index=1)  # => asic1_result
duthosts.frontend_nodes[2].foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index=1)  # => asic1_result
```
The sample code is to run ansible module `foo` on specific node. Because `asic_index` is specified, the module will be executed for specific ASIC/namespace.

Returned result of both lines are just single result.

Under the hood, the call is equivalent to run:
```python
duthosts.nodes['node1'].asics[1].foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1")  # => asic1_result
duthosts.frontend_nodes[2].asics[1].foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1")  # => asic1_result
```

### Run ASIC/namespace aware ansible module on specific node for all ASICs/namespaces
```python
duthosts.nodes['node1'].foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index="all")  # => [asic0_result, asic1_result, ...]
duthosts.frontend_nodes[2].foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1", asic_index="all")  # => [asic0_result, asic1_result, ...]
```
The sample code is to run ansible module `foo` on specific node. Because `asic_index` is specified, the module will be executed for specific ASIC/namespace.

Returned result of both lines are list of results for all the ASICs/namespaces

Under the hood, the call is equivalent to run:
```python
[asic.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1") for asic in duthosts.nodes['node1'].asics]  # => [asic0_result, asic1_result, ...]
[asic.foo(arg1, arg2, kwarg1="sample_value1", kwarg2="sample_value1") for asic in duthosts.frontend_nodes[2].asics]  # => [asic0_result, asic1_result, ...]
```


## More concerns

### Methods in `SonicHost` class

The `SonicHost` class has many methods for frequently used tasks like getting information or perform operations. If any of the method need to be updated to support multi ASIC, the updated method must be moved to the `MultiAsicSonicHost` class. The general rule is that `SonicHost` does not need to care about multi-ASIC. All multi-ASIC related methods should be implemented in `MultiAsicSonicHost` class.

### Wrapper for ASIC/namespace aware ansible modules in `SonicAsic` class
For each ASIC/namespace aware ansible module, a wrapper should be implemented in `SonicAsic` class as a method.

The `SonicAsic` class can have more methods for operations related with specific ASIC/namespace. Operations that are not related with specific ASIC/namespace should not be implemented in `SonicAsic`.

### Methods specific to multi DUT in `DutHosts` class

Some operations may be applicable to multi DUT only. These operations can be implemented as methods of `DutHosts` class.

For example, to power cycle a line card, we may need to run commands on the supervisor node. This kind of operation can be implemented as a method of `DutHosts` class.

## Acknowledgement

This is a work based on inputs from multiple discussions with many people. Special thanks to [Arvindsrinivasan Lakshminarasimhan](https://github.com/arlakshm) and [Sandeep Malhotra](https://github.com/sanmalho-git). The multi-ASIC ideas were mainly from Arvindsrinivasan. He also pioneered some multi-ASIC and multi-DUT work in PR https://github.com/Azure/sonic-mgmt/pull/2245. Sandeep also did a lot of prototyping for multi-DUT and multi-ASIC support and provided very valuable ideas in discussion of PR https://github.com/Azure/sonic-mgmt/pull/2282.
