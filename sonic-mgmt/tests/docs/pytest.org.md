# Pytest organization proposal

This proposal intends to achieve the following
  - Have a standard way of categorizing tests
  - Have some guidelines around test file organization
  - Have a master wrapper for test execution
  - Follow common documentation style
  - Test result collection

## Test categorization
Leverage pytest custom markers to group tests based on topology, asic, features, device type and connection type.
Every testcase needs to have a topology marker. Feature markers are recommended for any feature test that are getting added.
'Device_type' is optional but needs to be specified if there is a specific requirement that the test needs a physical DUT as opposed to a VS. The same criteria applies for 'connection_type'

```
pytest.ini
[pytest]
markers:
    topology(topo_name): The topologies this particular testcase can run against. topo_name can be individual topology names like 't0', 't1', 'ptf', 'any' or a comma separated like ('t0', 't1') if supported on multiple topologies
    asic(vendor_name): used for asic specific test(broadcom, mellanox etc)
    feature(feature_name): feature this test is written for. eg. acl, nat
    connection_type(name): names can be 'fabric' (which indicates the presence of a fanout switch) or 'direct' if a testcase uses directly connected links
    device_type(name): name can 'physical' (if this test requires a physical dut) or 'vs' (if this test can be run on a virtual switch)

```
conftest.py

```
def pytest_addoption(parser):
        parser.addoption("--topology", action="store", metavar="NAME",
                        help="only run tests matching the topology NAME")

def pytest_runtest_setup(item):
    if item.config.getoption("--topology"):
        check_topology(item)
    ......

def check_topology(item):
    # The closest marker is used here so that the module or class level
    # marker will be overrided by case level marker
    topo_marks = [mark for mark in item.iter_markers(name="topology")]   # Get all 'topology' marks on the chain
    if topo_marks:
        topo_mark = topo_marks[0]   # The nearest mark overides others
        cfg_topos = item.config.getoption("--topology").split(',')
        if all(topo not in topo_mark.args for topo in cfg_topos):
            pytest.skip("{} supports topologies: {}, specified topologies: {}"\
                .format(item.nodeid, topo_mark.args, cfg_topos))
    else:
        warn_msg = "testcase {} is skipped when no topology marker is given".format(item.nodeid)
        warnings.warn(warn_msg)
        pytest.skip(warn_msg)
```

Sample test file: test_topo.py

```
#topology marker on module level
pytestmark = [
    pytest.mark.topology('t0', 't1', 'any')
]
#This case will be run if topo_name t0/t1/any or no topo_name is given in command line
def test_all():
   assert 1 == 1

#topology marker on case level, will override that on module level
#This case will be run if topo_name t0 or no topo_name is given in command line
@pytest.mark.topology('t0')
def test_t0():
   assert 1 == 1

#This case will be run if topo_name t1 or no topo_name is given in command line
@pytest.mark.topology('t1')
def test_t1():
   assert 1 == 1

#This case will be run if topo_name any or no topo_name is given in command line
@pytest.mark.topology('any')
def test_any():
   assert 1 == 1

```
**Note:** testcases without topology marker will be skipped if topology is given in commandline

Sample test file: test_notopo.py

```
#this case will be skipped
def test_notopo():
   assert 1 == 1

```

Test run

```
pytest --inventory inv --host-pattern dut-1 --module-path ../ansible/library/ --testbed tb --testbed_file tb.csv --junit-xml=tr.xml --log-cli-level warn --topology t1 test_topo
 --disable_loganalyzer --topology t1 test_topo.py
================================= test session starts ==================================
platform linux2 -- Python 2.7.12, pytest-4.6.5, py-1.8.1, pluggy-0.13.1
ansible: 2.8.7
rootdir: /var/johnar/code/sonic-mgmt/tests, inifile: pytest.ini
plugins: repeat-0.8.0, xdist-1.28.0, forked-1.1.3, ansible-2.2.2
collected 4 items

test_topo.py::test_all PASSED                                                    [ 25%]
test_topo.py::test_t0 SKIPPED                                                    [ 50%]
test_topo.py::test_t1 PASSED                                                     [ 75%]
test_topo.py::test_any SKIPPED                                                   [100%]

=============================== short test summary info ================================
SKIPPED [1] /var/johnar/code/sonic-mgmt/tests/common/plugins/custom_markers/__init__.py:56: test_topo.py::test_any supports topologies: ('any',), specified topologies: ['t1']
SKIPPED [1] /var/johnar/code/sonic-mgmt/tests/common/plugins/custom_markers/__init__.py:56: test_topo.py::test_t0 supports topologies: ('t0',), specified topologies: ['t1']
========================= 2 passed, 2 skipped in 10.24 seconds =========================
```
## Test file organization
- Have 2 broad categories (platform and feature). Feature specific tests and their helpers go into specific feature folders.

```
tests
  |_ common
  |_ platform
  |_ ptftests
  |_ nat
      |_ test_nat_bindings.py
      |_ files
           |_ all helpers for the nat feature
  |_ acl

```

- Any reusable code needs to go under tests/common

- File naming convention
  The objective here is to provide meaningful names for helper files/testcase files so that the user gets a general idea of the file contents.


## Master wrapper
Make it easier to run a nightly test against a feature/platform/topology from the command line. Have something similar to the 'ansible/testbed-cli.sh' script which can be invoked with just the basic parameters (testbed name, what flavor of test to run)


## Documentation style
Follow a common style of documentation for test methods which can be used by some tool to generate html content


## Test result collection
Use the --junitxml attribute to collect test results. Can leverage the existing format used in sonic-utilities/sonic-swss repo for reporting test results.
