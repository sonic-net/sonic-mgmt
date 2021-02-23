import sys
import pytest
import warnings
import logging
from tests.common.plugins import test_completeness


def pytest_addoption(parser):
        parser.addoption("--topology", action="store", metavar="TOPO_NAME",
                         help="only run tests matching the topology TOPO_NAME ('t0', 't1', 'ptf', 'any')")
        parser.addoption("--feature", action="store", metavar="FEATURE_NAME",
                         help="only run tests matching the feature FEATURE_NAME")
        parser.addoption("--asic", action="store", metavar="ASIC_TYPE",
                         help="only run tests matching the asic ASIC_TYPE ('broadcom', 'mellanox')")
        parser.addoption("--connection_type", action="store", metavar="CONN_TYPE",
                         help="only run tests matching the connection CONN_TYPE ('fabric', 'direct')")
        parser.addoption("--device_type", action="store", metavar="DEV_TYPE",
                         help="only run tests matching the device DEV_TYPE ('physical', 'vs')")
        parser.addoption("--completeness_level", metavar="TEST_LEVEL", action="store",
                         help="Coverage level of test \n Defined levels: Debug, Basic, Confident, Thorough")


def pytest_configure(config):
    # register all the markers
    config.addinivalue_line(
        "markers", "topology(TOPO_NAME): mark test to run only on specified topologies. allowed values: 't0', 't1', 'ptf', 'any'. comma separated values are also allowed. eg. ('t0','t1')"
    )
    config.addinivalue_line(
        "markers", "feature(FEATURE_NAME): mark test against a feature. eg. 'acl', 'nat' or if a test case tests multiple features ('acl', 'nat')"
    )
    config.addinivalue_line(
        "markers", "asic(ASIC_TYPE): mark test that can only be run on a specific asic. allowed values: 'broadcom', 'mellanox'"
    )
    config.addinivalue_line(
        "markers", "connection_type(CONN_TYPE): mark test to specify the need for a fanout or direct conn. allowed values: 'fabric', 'direct'"
    )
    config.addinivalue_line(
        "markers", "device_type(DEV_TYPE): mark test to specify the need for a physical dut or vs only test. allowed values: 'physical', 'vs'"
    )
    config.addinivalue_line(
        "markers", "supported_completeness_level(TEST_LEVEL): mark test to specify the completeness level for the test. Allowed values: 'debug', 'basic' ,'confident', 'thorough'"
    )

def pytest_collection_modifyitems(session):
    if session.config.getoption("--topology"):
        for item in session.items[:]:
            check_topology(session, item)

def pytest_runtest_setup(item):
    if item.config.getoption("--feature"):
        check_feature(item)
    if item.config.getoption("--asic"):
        check_asic(item)
    if item.config.getoption("--connection_type"):
        check_conn_type(item)
    if item.config.getoption("--device_type"):
        check_device_type(item)

    check_test_completeness(item)

def check_topology(session, item):
    # The closest marker is used here so that the module or class level
    # marker will be overrided by case level marker
    topo_marks = [mark for mark in item.iter_markers(name="topology")]   # Get all 'topology' marks on the chain
    if topo_marks:
        topo_mark = topo_marks[0]   # The nearest mark overides others
        cfg_topos = session.config.getoption("--topology").split(',')
        if all(topo not in topo_mark.args for topo in cfg_topos):
            if session.config.getoption("--collectonly"):
                session.items.remove(item)
                session.config.hook.pytest_deselected(items=[item])
            else:
                item.add_marker(pytest.mark.skip("test requires topology in {!r}".format(topo_mark)))
    else:
        if session.config.getoption("--collectonly"):
            session.items.remove(item)
            session.config.hook.pytest_deselected(items=[item])
        else:
            warn_msg = "testcase {} is skipped when no topology marker is given".format(item.nodeid)
            warnings.warn(warn_msg)
            item.add_marker(pytest.mark.skip(warn_msg))

def check_feature(item):
    feature_names = [mark.args for mark in item.iter_markers(name="feature")]
    if feature_names:
        cfg_features = item.config.getoption("--feature").split(',')
        if all(feature not in feature_names[0] for feature in cfg_features):
            pytest.skip("test requires feature name in {!r}".format(feature_names))
    else:
        pytest.skip("test does not match feature")

def check_asic(item):
    asic = [mark.args[0] for mark in item.iter_markers(name="asic")]
    if asic:
        if item.config.getoption("--asic") not in asic:
            pytest.skip("test requires asic in {!r}".format(asic))
    else:
        pytest.skip("test does not match asic type")

def check_conn_type(item):
    conn = [mark.args[0] for mark in item.iter_markers(name="connection_type")]
    if conn:
        if item.config.getoption("--connection_type") not in conn:
            pytest.skip("test requires connection in {!r}".format(conn))
    else:
        pytest.skip("test does not match connection type")

def check_device_type(item):
    dev = [mark.args[0] for mark in item.iter_markers(name="device_type")]
    if dev:
        if item.config.getoption("--device_type") not in dev:
            pytest.skip("test requires device type in {!r}".format(dev))
    else:
        pytest.skip("test does not match device type")

def check_test_completeness(item):
    '''
    API to set the completeness level. If the specified level does not match
    a defined level in the testcase, level-normalization is done based on below
    defined cases. The normalized level is set as a Pytest marker "supported_completeness_level":
    Cases:
    1. Completeness level not specified - set to the default (basic) value of test completeness.
    2. Test does not define any completeness level - run the testcase entirely.
    3. Specified completeness level do not match any defined level in a test case:
        3.1 Specified level is higher than any defined level - go to highest level defined
        3.2 Specified level is lower than any defined level - go to lowest level defined
        3.3 Specified level is in between two defined levels - go to next lower level
    4. Specified level matches one of the defined levels
    '''
    specified_level = item.config.getoption("--completeness_level")
    # Check for case 1
    specified_level = test_completeness.set_default(specified_level)

    # The closest marker is used here so that the module or class level
    # marker will be overrided by case level marker
    defined_levels = [mark.args for mark in item.iter_markers(name="supported_completeness_level")]
    # Check for case 2
    if len(defined_levels) == 0:
        logging.info("Test has no defined levels. Continue without test completeness checks")
        return
    defined_levels = defined_levels[0] # The nearest mark overides others

    # Check for case 3, 4
    normalized_completeness_level = test_completeness.normalize_levels(specified_level, defined_levels)

    normalized_completeness_level = pytest.mark.supported_completeness_level(normalized_completeness_level)
    item.add_marker(normalized_completeness_level, append=False)
