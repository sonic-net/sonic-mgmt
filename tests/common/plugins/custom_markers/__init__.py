import pytest

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

def pytest_runtest_setup(item):
    if item.config.getoption("--topology"):
        check_topology(item)
    if item.config.getoption("--feature"):
        check_feature(item)
    if item.config.getoption("--asic"):
        check_asic(item)
    if item.config.getoption("--connection_type"):
        check_conn_type(item)
    if item.config.getoption("--device_type"):
        check_device_type(item)

def check_topology(item):
    toponames = [mark.args for mark in item.iter_markers(name="topology")]
    if toponames:
        cfg_topos = item.config.getoption("--topology").split(',')
        if all(topo not in toponames[0] for topo in cfg_topos):
            pytest.skip("test requires topology in {!r}".format(toponames))
    else:
        pytest.skip("test does not match topology")

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
