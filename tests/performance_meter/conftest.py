import pytest
import os
import yaml
import logging
from tests.common.plugins.sanity_check import _sanity_check
from tests.common.testbed import TestbedInfo
from tests.common.devices.duthosts import DutHosts
from tests.common.utilities import get_duts_from_host_pattern
from tests.conftest import cache
from tests.common.plugins.ansible_fixtures import _initialize
from tests.common.helpers.inventory_utils import trim_inventory


TEST_DIR = "performance_meter"
CONFIG_FILE_DIR = os.path.join(TEST_DIR, "config")


def load_test_config():
    if not os.path.exists(CONFIG_FILE_DIR):
        os.makedirs(CONFIG_FILE_DIR)
    config_paths = os.listdir(CONFIG_FILE_DIR)
    config_file_yaml = {}
    for path in config_paths:
        with open(os.path.join(CONFIG_FILE_DIR, path)) as f:
            config_file_yaml[path] = yaml.safe_load(f.read())
    return config_file_yaml


def eval_condition(condition, duthosts, rand_one_dut_hostname, tbinfo):
    return any(map(lambda duthost: eval(condition, {}, {"duthosts": duthosts, "duthost": duthost, "tbinfo": tbinfo}),
                   filter(lambda duthost: rand_one_dut_hostname is None or duthost.hostname == rand_one_dut_hostname,
                          duthosts)))


def filter_test_config(duthosts, rand_one_dut_hostname, tbinfo, load_test_config):
    def checker(item):
        if "run_when" not in item[1]:
            return True
        if "performance_meter" not in item[1]:
            return False
        run_condition = item[1]["run_when"]
        if isinstance(run_condition, list):
            return all(map(lambda item: eval_condition(item, duthosts, rand_one_dut_hostname, tbinfo),
                           run_condition))
        if isinstance(run_condition, str):
            return eval_condition(run_condition, duthosts, rand_one_dut_hostname, tbinfo)
        return False
    return dict(filter(checker, load_test_config.items()))


# Original config structure similar to the config files as defined by user
@pytest.fixture(scope="module")
def filtered_test_config(duthosts, rand_one_dut_hostname, tbinfo):
    all_test_config = load_test_config()
    filtered_test_config = filter_test_config(duthosts, rand_one_dut_hostname, tbinfo, all_test_config)
    yield filtered_test_config


required_items_for_each_test = ["op", "success_criteria", "run"]


# Reorg config structure around ops
@pytest.fixture(scope="module")
def reorged_test_config(filtered_test_config):
    all_test_config = {}
    for path, config in filtered_test_config.items():
        for test_name, test_config in config["performance_meter"].items():
            assert all(map(lambda item: item in test_config, required_items_for_each_test)), \
                   "{} should be in config".format(required_items_for_each_test)
            assert (test_config["success_criteria"] + "_timeout") in test_config, \
                   "success_criteria timeout should be in config"
            op = test_config["op"]
            test_config_for_op = all_test_config.get(op, {})
            test_config_under_path_for_op = test_config_for_op.get(path, {})
            test_config_under_path_for_op[test_name] = test_config
            test_config_for_op[path] = test_config_under_path_for_op
            all_test_config[op] = test_config_for_op
    return all_test_config


test_result = {}


# Test result structures are structured around ops like reorged_test_config
@pytest.fixture(scope="module")
def store_test_result(reorged_test_config):
    for op, test_config_for_op in reorged_test_config.items():
        test_result[op] = [None] * \
                          max(map(lambda test_config_under_path_for_op:
                                  max(map(lambda test_config: test_config["run"],
                                          test_config_under_path_for_op.values())),
                                  test_config_for_op.values()))
    return test_result


# There are several differences between usage in sanity_check and this
# 1. sanity_check fixture does not have a yield at the end
# 2. sanity_check raise Exception on error instead of returning
# 3. sanity_check is only run for module
# The run_index and op param is purely for logging and is optional
@pytest.fixture(scope="function")
def call_sanity_check(request, parallel_run_context):
    if request.config.option.skip_sanity:
        return lambda *args, **kwargs: True, lambda *args, **kwargs: True

    generator = None

    def sanity_check_setup(run_index=None, op=None):
        nonlocal generator
        assert generator is None, "sanity_check_setup called again without sanity_check_cleanup"
        generator = _sanity_check(request, parallel_run_context)
        try:
            next(generator)
            return True
        except Exception as e:
            logging.warning("Test run {} op {} precheck failed on {}".format(run_index, op, e))
            return False

    def sanity_check_cleanup(run_index=None, op=None):
        nonlocal generator
        assert generator is not None, "sanity_check_cleanup called without sanity_check_setup"
        try:
            next(generator)
        except StopIteration:
            return True
        except Exception as e:
            logging.warning("Test run {} op {} postcheck failed on {}".format(run_index, op, e))
            return False
        finally:
            generator = None
    return sanity_check_setup, sanity_check_cleanup


def get_tbinfo(config):
    tbname = config.getoption("--testbed")
    tbfile = config.getoption("--testbed_file")
    if tbname is None or tbfile is None:
        raise ValueError("testbed and testbed_file are required!")
    testbedinfo = cache.read(tbname, "tbinfo")
    if testbedinfo is cache.NOTEXIST:
        testbedinfo = TestbedInfo(tbfile)
        cache.write(tbname, "tbinfo", testbedinfo)
    return testbedinfo.testbed_topo.get(tbname, {})


def get_specified_duts(config, tbinfo):
    if config.getoption("--target_hostname") is not None:
        return [config.getoption("--target_hostname")]
    testbed_duts = tbinfo["duts"]
    host_pattern = config.getoption("--host-pattern")
    if host_pattern == 'all':
        return testbed_duts
    specified_duts = get_duts_from_host_pattern(host_pattern)
    if any([dut not in testbed_duts for dut in specified_duts]):
        raise Exception("One of the specified DUTs {} does not belong to the testbed {}"
                        .format(specified_duts, testbed_duts))
    return specified_duts


def get_duthosts(config, tbinfo):
    plugin = config.pluginmanager.getplugin("ansible")
    plugin.initialize = _initialize.__get__(plugin)

    def ansible_adhoc(**kwargs):
        return plugin.initialize(config, None, **kwargs)
    return DutHosts(ansible_adhoc, tbinfo, None, get_specified_duts(config, tbinfo),
                    target_hostname=config.getoption("--target_hostname"),
                    is_parallel_leader=config.getoption("--is_parallel_leader"))


def enhance_inventory(config, tbinfo):
    inv_opt = config.getoption("ansible_inventory")
    if isinstance(inv_opt, list):
        return
    inv_files = [inv_file.strip() for inv_file in inv_opt.split(",")]

    if config.getoption("trim_inv"):
        trim_inventory(inv_files, tbinfo)

    try:
        logging.info(f"Inventory file: {inv_files}")
        setattr(config.option, "ansible_inventory", inv_files)
    except AttributeError:
        logging.error("Failed to set enhanced 'ansible_inventory' to request.config.option")


def pytest_generate_tests(metafunc):
    if metafunc.function.__name__ != "test_performance":
        return

    config = metafunc.config
    tbinfo = get_tbinfo(config)
    enhance_inventory(config, tbinfo)
    duthosts = get_duthosts(config, tbinfo)

    all_test_config = load_test_config()
    filtered_test_config = filter_test_config(duthosts, None, tbinfo, all_test_config)

    params = []
    for path, config in filtered_test_config.items():
        for test_name, test_config in config["performance_meter"].items():
            assert all(map(lambda item: item in test_config, required_items_for_each_test)), \
                   "{} should be in config".format(required_items_for_each_test)
            op = test_config["op"]
            success_criteria = test_config["success_criteria"]
            run = test_config["run"]
            params.extend(map(lambda run_index: [path, test_name, op, success_criteria, run_index], range(run)))
    metafunc.parametrize("path,test_name,op,success_criteria,run_index", params)
