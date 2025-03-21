import pytest
import os
import yaml
import logging
from tests.common.plugins.sanity_check import _sanity_check


TEST_DIR = "performance_meter"
CONFIG_FILE_DIR = os.path.join(TEST_DIR, "config")


test_result = None


@pytest.fixture(scope="module")
def load_test_config():
    if not os.path.exists(CONFIG_FILE_DIR):
        os.makedirs(CONFIG_FILE_DIR)
    config_paths = os.listdir(CONFIG_FILE_DIR)
    open_config_files = {path: open(os.path.join(CONFIG_FILE_DIR, path)) for path in config_paths}

    yield {path: yaml.safe_load(fp) for path, fp in open_config_files.items()}

    for fp in open_config_files.values():
        fp.close()


def eval_condition(condition, duthost, tbinfo):
    return eval(condition, {}, {"duthost": duthost, "tbinfo": tbinfo})


@pytest.fixture(scope="module")
def filter_test_config(duthosts, rand_one_dut_hostname, tbinfo, load_test_config):
    duthost = duthosts[rand_one_dut_hostname]

    def checker(item):
        run_condition = item[1]["run_when"]
        if isinstance(run_condition, list):
            return all(map(lambda item: eval_condition(item, duthost, tbinfo), run_condition))
        if isinstance(run_condition, str):
            return eval_condition(run_condition, duthost, tbinfo)
        return False
    return dict(filter(checker, load_test_config.items()))


@pytest.fixture(scope="module")
def reorg_test_config(filter_test_config):
    all_test_config = {}
    for path, config in filter_test_config.items():
        for test_name, test_config in config["performance_meter"].items():
            op = test_config["op"]
            test_config_for_op = all_test_config.get(op, {})
            test_config_under_path_for_op = test_config_for_op.get(path, {})
            test_config_under_path_for_op[test_name] = test_config
            test_config_for_op[path] = test_config_under_path_for_op
            all_test_config[op] = test_config_for_op
    return all_test_config


@pytest.fixture(scope="module")
def store_test_result():
    return test_result


# There are several differences between usage in sanity_check and this
# 1. sanity_check fixture does not have a yield at the end
# 2. sanity_check raise Exception on error instead of returning
# 3. sanity_check is only run for module
# The run_index and op param is purely for logging and is optional
@pytest.fixture(scope="function")
def call_sanity_check(request, parallel_run_context):
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


def pytest_generate_tests(metafunc):
    global test_result
    if "run_index" in metafunc.fixturenames:
        total_run = metafunc.config.getoption("--performance-meter-run")
        test_result = [None] * total_run
        metafunc.parametrize("run_index", range(total_run))
