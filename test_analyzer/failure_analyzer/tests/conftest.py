import pytest
import logging
import sys
import json

'''
Parse Arguments
'''

def pytest_addoption(parser):
    parser.addoption("--extb", action="store", default="ixia,t2")
    parser.addoption("--exerr", action="store", default="ixia,t2")
    parser.addoption("--incbr", action="store", default='["master", "internal", "202311"]')
    parser.addoption("--rlsbr", action="store", default='["202311"]')

'''
Argument fixtures
'''
@pytest.fixture(scope="session")
def excluded_testbed_keywords(pytestconfig):
    return pytestconfig.getoption("extb").split(",")

@pytest.fixture(scope="session")
def excluded_testbed_keywords_setup_error(pytestconfig):
    return pytestconfig.getoption("exerr").split(",")

@pytest.fixture(scope="session")
def included_branch(pytestconfig):
    return json.loads(pytestconfig.getoption("incbr"))

@pytest.fixture(scope="session")
def released_branch(pytestconfig):
    return json.loads(pytestconfig.getoption("rlsbr"))

'''
General Fixtures
'''

@pytest.fixture
def logger():
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s'
    )
    return logging.getLogger('test_logger')

