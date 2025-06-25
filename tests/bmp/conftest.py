import pytest

def pytest_addoption(parser):
    parser.addoption("--container_test", action="store", default="",
                     help="This flag indicate the test running by conntainer test")
