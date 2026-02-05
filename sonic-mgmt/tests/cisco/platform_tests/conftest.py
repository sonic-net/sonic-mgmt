import pytest

def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the snmp tests.
    """
    parser.addoption(
        "--platform_npu_tc_name",
        action="store",
        default="all",
        help="Set platform npu testcase name",
        type=str)
