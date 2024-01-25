import logging
import ipaddress
import time
import pytest

NUM_ROUTES = 10
START_IP = ipaddress.IPv4Address('10.210.25.0')
GATEWAY_IP = ipaddress.IPv4Address('10.210.25.44')
SUBNET_MASK = 32
logger = logging.getLogger()
MEM_LIST = []


def timing_decorator(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        logger.info("{} took {:.5f} seconds to execute".format(func.__name__, execution_time))
        return result

    return wrapper


def fixture_timing_decorator(func):
    @pytest.fixture
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print("{} took {:.5f} seconds to execute".format(func.__name__, execution_time))
        return result

    return wrapper
