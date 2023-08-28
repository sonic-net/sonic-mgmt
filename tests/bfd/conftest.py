import pytest
from bfd_base import BfdBase

@pytest.fixture(scope='class')
def bfd_base_instance():
    return BfdBase()

def pytest_addoption(parser):
    parser.addoption("--num_sessions", action="store", default=5)
    parser.addoption("--num_sessions_scale", action="store", default=128)

@pytest.fixture(scope='function')
def bfd_cleanup_db(request, autouse=True):
    yield
    command = 'sonic-db-cli -n asic{} CONFIG_DB HSET "STATIC_ROUTE|{}" bfd \'true\''.format(request.config.src_asic.asic_index, request.config.src_prefix).replace('\\', '')
    #1 - for new entry , 0 for modification of existing entry
    request.config.src_dut.shell(command)
    command = 'sonic-db-cli -n asic{} CONFIG_DB HSET "STATIC_ROUTE|{}" bfd \'true\''.format(request.config.dst_asic.asic_index, request.config.dst_prefix).replace('\\', '')
    request.config.dst_dut.shell(command)
