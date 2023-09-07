import pytest
from bfd_base import BfdBase

@pytest.fixture(scope='class')
def bfd_base_instance():
    return BfdBase()

def pytest_addoption(parser):
    parser.addoption("--num_sessions", action="store", default=5)
    parser.addoption("--num_sessions_scale", action="store", default=128)

@pytest.fixture(scope='function')
def bfd_cleanup_db(request, bfd_base_instance, autouse=True):
    yield
    command = 'sonic-db-cli -n asic{} CONFIG_DB HSET "STATIC_ROUTE|{}" bfd \'false\''.format(request.config.src_asic.asic_index, request.config.src_prefix).replace('\\', '')
    #1 - for new entry , 0 for modification of existing entry
    request.config.src_dut.shell(command)
    command = 'sonic-db-cli -n asic{} CONFIG_DB HSET "STATIC_ROUTE|{}" bfd \'false\''.format(request.config.dst_asic.asic_index, request.config.dst_prefix).replace('\\', '')
    request.config.dst_dut.shell(command)
    if request.config.portchannels_on_dut == "src":
        for interface in request.config.selected_portchannels:
            bfd_base_instance.interface_cleanup(request.config.src_dut, request.config.src_asic, interface)
    elif request.config.portchannels_on_dut == "dst":
        for interface in request.config.selected_portchannels:
            bfd_base_instance.interface_cleanup(request.config.dst_dut, request.config.dst_asic, interface)
