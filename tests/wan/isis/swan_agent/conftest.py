import pytest
from swan_agent_helpers import get_swan_agent_file
from swan_agent_helpers import load_swan_agent, remove_swan_agent

def pytest_collection_modifyitems(config, items):
    if not config.getoption("--swan_agent"):
        skip_swanagent = pytest.mark.skip(reason="swan agent test cases")
        for item in items:
            if "swanagent_required" in item.keywords:
                item.add_marker(skip_swanagent)
    elif not get_swan_agent_file():
        skip_swanagent = pytest.mark.skip(reason="swan agent file not found")
        for item in items:
            if "swanagent_required" in item.keywords:
                item.add_marker(skip_swanagent)


@pytest.fixture(scope="module")
def swan_agent_setup_teardown(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    load_swan_agent(dut_host)
    request.addfinalizer(functools.partial(remove_swan_agent, dut_host))
    yield dut_host
