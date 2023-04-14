import logging
import pytest
from .args.qos_sai_args import add_qos_sai_args
from .args.buffer_args import add_dynamic_buffer_calculation_args
from tests.common.errors import RunAnsibleModuleFail

# QoS pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to QoS pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_qos_sai_args(parser)
    add_dynamic_buffer_calculation_args(parser)

@pytest.fixture(scope="function")
def singleMemberPort(duthost, mg_facts):
    '''
        Installs static route for a port that is either a single-member lag or not part of a port channel.
    '''
    dst_port = None
    # Try to find a port with no port channel
    all_lag_members = []
    for lag_dict in mg_facts["minigraph_portchannels"].values():
        all_lag_members += lag_dict["members"]
    all_ports = mg_facts["minigraph_ports"].keys()
    non_lag_ports = set(all_ports) - set(all_lag_members)
    assert len(non_lag_ports) > 0, "Failed to find either a single-member lag or a non-lag port"
    dst_port = non_lag_ports.pop()
    if dst_port == None:
        # Only port-channels were found, so try to find a single-member LAG
        for lag_dict in mg_facts["minigraph_portchannels"].values():
            if len(lag_dict["members"]) == 1:
                dst_port = lag_dict["members"][0]
                break
    assert dst_port != None, "Failed to find an invidivual port for testing"
    yield dst_port

