import pytest
import utils
import routing_module
pytestmark = [
    pytest.mark.topology("any"),
    # pytest.mark.disable_loganalyzer
]


@pytest.mark.usefixtures("setup_interface_ip")
def test_show_routes_timing(duthost):
    routing_module.remove_routes(duthost)
    routing_module.setup_routes(duthost, utils.NUM_ROUTES)
    routing_module.remove_routes(duthost)
