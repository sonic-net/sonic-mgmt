import pytest

from vnet_config import CLEANUP_KEY, IPV6_VXLAN_TEST_KEY, \
                        NUM_VNET_KEY, NUM_ROUTES_KEY, NUM_ENDPOINTS_KEY

def pytest_addoption(parser):
    """
    Adds pytest options that are used by VxLAN tests
    """
    
    parser.addoption(
        "--num_vnet", 
        action="store", 
        default=None, 
        type=int, 
        help="number of VNETs for VNET VxLAN test"
    )

    parser.addoption(
        "--num_routes", 
        action="store", 
        default=None, 
        type=int, 
        help="number of routes for VNET VxLAN test"
    )

    parser.addoption(
        "--num_endpoints", 
        action="store", 
        default=None, 
        type=int, 
        help="number of endpoints for VNET VxLAN"
    )

    parser.addoption(
        "--ipv6_vxlan_test", 
        action="store_true", 
        help="Use IPV6 for VxLAN test"
    )

    parser.addoption(
        "--skip_cleanup", 
        action="store_true", 
        help="Do not cleanup after VNET VxLAN test"
    )

@pytest.fixture(scope="module")
def scaled_vnet_params(request):
    params = {}
    params[NUM_VNET_KEY] = request.config.option.num_vnet
    params[NUM_ROUTES_KEY] = request.config.option.num_routes
    params[NUM_ENDPOINTS_KEY] = request.config.option.num_endpoints
    return params
    
@pytest.fixture(scope="module")
def vnet_test_params(request):
    params = {}
    params[IPV6_VXLAN_TEST_KEY] = request.config.option.ipv6_vxlan_test
    params[CLEANUP_KEY] = not request.config.option.skip_cleanup
    return params
