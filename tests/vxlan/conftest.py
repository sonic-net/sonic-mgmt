def pytest_addoption(parser):
    """
    Adds pytest options that are used by VxLAN tests
    """

    parser.addoption(
        "--num_vnet",
        action="store",
        default=8,
        type=int,
        help="number of VNETs for VNET VxLAN test"
    )

    parser.addoption(
        "--num_routes",
        action="store",
        default=16000,
        type=int,
        help="number of routes for VNET VxLAN test"
    )

    parser.addoption(
        "--num_endpoints",
        action="store",
        default=4000,
        type=int,
        help="number of endpoints for VNET VxLAN"
    )

    parser.addoption(
        "--num_intf_per_vnet",
        action="store",
        default=1,
        type=int,
        help="number of VLAN interfaces per VNET"
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

    parser.addoption(
        "--skip_apply_config",
        action="store_true",
        help="Apply new configurations on DUT"
    )