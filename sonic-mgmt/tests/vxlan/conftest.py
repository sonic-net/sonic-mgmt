def pytest_addoption(parser):
    """
    Adds pytest options that are used by VxLAN tests
    """

    vxlan_group = parser.getgroup("VXLAN test suite options")

    vxlan_group.addoption(
        "--num_vnet",
        action="store",
        default=8,
        type=int,
        help="number of VNETs for VNET VxLAN test"
    )

    vxlan_group.addoption(
        "--num_routes",
        action="store",
        default=16000,
        type=int,
        help="number of routes for VNET VxLAN test"
    )

    vxlan_group.addoption(
        "--num_endpoints",
        action="store",
        default=4000,
        type=int,
        help="number of endpoints for VNET VxLAN"
    )

    vxlan_group.addoption(
        "--num_intf_per_vnet",
        action="store",
        default=1,
        type=int,
        help="number of VLAN interfaces per VNET"
    )

    vxlan_group.addoption(
        "--ipv6_vxlan_test",
        action="store_true",
        help="Use IPV6 for VxLAN test"
    )

    vxlan_group.addoption(
        "--skip_cleanup",
        action="store_true",
        help="Do not cleanup after VNET VxLAN test"
    )

    vxlan_group.addoption(
        "--skip_apply_config",
        action="store_true",
        help="Apply new configurations on DUT"
    )

    vxlan_group.addoption(
        "--lower_bound_udp_port",
        action="store",
        default=0,
        type=int,
        help="Lowest expected src port for VXLAN UPD packet"
    )

    vxlan_group.addoption(
        "--upper_bound_udp_port",
        action="store",
        default=65535,
        type=int,
        help="Highest expected src port for VXLAN UPD packet"
    )
