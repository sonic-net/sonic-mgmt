def pytest_addoption(parser):
    """
    Adds pytest options that are used by VxLAN tests
    """

    vxlan_group = parser.getgroup("VXLAN test suite options")

    vxlan_group.addoption(
        "--vxlan_port",
        action="store",
        default=4789,
        type=int,
        help="The UDP port to use for VxLAN. It must be a viable UDP port - not one of the already used standard protocol ports"
    )

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

    # ECMP options
    vxlan_group.addoption(
        "--total_number_of_endpoints",
        action="store",
        default=2,
        type=int,
        help="Total number of uniq endpoints that can be used in the DUT"
    )

    vxlan_group.addoption(
        "--ecmp_nhs_per_destination",
        action="store",
        default=1,
        type=int,
        help="ECMP: Number of tunnel endpoints to provide for each tunnel destination"
    )

    vxlan_group.addoption(
        "--debug_enabled",
        action="store_true",
        help="Enable debugging the script. The config file names will *not* be time-stamped, every run of the script will over-write the previously created config files."
    )

    vxlan_group.addoption(
        "--keep_temp_files",
        action="store_true",
        help="This will keep the config files in the DUT and PTF."
    )

    vxlan_group.addoption(
        "--dut_hostid",
        default=1,
        type=int,
        help="This is the host part of the IP addresses for interfaces in the DUT to be used in this script."
    )

    # This will decide the number of destinations.
    vxlan_group.addoption(
        "--total_number_of_nexthops",
        action="store",
        default=2, # Max: 32k, 64K, or 128 K
        type=int,
        help="ECMP: Number of tunnel nexthops to be tested. (number of nhs_per_destination X number_of_destinations)"
    )
