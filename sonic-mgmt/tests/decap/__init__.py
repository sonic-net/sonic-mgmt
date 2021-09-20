# Decap pytest arguments
def pytest_addoption(parser):

    decap_group = parser.getgroup("Decap test suite options")

    decap_group.addoption(
        "--outer_ipv4",
        default=True,
        help="Specify whether outer layer IPv4 testing will be covered",
    )

    decap_group.addoption(
        "--outer_ipv6",
        default=True,
        help="Specify whether outer layer IPv6 testing will be covered",
    )

    decap_group.addoption(
        "--inner_ipv4",
        default=True,
        help="Specify whether inner layer IPv4 testing will be covered",
    )

    decap_group.addoption(
        "--inner_ipv6",
        default=True,
        help="Specify whether inner layer IPv6 testing will be covered",
    )
    
    decap_group.addoption(
        "--ttl_uniform",
        action="store_true", 
        default=False,
        help="indicates TTL uniform is supported"
    )
    decap_group.addoption(
        "--dscp_uniform",
        action="store_true",
        default=True,
        help="indicates DSCP uniform is supported"
    )
    decap_group.addoption(
        "--no_ttl_uniform",
        dest='ttl_uniform',
        action="store_false",
        help="indicates TTL uniform is not supported"
    )
    decap_group.addoption(
        "--no_dscp_uniform",
        dest='dscp_uniform',
        action="store_false",
        help="indicates DSCP uniform is not supported"
    )
