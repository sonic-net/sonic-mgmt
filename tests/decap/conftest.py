
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
