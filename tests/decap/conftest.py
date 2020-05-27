
# Decap pytest arguments
def pytest_addoption(parser):

    parser.addoption(
        "--outer_ipv4",
        default=True,
        help="Specify whether outer layer IPv4 testing will be covered",
    )

    parser.addoption(
        "--outer_ipv6",
        default=True,
        help="Specify whether outer layer IPv6 testing will be covered",
    )

    parser.addoption(
        "--inner_ipv4",
        default=True,
        help="Specify whether inner layer IPv4 testing will be covered",
    )

    parser.addoption(
        "--inner_ipv6",
        default=True,
        help="Specify whether inner layer IPv6 testing will be covered",
    )
