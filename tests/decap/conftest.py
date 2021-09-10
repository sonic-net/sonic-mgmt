
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


def build_ttl_dscp_params(uniform_support_info):
    ttl_uni = {'ttl': 'uniform', 'dscp': 'pipe'}
    dscp_uni = {'ttl': 'pipe', 'dscp': 'uniform'}
    both_pipe = {'ttl': 'pipe', 'dscp': 'pipe'}
    params = []
    if uniform_support_info['ttl']:
        params.append(ttl_uni)
    if uniform_support_info['dscp']:
        params.append(dscp_uni)
    if len(params) < 2:
        params.append(both_pipe)
    return params

def pytest_generate_tests(metafunc):
  ttl = metafunc.config.getoption("ttl_uniform")
  dscp = metafunc.config.getoption("dscp_uniform")
  if "supported_ttl_dscp_params" in metafunc.fixturenames:
      params = build_ttl_dscp_params({'ttl': ttl, 'dscp': dscp})
      metafunc.parametrize("supported_ttl_dscp_params", params, ids=lambda p: "ttl=%s, dscp=%s" % (p['ttl'], p['dscp']), scope="module")

