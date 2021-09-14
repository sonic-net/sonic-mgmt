
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

