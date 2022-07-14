def build_ttl_dscp_params(uniform_support_info):
    ttl_uni_vxlan = {'ttl': 'uniform', 'dscp': 'pipe', 'vxlan': 'set_unset'}
    dscp_uni_vxlan = {'ttl': 'pipe', 'dscp': 'uniform', 'vxlan': 'set_unset'}
    both_pipe_vxlan = {'ttl': 'pipe', 'dscp': 'pipe', 'vxlan': 'set_unset'}
    ttl_uni = {'ttl': 'uniform', 'dscp': 'pipe', 'vxlan': 'disable'}
    dscp_uni = {'ttl': 'pipe', 'dscp': 'uniform', 'vxlan': 'disable'}
    both_pipe = {'ttl': 'pipe', 'dscp': 'pipe', 'vxlan': 'disable'}
    params = []
    if uniform_support_info['ttl']:
        params.append(ttl_uni)
        params.append(ttl_uni_vxlan)
    if uniform_support_info['dscp']:
        params.append(dscp_uni)
        params.append(dscp_uni_vxlan)
    if len(params) < 4:
        params.append(both_pipe)
        params.append(both_pipe_vxlan)
    return params

def pytest_generate_tests(metafunc):
  ttl = metafunc.config.getoption("ttl_uniform")
  dscp = metafunc.config.getoption("dscp_uniform")
  if "supported_ttl_dscp_params" in metafunc.fixturenames:
      params = build_ttl_dscp_params({'ttl': ttl, 'dscp': dscp})
      metafunc.parametrize("supported_ttl_dscp_params", params, ids=lambda p: "ttl=%s, dscp=%s, vxlan=%s" % (p['ttl'], p['dscp'], p['vxlan']), scope="module")
