from spytest import st


def config_vlan(node, vlan, members = [], vrf = None, add = True):
    config = ''
    if add:
        config = config + 'sudo config vlan add {}\n'.format(vlan)
        for member in members:
            config = config + 'sudo config vlan member add -u {} {}\n'.format(vlan, member)
        if vrf:
            config = config + 'sudo config interface vrf bind {} {}\n'.format('Vlan' + str(vlan), vrf)

    else:
        if vrf:
            config = config + 'sudo config interface vrf unbind {}\n'.format('Vlan' + str(vlan))
        for member in members:
            config = config + 'sudo config vlan member del {} {}\n'.format(vlan, member)
        config = config + 'sudo config vlan del {}\n'.format(vlan)

    st.config(node, config, skip_error_check=False, conf=True)


def config_vxlan_map(node, vxlan, vni, vrf=None, vlan=None, add=True):
    config = ''
    if add:
        if vlan:
            config = config + 'sudo config vxlan map add {} {} {}\n'.format(vxlan, vlan, vni)
        if vrf:
            config = config + 'sudo config vrf add_vrf_vni_map {} {}\n'.format(vrf, vni)
    else:
        if vrf:
            config = config + 'sudo config vrf del_vrf_vni_map {}\n'.format(vrf)
        if vlan:
            config = config + 'sudo config vxlan map del {} {} {}\n'.format(vxlan, vlan, vni)
    st.config(node, config, skip_error_check=False, conf=True)


def config_vrf(node, vrf, add=True):
    config = ''
    if add:
        config = config + 'sudo config vrf add {}'.format(vrf)
    else:
        config = config + 'sudo config vrf del {}'.format(vrf)

    st.config(node, config, skip_error_check=False, conf=True)
