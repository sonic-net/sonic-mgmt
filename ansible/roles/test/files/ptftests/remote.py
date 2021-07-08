"""
Remote platform

This platform uses physical ethernet interfaces.
"""

ETH_PFX = 'eth'
SUB_INTF_SEP = '.'


def get_ifaces():
    with open('/proc/net/dev') as fp:
        all = fp.read()

    ifaces = []
    for line in all.split('\n'):
        # Skip a header
        if ':' not in line:
            continue

        iface = line.split(':')[0].strip()

        # Skip not FP interfaces and vlan interface, like eth1.20
        if ETH_PFX not in iface:
            continue
        
        ifaces.append(iface)

    # Sort before return
    return ifaces


def build_ifaces_map(ifaces):
    """Build interface map for ptf to init dataplane."""
    sub_ifaces = []
    iface_map = {}
    for iface in ifaces:
        iface_suffix = iface.lstrip(ETH_PFX)
        if SUB_INTF_SEP in iface_suffix:
            iface_index = int(iface_suffix.split(SUB_INTF_SEP)[0])
            sub_ifaces.append((iface_index, iface))
        else:
            iface_index = int(iface_suffix)
            iface_map[(0, iface_index)] = iface

    # override those interfaces that has sub interfaces
    for i, si in sub_ifaces:
        iface_map[(0, i)] = si;
    return iface_map


def platform_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    """

    remote_port_map = build_ifaces_map(get_ifaces())
    config["port_map"] = remote_port_map.copy()
    config["caps_table_idx"] = 0
