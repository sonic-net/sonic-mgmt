"""
Remote platform

This platform uses physical ethernet interfaces.
"""

def get_ifaces():
    with open('/proc/net/dev') as fp:
        all = fp.read()

    ifaces = []
    for line in all.split('\n'):
        # Skip a header
        if ':' not in line:
            continue

        iface = line.split(':')[0].strip()

        # Skip not FP interfaces
        if 'eth' not in iface:
            continue

        ifaces.append(iface)

    # Sort before return
    return ifaces


def platform_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    """

    remote_port_map = {(0, int(i.replace('eth', ''))) : i for i in get_ifaces()}
    config["port_map"] = remote_port_map.copy()
    config["caps_table_idx"] = 0
