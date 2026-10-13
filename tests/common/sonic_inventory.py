"""Helpers for resolving SONiC-neighbor settings from Ansible inventory."""


def register_neighbor_inventory_host(devices, neighbor_name, device,
                                     inventory_hostname):
    """Register a neighbor with its real Ansible inventory hostname."""
    device['inventory_hostname'] = inventory_hostname
    devices[neighbor_name] = device


def get_sonic_neighbor_vars(inv_files, nbrhosts, neighbor_name,
                            get_host_visible_vars):
    """Return settings visible to a neighbor's real inventory host."""
    neighbor = nbrhosts.get(neighbor_name)
    inventory_hostname = neighbor and neighbor.get('inventory_hostname')
    if not inventory_hostname:
        raise ValueError(
            "Unable to resolve inventory host for SONiC neighbor '{}'".format(
                neighbor_name))

    sonic_vars = get_host_visible_vars(inv_files, inventory_hostname)
    if not sonic_vars or not sonic_vars.get('snmp_rocommunity'):
        raise ValueError(
            "Inventory host '{}' has no SONiC SNMP read community".format(
                inventory_hostname))
    return {'snmp_rocommunity': sonic_vars['snmp_rocommunity']}
