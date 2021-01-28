from tests.common.utilities import get_host_visible_vars


def is_supervisor_node(inv_files, hostname):
    """Check if the current node is a supervisor node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
    Returns:
          Currently, we are using 'type' in the inventory to make the decision. If 'type' for the node is defined in
          the inventory, and it is 'supervisor', then return True, else return False. In future, we can change this
          logic if possible to derive it from the DUT.
    """
    node_type = get_host_visible_vars(inv_files, hostname, variable='type')
    if node_type and node_type == 'supervisor':
        return True
    return False


def is_frontend_node(inv_files, hostname):
    """Check if the current node is a frontend node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
     Returns:
          True if it is not any other type of node. Currently, the only other type of node supported is 'supervisor'
          node. If we add more types of nodes, then we need to exclude them from this method as well.
    """
    return not is_supervisor_node(inv_files, hostname)



