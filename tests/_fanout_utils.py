def get_fanout_host_vars(inv_files, fanout_name, host_visible_vars_getter):
    """Return visible fanout inventory variables for a host.

    Args:
        inv_files: Inventory sources to inspect when resolving host variables.
        fanout_name: Fanout hostname to resolve from the inventory.
        host_visible_vars_getter: Callable that accepts ``(inv_files, fanout_name)``
            and returns either the variables visible to that host as a ``dict``
            or ``None`` when the host is not present.

    Returns:
        dict: Host variables for ``fanout_name``. Returns an empty dict when the
        host is missing from the provided inventory sources.
    """
    host_vars = host_visible_vars_getter(inv_files, fanout_name)
    return host_vars or {}
