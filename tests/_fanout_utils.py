def get_fanout_host_vars(inv_files, fanout_name, host_visible_vars_getter):
    host_vars = host_visible_vars_getter(inv_files, fanout_name)
    return host_vars or {}
