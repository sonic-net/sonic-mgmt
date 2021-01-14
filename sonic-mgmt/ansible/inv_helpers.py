import yaml


def get_all_hosts(inventory):
    hosts = {}
    for key, val in inventory.items():
        vtype = type(val)
        if vtype == dict:
            if 'hosts' in val:
                hosts.update({ key : val['hosts'] })
            else:
                hosts.update(get_all_hosts(val))
    return hosts


def get_host_list(inventory, category):
    with open(inventory, 'r') as file:
        inv = yaml.safe_load(file)

    all_hosts = get_all_hosts(inv)
    hosts = {}
    for key, val in all_hosts.items():
        if category == 'all' or category in key:
            hosts.update({key : val})

    return hosts

