import yaml

try:
    from ansible.parsing.dataloader import DataLoader
    from ansible.vars.manager import VariableManager
    from ansible.inventory.manager import InventoryManager
    has_ansible = True
except ImportError:
    # ToDo: Support running without Ansible
    has_ansible = False

def log(msg):
    print(msg)

# deprecated since same method is implemented in HostManager
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


# deprecated since same method is implemented in HostManager
def get_host_list(inventory, category):
    with open(inventory, 'r') as file:
        inv = yaml.safe_load(file)

    all_hosts = get_all_hosts(inv)
    hosts = {}
    for key, val in all_hosts.items():
        if category == 'all' or category in key:
            hosts.update({key : val})

    return hosts


class HostManager():
    """
    A helper class for managing hosts
    """
    def __init__(self, inventory_files):
        if not has_ansible:
            raise Exception("Ansible is needed for this module")
        self._dataloader = DataLoader()
        self._inv_mgr = InventoryManager(loader=self._dataloader, sources=inventory_files)
        self._var_mgr = VariableManager(loader=self._dataloader, inventory=self._inv_mgr)

    def get_host_vars(self, hostname):
        """
        @summary: Retrieve vars for given hostname
        @param hostname: The hostname for retrieving vars
        @return: A dict of hostvars
        """
        host = self._inv_mgr.get_host(hostname)
        vars = self._var_mgr.get_vars(host=host)
        vars['creds'] = self.get_host_creds(hostname)
        vars.update(host.vars)
        return vars

    def get_all_hosts(self):
        """
        @summary: Retrieve all hosts and vars in given inventory files
        @return: A dict {hostname: vars}
        """
        hosts = {}
        for hostname, _ in self._inv_mgr.hosts.items():
            hosts.update({hostname: self.get_host_vars(hostname)})
        return hosts

    def get_host_list(self, category, limit=None):
        """
        @summary: Retrieve host and vars for given category and limit
        @param category: The Ansible group, like sonic, veos...
        @param limit: The host patterns (None and empty string mean no limit)
        @return: A dict {hostname:vars}
        """
        if not limit or limit == '':
            limit = '*'
        res = {}
        hosts = self._inv_mgr.get_hosts(pattern=limit)
        for host in hosts:
            if category in [group.name for group in host.groups]:
                res.update({host.name: self.get_host_vars(host.name)})
        return res

    def get_host_creds(self, hostname):
        """
        @summary: A helper method for retrieving creds for given hostname
        @param hostname: The hostname for retrieving creds
        @return: A dict
        """
        res = {}
        host = self._inv_mgr.get_host(hostname)
        vars = self._var_mgr.get_vars(host=host)
        groups = [group.name for group in host.groups]
        k_v = {
            'fanout': {'alias': 'fanout',
                        'username': 'ansible_ssh_user',
                        'password': ['ansible_ssh_pass']},
            'ptf': {'alias': 'ptf_host',
                    'username': 'ansible_ssh_user',
                    'password': ['ansible_ssh_pass']},
            'eos': {'alias': 'eos',
                    'username': 'ansible_user',
                    'password': ['ansible_password']},
             'vm_host': {'alias': 'vm_host',
                        'username': 'ansible_user',
                        'password': ['ansible_password']}
        }
        if 'sonic' in groups:
            res['username'] = vars['secret_group_vars']['str']['sonicadmin_user']
            res['password'] = [vars['secret_group_vars']['str']['sonicadmin_password']]
            res['password'].append(vars['ansible_altpassword'])
        else:
            for group, cred in k_v.items():
                if group in groups:
                    res['username'] = vars['secret_group_vars'][cred['alias']][cred['username']]
                    res['password'] = [vars['secret_group_vars'][cred['alias']][p] for p in cred['password']]
                    break
        # console username and password
        console_login_creds = vars.get("console_login", {})
        res["console_user"] = {}
        res["console_password"] = {}

        for k, v in console_login_creds.iteritems():
            res["console_user"][k] = v["user"]
            res["console_password"][k] = v["passwd"]

        return res


