PTF_NN_AGENT_CONF = '/etc/supervisor/conf.d/ptf_nn_agent.conf'


class PtfAgentUpdater(object):
    """
    PtfAgentUpdater class for updating ptf_nn_agent on PTF host
    """
    def __init__(self, ptfhosts, ptfadapter, ptf_nn_agent_template):
        """
        Initialize an object for updating ptf_nn_agent

        Args:
            ptfhosts: PTF hosts object
            ptfadapter: PTF adapter
            ptf_nn_agent_template: ptf_nn_agent template
        """
        self.ptfhosts = ptfhosts
        self.ptfadapter = ptfadapter
        self.ptf_nn_agent_template = ptf_nn_agent_template

    def configure_ptf_nn_agent(self, ifaces, ptf_index=0):
        """
        Add new interfaces to interfaces map of ptfadapter

        Args:
            ifaces: List of interface names
            ptf_index: The index of ptfhost in ptfhosts to configure ptf_nn_agent
        """
        ptfhost = self.ptfhosts[ptf_index]
        ifaces = [ifaces] if not isinstance(ifaces, list) else ifaces
        last_iface_id = sorted(ptfhost.host.options['variable_manager'].extra_vars['ifaces_map'].keys())[-1]

        for iface_id, iface in enumerate(ifaces, last_iface_id+1):
            ptfhost.host.options['variable_manager'].extra_vars['ifaces_map'][iface_id] = iface
            self.ptfadapter.ptf_port_set.append(iface_id)

        self._restart_ptf_nn_agent(ptf_index)

        self.ptfadapter.reinit()

    def cleanup_ptf_nn_agent(self, ifaces, ptf_index=0):
        """
        Remove interfaces from interfaces map of ptfadapter

        Args:
            ifaces: List of interface names
            ptf_index: The index of ptfhost in ptfhosts to configure ptf_nn_agent
        """
        ptfhost = self.ptfhosts[ptf_index]
        ifaces = [ifaces] if not isinstance(ifaces, list) else ifaces
        ifaces_map = ptfhost.host.options['variable_manager'].extra_vars['ifaces_map']
        config_port_indices = {v: k for k, v in list(ifaces_map.items())}

        for iface in ifaces:
            ptfhost.host.options['variable_manager'].extra_vars['ifaces_map'].pop(config_port_indices[iface])
            self.ptfadapter.ptf_port_set.remove(config_port_indices[iface])

        self._restart_ptf_nn_agent(ptf_index)

        self.ptfadapter.reinit()

    def _restart_ptf_nn_agent(self, ptf_index=0):
        """
        Restart ptf_nn_agent
        """
        ptfhost = self.ptfhosts[ptf_index]
        ptfhost.template(src=self.ptf_nn_agent_template, dest=PTF_NN_AGENT_CONF)
        ptfhost.command('supervisorctl reread')
        ptfhost.command('supervisorctl update')
        ptfhost.command('supervisorctl restart ptf_nn_agent')
