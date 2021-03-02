import logging

from tests.common.devices.multi_asic import MultiAsicSonicHost

logger = logging.getLogger(__name__)


class DutHosts(object):
    """ Represents all the DUTs (nodes) in a testbed. class has 3 important attributes:
    nodes: List of all the MultiAsicSonicHost instances for all the SONiC nodes (or cards for chassis) in a multi-dut testbed
    frontend_nodes: subset of nodes and holds list of MultiAsicSonicHost instances for DUTs with front-panel ports (like linecards in chassis
    supervisor_nodes: subset of nodes and holds list of MultiAsicSonicHost instances for supervisor cards.
    """
    class _Nodes(list):
        """ Internal class representing a list of MultiAsicSonicHosts """
        def _run_on_nodes(self, *module_args, **complex_args):
            """ Delegate the call to each of the nodes, return the results in a dict."""
            return {node.hostname: getattr(node, self.attr)(*module_args, **complex_args) for node in self}

        def __getattr__(self, attr):
            """ To support calling ansible modules on a list of MultiAsicSonicHost
            Args:
                attr: attribute to get

            Returns:
               a dictionary with key being the MultiAsicSonicHost's hostname, and value being the output of ansible module
               on that MultiAsicSonicHost
            """
            self.attr = attr
            return self._run_on_nodes

        def __eq__(self, o):
            """ To support eq operator on the DUTs (nodes) in the testbed """
            return list.__eq__(o)

        def __ne__(self, o):
            """ To support ne operator on the DUTs (nodes) in the testbed """
            return list.__ne__(o)

        def __hash__(self):
            """ To support hash operator on the DUTs (nodes) in the testbed """
            return list.__hash__()

    def __init__(self, ansible_adhoc, tbinfo):
        """ Initialize a multi-dut testbed with all the DUT's defined in testbed info.

        Args:
            ansible_adhoc: The pytest-ansible fixture
            tbinfo - Testbed info whose "duts" holds the hostnames for the DUT's in the multi-dut testbed.

        """
        # TODO: Initialize the nodes in parallel using multi-threads?
        self.nodes = self._Nodes([MultiAsicSonicHost(ansible_adhoc, hostname) for hostname in tbinfo["duts"]])
        self.supervisor_nodes = self._Nodes([node for node in self.nodes if node.is_supervisor_node()])
        self.frontend_nodes = self._Nodes([node for node in self.nodes if node.is_frontend_node()])

    def __getitem__(self, index):
        """To support operations like duthosts[0] and duthost['sonic1_hostname']

        Args:
            index (int or string): Index or hostname of a duthost.

        Raises:
            KeyError: Raised when duthost with supplied hostname is not found.
            IndexError: Raised when duthost with supplied index is not found.

        Returns:
            [MultiAsicSonicHost]: Returns the specified duthost in duthosts. It is an instance of MultiAsicSonicHost.
        """
        if type(index) == int:
            return self.nodes[index]
        elif type(index) in [ str, unicode ]:
            for node in self.nodes:
                if node.hostname == index:
                    return node
            raise KeyError("No node has hostname '{}'".format(index))
        else:
            raise IndexError("Bad index '{}' type {}".format(index, type(index)))

    # Below method are to support treating an instance of DutHosts as a list
    def __iter__(self):
        """ To support iteration over all the DUTs (nodes) in the testbed"""
        return iter(self.nodes)

    def __len__(self):
        """ To support length of the number of DUTs (nodes) in the testbed """
        return len(self.nodes)

    def __eq__(self, o):
        """ To support eq operator on the DUTs (nodes) in the testbed """
        return self.nodes.__eq__(o)

    def __ne__(self, o):
        """ To support ne operator on the DUTs (nodes) in the testbed """
        return self.nodes.__ne__(o)

    def __hash__(self):
        """ To support hash operator on the DUTs (nodes) in the testbed """
        return self.nodes.__hash__()

    def __getattr__(self, attr):
        """To support calling ansible modules directly on all the DUTs (nodes) in the testbed
         Args:
            attr: attribute to get

        Returns:
            a dictionary with key being the MultiAsicSonicHost's hostname, and value being the output of ansible module
            on that MultiAsicSonicHost
        """
        return getattr(self.nodes, attr)

    def config_facts(self, *module_args, **complex_args):
        result = {}
        for node in self.nodes:
            complex_args['host'] = node.hostname
            result[node.hostname] = node.config_facts(*module_args, **complex_args)['ansible_facts']
        return result
