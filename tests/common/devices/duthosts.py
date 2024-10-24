import logging
import sys

from tests.common.devices.multi_asic import MultiAsicSonicHost
from tests.common.helpers.parallel_utils import is_initial_checks_active

logger = logging.getLogger(__name__)
NON_INITIAL_CHECKS_STAGE = "non_initial_checks"
INITIAL_CHECKS_STAGE = "initial_checks"


class DutHosts(object):
    """ Represents all the DUTs (nodes) in a testbed. class has 3 important attributes:
    nodes: List of all the MultiAsicSonicHost instances for all the SONiC nodes (or cards for chassis)
           in a multi-dut testbed
    frontend_nodes: subset of nodes and holds list of MultiAsicSonicHost instances for DUTs with
                    front-panel ports (like linecards in chassis)
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
               a dictionary with key being the MultiAsicSonicHost's hostname,
               and value being the output of ansible module on that MultiAsicSonicHost
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

    def __init__(self, ansible_adhoc, tbinfo, request, duts, target_hostname=None, is_parallel_leader=False):
        """ Initialize a multi-dut testbed with all the DUT's defined in testbed info.

        Args:
            ansible_adhoc: The pytest-ansible fixture
            tbinfo - Testbed info whose "duts" holds the hostnames for the DUT's in the multi-dut testbed.
            duts - list of DUT hostnames from the `--host-pattern` CLI option. Can be specified if only a subset of
                   DUTs in the testbed should be used

        """
        self.ansible_adhoc = ansible_adhoc
        self.tbinfo = tbinfo
        self.request = request
        self.duts = duts
        self.is_parallel_run = target_hostname is not None
        # TODO: Initialize the nodes in parallel using multi-threads?
        if self.is_parallel_run:
            self.parallel_run_stage = NON_INITIAL_CHECKS_STAGE
            self.target_hostname = target_hostname
            self.is_parallel_leader = is_parallel_leader
            self.__initialize_nodes_for_parallel()
        else:
            self.__initialize_nodes()

    def __initialize_nodes_for_parallel(self):
        self._nodes_for_parallel_initial_checks = self._Nodes([
            MultiAsicSonicHost(
                self.ansible_adhoc,
                hostname,
                self,
                self.tbinfo['topo']['type'],
            ) for hostname in self.tbinfo["duts"]
        ])

        self._nodes_for_parallel_tests = self._Nodes([
            node for node in self._nodes_for_parallel_initial_checks if node.hostname == self.target_hostname
        ])

        self._nodes_for_parallel = (
            self._nodes_for_parallel_initial_checks if self.is_parallel_leader else self._nodes_for_parallel_tests
        )

        self._supervisor_nodes = self._Nodes([
            node for node in self._nodes_for_parallel if node.is_supervisor_node()
        ])

        self._frontend_nodes = self._Nodes([
            node for node in self._nodes_for_parallel if node.is_frontend_node()
        ])

    def __initialize_nodes(self):
        self._nodes = self._Nodes([
            MultiAsicSonicHost(
                self.ansible_adhoc,
                hostname,
                self,
                self.tbinfo['topo']['type'],
            ) for hostname in self.tbinfo["duts"] if hostname in self.duts
        ])

        self._supervisor_nodes = self._Nodes([node for node in self._nodes if node.is_supervisor_node()])
        self._frontend_nodes = self._Nodes([node for node in self._nodes if node.is_frontend_node()])

    def __should_reinit_when_parallel(self):
        return (
            self.is_parallel_leader and (
                self.parallel_run_stage == INITIAL_CHECKS_STAGE and not is_initial_checks_active(self.request) or
                self.parallel_run_stage == NON_INITIAL_CHECKS_STAGE and is_initial_checks_active(self.request)
            )
        )

    def __reinit_nodes_for_parallel(self):
        if is_initial_checks_active(self.request):
            self.parallel_run_stage = INITIAL_CHECKS_STAGE
            self._nodes_for_parallel = self._nodes_for_parallel_initial_checks
        else:
            self.parallel_run_stage = NON_INITIAL_CHECKS_STAGE
            self._nodes_for_parallel = self._nodes_for_parallel_tests

        self._supervisor_nodes = self._Nodes([node for node in self._nodes_for_parallel if node.is_supervisor_node()])
        self._frontend_nodes = self._Nodes([node for node in self._nodes_for_parallel if node.is_frontend_node()])

    @property
    def nodes(self):
        if self.is_parallel_run:
            if self.__should_reinit_when_parallel():
                self.__reinit_nodes_for_parallel()

            return self._nodes_for_parallel
        else:
            return self._nodes

    @property
    def supervisor_nodes(self):
        return self._supervisor_nodes

    @property
    def frontend_nodes(self):
        return self._frontend_nodes

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
        unicode_type = str if sys.version_info.major >= 3 else unicode      # noqa F821
        if type(index) == int:
            return self.nodes[index]
        elif type(index) in [str, unicode_type]:
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

    def __repr__(self):
        return self.nodes.__repr__()

    def config_facts(self, *module_args, **complex_args):
        result = {}
        for node in self.nodes:
            complex_args['host'] = node.hostname
            result[node.hostname] = node.config_facts(*module_args, **complex_args)['ansible_facts']
        return result

    def reset(self):
        self.__initialize_nodes()
