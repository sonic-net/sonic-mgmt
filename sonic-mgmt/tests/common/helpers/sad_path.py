""" Module contains sad path operations. """

import datetime
import logging

from itertools import groupby, chain, islice

from tests.common.platform.device_utils import fanout_switch_port_lookup

logger = logging.getLogger(__name__)


class SadOperation(object):
    """ SadOperation interface class. """

    def setup(self, test_data):
        """ Perform sad path setup operations and modify the test_data
        passed to PTF script accordingly. """
        raise NotImplementedError

    # TODO: split verification into to phases - preboot verify and postboot verify.
    # Currently there is no verification in sad_path.py done prior to warm-reboot.
    # So it could be a race when sad operation takes a while to affect the testbed
    # but we are doing warm-reboot prior to that. Currently the preparation in
    # advanced-reboot.py is long enough so that won't happen.
    def verify(self):
        """ Verify handler that runs after warm-reboot completes.
        Checks sad path operataions result after warm-reboot. """
        raise NotImplementedError

    def revert(self):
        """ Revert changes done in setup. """
        raise NotImplementedError


class Selector(object):
    """ Selector interface provides a select() method
    to choose test objects from the input list. """

    def select(self, objlist):
        """ Choose test objects from objlist. """
        raise NotImplementedError


class PhyPropsPortSelector(Selector):
    """ Select the port based on physical port settings. """

    def __init__(self, duthost, count):
        self.duthost = duthost
        self.count = count

    def select(self, objlist):
        port_table = self.duthost.get_running_config_facts()["PORT"]

        def group_func(port):
            _, attrs = port
            width = len(attrs["lanes"].split(","))
            speed = attrs.get("speed")
            fec = attrs.get("fec")

            return width, speed, fec

        # For ports passed to this method group them by width, speed and fec
        # and choose <self.count> number of ports taking each from a different group.
        # If <self.count> is greater then the number of groups start over till we fill
        # the output list with the number of ports requested.
        # Assertion is raised when there are no enough ports.
        port_items = [(name, attrs) for name, attrs in port_table.items() if name in objlist]
        assert len(port_items) >= self.count, "No enough ports to test, required at least {}".format(self.count)
        groups = [list(group) for _, group in groupby(sorted(port_items, key=group_func), key=group_func)]
        return [name for name, _ in islice(chain.from_iterable(zip(*groups)), self.count)]


class DatetimeSelector(Selector):
    """ Select from list based on current datetime. """

    def __init__(self, count):
        self.count = count

    def select(self, objlist):
        assert len(objlist) >= self.count, "Not enough elements, required at least {}".format(self.count)
        # Get some start index and select items from the list
        # starting from index till the end, if the amount is less then
        # self.count it will fill the rest starting from the beginning of
        # the list.
        index = datetime.datetime.now().day % len(objlist)
        selected = (objlist[index:] + objlist[:index])[:self.count]
        return selected


class VlanMemberDown(SadOperation):
    """ Base class for vlan member down scenarios. """

    def __init__(self, duthost, port_selector):
        self.duthost = duthost
        self.ports = port_selector.select(duthost.get_vlan_intfs())

    def setup(self, test_data):
        vlans = test_data["vlan_interfaces"]
        # Exclude down vlan members
        for vlan in vlans.values():
            vlan["members"] = list(set(vlan["members"]) - set(self.ports))


class DutVlanMemberDown(VlanMemberDown):
    """ Sad path test case to verify warm-reboot when vlan member port goes administartively down. """

    def __init__(self, duthost, port_selector):
        super(DutVlanMemberDown, self).__init__(duthost, port_selector)
        logger.info("Selected ports for DUT vlan member down case {}".format(self.ports))

    def setup(self, test_data):
        super(DutVlanMemberDown, self).setup(test_data)
        self.duthost.shutdown_multiple(self.ports)

    def verify(self):
        facts = self.duthost.show_interface(command="status", interfaces=self.ports)
        port_facts = facts["ansible_facts"]["int_status"]
        assert all([port["admin_state"] == "down" for port in port_facts.values()])

    def revert(self):
        self.duthost.no_shutdown_multiple(self.ports)

    def __str__(self):
        return "vlan_port_down:{}".format(len(self.ports))


class NeighVlanMemberDown(VlanMemberDown):
    """ Sad path test case to verify warm-reboot when vlan member port goes operationaly down
    by shutting down the corresponding port on the neighbor side. """

    def __init__(self, duthost, fanouthosts, port_selector):
        super(NeighVlanMemberDown, self).__init__(duthost, port_selector)
        self.fanouthosts = fanouthosts
        logger.info("Selected ports for neighbor vlan member down case {}".format(self.ports))

    def setup(self, test_data):
        super(NeighVlanMemberDown, self).setup(test_data)

        for port in self.ports:
            fanout, fanport = fanout_switch_port_lookup(self.fanouthosts, self.duthost.hostname, port)
            fanout.shutdown(fanport)

    def verify(self):
        facts = self.duthost.show_interface(command="status", interfaces=self.ports)
        port_facts = facts["ansible_facts"]["int_status"]
        assert all([port["oper_state"] == "down" for port in port_facts.values()])

    def revert(self):
        for port in self.ports:
            fanout, fanport = fanout_switch_port_lookup(self.fanouthosts, self.duthost.hostname, port)
            fanout.no_shutdown(fanport)

    def __str__(self):
        return "neigh_vlan_member_down:{}".format(len(self.ports))


class LagMemberDown(SadOperation):
    """ Base class for LAG member down sad path scenarios. """

    def __init__(self, duthost, nbrhosts, vm_selector, port_selector):
        super(LagMemberDown, self).__init__()
        vms = {vm: nbrhosts[vm] for vm in vm_selector.select(list(nbrhosts))}
        mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
        dut_port_to_neighbor = mg_facts["minigraph_neighbors"]
        lags = mg_facts["minigraph_portchannels"]

        # Build neighbor hostname to DUT LAG mapping and
        # DUT port to DUT LAG mapping.
        neigh_to_lag = {}
        port_to_lag = {}
        for dut_port, neigh_info in dut_port_to_neighbor.items():
            for lag in lags.values():
                if dut_port in lag["members"]:
                    neigh_to_lag[neigh_info["name"]] = lag
                    port_to_lag[dut_port] = lag

        ports = []
        for vm in vms:
            ports.extend(port_selector.select(neigh_to_lag[vm]["members"]))

        self.vms = vms
        self.ports = ports
        self.duthost = duthost
        self.nbrhosts = nbrhosts
        self.neigh_to_lag = neigh_to_lag
        self.port_to_lag = port_to_lag

    def setup(self, test_data):
        lags = test_data["portchannel_interfaces"]
        peer_dev_info = test_data["peer_dev_info"]

        # Exclude down LAG members
        for lag in lags.values():
            lag["members"] = list(set(lag["members"]) - set(self.ports))

        # Exclude VMs corresponding to down LAGs
        for vm in self.vms:
            peer_dev_info.pop(vm)

    def verify(self):
        lag_facts = self.duthost.lag_facts(host=self.duthost.hostname)["ansible_facts"]["lag_facts"]
        port_facts = self.duthost.show_interface(command="status")["ansible_facts"]["int_status"]

        for port in self.ports:
            lag = self.port_to_lag[port]
            port_stats = lag_facts["lags"][lag["name"]]["po_stats"]["ports"][port]
            assert not port_stats["runner"]["aggregator"]["selected"]

        for vm in self.vms:
            assert port_facts[self.neigh_to_lag[vm]["name"]]["oper_state"] == "down"
            nbrhost = self.nbrhosts[vm]["host"]
            # TODO: remove this hardcode, implement a mapping of DUT LAG to VM LAG.
            nbr_lag_name = "Port-Channel1"
            commands = ["show interface {} | json".format(nbr_lag_name)]
            output = nbrhost.eos_command(commands=commands)["stdout"][0]
            state = output["interfaces"][nbr_lag_name]["interfaceStatus"]
            assert state in ["notconnect"]


class DutLagMemberDown(LagMemberDown):
    """ Sad path to test warm-reboot when LAG member on DUT is shutdown
    and verify that after warm-reboot LAG member state is still down on DUT and neighbor. """

    def __init__(self, duthost, nbrhosts, vm_selector, port_selector):
        super(DutLagMemberDown, self).__init__(duthost, nbrhosts, vm_selector, port_selector)
        logger.info("Selected ports for DUT LAG member down case {}".format(self.ports))

    def setup(self, test_data):
        super(DutLagMemberDown, self).setup(test_data)
        self.duthost.shutdown_multiple(self.ports)

    def revert(self):
        self.duthost.no_shutdown_multiple(self.ports)

    def __str__(self):
        return "dut_lag_member_down:{}:{}".format(len(self.vms), len(self.ports))


class NeighLagMemberDown(LagMemberDown):
    """ Sad path to test warm-reboot when LAG member on neighbor is shutdown
    and verify that after warm-reboot LAG member state is still down on DUT and neighbor. """

    def __init__(self, duthost, nbrhosts, fanouthosts, vm_selector, port_selector):
        super(NeighLagMemberDown, self).__init__(duthost, nbrhosts, vm_selector, port_selector)
        logger.info("Selected ports for neighbor LAG member down case {}".format(self.ports))

        mg_facts = self.duthost.minigraph_facts(host=self.duthost.hostname)["ansible_facts"]
        mg_neighs = mg_facts["minigraph_neighbors"].items()

        self.fanouthosts = fanouthosts
        self.dut_port_to_nbr = {port: nbr_info["name"] for port, nbr_info in mg_neighs}
        self.dut_port_to_nbr_port = {port: nbr_info["port"] for port, nbr_info in mg_neighs}

    def setup(self, test_data):
        super(NeighLagMemberDown, self).setup(test_data)
        self._change_ports_state(bring_up=False)

    def revert(self):
        self._change_ports_state(bring_up=True)

    def _change_ports_state(self, bring_up):
        for port in self.ports:
            nbrname = self.dut_port_to_nbr[port]
            nbrport = self.dut_port_to_nbr_port[port]
            nbrhost = self.nbrhosts[nbrname]["host"]
            if bring_up:
                nbrhost.no_shutdown(nbrport)
            else:
                nbrhost.shutdown(nbrport)

            fanout, fanport = fanout_switch_port_lookup(self.fanouthosts, self.duthost.hostname, port)
            if bring_up:
                fanout.no_shutdown(fanport)
            else:
                fanout.shutdown(fanport)


    def __str__(self):
        return "neigh_lag_member_down:{}:{}".format(len(self.vms), len(self.ports))
