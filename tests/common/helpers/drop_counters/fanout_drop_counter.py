import re
import logging
from abc import abstractmethod

logger = logging.getLogger(__name__)


MAX_OPENFLOW_RULE_ID = 65535
DEVICE_PORT_VLANS = 'device_port_vlans'
TRUNK = 'Trunk'
MODE = "mode"
FAILED = 'failed'
INVOCATION = 'invocation'
STDOUT = 'stdout'


class FanoutDropCounter:
    def __init__(self):
        self.fanout_graph_facts = None

    @abstractmethod
    def prepare_config(self, fanout_graph_facts, match_mac, set_mac, eth_field):
        pass

    @abstractmethod
    def restore_drop_counter_config(self):
        pass


class FanoutOnyxDropCounter(FanoutDropCounter):
    def __init__(self, onyx_switch):
        FanoutDropCounter.__init__(self)
        self.onyx_switch = onyx_switch

    def prepare_config(self, fanout_graph_facts, match_mac, set_mac, eth_field):
        self.fanout_graph_facts = fanout_graph_facts
        trunk_port = self._get_trunk_port_to_server()
        openflow_port_id = self._get_openflow_port_id(trunk_port)
        cmd = 'openflow add-flows {rule_id} table=0,priority=10,dl_src={match_mac},' \
              'in_port={openflow_port_id},actions=set_field:{set_mac}->{eth_field}'
        out = self.onyx_switch.host.onyx_config(lines=[cmd.format(
            rule_id=MAX_OPENFLOW_RULE_ID, match_mac=match_mac,
            openflow_port_id=openflow_port_id, set_mac=set_mac, eth_field=eth_field)])
        if FAILED in out and out[FAILED]:
            logger.error('Failed to set openflow rule - {}'.format(out['msg']))
            return False
        logger.debug('Setting openflow rule succeed from onyx: {}'.format(out))
        return True

    def _get_trunk_port_to_server(self):
        fanout_trunk_port = None
        for iface, iface_info in self.fanout_graph_facts[self.onyx_switch.hostname][DEVICE_PORT_VLANS].items():
            if iface_info[MODE] == TRUNK:
                fanout_trunk_port = '/'.join(iface.split('/')[1:])
                break
        return fanout_trunk_port

    def _get_openflow_port_id(self, port):
        out = self.onyx_switch.host.onyx_command(
            commands=['show openflow'])[self.onyx_switch.hostname]
        if FAILED in out and out[FAILED]:
            logger.error('Failed to get openflow table- {}'.format(out['msg']))
        show_openflow = out[STDOUT][0]
        return self._get_openflow_port_id_from_show_openflow(show_openflow, port)

    @staticmethod
    def _get_openflow_port_id_from_show_openflow(show_openflow, port):
        regexp = 'Eth1/{}\s*OF-(\d+)'.format(port)
        match = re.search(regexp, show_openflow)
        if match:
            return match.group(1)
        else:
            raise Exception('Can not find openflow port id for port {}. Show openflow output: {}'.format(
                port, show_openflow))

    def restore_drop_counter_config(self):
        """Delete configuraion for drop_packets tests if fanout has onyx OS
        Affected tests:test_equal_smac_dmac_drop, test_multicast_smac_drop

        Returns:
            boolean: True if success. Usually, the method return False only if the operation
            is not supported or failed.
        """
        cmd = 'openflow del-flows {}'.format(MAX_OPENFLOW_RULE_ID)
        out = self.onyx_switch.host.onyx_config(lines=[cmd])
        if FAILED in out and out[FAILED]:
            logger.error('Failed to remove openflow rule - {}'.format(out['msg']))
            return False
        logger.debug('Removing openflow rule succeed from onyx: {}'.format(out))
        return True
