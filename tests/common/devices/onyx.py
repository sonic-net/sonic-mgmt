import json
import logging
from tests.common.devices.base import AnsibleHostBase
from tests.common.helpers.drop_counters.fanout_drop_counter import FanoutOnyxDropCounter

logger = logging.getLogger(__name__)


class OnyxHost(AnsibleHostBase):
    """
    @summary: Class for ONYX switch

    For running ansible module on the ONYX switch
    """

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname, connection="network_cli")
        evars = {'ansible_connection':'network_cli',
                'ansible_network_os':'onyx',
                'ansible_user': user,
                'ansible_password': passwd,
                'ansible_ssh_user': user,
                'ansible_ssh_pass': passwd,
                'ansible_become_method': 'enable'
                }

        self.host.options['variable_manager'].extra_vars.update(evars)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]
        self.fanout_helper = FanoutOnyxDropCounter(self)

    def __str__(self):
        return '<OnyxHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['shutdown'],
            parents='interface %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['no shutdown'],
            parents='interface %s' % interface_name)
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def check_intf_link_state(self, interface_name):
        show_int_result = self.host.onyx_command(
            commands=['show interfaces ethernet {} | include "Operational state"'.format(interface_name)])[self.hostname]
        return 'Up' in show_int_result['stdout'][0]

    def command(self, cmd):
        out = self.host.onyx_command(commands=[cmd])
        return out

    def config(self, cmd):
        out = self.host.onyx_config(commands=[cmd])
        return out

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.host.onyx_config(
            lines=['lacp rate %s' % mode],
            parents='interface %s' % interface_name)
        logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        """
        Execute ansible playbook with specified parameters
        """
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
            fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))

    def get_supported_speeds(self, interface_name):
        """Get supported speeds for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            list: A list of supported speed strings or None
        """
        show_int_result = self.host.onyx_command(
            commands=['show interfaces {} | include "Supported speeds"'.format(interface_name)])[self.hostname]

        if 'failed' in show_int_result and show_int_result['failed']:
            logger.error('Failed to get supported speed for {} - {}'.format(interface_name, show_int_result['msg']))
            return None

        out = show_int_result['stdout'][0].strip()
        logger.debug('Get supported speeds for port {} from onyx: {}'.format(interface_name, out))
        if not out:
            return None

        # The output should be something like: "Supported speeds:1G 10G 25G 50G"
        speeds = out.split(':')[-1].split()
        return list(set([x.split('G')[0] + '000' for x in speeds]))

    def set_auto_negotiation_mode(self, interface_name, mode):
        """Set auto negotiation mode for a given interface

        Args:
            interface_name (str): Interface name
            mode (boolean): True to enable auto negotiation else disable

        Returns:
            boolean: False if the operation is not supported else True
        """
        if mode:
            return self.set_speed(interface_name, None)
        else:
            speed = self.get_speed(interface_name)
            out = self.host.onyx_config(
                lines=['shutdown', 'speed {}G no-autoneg'.format(speed[:-3]), 'no shutdown'],
                parents='interface %s' % interface_name)[self.hostname]

            if 'failed' in out and out['failed']:
                logger.error('Failed to set auto neg to False for port {} - {}'.format(interface_name, out['msg']))
                return False
            logger.debug('Set auto neg to False for port {} from onyx: {}'.format(interface_name, out))
        return True

    def get_auto_negotiation_mode(self, interface_name):
        """Get auto negotiation mode for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            boolean: True if auto negotiation mode is enabled else False. Return None if
            the auto negotiation mode is unknown or unsupported.
        """
        show_int_result = self.host.onyx_command(
            commands=['show interfaces {} | include "Auto-negotiation"'.format(interface_name)])[self.hostname]

        if 'failed' in show_int_result and show_int_result['failed']:
            logger.error('Failed to get auto neg mode for port {} - {}'.format(interface_name, show_int_result['msg']))
            return None

        out = show_int_result['stdout'][0].strip()
        logger.debug('Get auto negotiation mode for port {} from onyx: {}'.format(interface_name, out))
        if not out:
            return None

        # The output should be something like: "Auto-negotiation:Enabled"
        return 'Enabled' in out

    def set_speed(self, interface_name, speed):
        """Set interface speed according to the auto negotiation mode. When auto negotiation mode
        is enabled, set the advertised speeds; otherwise, set the force speed.

        Args:
            interface_name (str): Interface name
            speed (str): SONiC style interface speed. E.g, 1G=1000, 10G=10000, 100G=100000. If the speed
            is None and auto negotiation mode is enabled, it sets the advertised speeds to all supported
            speeds.

        Returns:
            boolean: True if success. Usually, the method return False only if the operation
            is not supported or failed.
        """
        autoneg_mode = self.get_auto_negotiation_mode(interface_name)
        if not speed:
            speed = 'auto'
        else:
            speed = speed[:-3] + 'G'
        if autoneg_mode or speed == 'auto':
            out = self.host.onyx_config(
                    lines=['shutdown', 'speed {}'.format(speed), 'no shutdown'],
                    parents='interface %s' % interface_name)[self.hostname]
            if 'failed' in out and out['failed']:
                logger.error('Failed to set speed for port {} - {}'.format(interface_name, out['msg']))
                return False
            logger.debug('Set auto speed for port {} from onyx: {}'.format(interface_name, out))
            return True
        else:
            out = self.host.onyx_config(
                lines=['shutdown', 'speed {} no-autoneg'.format(speed), 'no shutdown'],
                parents='interface %s' % interface_name)[self.hostname]
            if 'failed' in out and out['failed']:
                logger.error('Failed to set speed for port {} - {}'.format(interface_name, out['msg']))
                return False
            logger.debug('Set force speed for port {} from onyx: {}'.format(interface_name, out))
            return True

    def get_speed(self, interface_name):
        """Get interface speed

        Args:
            interface_name (str): Interface name

        Returns:
            str: SONiC style interface speed value. E.g, 1G=1000, 10G=10000, 100G=100000.
        """
        show_int_result = self.host.onyx_command(
            commands=['show interfaces {} | include "Actual speed"'.format(interface_name)])[self.hostname]

        if 'failed' in show_int_result and show_int_result['failed']:
            logger.error('Failed to get speed for port {} - {}'.format(interface_name, show_int_result['msg']))
            return False

        out = show_int_result['stdout'][0].strip()
        logger.debug('Get speed for port {} from onyx: {}'.format(interface_name, out))
        if not out:
            return None

        # The output should be something like: "Actual speed:50G"
        speed = out.split(':')[-1].strip()
        pos = speed.find('G')
        return speed[:pos] + '000'

    def prepare_drop_counter_config(self, fanout_graph_facts, match_mac, set_mac, eth_field):
        """Set configuration for drop_packets tests if fanout has onyx OS
        Affected tests:test_equal_smac_dmac_drop, test_multicast_smac_drop

        Args:
            fanout_graph_facts (dict): fixture fanout_graph_facts
            match_mac (str): mac address to match in openflow rule
            set_mac (str): mac address to which match mac should be changed
            eth_field (str): place in which replace match mac to set_mac, usually 'eth_src'

        Returns:
            boolean: True if success. Usually, the method return False only if the operation
            is not supported or failed.
        """
        return self.fanout_helper.prepare_config(fanout_graph_facts, match_mac, set_mac, eth_field)

    def restore_drop_counter_config(self):
        """Delete configuraion for drop_packets tests if fanout has onyx OS
        Affected tests:test_equal_smac_dmac_drop, test_multicast_smac_drop

        Returns:
            boolean: True if success. Usually, the method return False only if the operation
            is not supported or failed.
        """
        return self.fanout_helper.restore_drop_counter_config()
