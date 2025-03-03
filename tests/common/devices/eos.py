import ipaddress
import json
import logging
import re
import os

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


def _raise_err(msg):
    logger.error(msg)
    raise Exception(msg)


FEC_MAP = {
    'fc': 'fire-code',
    'rs': 'reed-solomon'
}


class EosHost(AnsibleHostBase):
    """
    @summary: Class for Eos switch

    For running ansible module on the Eos switch
    """

    def __init__(self, ansible_adhoc, hostname, eos_user, eos_passwd,
                 shell_user=None, shell_passwd=None, gather_facts=False):
        '''Initialize an object for interacting with EoS type device using ansible modules

        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the EOS device
            eos_user (string): Username for accessing the EOS CLI interface
            eos_passwd (string): Password for the eos_user
            shell_user (string, optional): Username for accessing the Linux shell CLI interface. Defaults to None.
            shell_passwd (string, optional): Password for the shell_user. Defaults to None.
            gather_facts (bool, optional): Whether to gather some basic facts. Defaults to False.
        '''
        self.eos_user = eos_user
        self.eos_passwd = eos_passwd
        self.shell_user = shell_user
        self.shell_passwd = shell_passwd
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local',
                                       host_pattern="localhost")["localhost"]

    def __getattr__(self, module_name):
        if module_name.startswith('eos_'):
            evars = {
                'ansible_connection': 'network_cli',
                'ansible_network_os': 'eos',
                'ansible_user': self.eos_user,
                'ansible_password': self.eos_passwd,
                'ansible_ssh_user': self.eos_user,
                'ansible_ssh_pass': self.eos_passwd,
                'ansible_become_method': 'enable'
            }
        else:
            if not self.shell_user or not self.shell_passwd:
                raise Exception("Please specify shell_user and shell_passwd for {}".format(self.hostname))
            evars = {
                'ansible_connection': 'ssh',
                'ansible_network_os': 'linux',
                'ansible_user': self.shell_user,
                'ansible_password': self.shell_passwd,
                'ansible_ssh_user': self.shell_user,
                'ansible_ssh_pass': self.shell_passwd,
                'ansible_become_method': 'sudo'
            }
        self.host.options['variable_manager'].extra_vars.update(evars)
        return super(EosHost, self).__getattr__(module_name)

    def __str__(self):
        return '<EosHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def shutdown(self, interface_name):
        out = self.eos_config(
            lines=['shutdown'],
            parents=['interface {}'.format(interface_name)])
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def shutdown_multiple(self, interfaces):
        intf_str = ','.join(interfaces)
        return self.shutdown(intf_str)

    def no_shutdown(self, interface_name):
        out = self.eos_config(
            lines=['no shutdown'],
            parents=['interface {}'.format(interface_name)])
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def no_shutdown_multiple(self, interfaces):
        intf_str = ','.join(interfaces)
        return self.no_shutdown(intf_str)

    def is_lldp_disabled(self):
        """
        Checks if LLDP is enabled by neighbors
        Returns True if disabled (i.e. neighbors absent)
        Returns False if enabled (i.e. found neighbors)
        """
        command = 'show lldp neighbors | json'
        output = self.eos_command(commands=[command])['stdout']
        logger.debug(f'lldp neighbors returned: {output}')
        # check for empty output -> ['']
        if output is None or (len(output) == 1 and len(output[0]) == 0):
            return True
        return False

    def check_intf_link_state(self, interface_name):
        """
        This function returns link oper status
            e.g. cable not connected:
                     Ethernet1/1 is down, line protocol is notpresent (notconnect)
                 link is admin down(cable not present):
                     Ethernet1/1 is administratively down, line protocol is notpresent (disabled)
                 link is admin down(cable present):
                     Ethernet2/1 is administratively down, line protocol is down (disabled)
                 link is admin up&oper up:
                     Ethernet2/1 is up, line protocol is up (connected)
                 link is admin up&oper down:
                     Ethernet2/1 is down, line protocol is down (notconnect)
        In conclusion:
            connected = admin up & oper up
            disabled  = admin down
            notconnect= admin up & oper down
        """
        show_int_result = self.eos_command(
            commands=['show interface %s | json' % interface_name])
        int_status = show_int_result['stdout'][0]['interfaces'][interface_name]['interfaceStatus']
        return int_status == 'connected'

    def links_status_down(self, ports):
        show_int_result = self.eos_command(commands=['show interface status'])
        for output_line in show_int_result['stdout_lines'][0]:
            """
            Note:
            (Pdb) output_line
            u'Et33/1     lc-1-Ethernet0            notconnect   1134     full   100G   100GBASE-CR4
            e.g.
            (Pdb) output_line.split(' ')[0]
            u'Et1/1'
            """
            output_port = output_line.split(' ')[0].replace('Et', 'Ethernet')
            # Only care about port that connect to current DUT
            if output_port in ports:
                if 'notconnect' in output_line:
                    logging.info("Interface {} is down on {}".format(output_port, self.hostname))
                    continue
                if 'connected' in output_line:
                    logging.info("Interface {} is up on {}".format(output_port, self.hostname))
                    return False
                else:
                    logging.info("Please check status for interface {} on {}".format(output_port, self.hostname))
                    return False
        return True

    def links_status_up(self, ports):
        show_int_result = self.eos_command(commands=['show interface status'])
        for output_line in show_int_result['stdout_lines'][0]:
            """
            Note:
            (Pdb) output_line
            u'Et33/1     lc-1-Ethernet0            notconnect   1134     full   100G   100GBASE-CR4
            e.g.
            (Pdb) output_line.split(' ')[0]
            u'Et1/1'
            """
            output_port = output_line.split(' ')[0].replace('Et', 'Ethernet')
            # Only care about port that connect to current DUT
            if output_port in ports:
                if 'connected' in output_line:
                    logging.info("Interface {} is up on {}".format(output_port, self.hostname))
                    continue
                if 'notconnect' in output_line:
                    logging.info("Interface {} is down on {}".format(output_port, self.hostname))
                    return False
                else:
                    logging.info("Please check status for interface {} on {}".format(output_port, self.hostname))
                    return False
        return True

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.eos_config(
            lines=['lacp rate %s' % mode],
            parents='interface %s' % interface_name)

        # FIXME: out['failed'] will be False even when a command is deprecated, so we have to check out['changed']
        # However, if the lacp rate is already in expected state, out['changed'] will be False and treated as
        # error.
        if out['failed'] is True or out['changed'] is False:
            # new eos deprecate lacp rate and use lacp timer command
            out = self.eos_config(
                lines=['lacp timer %s' % mode],
                parents='interface %s' % interface_name)
            if out['changed'] is False:
                logging.warning("Unable to set interface [%s] lacp timer to [%s]" % (interface_name, mode))
                raise Exception("Unable to set interface [%s] lacp timer to [%s]" % (interface_name, mode))
            else:
                logging.info("Set interface [%s] lacp timer to [%s]" % (interface_name, mode))
        else:
            logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def kill_bgpd(self):
        out = self.eos_config(lines=['agent Rib shutdown'])
        return out

    def start_bgpd(self):
        out = self.eos_config(lines=['no agent Rib shutdown'])
        return out

    def no_shutdown_bgp(self, asn):
        out = self.eos_config(
            lines=['no shut'],
            parents=['router bgp {}'.format(asn)])
        logging.info('No shut BGP [%s]' % asn)
        return out

    def no_shutdown_bgp_neighbors(self, asn, neighbors=[]):
        if not neighbors:
            return

        out = self.eos_config(
            lines=['no neighbor {} shutdown'.format(neighbor) for neighbor in neighbors],
            parents=['router bgp {}'.format(asn)]
        )
        logging.info('No shut BGP neighbors: {}'.format(json.dumps(neighbors)))
        return out

    def check_bgp_session_state(self, neigh_ips, neigh_desc, state="established"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param neigh_desc: bgp neighbor description
        @param state: target state
        """
        neigh_ips = [ip.lower() for ip in neigh_ips]
        neigh_ips_ok = []
        neigh_desc_ok = []
        neigh_desc_available = False

        out_v4 = self.eos_command(
            commands=['show ip bgp summary | json'])
        logging.info("ip bgp summary: {}".format(out_v4))

        out_v6 = self.eos_command(
            commands=['show ipv6 bgp summary | json'])
        logging.info("ipv6 bgp summary: {}".format(out_v6))

        # when bgpd is inactive, the bgp summary output: [{u'vrfs': {}, u'warnings': [u'BGP inactive']}]
        if 'BGP inactive' in out_v4['stdout'][0].get('warnings', '') \
                and 'BGP inactive' in out_v6['stdout'][0].get('warnings', ''):
            return False

        try:
            for k, v in list(out_v4['stdout'][0]['vrfs']['default']['peers'].items()):
                if v['peerState'].lower() == state.lower():
                    if k in neigh_ips:
                        neigh_ips_ok.append(k)
                    if 'description' in v:
                        neigh_desc_available = True
                        if v['description'] in neigh_desc:
                            neigh_desc_ok.append(v['description'])

            for k, v in list(out_v6['stdout'][0]['vrfs']['default']['peers'].items()):
                if v['peerState'].lower() == state.lower():
                    if k.lower() in neigh_ips:
                        neigh_ips_ok.append(k)
                    if 'description' in v:
                        neigh_desc_available = True
                        if v['description'] in neigh_desc:
                            neigh_desc_ok.append(v['description'])
        except KeyError:
            # ignore any KeyError due to unexpected BGP summary output
            pass

        logging.info("neigh_ips_ok={} neigh_desc_available={} neigh_desc_ok={}"
                     .format(str(neigh_ips_ok), str(neigh_desc_available), str(neigh_desc_ok)))
        if neigh_desc_available:
            if len(neigh_ips) == len(neigh_ips_ok) and len(neigh_desc) == len(neigh_desc_ok):
                return True
        else:
            if len(neigh_ips) == len(neigh_ips_ok):
                return True

        return False

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} \
                            -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
                                           fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))

    def get_route(self, prefix):
        cmd = 'show ip bgp' if ipaddress.ip_network(prefix.encode().decode()).version == 4 else 'show ipv6 bgp'
        return self.eos_command(commands=[{
            'command': '{} {}'.format(cmd, prefix),
            'output': 'json'
        }])['stdout'][0]

    def run_command_json(self, cmd):
        return self.eos_command(commands=[{
            'command': '{}'.format(cmd),
            'output': 'json'
        }])['stdout'][0]

    def run_command(self, cmd):
        return self.eos_command(commands=[cmd])

    def run_command_list(self, cmd):
        return self.eos_command(commands=cmd)

    def get_auto_negotiation_mode(self, interface_name):
        output = self.eos_command(commands=[{
            'command': 'show interfaces %s status' % interface_name,
            'output': 'json'
        }], module_ignore_errors=True)
        if self._has_cli_cmd_failed(output):
            logger.info('Failed to get auto neg state for {}: {}'.format(interface_name, output['msg']))
            return None
        autoneg_enabled = output['stdout'][0]['interfaceStatuses'][interface_name]['autoNegotiateActive']
        return autoneg_enabled

    def get_version(self):
        return self.eos_command(commands=["show version"])

    def _reset_port_speed(self, interface_name):
        out = self.eos_config(
                lines=['default speed'],
                parents=['interface {}'.format(interface_name)])
        logger.debug('Reset port speed for %s: %s' % (interface_name, out))
        return not self._has_cli_cmd_failed(out)

    def set_auto_negotiation_mode(self, interface_name, enabled):
        if self.get_auto_negotiation_mode(interface_name) == enabled:
            return True

        if enabled:
            speed_to_advertise = self.get_supported_speeds(interface_name)[-1]
            speed_to_advertise = speed_to_advertise[:-3] + 'gfull'
            out = self.eos_config(
                lines=['speed auto %s' % speed_to_advertise],
                parents=['interface {}'.format(interface_name)])
            logger.debug('Set auto neg to {} for port {}: {}'.format(enabled, interface_name, out))
            return not self._has_cli_cmd_failed(out)
        return self._reset_port_speed(interface_name)

    def get_speed(self, interface_name):
        output = self.eos_command(commands=['show interfaces %s transceiver properties' % interface_name])
        found_txt = re.search(r'Operational Speed: (\S+)', output['stdout'][0])
        if found_txt is None:
            _raise_err('Not able to extract interface %s speed from output: %s' % (interface_name, output['stdout']))

        v = found_txt.groups()[0]
        return v[:-1] + '000'

    def _has_cli_cmd_failed(self, cmd_output_obj):
        err_out = False
        if 'stdout' in cmd_output_obj:
            stdout = cmd_output_obj['stdout']
            msg = stdout[-1] if type(stdout) == list else stdout
            err_out = 'Cannot advertise' in msg

        return ('failed' in cmd_output_obj and cmd_output_obj['failed']) or err_out

    def set_speed(self, interface_name, speed):

        if not speed:
            # other set_speed implementations advertise port speeds when speed=None
            # but in EOS autoneg activation and speeds advertisement is done via a single CLI cmd
            # so this branch left nop intentionally
            return True

        speed_mode = 'auto' if self.get_auto_negotiation_mode(interface_name) else 'forced'
        speed = speed[:-3] + 'gfull'

        out = self.host.eos_command(commands=[
            'conf',
            'interface %s' % interface_name,
            {
                'command': 'speed {} {}'.format(speed_mode, speed),
                'prompt': ['Do you wish to proceed with this command'],
                'answer': ['y']}
            ])[self.hostname]
        logger.debug('Set force speed for port {} : {}'.format(interface_name, out))
        return not self._has_cli_cmd_failed(out)

    def get_supported_speeds(self, interface_name):
        """Get supported speeds for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            list: A list of supported speed strings or None
        """
        commands = ['show interfaces {} capabilities'.format(interface_name),
                    'show interface {} hardware'.format(interface_name)]
        for command in commands:
            output = self.eos_command(commands=[command])
            found_txt = re.search("Speed/Duplex: (.+)", output['stdout'][0])
            if found_txt is not None:
                break

        if found_txt is None:
            _raise_err('Failed to find port speeds list in output: %s' % output['stdout'])

        speed_list = found_txt.groups()[0]
        speed_list = speed_list.split(',')
        speed_list.remove('auto')

        def extract_speed_only(v):
            return re.match(r'\d+', v.strip()).group() + '000'
        return list(map(extract_speed_only, speed_list))

    def get_dut_iface_mac(self, interface_name):
        """
        Gets the MAC address of specified interface.

        Returns:
            str: The MAC address of the specified interface, or None if it is not found.
        """
        try:
            command = 'show interfaces {} | json'.format(interface_name)
            output = self.eos_command(commands=[command])['stdout'][0]
            mac = output["interfaces"][interface_name]["physicalAddress"]
            return mac
        except Exception as e:
            logger.error('Failed to get MAC address for interface "{}", exception: {}'.format(interface_name, repr(e)))
            return None

    def iface_macsec_ok(self, interface_name):
        """
        Check if macsec is functional on specified interface.

        Returns: True or False
        """
        try:
            command = 'show mac security interface {} | json'.format(interface_name)
            output = self.eos_command(commands=[command])['stdout'][0]
            if interface_name in output["interfaces"]:
                return output["interfaces"][interface_name]["controlledPort"]
            return False
        except Exception as e:
            logger.error('Failed to get macsec status for interface "{}", exception: {}'
                         .format(interface_name, repr(e)))
            return False

    def _append_port_fec(self, interface_name, mode):
        def _exec(cmd):
            self.host.eos_command(commands=[
                'conf',
                'interface %s' % interface_name,
                cmd
            ])

        if mode:
            _exec('error-correction encoding ' + FEC_MAP[mode])
        else:
            _exec('no error-correction encoding')

    def set_port_fec(self, interface_name, mode):
        # reset FEC
        self._append_port_fec(interface_name, None)

        if mode:
            self._append_port_fec(interface_name, mode)

    def rm_member_from_channel_grp(self, interface_name, channel_group):
        out = self.eos_config(
            lines=['no channel-group {} mode active'.format(channel_group)],
            parents=['interface {}'.format(interface_name)])
        logging.info('Remove interface {} from channel_group {}'.format(interface_name, channel_group))
        return out

    def add_member_to_channel_grp(self, interface_name, channel_group):
        out = self.eos_config(
            lines=['channel-group {} mode active'.format(channel_group)],
            parents=['interface {}'.format(interface_name)])
        logging.info('Add interface {} to channel_group {}'.format(interface_name, channel_group))
        return out

    def ping_dest(self, dest):
        """
        Check if ping to dest IP sucess or not

        Returns: True or False
        """
        try:
            command = 'ping {} repeat 5'.format(dest)
            output = self.eos_command(commands=[command])['stdout'][0]
            return ' 0% packet loss' in output
        except Exception as e:
            logger.error('command {} failed. exception: {}'.format(command, repr(e)))
        return False

    def get_portchannel_by_member(self, member_intf):
        try:
            command = 'show lacp interface {} | json'.format(member_intf)
            output = self.eos_command(commands=[command])['stdout'][0]
            for port in list(output['portChannels'].keys()):
                return port
        except Exception as e:
            logger.error('Failed to get PortChannel for member interface "{}", exception: {}'.format(
                        member_intf, repr(e)
                        ))
            return None

    def load_configuration(self, config_file, backup_file=None):
        if backup_file is None:
            out = self.eos_config(
                src=config_file,
                replace='config',
            )
        else:
            out = self.eos_config(
                src=config_file,
                replace='line',
                backup='yes',
                backup_options={
                    'filename': os.path.basename(backup_file),
                    'dir_path': os.path.dirname(backup_file),
                }
            )
        return not self._has_cli_cmd_failed(out)

    def no_isis_interface(self, isis_instance, interface):
        out = self.eos_config(
            lines=['no isis enable'],
            parents=['interface {}'.format(interface)])
        return not self._has_cli_cmd_failed(out)

    def set_isis_metric(self, interface, metric):
        out = self.eos_config(
            lines=['isis metric {}'.format(metric)],
            parents=['interface {}'.format(interface)])
        return not self._has_cli_cmd_failed(out)

    def no_isis_metric(self, interface):
        out = self.eos_config(
            lines=['no isis metric'],
            parents=['interface {}'.format(interface)])
        return not self._has_cli_cmd_failed(out)

    def set_interface_lacp_time_multiplier(self, interface_name, multiplier):
        out = self.eos_config(
            lines=['lacp timer multiplier %d' % multiplier],
            parents='interface %s' % interface_name)

        if out['failed'] is True or out['changed'] is False:
            logging.warning("Unable to set interface [%s] lacp timer multiplier to [%d]" % (interface_name, multiplier))
        else:
            logging.info("Set interface [%s] lacp timer to [%d]" % (interface_name, multiplier))
        return out

    def no_lacp_time_multiplier(self, interface_name):
        out = self.eos_config(
            lines=['no lacp timer multiplier'],
            parents=['interface {}'.format(interface_name)])
        logging.info('Reset lacp timer to default for interface [%s]' % interface_name)
        return out
