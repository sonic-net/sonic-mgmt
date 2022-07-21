import re
import allure
import logging

logger = logging.getLogger()


class AutoTechSupportCli(object):

    def __new__(cls, *args, **kwargs):
        release = kwargs.get('release')
        duthost = kwargs.get('duthost')
        supported_cli_classes = {'default': AutoTechSupportCliDefault(duthost),
                                 '202111': AutoTechSupportCli202111(duthost),
                                 '202205': AutoTechSupportCli202205(duthost)}

        cli_class = supported_cli_classes.get(release, supported_cli_classes['default'])
        cli_class_name = cli_class.__class__.__name__
        logger.info('Going to use auto-techsupport CLI class: {}'.format(cli_class_name))

        return cli_class


class AutoTechSupportCliDefault:

    def __init__(self, duthost):
        self.duthost = duthost

    def show_auto_techsupport_global(self):
        """
        This method execute command: "show auto-techsupport global"
        :return: command output
        """
        return self.duthost.shell('show auto-techsupport global')['stdout']

    def parse_show_auto_techsupport_global(self):
        """
        Parse output for cmd "show auto-techsupport global"
        STATE    RATE LIMIT INTERVAL (sec)    MAX TECHSUPPORT LIMIT (%)    MAX CORE LIMIT (%)    AVAILABLE MEM THRESHOLD (%)    MIN AVAILABLE MEM (Kb)    SINCE
        -------  ---------------------------  ---------------------------  --------------------  -----------------------------  ------------------------  ----------
        enabled  180                          10                           5                     10                             200                       2 days ago
        :return: dictionary with parsed result, example: {'state': 'enabled', 'rate_limit_interval': '180',
        'max_techsupport_limit': '10', 'max_core_size': '5', 'since': '2 days ago'}
        """
        with allure.step('Parsing "show auto-techsupport global" output'):
            regexp = r'(enabled|disabled)\s+(\d+)\s+(\d+.\d+|\d+)\s+(\d+.\d+|\d+)\s+(\d+)\s+(\d+)\s+(.*)'
            cmd_output = self.show_auto_techsupport_global()
            state, rate_limit_interval, max_techsupport_limit, max_core_size, avail_mem, min_avail_mem, since = \
                re.search(regexp, cmd_output).groups()
            result_dict = {'state': state, 'rate_limit_interval': rate_limit_interval,
                           'max_techsupport_limit': max_techsupport_limit, 'max_core_size': max_core_size,
                           'available_mem_threshold': avail_mem, 'min_available_mem': min_avail_mem, 'since': since}
        return result_dict

    def show_auto_techsupport_feature(self):
        """
        This method execute command: "show auto-techsupport-feature"
        :return: command output
        """
        return self.duthost.shell('show auto-techsupport-feature')['stdout']

    def parse_show_auto_techsupport_feature(self):
        """
        Parse output for cmd "show auto-techsupport-feature"
        FEATURE NAME        STATE    RATE LIMIT INTERVAL (sec)    AVAILABLE MEM THRESHOLD (%)
        ------------------  -------  ---------------------------  -----------------------------
        bgp                 enabled  600                          10.0
        database            enabled  600                          10.0
        dhcp_relay          enabled  600                          N/A
        lldp                enabled  600                          10.0
        macsec              enabled  600                          N/A
        mgmt-framework      enabled  600                          10.0
        mux                 enabled  600                          10.0
        nat                 enabled  600                          10.0
        pmon                enabled  600                          10.0
        radv                enabled  600                          10.0
        sflow               enabled  600                          10.0
        snmp                enabled  600                          10.0
        swss                enabled  600                          10.0
        syncd               enabled  600                          10.0
        teamd               enabled  600                          10.0
        telemetry           enabled  600                          10.0
        what-just-happened  enabled  600                          N/A
        :return: dictionary with parsed result, example: {'bgp': {'status': 'enabled', 'rate_limit_interval': '600'},
        'database': {'status': 'enabled', 'rate_limit_interval': '600'}, ...}
        """
        with allure.step('Parsing "show auto-techsupport-feature" output'):
            result_dict = {}
            regexp = r'(.*)\s+(enabled|disabled)\s+(\d+)\s+(\d+\.\d|N/A)'
            cmd_output = self.show_auto_techsupport_feature()

            name_index = 0
            state_index = 1
            rate_limit_index = 2
            avail_mem_threshold_index = 3
            for feature in re.findall(regexp, cmd_output):
                result_dict[feature[name_index].strip()] = {'status': feature[state_index],
                                                            'rate_limit_interval': feature[rate_limit_index],
                                                            'available_mem_threshold': feature[
                                                                avail_mem_threshold_index]}
        return result_dict

    def show_auto_techsupport_history(self):
        """
        This method execute command: "show auto-techsupport history"
        :return: command output
        """
        return self.duthost.shell('show auto-techsupport history')['stdout']

    def parse_show_auto_techsupport_history(self):
        """
        Parse output for cmd "show auto-techsupport history"
        TECHSUPPORT DUMP                        TRIGGERED BY    EVENT TYPE    CORE DUMP
        --------------------------------------  --------------  ------------  ---------------------------
        sonic_dump_r-ocelot-07_20220627_142555  dhcp_relay      core          bash.1656339955.112.core.gz
        :return: dictionary with parsed result, example: {'sonic_dump_r-lionfish-16_20210901_221402':
        {'triggered_by': 'bgp', 'core_dump': 'bgpcfgd.1630534439.55.core.gz'}, ...}
        """
        with allure.step('Parsing "show auto-techsupport history" output'):
            result_dict = {}
            regexp = r'(sonic_dump_.*)\s+(\w+|\w+\W\w+)\s+(\w+)\s+(\w+\.\d+\.\d+\.core\.gz)'
            cmd_output = self.show_auto_techsupport_history()

            dump_name_index = 0
            triggered_by_index = 1
            event_type_index = 2
            core_dump_index = 3
            for dump in re.findall(regexp, cmd_output):
                result_dict[dump[dump_name_index].strip()] = {'triggered_by': dump[triggered_by_index],
                                                              'event_type': dump[event_type_index],
                                                              'core_dump': dump[core_dump_index]}
        return result_dict


class AutoTechSupportCli202111(AutoTechSupportCliDefault):

    def __int__(self, *args, **kwargs):
        pass

    def parse_show_auto_techsupport_global(self):
        """
        Parse output for cmd "show auto-techsupport global"
        STATE    RATE LIMIT INTERVAL (sec)    MAX TECHSUPPORT LIMIT (%)    MAX CORE LIMIT (%)    SINCE
        -------  ---------------------------  ---------------------------  --------------------  ----------
        enabled  180                          10                           5                     2 days ago
        :return: dictionary with parsed result, example: {'state': 'enabled', 'rate_limit_interval': '180',
        'max_techsupport_limit': '10', 'max_core_size': '5', 'since': '2 days ago'}
        """
        with allure.step('Parsing "show auto-techsupport global" output'):
            regexp = r'(enabled|disabled)\s+(\d+)\s+(\d+.\d+|\d+)\s+(\d+.\d+|\d+)\s+(.*)'
            cmd_output = self.show_auto_techsupport_global()
            state, rate_limit_interval, max_techsupport_limit, max_core_size, since = re.search(regexp,
                                                                                                cmd_output).groups()
            result_dict = {'state': state, 'rate_limit_interval': rate_limit_interval,
                           'max_techsupport_limit': max_techsupport_limit, 'max_core_size': max_core_size,
                           'since': since}
        return result_dict

    def parse_show_auto_techsupport_feature(self):
        """
        Parse output for cmd "show auto-techsupport-feature"
        FEATURE NAME    STATE    RATE LIMIT INTERVAL (sec)
        --------------  -------  ---------------------------
        bgp             enabled  600
        database        enabled  600
        dhcp_relay      enabled  600
        lldp            enabled  600
        macsec          enabled  600
        mgmt-framework  enabled  600
        mux             enabled  600
        nat             enabled  600
        pmon            enabled  600
        radv            enabled  600
        sflow           enabled  600
        snmp            enabled  600
        swss            enabled  600
        syncd           enabled  600
        teamd           enabled  600
        telemetry       enabled  600
        :return: dictionary with parsed result, example: {'bgp': {'status': 'enabled', 'rate_limit_interval': '600'},
        'database': {'status': 'enabled', 'rate_limit_interval': '600'}, ...}
        """
        with allure.step('Parsing "show auto-techsupport-feature" output'):
            result_dict = {}
            regexp = r'(\w+-\w+|\w+)\s+(enabled|disabled)\s+(\d+)'
            cmd_output = self.show_auto_techsupport_feature()

            name_index = 0
            state_index = 1
            rate_limit_index = 2
            for feature in re.findall(regexp, cmd_output):
                result_dict[feature[name_index]] = {'status': feature[state_index],
                                                    'rate_limit_interval': feature[rate_limit_index]}
        return result_dict

    def parse_show_auto_techsupport_history(self):
        """
        Parse output for cmd "show auto-techsupport history"
        TECHSUPPORT DUMP                          TRIGGERED BY    CORE DUMP
        ----------------------------------------  --------------  -----------------------------
        sonic_dump_r-lionfish-16_20210901_221402  bgp             bgpcfgd.1630534439.55.core.gz
        :return: dictionary with parsed result, example: {'sonic_dump_r-lionfish-16_20210901_221402':
        {'triggered_by': 'bgp', 'core_dump': 'bgpcfgd.1630534439.55.core.gz'}, ...}
        """
        with allure.step('Parsing "show auto-techsupport history" output'):
            result_dict = {}
            regexp = r'(sonic_dump_.*)\s+(\w+|\w+\W\w+)\s+(\w+\.\d+\.\d+\.core\.gz)'
            cmd_output = self.show_auto_techsupport_history()

            dump_name_index = 0
            triggered_by_index = 1
            core_dump_index = 2
            for dump in re.findall(regexp, cmd_output):
                result_dict[dump[dump_name_index].strip()] = {'triggered_by': dump[triggered_by_index],
                                                              'core_dump': dump[core_dump_index]}
        return result_dict


class AutoTechSupportCli202205(AutoTechSupportCli202111):
    def __int__(self, *args, **kwargs):
        pass
