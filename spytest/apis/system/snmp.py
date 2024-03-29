# This file contains the list of API's which performs SNMP operation.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re

from spytest import st

from apis.system.basic import replace_line_in_file, service_operations
from apis.system.connection import execute_command
import apis.routing.ip as ip_api

from utilities.common import filter_and_select, to_string, remove_last_line_from_string
from utilities.common import process_popen, get_query_params, make_list
import utilities.utils as utils_obj

try:
    import apis.yang.codegen.messages.snmp as umf_snmp
    from apis.yang.utils.common import Operation
except ImportError:
    pass


snmp_config_file_path = r'/etc/sonic/snmp.yml'

snmp_config_defaults = {
    'snmp_rocommunity': 'NotConfigured',
    'snmp_rocommunity6': 'NotConfigured',
    'snmp_location': 'NotConfigured',
    'snmp_syscontact': 'NotConfigured',
    'v1_trap_dest': 'NotConfigured',
    'v2_trap_dest': 'NotConfigured',
    'v3_trap_dest': 'NotConfigured'
}


def set_snmp_config(dut, **kwargs):
    """
    To set SNMP config, community and location
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :snmp_rocommunity: string
    :param :snmp_rocommunity6: string
    :param :snmp_location: string
    :param :v1_trap_dest: string
    :param :v2_trap_dest: string
    :param :v3_trap_dest: string
    :return:
    """
    st.banner("SNMP Config before change")
    output = get_snmp_config(dut)
    if not output:
        for key, value in snmp_config_defaults.items():
            line = "{}: {}".format(key, value.strip())
            st.config(dut, 'bash -c "echo {} >> {}" '.format(line, snmp_config_file_path))

    for each in kwargs:
        replace_line_in_file(dut, '{}:'.format(each), "{}: {}".format(each, kwargs[each].strip()),
                             snmp_config_file_path, device='dut')
    st.banner("SNMP Config after change")
    get_snmp_config(dut, skip_tmpl=True)

    st.log("Restarting the 'snmp' service , post configuring snmp community.")
    service_operations(dut, 'snmp', 'restart')
    return True


def get_snmp_config(dut, **kwargs):
    """
    To Get SNMP config, community and location
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    return st.show(dut, 'cat {}'.format(snmp_config_file_path), **kwargs)


def restore_snmp_config(dut):
    """
    To restore the snmp config to default.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    return set_snmp_config(dut, **snmp_config_defaults)


def verify_snmp_config(dut, **kwargs):
    """
    To restore the snmp config to default.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :snmp_rocommunity: string
    :param :snmp_rocommunity6: string
    :param :snmp_location: string
    :param :v1_trap_dest: string
    :param :v2_trap_dest: string
    :param :v3_trap_dest: string
    :return:
    """
    output = get_snmp_config(dut)
    for each in kwargs:
        if not filter_and_select(output, None, {each: kwargs[each]}):
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def _parse_snmp_output(output, remove_last=True):
    error_codes = ["No Such Object available on this agent at this OID",
                   "No Such Instance currently exists at this OID"]
    if remove_last and output:
        output = utils_obj.remove_last_line_from_string(output)
    if not output:
        return False
    for err_code in error_codes:
        if err_code in output:
            return False
    result = output.rstrip('\n').split("\n")
    return [each.replace('"', '') for each in result]


def get_snmp_operation(**kwargs):
    """
    To perform SNMP GET operation
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :ipaddress:
    :param :oid:
    :param :community_name:
    :param :timeout:
    :param :retry:
    :param :snmp_port:
    :param :get_next: True | False (default : False)
    version : -v, community_name : -c, usr_name: -u, auth_type: -a, auth_pwd: -A,
    privacy_type: -x, privacy_pwd: -X, security_lvl: -l
    :return:
    """
    report = kwargs.get('report', True)
    community_name = kwargs.get("community_name")
    ip_address = kwargs.get("ipaddress")
    oid = kwargs.get("oid")
    snmp_port = kwargs.get("snmp_port")
    timeout = kwargs.get("timeout")
    retry = kwargs.get("retry")
    version = kwargs.get("version", "2")
    user_name = kwargs.get("usr_name")
    auth_type = kwargs.get("auth_type")
    auth_pwd = kwargs.get("auth_pwd")
    privacy_type = kwargs.get("privacy_type")
    privacy_pwd = kwargs.get("privacy_pwd")
    security_lvl = kwargs.get("security_lvl")
    security_lvl_type = ["noAuthNoPriv", "authNoPriv", "authPriv"]
    connection_obj = kwargs.get("connection_obj")
    filter = kwargs.get("filter", "-Oqv")
    if 'bulk_get' in kwargs:
        command = "snmpbulkget"
    else:
        command = 'snmpget'
    if kwargs.get('get_next'):
        command = 'snmpgetnext'
    if version not in ["1", "2", "3"]:
        st.log("Unsupported version provided")
        return False
    if not ip_address or not oid:
        st.log("Mandatory parameters like ipaddress or/and oid not passed")
        return False
    if version in ["1", "2"]:
        if not community_name:
            st.log("Mandatory parameter community_name not passed")
            return False
        act_version = "1" if version == "1" else "2c"
        snmp_command = "{} {} -v {} -c '{}' {} {}".format(command, filter, act_version, community_name,
                                                          ip_address, oid)
        if snmp_port:
            snmp_command = "{} {} -v {} -c {} {}:{} {}".format(command, filter, act_version, community_name, ip_address,
                                                               snmp_port, oid)
        if timeout:
            snmp_command += " -t {}".format(timeout)
        if retry:
            snmp_command += " -r {}".format(retry)
    else:
        if not user_name:
            st.log("Please provide Username")
            return False
        if auth_type:
            if not auth_pwd:
                st.log("Please provide AUTHENTICATION PWD")
                return False
        if privacy_type:
            if not auth_type:
                st.log("Please provide AUTHENTICATION TYPE")
                return False
            if not privacy_pwd:
                st.log("Please provide PRIVACY PWD")
                return False
        if not security_lvl:
            st.log("Security level not provided ")
            return False
        if security_lvl not in security_lvl_type:
            st.log("Unsupported security level provided")
            return False
        if security_lvl == "authNoPriv":
            if not auth_type:
                st.log("Authentication type not provided with security lvl {}".format(security_lvl))
                return False
        if security_lvl == "authPriv":
            if not auth_type:
                st.log("Authentication type not provided with security lvl {}".format(security_lvl))
                return False
            if not privacy_type:
                st.log("Privacy type not provided with security lvl {}".format(security_lvl))
                return False
        snmp_command = "{} {} -v {} -n \"\" -u {} -l {}".format(command, filter, version, user_name, security_lvl)
        if auth_type:
            snmp_command += " -a {} -A {}".format(auth_type, auth_pwd)
            if privacy_type:
                snmp_command += " -x  {} -X {}".format(privacy_type, privacy_pwd)
        if not snmp_port:
            snmp_command += " {} {}".format(ip_address, oid)
        else:
            snmp_command += " {}:{} {}".format(ip_address, snmp_port, oid)
        if timeout:
            snmp_command += " -t {}".format(timeout)
        if retry:
            snmp_command += " -r {}".format(retry)

    st.log("executing: {}".format(snmp_command))
    if st.is_dry_run():
        return False

    if version in ["1", "2"]:
        pprocess = process_popen(snmp_command)
        stdout, stderr = pprocess.communicate()
        st.log("SNMPv{} output: {}".format(version, stdout))
        if pprocess.poll() is not None:
            if pprocess.returncode == 0:
                retval = _parse_snmp_output(stdout, False)
                if retval is not False:
                    return retval
            if "Timeout" in stderr:
                st.error("SNMP Timeout occurs")
                if report:
                    st.report_fail('snmp_operation_fail', 'GET', 'Timeout')
                return False
            else:
                st.log("SNMP Error: return code = {}".format(pprocess.returncode))
                st.log("SNMP stdout: {}".format(stdout))
                st.error("SNMP stderr: {}".format(stderr))
                if report:
                    st.report_fail('snmp_operation_fail', 'GET', 'Error')
                return False
        if "No Such Instance currently exists at this OID" in stdout:
            result = stderr.strip("\n")
            st.error(result)
            if report:
                st.report_fail('snmp_operation_fail', 'GET', 'No Instance Found')
            return False
    else:
        output = execute_command(connection_obj, snmp_command)
        st.log("SNMPv{} output: {}".format(version, output))
        retval = _parse_snmp_output(output)
        if retval is False:
            st.error("SNMP OUTPUT: {}".format(output))
            return False
        return retval


def walk_snmp_operation(**kwargs):
    """
    To perform SNMP WALK operation
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :ipaddress:
    :param :oid:
    :param :community_name:
    :param :timeout:
    :param :retry:
    :param :snmp_port:
    :param :filter:
    :return:
    """
    report = kwargs.get('report', True)
    community_name = kwargs.get("community_name")
    ip_address = kwargs.get("ipaddress")
    oid = kwargs.get("oid", "1")
    snmp_port = kwargs.get("snmp_port")
    timeout = kwargs.get("timeout")
    retry = kwargs.get("retry")
    version = kwargs.get("version", "2")
    user_name = kwargs.get("usr_name")
    auth_type = kwargs.get("auth_type")
    auth_pwd = kwargs.get("auth_pwd")
    privacy_type = kwargs.get("privacy_type")
    privacy_pwd = kwargs.get("privacy_pwd")
    security_lvl = kwargs.get("security_lvl")
    filter = kwargs.get("filter", '')
    security_lvl_type = ["noAuthNoPriv", "authNoPriv", "authPriv"]
    connection_obj = kwargs.get("connection_obj")
    skip_error = kwargs.get('skip_error_check', False)
    command = 'snmpwalk'
    if version not in ["1", "2", "3"]:
        st.log("Unsupported version provided")
        return False
    if not ip_address or not oid:
        st.log("Mandatory parameters like ipaddress or/and oid not passed")
        return False
    if version in ["1", "2"]:
        if not community_name:
            st.log("Mandatory parameter community_name not passed")
            return False
        if version == '1':
            act_version = "1"
        else:
            if 'bulk_walk' in kwargs:
                command = "snmpbulkwalk"
            act_version = "2c"
        snmp_command = "{} {} -v {} -c {} {} {}".format(command, filter, act_version, community_name,
                                                        ip_address, oid)
        if snmp_port:
            snmp_command = "{} {} -v {} -c {} {}:{} {}".format(command, filter, act_version, community_name, ip_address,
                                                               snmp_port, oid)
    else:
        if not user_name:
            st.log("Please provide Username")
            return False
        if auth_type:
            if not auth_pwd:
                st.log("Please provide AUTHENTICATION PWD")
                return False
        if privacy_type:
            if not auth_type:
                st.log("Please provide AUTHENTICATION TYPE")
                return False
            if not privacy_pwd:
                st.log("Please provide PRIVACY PWD")
                return False
        if not security_lvl:
            st.log("Security level not provided ")
            return False
        if security_lvl not in security_lvl_type:
            st.log("Unsupported security level provided")
            return False
        if security_lvl == "authNoPriv":
            if not auth_type:
                st.log("Authentication type not provided with security lvl {}".format(security_lvl))
                return False
        if security_lvl == "authPriv":
            if not auth_type:
                st.log("Authentication type not provided with security lvl {}".format(security_lvl))
                return False
            if not privacy_type:
                st.log("Privacy type not provided with security lvl {}".format(security_lvl))
                return False
        snmp_command = "{} {} -v {} -n \"\" -u {} -l {}".format(command, filter, version, user_name, security_lvl)
        if auth_type:
            snmp_command += " -a {} -A {}".format(auth_type, auth_pwd)
            if privacy_type:
                snmp_command += " -x  {} -X {}".format(privacy_type, privacy_pwd)
        if not snmp_port:
            snmp_command += " {} {}".format(ip_address, oid)
        else:
            snmp_command += " {}:{} {}".format(ip_address, snmp_port, oid)
    if timeout:
        snmp_command += " -t {}".format(timeout)
    if retry:
        snmp_command += " -r {}".format(retry)

    st.debug("executing: {}".format(snmp_command))
    if st.is_dry_run():
        return False
    if not skip_error:
        if version in ["1", "2", "3"]:
            pprocess = process_popen(snmp_command)
            result = []
            while True:
                output = pprocess.stdout.readline()
                try:
                    output = output.decode(errors='ignore')
                except Exception:
                    pass  # already decoded in python3
                if pprocess.poll() is not None and output.strip() == '':
                    snmp_error_stderr = to_string(pprocess.communicate()[1])
                    if snmp_error_stderr != r'':
                        if "Timeout" in snmp_error_stderr:
                            st.error("SNMP Timeout occurs")
                            if report:
                                st.report_fail('snmp_operation_fail', 'WALK', 'Timeout')
                            return False
                        st.error("SNMP ERROR: {}".format(snmp_error_stderr))
                        if report:
                            st.report_fail('snmp_operation_fail', 'WALK', 'Error')
                            return False
                    break

                elif output:
                    st.log(output.strip())
                    if "No Such Object available on this agent at this OID" in output or \
                            "No Such Instance currently exists at this OID" in output:
                        if report:
                            st.report_fail('snmp_operation_fail', 'WALK', 'No Instance Found')
                        return False
                    result.append(output.strip("\n"))

            if str(kwargs['oid']) == '1':
                if 'No more variables left in this MIB View' not in output:
                    if report:
                        st.report_fail('snmp_operation_fail', 'WALK', 'In-Complete Walk termination')
                    return False
            return result

    else:
        output = execute_command(connection_obj, snmp_command)
        st.log("OUTPUT: {}".format(output))
        retval = _parse_snmp_output(output)
        if retval is False:
            st.error("SNMP OUTPUT: {}".format(output))
            return False
        return retval


def poll_for_snmp(dut, iteration_count=30, delay=1, **kwargs):
    """
    This API is to  poll the DUT to get the snmp operation output
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param iteration_count:
    :param delay:
    :param kwargs:
    :return:
    """
    i = 1
    while True:
        snmp_operation = get_snmp_operation(report=False, **kwargs)
        if snmp_operation or st.is_dry_run():
            st.log("snmp o/p is found ...")
            return True
        if i > iteration_count:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.wait(delay)


def poll_for_snmp_walk(dut, iteration_count=30, delay=1, **kwargs):
    """
    This API is to  poll the DUT to get the snmp operation output
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param iteration_count:
    :param delay:
    :param kwargs:
    :return:
    """
    i = 1
    while True:
        snmp_operation = walk_snmp_operation(report=False, **kwargs)
        if snmp_operation or st.is_dry_run():
            st.log("snmp o/p is found ...")
            return True
        if i > iteration_count:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.wait(delay)


def get_oids_from_walk_output(data):
    """
    To get OID from SNMP WALK operation output.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param data:
    :return:
    """
    result = []
    for each in make_list(data):
        if "=" in each:
            result.append(re.findall(r"(\S+)\s+=", each)[0])
    return result


def config_snmp_agent(dut, **kwargs):
    """
    API to create SNMP agent address.
    Author : Kiran Vedula (kvedula@broadcom.com)
    :param :dut:
    :param :cli_type:   default - click
    :param :no_form:   default - False
    :return:

    Usage:
    config_snmp_agent(vars.D1, ip_addr= ip_addr[0], port =161, vrf= 'mgmt')
    config_snmp_agent(vars.D1, ip_addr= ip_addr[0], port =161, vrf= 'mgmt', no_form=True)

    """
    commands = []
    if 'ip_addr' not in kwargs:
        st.log("Mandatory parameter ipaddress  not passed")
        return False
    cli_type = kwargs.get("cli_type", "click")
    ip_addr = kwargs.get('ip_addr')
    port = kwargs.get("port", 161)
    vrf = kwargs.get("vrf", None)
    no_form = kwargs.get("no_form", False)
    if cli_type == 'klish':
        st.log("UNSUPPORTED CLI TYPE {}".format(cli_type))
    elif cli_type == "click":
        st.log('Config SNMP Agent address')
        action = "add" if not no_form else "del"
        my_cmd = 'config snmpagentaddress {} {} -p {} -v {}'.format(action, ip_addr, port, vrf)
        commands.append(my_cmd)
    if commands:
        st.config(dut, commands, type=cli_type)
    return True


def config_snmp_trap(dut, **kwargs):
    """
    API to create SNMP agent address.
    Author : Kiran Vedula (kvedula@broadcom.com)
    :param :dut:
    :param :cli_type:   default - click
    :param :no_form:   default - False
    :return:

    Usage:
    config_snmp_agent(vars.D1, version =2, ip_addr= ip_addr[0], port =162, vrf= 'mgmt', community= 'snmp_ro')
    config_snmp_agent(vars.D1, ip_addr= ip_addr[0], port =162, vrf= 'mgmt', no_form='True')

    """
    commands = []
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ['rest-patch', 'rest-put'] + utils_obj.get_supported_ui_type_list():
        cli_type = 'klish'
    ip_addr = kwargs.get('ip_addr', None)
    port = kwargs.get("port", 162)
    vrf = kwargs.get("vrf", None)
    community = kwargs.get("community", "public")
    no_form = kwargs.get("no_form", False)

    if not ip_addr or kwargs.get('version') != 2:
        st.log("Mandatory parameters not passed")
        return False

    if cli_type == 'klish':
        version = 'v2c'
        cmd = 'snmp-server enable trap'
        if no_form:
            cmd = 'no ' + cmd
        commands.append(cmd)
        cmd = 'snmp-server host {} community {} traps {}'.format(ip_addr, community, version)
        if port > 1024:
            cmd += ' port {}'.format(port)
        if no_form:
            cmd = 'no ' + 'snmp-server host {}'.format(ip_addr)
        commands.append(cmd)
    elif cli_type == "click":
        st.log('Config SNMP Trap receiver')
        if not no_form:
            version = kwargs.get("version", 2)
            my_cmd = 'config snmptrap modify {} {} -p {} -v {} -c {}'.format(version, ip_addr, port, vrf, community)
        else:
            my_cmd = 'config snmptrap del {}'.format(kwargs.get("version"))
        commands.append(my_cmd)
    if commands:
        st.config(dut, commands, type=cli_type)
    return True


def config(dut, params, skip_error=False, rest_operation="patch"):
    """
    API to create/Delete SNMP commands for communities,users,traps,system and location.
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    :param :dut:
    :param :params: {"cli_type":"klish","globals":{"contact":["Value","True/False"], "location":["Value",True/False],
    "sysname":["Value","True/False"],"engine":["Value","True/False"]},
    "traps":"enable/disable","community":{"name":"Value","group_name":"Value", "no_form":"True/False"},
    "groups":{"name":"Value","version":{"type":"v1|v2c|v3|any","options":"auth|noatuh|priv"},
    "operations":{"read_view":"value","write_view":"value","notify_view":"value"}},"host":{"address":"IP_ADDR",
    "community":{"name":"Value", "traps":"v2c | v1","informs":"Value","timeout":"Value","retries":"Value",
    "port":<UDP port>, "interface":"Value"},"user":{"name":"Value", "traps":" auth | noauth | priv",
    "informs":"auth | noauth | priv","timeout":"Value","retries":"Value", "port":<UDP port>, "interface":"Value"}},
    "user":{"name":"Value","group":"Value","encrypted":"enable/disable","auth":"Value",
    "auth_pwd":"Value","privacy":"Value","priv_pwd":"Value"},
    "view":{"name":"Value","oid":"Value","option":"included/excluded"}}
    "agent_address":{"agent-addr":"Value","udp-port":"Value","interface_name":"Value"}
    :return: True

    Usage:
    snmp-server [ contact <contact> ] [ location <location> ] [ sysname <system name> ] [ engine <octet-byte-string> ]
    snmp-server agentaddress <agent-addr> [port <port-id>] [interface <String>]
    snmp-server enable trap
    snmp-server community <community name>  [groupname  <group name>]
    snmp-server group <group name> { any | v1 | v2c | v3 { auth | noauth | priv }} [ read <viewname> ]
    [ write <viewname> ] [ notify <viewname> ]
    snmp-server host <host-addr> community <community name> {[ traps { v2c | v1 }] | informs [timeout seconds]
    [retries retries] [port udpPort] [interface ifaceName]}
    snmp-server host <host-addr> user <username> {[traps  {auth | noauth | priv}] | [informs {auth | noauth | priv}
     [timeout seconds] [retries retries]] [port udpPort] [interface ifaceName]}
    snmp-server user <sername> [ group <group-name> ] [ encrypted ] [ auth { md5 | sha | noauth }
    [ auth-password <password-string>  ] [ priv { DES | AES-128 } [ priv-password <password-string> ] ]
    snmp-server view <view name> <oid-tree> {included | excluded}


    """
    st.log('API_NAME: SNMP: config, API_ARGS: {}'.format(locals()))
    command = ''
    commands = list()
    mandatory_params = {"globals": ["contact", "location", "sysname", "engine"], "traps": ["enable", "disable"],
                        "community": ["name"], "groups": ["name", "version"], "host_name": ["address", "community"],
                        "host_user": ["address", "user"], "user": ["name", "group"], "view": ["name", "oid", "option"],
                        "agent_address": ["agent-addr"]}

    cli_type = st.get_ui_type(dut)
#    cli_type = params.get('cli_type', 'klish')
    if cli_type not in utils_obj.get_supported_ui_type_list():
        cli_type = 'klish'
    if cli_type == "click":
        st.log("This CLI TYPE is not supported for SNMP Commands {}". format(cli_type))
        return False
    # To verify mandatory values for given commands
    for key, value in params.items():
        if key == "globals":
            for field, data in value.items():
                if field not in mandatory_params["globals"]:
                    st.log("Mandatory params is not provided for Globals")
                    return False
        if key == "traps":
            if value not in mandatory_params["traps"]:
                st.log("Unsupported value for traps-- {}".format(value))
                return False
        if key == "community":
            if value.get("no_form") in [False, True]:
                if mandatory_params["community"][0] not in value.keys():
                    st.log("Mandatory params is not provided for community-- {}".
                           format(mandatory_params["community"][0]))
                    return False
            else:
                st.log("Unsupported no_form for key parameters")
                return False
        if key == "groups":
            if value.get("no_form") in [False, True]:
                for field in mandatory_params["groups"]:
                    if field not in value.keys():
                        st.log("Mandatory params is not provided for group-- {}".format(field))
                        return False
            else:
                st.log("Unsupported no_form for groups parameters")
                return False
        if key == "host":
            result = 0
            if value.get("no_form") in [False, True]:
                if not value.get("no_form"):
                    if value.get("community"):
                        for field in mandatory_params["host_name"]:
                            if field not in value.keys():
                                st.log("Mandatory params is not provided for host community-- {}".format(field))
                                result = result + 1
                        if result > 0:
                            return False

                    elif value.get("user"):
                        for field in mandatory_params["host_user"]:
                            if field not in value.keys():
                                st.log("Mandatory params is not provided for host user-- {}".format(field))
                                result = result + 1
                        if result > 0:
                            return False
                else:
                    if mandatory_params["host_name"][0] not in value.keys():
                        st.log("Mandatory params is not provided for no form of host -- {}".
                               format(mandatory_params["host_name"][0]))
                        return False
            else:
                st.log("Unsupported no_form for host parameters")
                return False
        if key == "user":
            result = 0
            if value.get("no_form") in [False, True]:
                if not value.get("no_form"):
                    for key_1 in mandatory_params["user"]:
                        if key_1 not in value.keys():
                            st.log("Mandatory params is not provided for user-- {}".format(key_1))
                            result = result + 1
                    if result > 0:
                        return False
                else:
                    if mandatory_params["user"][0] not in value.keys():
                        st.log("Mandatory params is not provided for no form of user -- {}".
                               format(mandatory_params["user"][0]))
                        return False
            else:
                st.log("Unsupported no_form for user parameters")
                return False
        if key == "view":
            result = 0
            if value.get("no_form") in [False, True]:
                if not value.get("no_form"):
                    for key_1 in mandatory_params["view"]:
                        if key_1 not in value.keys():
                            st.log("Mandatory params is not provided for view-- {}".format(key_1))
                            result = result + 1
                    if result > 0:
                        return False
                else:
                    if mandatory_params["view"][0] not in value.keys() and mandatory_params["view"][1] not in \
                            value.keys():
                        st.log("Mandatory params is not provided for no form of view -- {} {}".
                               format(mandatory_params["view"][0], mandatory_params["view"][1]))
                        return False
            else:
                st.log("Unsupported no_form for view parameters")
                return False
        if key == "agent_address":
            if value.get("no_form") in [False, True]:
                for field in mandatory_params["agent_address"]:
                    if field not in value.keys():
                        st.log("Mandatory params is not provided for agent_address-- {}".format(field))
                        return False
            else:
                st.log("Unsupported no_form for agent_address parameters")
                return False

    # To verify empty values in given lists
    for empty_parameter in [key for key, value in params.items() if value == ""]:
        st.log("Value is not defined for {} value ".format(empty_parameter))
        return False

    # To un-configure/configure snmp communities,traps, hosts and users
    ret_val = True
    for key, value in params.items():
        if key == "globals":
            attr_name_map = {'location': 'Location', 'contact': 'Contact', 'engine': 'EngineId'}
            if cli_type in utils_obj.get_supported_ui_type_list():
                for field, data in value.items():
                    if field not in mandatory_params["globals"]:
                        st.log("Unsupported params provided -- {}".format(field))
                        return False
                    if data:
                        snmp_obj = umf_snmp.Snmp()
                        if len(data) > 1 and data[1]:
                            setattr(snmp_obj, attr_name_map[field], data[0])
                            result = snmp_obj.configure(dut, cli_type=cli_type)
                        else:
                            target_attr = getattr(snmp_obj, attr_name_map[field])
                            result = snmp_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                            ret_val = False

            else:
                for field, data in value.items():
                    if field not in mandatory_params["globals"]:
                        st.log("Unsupported params provided -- {}".format(field))
                        return False
                    if data:
                        if len(data) > 1 and data[1]:
                            command = "snmp-server {} {}".format(field, data[0])
                        else:
                            command = "no snmp-server {}".format(field)
                    commands.append(command)
        if key == "traps":
            if params[key] not in ["enable", "disable"]:
                st.log("Unsupported operation for traps provided {}".format(params[key]))
                return False
            if cli_type in utils_obj.get_supported_ui_type_list():
                trap = True if params[key] == 'enable' else False
                snmp_obj = umf_snmp.Snmp(TrapEnable=trap)
                result = snmp_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server enable trap" if params[key] == "enable" else "no snmp-server enable trap"
                commands.append(command)
        if key == "community":
            if cli_type in utils_obj.get_supported_ui_type_list():
                snmp_obj = umf_snmp.Snmp()
                comm_obj = umf_snmp.Community(Index=value.get('name'), SecurityName='None')
                if not value.get('no_form'):
                    if value.get('group_name'):
                        setattr(comm_obj, 'SecurityName', value.get('group_name'))
                    snmp_obj.add_Community(comm_obj)
                    result = snmp_obj.configure(dut, target_path='/community', cli_type=cli_type)
                else:
                    result = comm_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server community"
                if not value.get("no_form"):
                    command += " {}".format(value.get("name"))
                    if value.get("group_name"):
                        command += " group {}".format(value.get("group_name"))
                else:
                    command = "no {} {}".format(command, value.get("name"))
                if command:
                    commands.append(command)
        if key == "view":
            if cli_type in utils_obj.get_supported_ui_type_list():
                snmp_obj = umf_snmp.Snmp()
                view_obj = umf_snmp.View(Name=value.get('name'))
                if not value.get('no_form'):
                    if value.get("option") not in ["included", "excluded"]:
                        st.log("Unsupported params for oid provided -- {}".format(value.get("option")))
                        return False
                    if value.get('option') == 'included':
                        setattr(view_obj, 'Include', value.get('oid'))
                    if value.get('option') == 'excluded':
                        setattr(view_obj, 'Exclude', value.get('oid'))
                    snmp_obj.add_View(view_obj)
                    result = snmp_obj.configure(dut, cli_type=cli_type)
                else:
                    result = view_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server view "
                if not value.get("no_form"):
                    command += " {}".format(value.get("name"))
                    if value.get("oid"):
                        command += " {}".format(value.get("oid"))
                        if value.get("option") not in ["included", "excluded"]:
                            st.log("Unsupported params for oid provided -- {}".format(value.get("option")))
                            return False
                        else:
                            command += " {}".format(value.get("option"))
                else:
                    command = "no {} {} {}".format(command, value.get("name"), value.get("oid"))
                if command:
                    commands.append(command)

        if key == "groups":
            if cli_type in utils_obj.get_supported_ui_type_list():
                snmp_obj = umf_snmp.Snmp()
                group_obj = umf_snmp.Group(Name=value.get('name'))
                if value.get('version'):
                    version_type = value.get('version').get('type')
                    version_options = value.get('version').get('options')
                    if version_type not in ["v1", "v2c", "v3", "any"]:
                        st.log("Unsupported params for snmp version type provided -- {}".format(version_type))
                        return False
                    else:
                        if version_type in ["v1", "v2c", "any"]:
                            security_model = version_type
                        elif version_type == 'v3':
                            security_model = 'usm'
                        if version_options not in ["auth", "noauth", "priv"]:
                            st.log("Unsupported params for group auth provided -- {}".format(version_options))
                            return False
                        else:
                            if version_options == 'noauth':
                                security_level = 'no-auth-no-priv'
                            if version_options == 'auth':
                                security_level = 'auth-no-priv'
                            if version_options == 'priv':
                                security_level = 'auth-priv'
                        access_obj = umf_snmp.Access(Context='Default', SecurityModel=security_model, SecurityLevel=security_level)
                if not value.get('no_form'):
                    if value.get('operations'):
                        view_options = value.get('operations')
                        if view_options.get('read_view'):
                            setattr(access_obj, 'ReadView', view_options.get('read_view'))
                        if view_options.get('write_view'):
                            setattr(access_obj, 'WriteView', view_options.get('write_view'))
                        if view_options.get('notify_view'):
                            setattr(access_obj, 'NotifyView', view_options.get('notify_view'))

                    group_obj.add_Access(access_obj)
                    snmp_obj.add_Group(group_obj)
                    result = snmp_obj.configure(dut, cli_type=cli_type)
                else:
                    access_obj = umf_snmp.Access(Context='Default', SecurityModel=security_model, SecurityLevel=security_level, Group=group_obj)
                    result = access_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server group"
                if not value.get("no_form"):
                    command += " {}".format(value.get("name"))
                    if value.get("version"):
                        version_type = value.get("version").get("type")
                        version_options = value.get("version").get("options")
                        if version_type not in ["v1", "v2c", "v3", "any"]:
                            st.log("Unsupported params for snmp version type provided -- {}".
                                   format(version_type))
                            return False
                        else:
                            if version_type in ["v1", "v2c", "any"]:
                                command += " {}".format(version_type)
                            elif version_type == 'v3':
                                if version_options not in ["auth", "noauth", "priv"]:
                                    st.log("Unsupported params for group auth provided -- {}".format(version_options))
                                    return False
                                else:
                                    command += " {} {}".format(version_type, version_options)
                    if value.get("operations"):
                        view_options = value.get("operations")
                        if view_options.get("read_view"):
                            command += " read {}".format(view_options.get("read_view"))
                        if view_options.get("write_view"):
                            command += " write {}".format(view_options.get("write_view"))
                        if view_options.get("notify_view"):
                            command += " notify {}".format(view_options.get("notify_view"))
                else:
                    if value.get("version").get("type") in ["v1", "v2c", "any"]:
                        command = "no {} {} {}".format(command, value.get("name"), value.get("version").get("type"))
                    else:
                        command = "no {} {} {} {}".format(command, value.get("name"), value.get("version").get("type"),
                                                          value.get("version").get("options"))
                if command:
                    commands.append(command)

        if key == "host":
            if cli_type in utils_obj.get_supported_ui_type_list():
                st.log('Executing show command to find configured host entries')
                snmp_obj = umf_snmp.Snmp()
                host_output = snmp_obj.get_payload(dut, cli_type=cli_type)
                if not host_output.ok():
                    st.log('test_step_failed: Get SNMP Server')
                    return False
                host_count = 0
                name = 'host_not_configured'
                if 'target' in host_output.payload['ietf-snmp:snmp']:
                    host_count = len(host_output.payload['ietf-snmp:snmp']['target'])
                for h_count in range(host_count):
                    host_ip = host_output.payload['ietf-snmp:snmp']['target'][h_count]['udp']['ip']
                    if value.get('address') == host_ip:
                        name = host_output.payload['ietf-snmp:snmp']['target'][h_count]['name']

                if not value.get('no_form'):
                    if name == 'host_not_configured':
                        # new entry
                        name = 'targetEntry' + str(host_count + 1)
                else:
                    if name == 'host_not_configured':
                        st.log('test_step_failed: host not configured: {}'.format(value.get('address')))
                        return False

                snmp_obj_1 = umf_snmp.Snmp()
                target_obj = umf_snmp.Target(Name=name, Ip=value.get('address'), TargetParams=name)
                if not value.get('no_form'):
                    if value.get('community'):
                        tp_info = value.get('community')
                        target_param_obj = umf_snmp.TargetParams(Name=name, SecurityName=tp_info.get('name'))
                        if tp_info.get('traps'):
                            if tp_info.get('traps') == 'v2c':
                                setattr(target_obj, 'Tag', 'trapNotify')
                            if tp_info.get('vrf'):
                                setattr(target_obj, 'Tag', ['trapNotify', 'mgmt'])
                        if tp_info.get('informs') == 'True':
                            setattr(target_obj, 'Tag', 'informNotify')
                            if tp_info.get('retries'):
                                setattr(target_obj, 'Retries', tp_info.get('retries'))
                            if tp_info.get('timeout'):
                                setattr(target_obj, 'Timeout', tp_info.get('timeout'))
                            if tp_info.get('vrf'):
                                setattr(target_obj, 'Tag', ['informNotify', 'mgmt'])
                        if tp_info.get('port'):
                            setattr(target_obj, 'Port', tp_info.get('port'))
                        if tp_info.get('source_interface'):
                            setattr(target_obj, 'SourceInterface', tp_info.get('source_interface'))
                        # if tp_info.get('vrf'): setattr(target_obj, 'VrfName', tp_info.get('vrf'))
                    elif value.get('user'):
                        tp_info = value.get('user')
                        target_param_obj = umf_snmp.TargetParams(Name=name, UserName=tp_info.get('name'))
                        if tp_info.get('traps'):
                            if tp_info.get("traps") not in ["auth", "noauth", "priv"]:
                                st.log("Unsupported params for trap community provided -- {}".format(tp_info.get("traps")))
                                return False
                            setattr(target_obj, 'Tag', 'trapNotify')
                            if tp_info.get('traps') == 'noauth':
                                setattr(target_param_obj, 'SecurityLevel', 'no-auth-no-priv')
                            if tp_info.get('traps') == 'auth':
                                setattr(target_param_obj, 'SecurityLevel', 'auth-no-priv')
                            if tp_info.get('traps') == 'priv':
                                setattr(target_param_obj, 'SecurityLevel', 'auth-priv')
                            if tp_info.get('vrf'):
                                setattr(target_obj, 'Tag', ['trapNotify', 'mgmt'])
                        elif tp_info.get('informs'):
                            if tp_info.get("informs") not in ["auth", "noauth", "priv"]:
                                st.log("Unsupported params for trap community provided -- {}".format(tp_info.get("informs")))
                                return False
                            setattr(target_obj, 'Tag', 'informNotify')
                            if tp_info.get('informs') == 'noauth':
                                setattr(target_param_obj, 'SecurityLevel', 'no-auth-no-priv')
                            if tp_info.get('informs') == 'auth':
                                setattr(target_param_obj, 'SecurityLevel', 'auth-no-priv')
                            if tp_info.get('informs') == 'priv':
                                setattr(target_param_obj, 'SecurityLevel', 'auth-priv')
                            if tp_info.get('timeout'):
                                setattr(target_obj, 'Timeout', tp_info.get('timeout'))
                            if tp_info.get('retries'):
                                setattr(target_obj, 'Retries', tp_info.get('retries'))
                            if tp_info.get('vrf'):
                                setattr(target_obj, 'Tag', ['informNotify', 'mgmt'])

                        if tp_info.get('port'):
                            setattr(target_obj, 'Port', tp_info.get('port'))
                        if tp_info.get('source_interface'):
                            setattr(target_obj, 'SourceInterface', tp_info.get('source_interface'))
#                        if tp_info.get('vrf'): setattr(target_obj, 'VrfName', tp_info.get('vrf'))

                    snmp_obj.add_TargetParams(target_param_obj)
                    result = snmp_obj.configure(dut, cli_type=cli_type)
                    snmp_obj_1.add_Target(target_obj)
                    result = snmp_obj_1.configure(dut, cli_type=cli_type)
                else:
                    result = target_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: unConfiguring SNMP Host: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server host"
                if not value.get("no_form"):
                    command += " {}".format(value.get("address"))
                    if value.get("community"):
                        host_community = value.get("community")
                        command += " community {}".format(host_community.get("name"))
                        if host_community.get("traps"):
                            if host_community.get("traps") not in ["v2c", "v1"]:
                                st.log("Unsupported params for trap community provided -- {}".
                                       format(host_community.get("traps")))
                                return False
                            else:
                                command += " traps {}".format(host_community.get("traps"))
                        elif host_community.get("informs") == "True":
                            command += " informs "
                            if host_community.get("timeout"):
                                command += " timeout {}".format(host_community.get("timeout"))
                            if host_community.get("retries"):
                                command += " retries {}".format(host_community.get("retries"))
                        if host_community.get("port"):
                            command += " port {}".format(host_community.get("port"))
                        if host_community.get("vrf"):
                            command += " vrf {}".format(host_community.get("vrf"))
                        if host_community.get("source_interface"):
                            command += " source-interface {}".format(host_community.get("source_interface"))

                    elif value.get("user"):
                        host_user = value.get("user")
                        command += " user {}".format(host_user.get("name"))
                        if host_user.get("traps"):
                            if host_user.get("traps") not in ["auth", "noauth", "priv"]:
                                st.log("Unsupported params for trap user provided -- {}".format(host_user.get("traps")))
                                return False
                            else:
                                command += " traps {}".format(host_user.get("traps"))
                        elif host_user.get("informs"):
                            if host_user.get("informs") not in ["auth", "noauth", "priv"]:
                                st.log("Unsupported params for inform user provided -- {}".format(host_user.get("informs")))
                                return False
                            else:
                                command += " informs {}".format(host_user.get("informs"))
                                if host_user.get("timeout"):
                                    command += " timeout {}".format(host_user.get("timeout"))
                                if host_user.get("retries"):
                                    command += " retries {}".format(host_user.get("retries"))
                        if host_user.get("port"):
                            command += " port {}".format(host_user.get("port"))
                        if host_user.get("vrf"):
                            command += " vrf {}".format(host_user.get("vrf"))
                        if host_user.get("source_interface"):
                            command += " source-interface {}".format(host_user.get("source_interface"))
                else:
                    command = "no {} {} ".format(command, value.get("address"))
                if command:
                    commands.append(command)

        if key == "user":
            if cli_type in utils_obj.get_supported_ui_type_list():
                snmp_obj = umf_snmp.Snmp()
                user_obj = umf_snmp.User(Name=value.get('name'))
                if not value.get('no_form'):
                    if value.get('group'):
                        snmp_obj_1 = umf_snmp.Snmp()
                        group_obj = umf_snmp.Group(Name=value.get('group'))
                        member_obj = umf_snmp.Member(SecurityName=value.get('name'), SecurityModel='usm')
                        group_obj.add_Member(member_obj)
                        if value.get("encrypted"):
                            if value.get("encrypted") not in ["enable", "disable"]:
                                st.log("Unsupported params for encrypted user provided--{}".format(value.get("encrypted")))
                                return False
                            else:
                                encrypt = 'true' if value.get("encrypted") == "enable" else 'false'
                                setattr(user_obj, 'Encrypted', encrypt)

                        if value.get('auth'):
                            user_auth = value.get("auth")
                            if user_auth in ["md5", "sha"]:
                                if not value.get("auth_pwd"):
                                    st.log("Authentication password is not provided {}".format(value.get("auth_pwd")))
                                    return False
                                if user_auth == 'md5':
                                    setattr(user_obj, 'Md5Key', value.get('auth_pwd'))
                                if user_auth == 'sha':
                                    setattr(user_obj, 'ShaKey', value.get('auth_pwd'))
                            elif user_auth == 'noauth':
                                pass
                            else:
                                st.log("Authentication protocol is not provided {}".format(user_auth))
                                return False
                            if value.get("priv"):
                                user_priv = value.get("priv")
                                if user_priv not in ["DES", "AES-128"]:
                                    st.log("Privacy protocol is not provided {}".format(user_priv))
                                    return False
                                if not value.get("priv_pwd"):
                                    st.log("Privacy password is not provided {}".format(value.get("priv_pwd")))
                                    return False
                                if user_priv == 'DES':
                                    setattr(user_obj, 'DesKey', value.get('priv_pwd'))
                                if user_priv == 'AES-128':
                                    setattr(user_obj, 'AesKey', value.get('priv_pwd'))

#                    snmp_obj.add_Group(group_obj)
                    snmp_obj.add_User(user_obj)
                    result = snmp_obj.configure(dut, cli_type=cli_type)
                    snmp_obj_1.add_Group(group_obj)
                    result = snmp_obj_1.configure(dut, cli_type=cli_type)
                else:
                    result = user_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server user"
                if not value.get("no_form"):
                    command += " {}".format(value.get("name"))
                    if value.get("group"):
                        command += " group {}".format(value.get("group"))
                        if value.get("encrypted"):
                            if value.get("encrypted") not in ["enable", "disable"]:
                                st.log("Unsupported params for encrypted user provided--{}".format(value.get("encrypted")))
                                return False
                            elif value.get("encrypted") == "enable":
                                command += " encrypted"
                            else:
                                pass
                        if value.get("auth"):
                            command += " auth"
                            user_auth = value.get("auth")
                            if user_auth in ["md5", "sha"]:
                                command += " {}".format(user_auth)
                                if not value.get("auth_pwd"):
                                    st.log("Authentication password is not provided {}".format(value.get("auth_pwd")))
                                    return False
                                else:
                                    command += " auth-password {}".format(value.get("auth_pwd"))
                            elif user_auth == "noauth":
                                command += " {}".format(user_auth)
                            else:
                                st.log("Authentication protocol is not provided {}".format(user_auth))
                                return False
                            if value.get("priv"):
                                command += " priv"
                                user_priv = value.get("priv")
                                if user_priv not in ["DES", "AES-128"]:
                                    st.log("Privacy protocol is not provided {}".format(user_priv))
                                    return False
                                else:
                                    command += " {}".format(user_priv)
                                    if not value.get("priv_pwd"):
                                        st.log("Privacy password is not provided {}".format(value.get("priv_pwd")))
                                        return False
                                    else:
                                        command += " priv-password {}".format(value.get("priv_pwd"))
                else:
                    command = "no {} {} ".format(command, value.get("name"))
                if command:
                    commands.append(command)

        if key == "agent_address":
            if cli_type in utils_obj.get_supported_ui_type_list():
                # operation = Operation.CREATE
                st.log('Executing show command to find configured agent addresses')
                snmp_obj = umf_snmp.Snmp()
                agent_output = snmp_obj.get_payload(dut, target_path='/engine', cli_type=cli_type)
                if not agent_output.ok():
                    st.log('test_step_failed: Get SNMP Server')
                    return False
                agent_count = 0
                if 'ietf-snmp:engine' in agent_output.payload and 'listen' in agent_output.payload['ietf-snmp:engine']:
                    agent_count = len(agent_output.payload['ietf-snmp:engine']['listen'])
                name = 'agent_not_configured'
                for a_count in range(agent_count):
                    agent_ip = agent_output.payload['ietf-snmp:engine']['listen'][a_count]['udp']['ip']
                    if value.get('agent-addr') == agent_ip:
                        name = agent_output.payload['ietf-snmp:engine']['listen'][a_count]['name']

                if not value.get('no_form'):
                    if name == 'agent_not_configured':
                        name = 'agentEntry' + str(agent_count + 1)
                else:
                    if name == 'agent_not_configured':
                        st.log('test_step_failed: Agent not configured: {}'.format(value.get('agent-addr')))
                        return False

                listen_obj = umf_snmp.Listen(Name=name)
                if value.get('agent-addr'):
                    setattr(listen_obj, 'Ip', value.get('agent-addr'))
                # setting port to 161 by default, to workaround SW defect:
                if value.get('udp-port', 161):
                    setattr(listen_obj, 'Port', value.get('udp-port', 161))
                if value.get('interface_name'):
                    setattr(listen_obj, 'Interface', value.get('interface_name'))

                if not value.get("no_form"):
                    snmp_obj.add_Listen(listen_obj)
                    if cli_type == "rest" and rest_operation == "put":
                        result = snmp_obj.configure(dut, target_path='/engine', cli_type="rest-put")
                    elif cli_type == "rest" and rest_operation == "post":
                        result = snmp_obj.configure(dut, target_path='/engine', cli_type="rest-post")
                    else:
                        result = snmp_obj.configure(dut, target_path='/engine', cli_type=cli_type)
                else:
                    result = listen_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring SNMP: {}, {}'.format(key, result.data))
                    ret_val = False
            else:
                command = "snmp-server agentaddress"
                if not value.get("no_form"):
                    if value.get("agent-addr"):
                        command += " {}".format(value.get("agent-addr"))
                    if value.get("udp-port"):
                        if value.get("udp-port") != 161:
                            command += " port {}".format(value.get("udp-port"))
                    if value.get("interface_name"):
                        command += " interface {}".format(value.get("interface_name"))
                    if command:
                        commands.append(command)
                else:
                    command = "no snmp-server agentaddress {}".format(value.get("agent-addr"))
                    if value.get("udp-port"):
                        if value.get("udp-port") != 161:
                            command += " port {}".format(value.get("udp-port"))
                    if value.get("interface_name"):
                        command += " interface {}".format(value.get("interface_name"))
                    if command:
                        commands.append(command)

    if cli_type in utils_obj.get_supported_ui_type_list():
        return ret_val
    else:
        if commands:
            st.config(dut, commands, type=cli_type, faster_cli=False, skip_error_check=skip_error)
            return True
        return False


def show(dut, **kwargs):
    """
    API to show snmp-server (community|group|user|view|host) commands
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    COMMAND : show snmp-server  OUTPUT: {'system_name': 'sonic', 'traps': 'enable', 'location': 'hyd',
    'engine_id': '8000013703d8c497726914', 'contact: 'admin'}
    COMMAND : show snmp-server community  OUTPUT: [{'group': 'None', 'community': 'sonic'},
    {'group': 'None', 'community': 'sonic1'}, {'group': 'None', 'community': 'sonic2'}]
    COMMAND : show snmp-server group  OUTPUT: [{'grp_name': 'group2', 'grp_model': 'v3', 'grp_security': 'auth-no-priv',
    'grp_read_view': 'view1', 'grp_write_view': 'view1', 'grp_notify_view': 'view1'}, {'grp_name': 'group2',
    'grp_model': 'v3', 'grp_security': 'auth-priv', 'grp_read_view': 'view1', 'grp_write_view': 'view1',
    'grp_notify_view': 'view1'}]
    COMMAND : show snmp-server view  OUTPUT: [{'view_name': 'view1', 'view_oid': 'iso', 'view_type': 'included'},
    {'view_name': 'view2', 'view_oid': 'iso', 'view_type': 'included'}]
    COMMAND : show snmp-server user  OUTPUT: [{'user_name': 'user1', 'usr_grp_name': 'group1',
    'usr_authentication': 'md5', 'usr_privacy': 'AES-128'}, {'user_name': 'user1', 'usr_grp_name': 'group2',
    'usr_authentication': 'md5', 'usr_privacy': 'AES-128'}]
    COMMAND : show snmp-server host  OUTPUT: {'target_address': '10.52.143.249', 'target_type': 'trapNotify',
    'target_community': 'sonic', 'target_version': 'v2c', 'target_timeout': '1500', 'target_retries': '3'}
    """
    response = list()
    cli_type = kwargs.get("cli_type", "klish")
    snmp_type = kwargs.get("snmp_type", "server")
    command = "show snmp-server"
    if snmp_type and snmp_type != "server":
        command += " {}".format(snmp_type)
    skip_tmpl = kwargs.get("skip_tmpl", False)
    output = st.show(dut, command, type=cli_type, skip_tmpl=skip_tmpl)
    if output:
        if snmp_type in ["server", "community", "group", "view", "user", "host"]:
            sub_attr = list()
            if snmp_type == "community":
                attributes = ["community", "group"]
            elif snmp_type == "group":
                attributes = ["grp_name", "grp_model", "grp_security", "grp_read_view", "grp_write_view",
                              "grp_notify_view"]
            elif snmp_type == "view":
                attributes = ["view_name", "view_oid", "view_type"]
            elif snmp_type == "user":
                attributes = ["user_name", "usr_grp_name", "usr_authentication", "usr_privacy"]
            elif snmp_type == "host":
                attributes = ["target_address", "target_type", "target_community_user", "target_version_security", "target_timeout",
                              "target_retries"]
            else:
                attributes = ["system_name", "traps", "location", "engine_id", "contact"]
                sub_attr = ["agent_ip_address", "agent_udp_port", "agent_interface"]
            if snmp_type != "server":
                for data in output:
                    result = dict()
                    for attr in attributes:
                        result.update({attr: data[attr]})
                    if result:
                        response.append(result)
            else:
                result = dict()
                for key, value in output[0].items():
                    if key in attributes:
                        result.update({key: value})
                result.update({"agents": []})
                for agent_data in output:
                    agents = dict()
                    for attr in sub_attr:
                        agents.update({attr: agent_data[attr]})
                    result["agents"].append(agents)
                if result:
                    response.append(result)
    return response


def show_snmp_counters(dut, **kwargs):
    """
    Api to show snmp counters
    :param dut:
    :param kwargs:
    :return:
    """
    command = "show snmp counters"
    return st.show(dut, command, type="klish")


def clear_snmp_counters(dut, **kwargs):
    """
    Api to clear snmp counters
    :param dut:
    :param kwargs:
    :return:
    """
    command = "clear snmp counters"
    return st.config(dut, command, type="klish", skip_error_check=True)


def verify_snmp_counters(dut, **kwargs):
    cli_type = kwargs.get("cli_type", "klish")
    output = show_snmp_counters(dut, cli_type=cli_type)
    if not output:
        st.error("Couldn't get the output for snmp counters")
        return False
    map = kwargs.get('map', {})
    if not map:
        st.error("Mandatory fields missing to verify the output for snmp counters")
        return False
    for key, value in map.items():
        if not int(output[0][key]) >= value:
            st.error('Match not found for %s :: Expected: %s  Actual : %s' % (key, value, output[0][key]))
            return False
        st.log('Match Found for %s :: and the counter value is non zero' % key)
    return True


def verify(dut, **kwargs):
    """
    API to verify snmp configurtion
    :param dut:
    :param kwargs: cli_type="klish","snmp_type":"community","data":[{'group': 'None', 'community': 'sonic'},
    {'group': 'None', 'community': 'sonic1'}, {'group': 'None', 'community': 'sonic2'}]
    :return: True/False
    """

    cli_type = st.get_ui_type(dut)
    # cli_type = kwargs.get("cli_type", "klish")
    if cli_type not in utils_obj.get_supported_ui_type_list():
        cli_type = 'klish'

    snmp_type = kwargs.get("snmp_type", "")
    filter_data = kwargs.get("data")

    if cli_type in utils_obj.get_supported_ui_type_list():
        if snmp_type not in ['server', 'community', 'group', 'view']:
            cli_type = 'klish'

    if cli_type in utils_obj.get_supported_ui_type_list():
        snmp_obj = umf_snmp.Snmp()
        if not filter_data:
            st.log("DATA TO BE VERIFIED IS NOT PROVIDED")
            return False
        for data in make_list(filter_data):
            if snmp_type == 'server':
                attr_name_map = {'location': 'Location', 'contact': 'Contact', 'engine_id': 'EngineId'}
                for attr_name, attr_val in data.items():
                    if attr_name in attr_name_map:
                        setattr(snmp_obj, attr_name_map[attr_name], attr_val)
                    if attr_name == 'traps':
                        trap = True if attr_val == 'enable' else False
                        setattr(snmp_obj, 'TrapEnable', trap)
                result = snmp_obj.verify(dut, match_subset=True, cli_type=cli_type)

            if snmp_type == 'community':
                comm_obj = umf_snmp.Community(Index=data.get('community'), SecurityName=data.get('group'))
                snmp_obj.add_Community(comm_obj)
                result = snmp_obj.verify(dut, match_subset=True, cli_type=cli_type)

            if snmp_type == "group":
                st.log(filter_data)
                group_obj = umf_snmp.Group(Name=data.get('grp_name'))
                attr_name_map = {'grp_name': 'Name', 'grp_model': 'SecurityModel', 'grp_security': 'SecurityLevel', 'grp_read_view': 'ReadView', 'grp_write_view': 'WriteView', 'grp_notify_view': 'NotifyView'}
                security_model = security_level = None
                st.log(data)
                for attr_name, attr_val in data.items():
                    st.log(attr_name)
                    st.log(attr_val)
                    if attr_name == 'grp_name':
                        continue
                    if attr_name == 'grp_model':
                        version_type = attr_val
                        if version_type in ["v1", "v2c", "any"]:
                            security_model = version_type
                        elif version_type == 'v3':
                            security_model = 'usm'
                    if attr_name == 'grp_security':
                        security_level = attr_val
                    if security_model and security_level:
                        access_obj = umf_snmp.Access(Context='Default', SecurityModel=security_model, SecurityLevel=security_level)
                        security_model = security_level = None
                        group_obj.add_Access(access_obj)
                        continue
                    if attr_name in attr_name_map:
                        setattr(group_obj, attr_name_map[attr_name], attr_val)
                snmp_obj.add_Group(group_obj)
                result = snmp_obj.verify(dut, match_subset=True, cli_type=cli_type)

            if snmp_type == 'view':
                view_obj = umf_snmp.View(Name=data.get('view_name'))
                if data.get('view_type') == 'included':
                    setattr(view_obj, 'Include', data.get('view_oid'))
                if data.get('view_type') == 'excluded':
                    setattr(view_obj, 'Exclude', data.get('view_oid'))
                snmp_obj.add_View(view_obj)
                result = snmp_obj.verify(dut, match_subset=True, cli_type=cli_type)

            if not result.ok():
                st.log('test_step_failed: Verify SNMP type: {}'.format(snmp_type))
                return False

        return True

    output = show(dut, cli_type=cli_type, snmp_type=snmp_type)
    if not output:
        st.log("SHOW OUTPUT NOT FOUND --- {}".format(output))
        return False
    if snmp_type == "server" and isinstance(filter_data, list):
        st.log("Observed invalid filter data for SNMP type Server")
        return False
    if filter_data:
        if isinstance(filter_data, list):
            for data in filter_data:
                entries = filter_and_select(output, data.keys(), data)
                if not entries:
                    return False
        else:
            agent_details = list()
            if snmp_type == "server" and "agents" in filter_data:
                agent_details = filter_data.pop("agents")
            entries = filter_and_select(output, filter_data.keys(), filter_data)
            if not entries:
                return False
            if agent_details and "agents" in output[0]:
                for agent_data in agent_details:
                    entries = filter_and_select(output[0]["agents"], agent_data.keys(), agent_data)
                    if not entries:
                        return False
        return True
    else:
        st.log("DATA TO BE VERIFIED IS NOT PROVIDED")
        return False


def poll_for_snmp_walk_output(dut, iteration_count=5, delay=1, expected_output="", **kwargs):
    """
    This API is to  poll the DUT to get the valid output for walk operation
    Author: Santosh Votarikari(santosh.votarikari@broadcom.com)
    :param dut:
    :param iteration_count:
    :param expected_output:
    :param delay:
    :param kwargs:
    :return: snmp walk output
    """
    i = 1
    while True:
        snmp_walk_out_put = walk_snmp_operation(**kwargs)
        for match in snmp_walk_out_put or []:
            if expected_output in match:
                st.debug("Found expected walk output\n")
                return snmp_walk_out_put
        if st.is_dry_run() or i > iteration_count:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return snmp_walk_out_put
        i += 1
        st.wait(delay)


def poll_for_snmp_get_output(dut, iteration_count=5, delay=1, expected_output="", **kwargs):
    """
    This API is to  poll the DUT to get the valid output for get operation
    Author: Santosh Votarikari(santosh.votarikari@broadcom.com)
    :param dut:
    :param iteration_count:
    :param expected_output:
    :param delay:
    :param kwargs:
    :return: snmp get output
    """
    i = 1
    while True:
        snmp_get_out_put = get_snmp_operation(**kwargs)
        if snmp_get_out_put is False:
            st.debug("Operation Failed")
            return snmp_get_out_put
        for match in snmp_get_out_put:
            if expected_output in match:
                st.debug("Found expected get output")
                return snmp_get_out_put
        if st.is_dry_run() or i > iteration_count:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return snmp_get_out_put
        i += 1
        st.wait(delay)


def get_auth_priv_keys(**kwargs):
    """
    This API is to get the encrypted password for SHA,MD5,AES and DES protocols
    Author: Santosh Votarikari(santosh.votarikari@broadcom.com)
    :param kwargs:
    :param engine_id:
    :param auth_type:
    :param priv_type:
    :param auth_password:
    :param priv_password:
    :return: authkey and privkey
    """
    command = "snmpkey "
    auth_protocol = ["md5", "sha"]
    priv_protocol = ["des", "aes-128", "aes"]
    engine_id = kwargs.get('engine_id')
    auth_type = kwargs.get('auth_type')
    priv_type = kwargs.get('priv_type')
    auth_password = kwargs.get('auth_password')
    priv_password = kwargs.get('priv_password')

    if not engine_id or not auth_type or not auth_password:
        st.log("Mandatory parameters like engine-id,auth_type,auth_password are not passed")
        return False
    if auth_type in auth_protocol:
        command += "{}".format(auth_type)
    else:
        st.log("Unsupported authentication protocol is provided:{}".format(auth_type))
        return False
    if auth_password:
        command += " {}".format(auth_password)
    if engine_id:
        command += " 0x{}".format(engine_id)
    if priv_type in priv_protocol:
        command += " {}".format(priv_type)
    else:
        st.log("Unsupported privacy protocol is provided:{}".format(priv_type))
        return False
    if priv_password:
        command += " {}".format(priv_password)

    st.log("Command is:{}".format(command))
    if st.is_dry_run():
        return False

    pprocess1 = process_popen(command)
    stdout, _ = pprocess1.communicate()
    st.log("Auth Priv Keys output: {}".format(stdout))
    if pprocess1.returncode == 0:
        result = stdout.rstrip('\n').split("\n")
        result1 = [each.replace('"', '') for each in result]
        return result1


def verify_snmp_details_using_docker(dut, **kwargs):
    """
    API to verify the configured SNMP details using docker commands
    :param dut:
    :param kwargs: {'sysname': 'sonic', 'syscontact': '', 'rocommunityv6': 'sonic', 'syslocation': 'Hyderabad', 'rocommunity': 'sonic'}
     {'sysname': 'sonic', 'syscontact': '', 'rocommunityv6': ['sonic','buzznik'], 'syslocation': 'Hyderabad', 'rocommunity': ['sonic','buzznik']}
    :return:
    """
    command = "sudo docker exec -ti snmp cat /etc/snmp/snmpd.conf"
    search_cmd = []
    for key, value in kwargs.items():
        if value:
            if isinstance(value, list):
                for search_str in value:
                    search_cmd.append("{} | grep {}".format(command, search_str))
            else:
                search_cmd.append("{} | grep {}".format(command, value))
    for cmd in search_cmd:
        output = st.show(dut, cmd)
        if not output:
            st.log("No output found with the command {}".format(cmd))
            return False
        for key, value in kwargs.items():
            if value:
                if isinstance(value, list):
                    if output[0][key] not in value:
                        st.log("Expected value not found for {} -- {} in output".format(key, value))
                        return False
                else:
                    if value != output[0][key]:
                        st.log("Expected value not found for {} -- {} in output".format(key, value))
                        return False
    return True


def config_agentx(dut, config='yes', cli_type=''):
    # cli_type = st.get_ui_type(dut, cli_type=cli_type)
    # No klish comnand to configure agentx(SONIC-31578). Revisit the API once the CLI available
    cli_type = 'vtysh'
    config = '' if config == 'yes' else 'no'
    cmd = config + ' agentx'
    st.config(dut, cmd, type=cli_type)


def set_snmp_operation(**kwargs):
    """
    To perform SNMP SET operation
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :ipaddress:
    :param :oid:
    :param :community_name:
    :param :timeout:
    :param :object_name:
    :return:
    """
    community_name = kwargs.get("community_name")
    ip_address = kwargs.get("ipaddress")
    oid = kwargs.get("oid")
    object_type = kwargs.get("objtype")
    object_name = kwargs.get("objname")
    version = kwargs.get("version", "2")
    filter = kwargs.get("filter", "-Oqv")
    report = False

    command = 'snmpset'
    if version not in ["1", "2"]:
        st.log("Unsupported version provided")
        return False
    if not ip_address or not oid:
        st.log("Mandatory parameters like ipaddress or/and oid not passed")
        return False
    if version in ["1", "2"]:
        if not community_name:
            st.log("Mandatory parameter community_name not passed")
            return False
        act_version = "1" if version == "1" else "2c"
        snmp_command = "{} {} -v {} -c {} {} {}".format(command, filter, act_version, community_name,
                                                        ip_address, oid)
        if object_name:
            snmp_command = "{} {} -v {} -c {} {} {} {} '{}'".format(command, filter, act_version, community_name, ip_address,
                                                                    oid, object_type, object_name)

        st.log("snmp command:{}".format(snmp_command))
        if st.is_dry_run():
            return False

        pprocess = process_popen(snmp_command)
        stdout, stderr = pprocess.communicate()
        st.log("SNMP stdout: {}".format(stdout))
        if pprocess.poll() is not None:
            if pprocess.returncode == 0 \
                    and "No Such Object available on this agent at this OID" not in stdout \
                    and "No Such Instance currently exists at this OID" not in stdout \
                    and "No more" not in stdout:
                result = stdout.rstrip('\n').split("\n")
                result1 = [each.replace('"', '') for each in result]
                return result1
            elif "Timeout" in stderr:
                st.error("SNMP Timeout occurs")
                if report:
                    st.report_fail('snmp_operation_fail', 'SET', 'Timeout')
                return False
            elif "No Such Instance currently exists at this OID" in stdout:
                result = stderr.strip("\n")
                st.error(result)
                if report:
                    st.report_fail('snmp_operation_fail', 'SET', 'No Instance Found')
                return False
            else:
                st.log("SNMP Error: return code = {}".format(pprocess.returncode))
                st.log("SNMP stdout: {}".format(stdout))
                st.error("SNMP stderr: {}".format(stderr))
                if report:
                    st.report_fail('snmp_operation_fail', 'SET', 'Error')
                return False

    return True


def verify_trans_info(dut):
    """
    To verify the transciever info is present
    :return:
    """
    cmd = "redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*"
    output = st.config(dut, cmd, skip_error_check=True)
    output = remove_last_line_from_string(output)
    st.log(output)

    if output in ["(empty list or set)", "(empty array)"]:
        return False
    return True


def snmp_int_trap(dut, interface, **kwargs):
    """
    To enable/disable traps on interface.
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    trap_status = kwargs.get('trap_status', 'False')
    if cli_type in utils_obj.get_supported_ui_type_list() + ['klish']:
        snmp_obj = umf_snmp.InterfaceTrap(Ifname=interface, TrapStatus=trap_status)
        operation = Operation.UPDATE if cli_type == 'gnmi' else Operation.CREATE
        resp = snmp_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not resp.ok():
            st.log('test_step_failed: snmp interface level operation failed {}'.format(resp.data))
            return False
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def verify_snmp_int_trap(dut, interface, **kwargs):
    """
    Verify the output status of snmp traps on interface.
    :param dut:
    :param kwargs:
    :return:
    """
    st.log('API_NAME: verify_snmp_int_trap, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    trap_status = kwargs.get('trap_status', 'True')
    if cli_type in utils_obj.get_supported_ui_type_list() + ['klish']:
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        snmp_obj = umf_snmp.InterfaceTrap(Ifname=interface, TrapStatus=trap_status)
        result = snmp_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if result is True:
            return True
        else:
            if not result.ok():
                st.log('test_step_failed: Match NOT Found: interface traps')
                return False
    return True

# deleting all existing trap logs from snmptrapd server


def clear_snmp_trapd_logs(dut, ssh_conn_obj):
    capture_file = utils_obj.ensure_service_params(dut, "snmptrap", "path")
    clear_cmd = "echo " " > {}".format(capture_file)
    execute_command(ssh_conn_obj, clear_cmd)

# check and start the snmptrap on the given server.


def ensure_snmp_trapd(dut, ssh_conn_obj, clear_logs=False):
    ip = utils_obj.ensure_service_params(dut, "snmptrap", "ip")
    ps_cmd = "ps -ealf | grep snmptrapd | grep -v grep"
    st.log("Checking for snmptrap process existence with command '{}'".format(ps_cmd))
    for _ in range(3):
        output = execute_command(ssh_conn_obj, ps_cmd)
        if "snmptrapd" not in output:
            st.wait(3, "Unable to find any logs with 'snmptrapd', So, waiting for snmptrapd server to be Up after restart")
            continue
        for line in output.split("\n"):
            if "snmptrapd" in line:
                if clear_logs:
                    clear_snmp_trapd_logs(dut, ssh_conn_obj)
                return

    if not ip_api.ping(dut, ip, family='ipv4', external=True):
        msg = 'SNMP trap server reachability is failed from the SNMP agent device. Please execute the testcase with valid server details.'
    else:
        msg = "Couldn't get the snmptrapd process details from snmp trap server. Please check the snmp trap server process in the server."
    st.report_env_fail('test_case_failed_msg', msg)
