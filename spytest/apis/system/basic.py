import json
import os
import re
import ast
import datetime
import yaml

from spytest import st
from spytest.utils import filter_and_select
from spytest.utils import exec_all
import apis.system.connection as conn_obj

from utilities.common import delete_file, do_eval, make_list, iterable
import utilities.utils as utils_obj
from apis.system.rest import get_rest,config_rest


def ensure_hwsku_config(dut):
    #TODO: call sudo config-hwsku set if present in device params
    pass

def ensure_certificate(dut):
    if st.is_feature_supported("certgen-command", dut):
        st.config(dut, "/usr/bin/certgen admin")

def get_system_status(dut, service=None, skip_error_check=False):
    output = "???"
    try:
        output = st.show(dut, "show system status", skip_tmpl=True,
                         skip_error_check=skip_error_check)
        if "Error: Got unexpected extra argument (status)" in output:
            return None

        output = st.parse_show(dut, "show system status", output)
        if not output:
            return False
        if output[0]["status"] == "ready":
            return True
        if service and output[0][service] == "Up":
            return True
    except Exception as exp:
        msg = "Failed to read system online status output='{}' error='{}'"
        st.warn(msg.format(output, exp))
    return False


def get_processes_memory(dut):
    """
    Author: Harsha Golla (harsgoll@cisco.com)
    Function to get the Memory usage
    :param dut:
    :return:
    """
    command = "show processes memory"
    return st.show(dut, command)

def get_processes_cpu(dut):
    """
    Author: Hareesh Ganipineni (hganipin@cisco.com)
    Function to get the CPU usage for each process
    :param dut:
    :return:
    """
    command = "show processes cpu"
    return st.show(dut, command)

def get_environment(dut):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Fucntion to get the show environment
    :param dut
    :return:
    """
    command = "show environment"
    return st.show(dut,command)

def apply_config_reload(dut):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get the show environment
    :param dut
    :return:
    """
    command = "config reload -y"
    return st.config(dut,command)

def apply_optics_flap(dut, port,operation='on'):
    """
    Author: Hareesh Ganipineni (hganipin@cisco.com)
    Function for simulation of  optics on for specified port
    :param dut
    :param port number: integer
    :operation: on/off
    :return:
    """
    command = "/opt/cisco/bin/sfp.py {} {} ".format(operation,port)
    return st.config(dut,command)

def get_show_run_all(dut):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Fucntion to get the show runningconfiguration all
    :param dut
    :return:
    """
    command = "show runningconfiguration all"
    return st.config(dut,command)

def get_interface(dut, interface_name,ctype='vtysh',asic='None'):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Fucntion to get the show interface interface_name 
    :param dut
    :param interface_name: Ethernet\d+
    :return:
    """
    command = "show interface "+interface_name
    if ctype == 'vtysh-multi-asic':
        Kwargs = {}
        Kwargs['type'] = ctype
        Kwargs['asic'] = asic
        return st.show(dut,command,**Kwargs)
    else:
        return st.show(dut,command,type=ctype)

def get_int_transceiver_eeprom(dut):
    """
    Author: Harsha Golla (harsgoll@cisco.com)
    Function to get the show int transciever eeprom -dom
    :param dut:
    :return:
    """
    command = "show int transceiver eeprom"
    return st.show(dut, command)

def get_sfputil_show_eeprom(dut):
    """
    Author: Deekshitha Kankanala(dkankana@cisco.com)
    Function to get the sfputil show eeprom
    :param dut:
    :return:
    """
    command = "sudo sfputil show eeprom"
    return st.show(dut, command) 

def get_sfputil_reset_ethernet(dut, port):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get the sfputil reset Ethernet[/d+]
    :param dut:
    :return:
    """
    command = "sudo sfputil reset "+port
    return st.show(dut,command)

def get_sysuptime(dut):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    up_time = show_version(dut)['uptime']
    return up_time


def get_hwsku(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to ge the hwsku of the device.
    :param dut:
    :return:
    """
    output = st.show(dut, "show platform summary")
    if len(output) <= 0 or "hwsku" not in output[0]:
        return None
    hwsku = output[0]["hwsku"]
    return hwsku

def set_hwsku(dut, hwsku):
    st.config(dut, "config-hwsku set {}".format(hwsku),
              confirm='y', expect_reboot=True)

def get_platform_summary(dut, value=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform summary")
    if value:
        if len(output) <= 0 or value not in output[0]:
            return None
        out = output[0][value]
        return out
    else:
        if output:
            return output[0]

def get_platform_ssdhealth(dut):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to ge the Platform ssdhealth of the device.
    :param dut:
    :param value:  devicemodel | health | temperature
    :return:
    """
    output = st.show(dut, "show platform ssdhealth")
    if output:
        return output[0]
    return output
    
def get_platform_idprom(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "sudo show platform idprom")
    if output:
        return output[0]
    return output

def get_users(dut,value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get users
    :param dut:
    :param value:  
    :return:
    """
    output = st.show(dut, "show users")
    return output

def get_platform_inventory(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform inventory")
    if output == []:
        output = st.show(dut, "sudo show platform inventory")
    if value:
        if len(output) <= 0 or value not in output[0]:
            return None
        out = output[0][value]
        return out
    else:
        if output:
            return output[0]

def get_platform_temperature(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to ge the Platform temperature of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform temperature")
    return output

def get_platform_psustatus(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform psustatus")
    return output

def get_show_boot(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show boot.
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show boot")
    if output:
        return output[0]
    return output

def get_show_mgmt_vrf(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show mgmt-vrf
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show mgmt-vrf")
    if output:
        return output[0]
    return output

def get_show_int_transceiver_presence(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show int transceiver presence
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show int transceiver presence")
    return output

def get_show_int_transceiver_lpmode(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show int transceiver presence
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show int transceiver lpmode")
    return output

def get_show_management_int_address(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show mgmt-vrf
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show management_interface address")
    if len(output) <= 0 :
        return None
    if output:
        return output[0]
    return output

def get_show_system_memory(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show system-memory
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show system-memory")
    if len(output) <= 0 :
        return None
    return output[0]

def apply_install(dut, image_name):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to apply "sonic-installer install xxxxx.bin"
    :param dut: dut
    :param image_name: value
    :return
    """
    cmd = "sonic-installer install -y "+image_name
    output = st.config(dut, cmd)
    return output

def shutdown_dut(dut):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to apply "shutdown -r now"
    :param dut: dut
    """
    cmd = "shutdown -r now"
    output = st.config(dut, cmd, skip_tmpl=True)
    return output

def get_show_services(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show services
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show services")
    return output

def get_show_environment(dut):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show environment
    :param dut:
    :param value:  dut name 
    :return:
    """
    output = st.show(dut, "show environment")
    return output

def enable_show_mgmt_vrf(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show mgmt-vrf
    :param dut:
    :param value:  dut name 
    :return:
    """
    command = "sudo config vrf add mgmt"
    st.config(dut, command)    

def disable_show_mgmt_vrf(dut, value = None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to get show mgmt-vrf
    :param dut:
    :param value:  dut name 
    :return:
    """
    command = "sudo config vrf del mgmt"
    st.config(dut, command)

def get_platform_fan(dut, value=None):
    """
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    Function to ge the Platform summary of the device.
    :param dut:
    :param value:  hwsku | platform | asic
    :return:
    """
    output = st.show(dut, "show platform fan")
    return output

def get_dut_date_time(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the DUT date and time
    :param dut:
    :return:
    """
    return utils_obj.remove_last_line_from_string(st.config(dut, "date"))


def get_dut_date_time_obj(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the dur date and time object
    :param dut:
    :return:
    """
    date_val = get_dut_date_time(dut)
    try:
        match = re.search('[A-Z]{2,}', date_val)
        if match:
            timezone = match.group(0)
            return datetime.datetime.strptime(date_val, '%a %b  %d %H:%M:%S {} %Y'.format(timezone))
    except Exception as e:
        st.error(e)
        return None


def get_mac_address(base_mac="00:00:00:00:00:00", start=1, end=100):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the mac addressses
    :param base_mac:
    :param start:
    :param end:
    :return:
    """
    mac_address_list = list()
    base_mac = base_mac.replace(":", '').replace(" ", '')
    mac_int = int("0x"+base_mac, 16)
    for i in range(mac_int+start, mac_int+end+1):
        mac_address = "{0:0{1}x}".format(i, 12)
        mac_formated = ":".join([mac_address[i:i+2] for i in range(0, len(mac_address), 2)])
        mac_address_list.append(mac_formated)
    return mac_address_list


def get_ifconfig(dut, interface=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig output
    :param dut:
    :param interface:
    :return:
    """
    interface = interface or st.get_mgmt_ifname(dut)
    if '/' in interface:
        interface = st.get_other_names(dut,[interface])[0]
    command = "/sbin/ifconfig {}".format(interface)
    return st.show(dut, command)


def get_ifconfig_inet(dut, interface=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig inet
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface)
    if len(output) <= 0 or "inet" not in output[0]:
        return None
    ip_addresses = output[0]['inet']
    return ip_addresses


def get_ifconfig_inet6(dut, interface=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig inet6
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface)
    if len(output) <= 0 or "inet6" not in output[0]:
        return None
    ip_addresses = output[0]['inet6']
    return ip_addresses


def get_ifconfig_ether(dut, interface=None):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to get the ifconfig ethernet
    :param dut:
    :param interface:
    :return:
    """
    output = get_ifconfig(dut, interface)
    if len(output) <= 0 or "mac" not in output[0]:
        return None
    mac_address = output[0]['mac']
    return mac_address


def ifconfig_operation(connection_obj, interface_name, operation, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to perform operations on ifconfig interface
    :param connection_obj:
    :param interface_name:
    :param operation:
    :param device:
    :return:
    """
    command = "if{} {}".format(operation, interface_name)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def get_hostname(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the hostname
    :param dut:
    :return:
    """
    cmd = 'hostname'
    hostname = utils_obj.remove_last_line_from_string(st.show(dut, cmd, skip_tmpl=True))
    hostname = hostname.strip()
    if hostname.startswith(cmd+'\n'):
        hostname = hostname[len(cmd+'\n'):]
    return hostname


def whoami(connection_obj):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the whoami
    :param connection_obj:
    :return:
    """
    return utils_obj.remove_last_line_from_string(conn_obj.execute_command(connection_obj, "whoami"))


def service_operations(connection_obj, service, action="start", client="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to do the service operations
    :param connection_obj:
    :param service:
    :param action:
    :param client:
    :return:
    """
    st.log("####### Restarting {} service ########".format(service))
    command = "sudo service {} {}".format(service, action)
    if client == "dut":
        st.config(connection_obj, command)
    else:
        cnt = 1
        iteration = 4
        while True:
            response = conn_obj.execute_command(connection_obj, command)
            if response is None:
                st.log("No response received, hence retrying..")
                conn_obj.execute_command(connection_obj, command)
            if response is not None:
                st.log("Received response after executing command")
                break
            if cnt > iteration:
                st.error("Prompt not found after {} attempts".format(iteration))
                break
            cnt += 1
            st.wait(3)


def verify_service_status(dut, service, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to verify the service status
    :param dut: DUT or server
    :param service:
    :param device :
    :return:
    """
    command = "systemctl is-active {}".format(service)
    if device == "dut":
        result = st.config(dut, command)
    else:
        result = conn_obj.execute_command(dut, command)
    if utils_obj.remove_last_line_from_string(result) != "active":
        if "active" not in result or result != "inactive":
            return False
    return True

def systemctl_restart_service(dut, name, max_wait=10, skip_error_check=False):
    command = "systemctl restart {}".format(name)
    st.config(dut, command, skip_error_check=skip_error_check)

    i, delay, retval = 1, 1, False
    while True:
        if verify_service_status(dut, name):
            retval = True
            break
        if delay < 0 or i > int(max_wait/delay):
            break
        i += delay
        st.wait(delay)

    return retval

def service_operations_by_systemctl(dut, service, operation, skip_error_check=False):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to do the service operations using systemctl
    :param dut:
    :param service:
    :param operation:
    :return:
    """
    command = "systemctl {} {}".format(operation, service)
    return st.config(dut, command, skip_error_check=skip_error_check)


def copy_file_to_local_path(dut, src_path, dst_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to copy the file to local path
    :param dut:
    :param src_path:
    :param dst_path:
    :return:
    """
    command = "cp {} {}".format(src_path, dst_path)
    st.config(dut, command)


def delete_line_from_file(connection_obj, line_number, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to delete the line from file
    :param connection_obj:
    :param line_number:
    :param file_path:
    :param device:
    :return:
    """
    command = "sed -i -e '{}d' {}".format(line_number, file_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def write_to_file(connection_obj, content, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write to file
    :param connection_obj:
    :param content:
    :param file_path:
    :param device:
    :return:
    """
    command = "sudo echo {} >> {}".format(content, file_path)
    st.log(command)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def create_and_write_to_file_sudo_mode(dut, content, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Functcion to creat and write to file
    :param dut:
    :param content:
    :param file_path:
    :return:
    """
    command = 'sudo bash -c "echo {} > {}" '.format(content, file_path)
    st.config(dut, command)


def write_to_file_sudo_mode(dut, content, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write to file using sudo mode
    :param dut:
    :param content:
    :param file_path:
    :return:
    """
    command = 'sudo bash -c "echo {} >> {}" '.format(content, file_path)
    st.config(dut, command)


def verify_file_on_device(connection_obj, client_path, file_name="client.pem", device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to verify the file on device
    :param connection_obj:
    :param client_path:
    :param file_name:
    :param device:
    :return:
    """
    path = "{}/{}".format(client_path, file_name)
    command = '[ -f {} ] && echo 1 || echo 0'.format(path)
    try:
        if device == "dut":
            files_list = st.config(connection_obj, command)
        else:
            files_list = conn_obj.execute_command(connection_obj, command)
        if int(utils_obj.remove_last_line_from_string(files_list)) != 1:
            return False
        return True
    except Exception as e:
        st.log(e)
        return False


def make_dir(connection_obj, folder_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to make directory
    :param connection_obj:
    :param folder_path:
    :param device:
    :return:
    """
    command = "mkdir -p {}".format(folder_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def change_permissions(connection_obj, folder_path, permission=777, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to change permissions of the file
    :param connection_obj:
    :param folder_path:
    :param permission:
    :param device:
    :return:
    """
    command = "chmod {} {}".format(permission, folder_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def write_to_file_to_line(connection_obj, content, line, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write content to a line in a file.
    :param connection_obj:
    :param content:
    :param line:
    :param file_path:
    :param device:
    :return:
    """
    command = "sudo sed -i '{}i {}' {}".format(line, content, file_path)
    st.log("COMMAND -- {}".format(command))
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def get_pwd(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Get present working directory on the device
    :param dut:
    :return:
    """
    return utils_obj.remove_last_line_from_string(st.show(dut, "pwd", skip_tmpl=True))


def write_to_file_before_line(connection_obj, content, before_line, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write content to a file before specific line
    :param connection_obj:
    :param content:
    :param before_line:
    :param file_path:
    :param device:
    :return:
    """
    command = "sed -i '/^{}.*/i {}' {}".format(before_line, content, file_path)
    if device == "dut":
        st.config(connection_obj, command)
    else:
        conn_obj.execute_command(connection_obj, command)


def get_match_string_line_number(connection_obj, search_string, file_path, device="dut"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to get the matching string line number
    :param connection_obj:
    :param search_string:
    :param file_path:
    :param device:
    :return:
    """
    command = "grep -hnr --color=never '{}' {}".format(search_string, file_path)
    if device == "dut":
        result = st.config(connection_obj, command)
    else:
        result = conn_obj.execute_command(connection_obj, command)
    result = utils_obj.remove_last_line_from_string(result)
    if result:
        result = str(result)
        match_string = re.search(r"(\d+):", result)
        if match_string:
            line_number = match_string.group(1)
            return line_number
    return -1


def write_update_file(connection_obj, old_string, new_string, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write the file to be updated
    :param connection_obj:
    :param old_string:
    :param new_string:
    :param file_path:
    :return:
    """
    # line_number = get_match_string_line_number(connection_obj, new_string, file_path, "server")
    replace_line_in_file(connection_obj, old_string, new_string, file_path)
    if not find_line_in_file(connection_obj, new_string, file_path):
        new_string = "{}".format(new_string)
        write_to_file_to_line(connection_obj, new_string, 51, file_path, device="server")
        # before_line = "key dhcpupdate {"
        # write_to_file_before_line(connection_obj, new_string, before_line, file_path, "server")
        if not find_line_in_file(connection_obj, new_string, file_path):
            return False
        else:
            return True
    return True


def write_to_text_file(content):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to write content to a file
    :param content:
    :return:
    """
    if content:
        src_file = st.mktemp()
        src_fp = open(src_file, "w")
        src_fp.write(content)
        src_fp.close()
        return src_file


def replace_line_in_file(ssh_conn_obj, old_string, new_string, file_path,device = 'server'):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to replace the content in a file in a specific line
    :param ssh_conn_obj:
    :param old_string:
    :param new_string:
    :param file_path:
    :return:
    """
    command = "sudo sed -i '/^{}/ c {}' {}".format(old_string, new_string, file_path)
    if device == 'server':
        conn_obj.execute_command(ssh_conn_obj, command)
    else:
        st.config(ssh_conn_obj, command, faster_cli=False)


def replace_line_in_file_with_line_number(dut,**kwargs):
    """
    Author:Chaitanya Lohith Bollapragada
    Usage:
    This api take the file path, line number of the text in the file and the new_text to insert in.
    for example to change the ssh port number in " /etc/ssh/sshd_config"
    replace_line_in_file_with_line_number(vars.D1, line_number = 12, text = 'Port 233', file_path = '/etc/ssh/sshd_config')
    User do not have to know about previous line to change it.
    to get line number use api get_match_string_line_number(vars.D1, 'Port ', '/etc/ssh/sshd_config')
    advanced usage:
    replace_line_in_file_with_line_number(vars.D1, line_number = get_match_string_line_number(vars.D1, 'Port ', '/etc/ssh/sshd_config'),
                                          text = 'Port 233', file_path = '/etc/ssh/sshd_config')
    Assuming default device is server.
    :param dut:
    :param line_number:
    :param text:
    :param file_path:
    :return: bool
    """
    if not ('line_number' in kwargs and 'text' in kwargs and 'file_path' in kwargs):
        return False
    command = 'sed -i "{}s/.*/{}/" {}'.format(kwargs['line_number'], kwargs['text'], kwargs['file_path'])
    if 'device' not in kwargs:
        conn_obj.execute_command(dut, command)
    else:
        st.config(dut, command)
    return True


def find_line_in_file(ssh_conn_obj, search_string, file_path, device='server'):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to file line in  a file
    :param ssh_conn_obj:
    :param search_string:
    :param file_path:
    :return:
    """
    command = "grep -w '{}' {}".format(search_string, file_path)
    result = conn_obj.execute_command(ssh_conn_obj, command) if device == 'server' else st.config(ssh_conn_obj, command)
    if utils_obj.remove_last_line_from_string(result).find(search_string) < 1:
        return False
    return True


def check_service_status(ssh_conn_obj, service_name, status="running", device='server'):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to check the service status
    :param ssh_conn_obj:
    :param service_name:
    :param status:
    :return:
    """
    st.log("##### Checking {} status for {} service ######".format(status, service_name))
    command = "status {}".format(service_name)
    result = conn_obj.execute_command(ssh_conn_obj, command) if device == 'server' else st.config(ssh_conn_obj, command)
    result = utils_obj.remove_last_line_from_string(result)
    if "command not found" not in result:
        match = "start/running" if status == "running" else "stop/waiting"
        if result.find("{}".format(match)) > 1:
            return True
    else:
        command = "service --status-all | grep {}".format(service_name)
        result = conn_obj.execute_command(ssh_conn_obj, command)
        result = utils_obj.remove_last_line_from_string(result)
        operator = "+" if status == "running" else "-"
        return True if operator in result and service_name in result else False
    return False


def write_to_json_file(json_content):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to  write the json content to a file
    :param json_content:
    :return:
    """
    json_dump = json.dumps(json_content)
    parsed = json.loads(json_dump)
    chef_cookbook_json = json.dumps(parsed, indent=4, sort_keys=True)
    src_file = st.mktemp()
    src_fp = open(src_file, "w")
    src_fp.write(chef_cookbook_json)
    src_fp.close()
    return src_file


def copy_file_from_client_to_server(ssh_con_obj, **kwargs):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to copy file from client to server
    :param ssh_con_obj:
    :param kwargs:
    :return:
    """
    try:
        import netmiko
        scp_conn = netmiko.SCPConn(ssh_con_obj)
        scp_conn.scp_transfer_file(kwargs["src_path"], kwargs["dst_path"])
        scp_conn.close()
        if "persist" not in kwargs:
            os.remove(kwargs["src_path"])
    except Exception as e:
        st.log(e)
        st.report_fail("scp_file_transfer_failed", kwargs["src_path"], kwargs["dst_path"])


def check_error_log(dut, file_path, error_string, lines=1, file_length=50, match=None, start_line=0):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to check the error log
    :param dut:
    :param file_path:
    :param error_string:
    :param lines:
    :param file_length:
    :return:
    """
    if start_line != 0:
        command = 'sudo tail -n +{} {} | grep "{}" | grep -Ev "sudo tail"'.format(start_line, file_path, error_string)
    else:
        command = 'sudo tail -{} {} | grep "{}" | tail -{}'.format(file_length, file_path, error_string, lines)
    try:
        response = utils_obj.remove_last_line_from_string(st.show(dut, command, skip_tmpl=True, skip_error_check=True))
        result = response.find(error_string) > 1 if not match else response
        if result:
            return True
        else:
            return False
    except ValueError as e:
        st.log(e)
        return False


def poll_for_error_logs(dut, file_path, error_string, lines=1, file_length=50, iteration_cnt=10, delay=1, match=None):
    """
    API to poll for error logs
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_path:
    :param error_string:
    :param lines:
    :param file_length:
    :param iteration_cnt:
    :param delay:
    :return:
    """
    i=1
    while True:
        if check_error_log(dut, file_path, error_string, lines, file_length, match=match):
            st.log("Log found in {} iteration".format(i))
            return True
        if i > iteration_cnt:
            st.log("Max iteration count {} reached ".format(i))
            return False
        i+=delay
        st.wait(delay)


def show_version(dut, cli_type= ''):
    """
    Get Show Version
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    #rest support is blocked due to SONIC-24371. So falling back to klish
    if cli_type in ['rest-put', 'rest-patch']:
        cli_type = 'klish'
    if cli_type in ['click', 'klish']:
        command = 'show version'
        output = st.show(dut, command, type= cli_type)
        if not output or st.is_dry_run(): return []
        exclude_keys = ['repository', 'tag', 'image_id', 'size']
        rv = {each_key: output[0][each_key] for each_key in output[0] if each_key not in exclude_keys}
        return rv
    else:
        st.log("UNSUPPORTED CLI TYPE ")
        return False


def get_docker_info(dut):
    """
    Get the docker infor from the show version output
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = 'show version'
    output = st.show(dut, command)
    include_keys = ['repository', 'tag', 'image_id', 'size']
    rv = [{each_key: each_line[each_key] for each_key in each_line if each_key in include_keys} for each_line in
          output[1:]]
    return rv


def get_docker_ps(dut):
    """
    Get docker ps
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = 'docker ps --no-trunc'
    output = st.show(dut, command)
    return output

def get_docker_ps_container(dut, container_name):
    """
    Get docker ps -f name=""
    Author: Deekshitha Kankanala (dkankana@cisco.com)
    :param dut:
    :return:
    """
    command = 'docker ps -f {}={}'.format('name', container_name)
    output = st.show(dut, command)
    if output:
        return output[0]
    return output     

def get_docker_stats(dut):
    """
    Get docker ps
    :param dut:
    :return:
    """
    command = 'docker stats -a --no-stream'
    output = st.show(dut, command)
    return output


def verify_docker_ps(dut, image, **kwargs):
    """
    To verify docker ps info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param image:
    :param container_id:
    :param command:
    :param created:
    :param status:
    :param ports:
    :param names:
    :return:
    """
    output = get_docker_ps(dut)
    rv = filter_and_select(output, None, {'image': image})
    if not rv:
        st.error("No match for {} = {} in table".format('image', image))
        return False
    for each in kwargs.keys():
        if not filter_and_select(rv, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
        else:
            st.log("Match found for {} = {} in table".format(each, kwargs[each]))

    return True


def docker_operation(dut, docker_name, operation):
    """
    To Perform Docker operations
    Author: kesava-swamy.karedla@broadcom.com
    :param dut:
    :param docker_name:
    :param operation:
    :return:
    """
    command = 'docker {} {}'.format(operation, docker_name)
    return st.config(dut, command)


def get_memory_info(dut):
    """
    Get Memory information form TOP command
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = "top -n 1 b | head -n 4 | tail -n 1"
    output = st.show(dut, command)
    rv = {}
    if output:
        include_keys = ['total', 'used', 'free', 'buff_cache']
        rv = {each_key:  ast.literal_eval(output[0][each_key]) for each_key in output[0] if each_key in include_keys}
    return rv


def get_top_info(dut, proc_name=None):
    """
    Get Process details from the TOP command
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param proc_name: process name
    :return:
    """
    exclude_keys = ['total', 'used', 'free', 'buff_cache']
    if proc_name:
        command = "top -n 1 b | grep {}".format(proc_name)
        output = st.show(dut, command)
        rv = [{each_key: each_line[each_key] for each_key in each_line if each_key not in exclude_keys}
              for each_line in output]
        rv = filter_and_select(rv, None, {'command': proc_name})
    else:
        command = "top -n 1 b"
        output = st.show(dut, command)
        rv = [{each_key: each_line[each_key] for each_key in each_line if each_key not in exclude_keys}
              for each_line in output[1:]]
    return rv


def get_overall_cpu_util(dut, exclude_proc_name=None):
    """
    Get Over all CPU Utlization - WIP
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param exclude_proc_name: exclude proc name
    :return:
    """



def get_platform_syseeprom(dut, tlv_name=None, key='value', decode=False, cli_type=''):
    """
    Get Platform Syseeprom
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param tlv_name:
    :param key:  value/len/code
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        if decode:
            command = "sudo decode-syseeprom"
        else:
            command = "show platform syseeprom"
        result = st.show(dut, command, type=cli_type)
    elif cli_type in ["klish","rest-patch","rest-put"]:
        result = list()
        if cli_type == "klish":
            command = "show platform syseeprom"
            output = st.show(dut, command, type=cli_type)
        else:
            output = list()
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['get_system_component'].format("System Eeprom")
            try:
                data=get_rest(dut, rest_url=url1)["output"]["openconfig-platform:component"][0]["state"]
            except Exception as e:
                st.error(e)
                return False
            for k in data:
                temp = dict()
                temp["value"] = data[k]
                k = k.split(":").pop()
                temp["ktlv_name"] = k
                output.append(temp)
        st.log(output)
        key_mapping = {"Platform":"Platform Name","Base Mac Address":"Base MAC Address","Mfg Date":"Manufacture Date",
                       "Hardware Version":"Label Revision","Onie Version":"ONIE Version","Mac Addresses":"MAC Addresses",
                       "Mfg Name":"Manufacturer","Manufacture Country":"Manufacture Country","Vendor Name":"Vendor Name",
                       "Diag Version":"Diag Version","description":"Platform Name","id":"Product Name",
                       "part-no":"Part Number","serial-no":"Serial Number","base-mac-address":"Base MAC Address",
                       "mfg-date":"Manufacture Date","hardware-version":"Label Revision","onie-version":"ONIE Version",
                       "mac-addresses":"MAC Addresses","mfg-name":"Manufacturer",
                       "manufacture-country":"Manufacture Country","vendor-name":"Vendor Name",
                       "diag-version":"Diag Version"}
        for each in output:
            if each.get("ktlv_name",""):
                if each["ktlv_name"] in key_mapping.keys():
                    each["tlv_name"] = key_mapping[each["ktlv_name"]]
                else:
                    each["tlv_name"] = each["ktlv_name"]
            each.pop("ktlv_name",None)
            result.append(each)
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    if tlv_name:
        result = filter_and_select(result, [key], {"tlv_name": tlv_name})[0][key]
    return result


def get_platform_syseeprom_as_dict(dut, tlv_name=None, key='value', decode=False):
    """
    Get Platform Syseeprom as dict
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param tlv_name:
    :param key:
    :param decode:
    :return:
    """
    rv = {}
    output = get_platform_syseeprom(dut, tlv_name=tlv_name, key=key, decode=decode)
    for each in iterable(output):
        rv[each['tlv_name']] = each[key]
    return rv


def copy_config_db_to_temp(dut, source_path, destination_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    This API is to backup config db json.
    :param dut:
    :param source_path:
    :param destination_path:
    :return:
    """
    if not verify_file_on_device(dut, "/etc/sonic", "config_db.json", "dut"):
        command = "config save -y"
        st.config(dut, command)
    copy_file_to_local_path(dut, source_path, destination_path)


def remove_file(dut, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    This API is to remove file from a specifc path
    :param dut:
    :param file_path:
    :return:
    """
    st.log("####### Removing file {} #######".format(file_path))
    command = "rm -f -- {}".format(file_path)
    st.config(dut, command)


def verify_package(dut, packane_name):
    """
    To verify package is installed or not
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param packane_name:
    :return:
    """
    command = "dpkg -s {} | grep Status".format(packane_name)
    output = st.config(dut, command, skip_error_check=True)
    if "package '{}' is not installed".format(packane_name) in output:
        st.log("Package '{}' is not installed in DUT".format(packane_name))
        return False
    return True


def deploy_package(dut, packane_name=None, mode='install', skip_verify_package=False, options=None):
    """
    To verify package is installed or not
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param packane_name:
    :param mode: install | update | remove | purge
    :return:
    """

    if mode == "install":
        if options:
            command = "apt-get install {} {} -y".format(options, packane_name)
        else:
            command = "apt-get install {} -y".format(packane_name)

        if not skip_verify_package:
            if verify_package(dut, packane_name):
                st.log("Package '{}' is already installed".format(packane_name), dut=dut)
                return True

        for attempt in range(3):
            st.config(dut, command, skip_error_check=True, faster_cli=False)
            if verify_package(dut, packane_name):
                st.log("Successfully installed package '{}'".format(packane_name), dut=dut)
                return True
            if attempt <= 2:
                st.warn("Failed to install package '{}' attempt {}".format(packane_name, attempt), dut=dut)
                st.wait(10, "Wait to retry installation")
        st.error("Failed to install package '{}'".format(packane_name), dut=dut)
        return False

    if mode in ['remove', 'purge']:
        command = "apt-get {} {} -y".format(mode, packane_name)
        st.config(dut, command, skip_error_check=True, faster_cli=False)
        if verify_package(dut, packane_name):
            st.warn("Failed to {} package '{}'".format(mode, packane_name), dut=dut)
            return False
        st.log("Successfully {}d package '{}'".format(mode, packane_name), dut=dut)
        return True

    if mode == "update":
        command = "apt-get update"
        for attempt in range(3):
            output = st.config(dut, command, skip_error_check=True, faster_cli=False)
            if "Done" in output:
                st.log("Successfully {}d packages".format(mode), dut=dut)
                return True
            if attempt <= 2:
                st.warn("Failed to update packages attempt {}".format(attempt), dut=dut)
                st.wait(10, "Wait to retry update")
        st.error("Failed to update packages", dut=dut)
        return False

    st.log("invalid mode - {}".format(mode))
    return False


def download_file_content(dut, file_path, device="dut"):
    """
    This is the API to read the file content and return for further processing
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_path:
    :param device:
    :return:
    """
    file_content = ""
    if device == "dut":
        command = "value=$(<{})".format(file_path)
        st.show(dut, command, skip_tmpl=True)
        command = "echo $value"
        file_content = utils_obj.remove_last_line_from_string(st.show(dut, command, skip_tmpl=True))
    return file_content


def poll_for_system_status(dut, service=None, iteration=150, delay=2):

    if not st.is_feature_supported("system-status", dut):
        return st.wait_system_status(dut, (iteration*delay))

    i = 1
    while True:
        if get_system_status(dut, service):
            st.log("System is ready in {} iteration".format(i))
            return True
        if i > iteration:
            st.log("Max iteration count {} reached ".format(i))
            return False
        i += delay
        st.wait(delay)


def get_interface_status(conn_obj, interface, device="dut"):
    """
    API to get the linux interface status
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param conn_obj:
    :param interface:
    :param device:
    :return:
    """
    command = "cat /sys/class/net/{}/operstate".format(interface)
    if device=="dut":
        return utils_obj.remove_last_line_from_string(st.show(conn_obj, command, skip_tmpl=True))


def check_interface_status(conn_obj, interface, state, device="dut"):
    """
    API to check the interface state
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param conn_obj:
    :param interface:
    :param state:
    :param device:
    :return:
    """
    interface_state = get_interface_status(conn_obj, interface, device=device)
    if "No such file or directory" in interface_state:
        return None
    if interface_state != state:
        return False
    return True


def get_ps_aux(connection_obj, search_string, device="dut"):
    """
    API to get the ps aux output
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param conn_obj:
    :param search_string:
    :param device:
    :return:
    """
    command = "sudo ps aux"
    if search_string:
        command += " | grep {}".format(search_string)
    if device == "dut":
        return st.show(connection_obj, command)
    else:
        return conn_obj.execute_command(connection_obj, command)


def get_ifconfig_gateway(dut, interface=None):
    """
    API will return Gateway ip address
    :param dut:
    :param interface:
    :return:
    """
    interface = interface or st.get_mgmt_ifname(dut)
    output = st.show(dut, "sudo route -n")
    gateway_list = [row['gateway'] for row in output if 'G' in row['flags'] and row['iface'] == interface]
    return None if len(gateway_list) == 0 else gateway_list[0]


def get_frr_config(conn_obj, device="dut", protocol=None, cli_type= ''):
    """
    API to get frr config from frr.conf file
    Author: Sooriya G (sooriya.gajendrababu@broadcom.com)
    :param conn_obj:
    :param device:
    :return:
    """
    cli_type = st.get_ui_type(cli_type=cli_type)

    if cli_type == 'click':
        command = " sudo cat /etc/sonic/frr/frr.conf"
    elif cli_type in ['klish', 'rest-patch', 'rest-put']:
        if not protocol:
            st.error("Please provide the protocol name to get frr config for cli_type {}".format(cli_type))
            return ''
        command = " sudo cat /etc/sonic/frr/{}d.conf".format(protocol)
    if device == "dut":
        return utils_obj.remove_last_line_from_string(st.show(conn_obj, command, skip_tmpl=True))


def remove_user_log_in_frr(dut,log_file_name):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    st.config(dut,"docker exec -it bgp rm /var/log/frr/%s"%log_file_name)

def add_user_log_in_frr(dut,log_file_name):
    """
    API to create frr log file in BGP frr docker
    Author: vishnuvardhan talluri (vishnuvardhan.talluri@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    st.config(dut,"docker exec -it bgp touch /var/log/frr/%s"%log_file_name)
    st.config(dut,"docker exec -it bgp chmod 777 /var/log/frr/%s"%log_file_name)

def return_user_log_from_frr(dut,log_file_name):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param log_file_name:
    :return:
    """
    return st.config(dut,"docker exec -it bgp bash -c  \"grep 'BFD: state-change'  /var/log/frr/%s | tail -50\""%log_file_name)


def debug_bfdconfig_using_frrlog(dut,config="",log_file_name=""):
    """
    API to get frr config from frr.conf file
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param config:
    :param log_file_name:
    :return:
    """
    if config == "yes" or config=="":
        st.config(dut,"debug bfd", type='vtysh')
        st.config(dut,"log syslog warnings", type='vtysh')
        st.config(dut,"log file /var/log/frr/%s"%log_file_name, type='vtysh')
    elif config == "no":
        st.config(dut,"no debug bfd", type='vtysh')
        st.config(dut,"no log syslog warnings", type='vtysh')
        st.config(dut,"no log file /var/log/frr/%s"%log_file_name, type='vtysh')


def set_hostname(dut, host_name, **kwargs):
    """
    this function is used to set hostname in DUT
    :param dut: Device name where the command to be executed
    :type dut: string
    :param host_name: hostname to be set
    :type host_name: string
    :return: None

    usage: set_hostname(dut1, "host1")

    created by: Julius <julius.mariyan@broadcom>
    """
    cli_type = st.get_ui_type(dut,**kwargs)
    if cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_hostname']
        payload = {"openconfig-system:hostname": host_name}
        response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
        if not response:
            st.banner('FAIL-OCYANG: hostname config Failed')
            return False
        else:
            return True
    elif cli_type == "click":
        cmd = "config hostname {}".format(host_name)
    elif cli_type == "klish":
        cmd = "hostname {}".format(host_name)
    return st.config(dut, cmd, type=cli_type)


def get_attr_from_cfgdbjson(dut, attr):
    """
    this function is used to get some attribute from DUT's config_db.json file
    :param dut: Device name where the command to be executed
    :type dut: string
    :param attr: attribute details to be fetched
    :type host_name: string
    :return: attribute details

    usage: get_attr_from_cfgdbjson(dut1, "fdb_aging_time")

    created by: Julius <julius.mariyan@broadcom>
    """
    cmd = "sudo cat /etc/sonic/config_db.json | grep {}".format(attr)
    return utils_obj.remove_last_line_from_string(st.config(dut, cmd))


def update_config_db_json(dut, attr, val1, val2):
    """
    this function is used to replace val1 of attribute by val2 in DUT's config_db.json file
    :param dut: Device name where the command to be executed
    :type dut: string
    :param attr: attribute name to be modified
    :type attr: string
    :param val1: to be replaced from val1
    :type val1: string
    :param val2: to be changed to val2
    :type val2: string
    :return: None

    usage: update_config_db_json(dut1, "fdb_aging_time", "300", "30")

    created by: Julius <julius.mariyan@broadcom>
    """
    cmd = "sudo sed -i 's/\"{}\": \"{}\"/\"{}\": \"{}\"/g' /etc/sonic/config_db.json"\
                                                        .format(attr,val1,attr,val2)
    st.config(dut, cmd)
    return


def delete_directory_contents(conn_obj, path, device="dut"):
    """
    API to delete contents in the provided directory
    :param conn_obj:
    :param path:
    :param device:
    :return:
    """
    command = "rm -rf {}/*".format(path.rstrip("/"))
    if device == "dut":
        st.config(conn_obj, command)
    else:
        conn_obj.execute_command(conn_obj, command)
    return True


def get_file_number_with_regex(connection_obj, search_pattern, file_path, device="server"):
    #COMMAND :  sed -nE '/^\s*option\s+dhcp6.boot-file-url\s+"\S+";/=' /etc/dhcp/dhcpd6.conf
    '''
    :param connection_obj:
    :param search_pattern:
    :param file_path:
    :param device:
    :return:
    '''
    command = "sed -nE '/^{}/=' {}".format(search_pattern, file_path)
    st.log("######{}##".format(command))
    if device == "server":
        result = conn_obj.execute_command(connection_obj, command)
    else:
        result = st.config(connection_obj, command)
    if utils_obj.remove_last_line_from_string(result):
        line_number = re.findall(r'\d+',utils_obj.remove_last_line_from_string(result))
        if line_number:
            return line_number[0]
    return 0


def delete_line_using_line_number(connection_obj, line_number, file_path, device="server"):
    '''
    COMMAND: sed -i '20d' /etc/dhcp/dhcpd6.conf
    :param connection_obj:
    :param line_number:
    :param file_path:
    :param device:
    :return:
    '''
    st.log("Line number is {}".format(line_number))
    if line_number > 0:
        command = "sed -i '{}d' {}".format(line_number, file_path)
        st.log("COMMAND-- {}".format(command))
        if device == "server":
            return conn_obj.execute_command(connection_obj, command)
        else:
            return st.config(connection_obj, command)


def get_dut_mac_address(dut):
    """
        This is used to get the Duts and its mac addresses mapping
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    duts_mac_addresses = {}
    cmd = "show platform syseeprom"
    eeprom_details = st.show(dut, cmd, skip_error_check=True)
    if not eeprom_details:
        iteration=3
        for i in range(1, iteration+1):
            st.wait(2)
            eeprom_details = st.show(dut, cmd, skip_error_check=True)
            if eeprom_details:
                break
            if not eeprom_details and i >= iteration + 1:
                st.log("EEPROM data not found for {}".format(dut))
                st.report_fail("eeprom_data_not_found", dut)
    dut_mac_address = [details for details in eeprom_details if details.get('tlv_name') == "Base MAC Address"][
        0].get("value").replace(':', "")
    duts_mac_addresses[dut] = dut_mac_address
    return duts_mac_addresses


def get_dut_mac_address_thread(dut_list, thread=True):
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    result = dict()
    params = list()
    for dut in dut_li:
        params.append([get_dut_mac_address, dut])
    if params:
        [out, exceptions] = exec_all(thread, params)
        st.log("#########OUTPUT###########")
        st.log(out)
        st.log(exceptions)
        for value in exceptions:
            if value is not None:
                st.log("Exceptions Observed {}, hence returning None".format(value))
                return None
        st.log("Framing required data as no exceptions observed ...")
        for data in out:
            st.log(data)
            result[data.keys()[0]] = data.values()[0]
        return result
    else:
        st.log("Empty Params Observed .... ")
        return None


def get_number_of_lines_in_file(connection_obj, file_path, device="server"):
    line_number=0
    if file_path:
        command = "wc -l {}".format(file_path)
        if device == "server":
            output = conn_obj.execute_command(connection_obj, command)
        else:
            output = st.config(connection_obj, command)
        result = utils_obj.remove_last_line_from_string(output)
        if result:
            match = re.match(r'^\d+', result)
            if match:
                st.log("####### LINE NUMBER- {}".format(match.group(0)))
                return int(match.group(0))
    return line_number

def is_vsonic_device(dut):
    return st.is_vsonic(dut)

def get_config_profiles(dut):
    """
    Author: Nagappa Chincholi (nagappa.chincholi@broadcom.com)
    Function to get configured profiles (L2/L3).
    :param dut:
    :return:
    """
    if not st.is_feature_supported("config-profiles-get-factory-command", dut):
        return "l3"
    command = 'sudo config-profiles get factory'
    output = st.show(dut, command, skip_tmpl=True)
    if len(output) <= 0:
        return None
    return output[:2]

def set_config_profiles(dut, profile, check_system_status=True):
    cur_profile = get_config_profiles(dut)
    if cur_profile == profile.lower():
        st.log('Device is in the desired profile')
    else:
        cmd = 'sudo config-setup factory'
        cmd += '\n sudo config-profiles factory {}'.format(profile.lower())
        st.config(dut, cmd, max_time=900)
    if check_system_status:
        return bool(get_system_status(dut))
    return True

def get_show_command_data(dut, command, type="txt"):
    file_extension = "txt" if type != "json" else "json"
    data = None
    remote_file = "/tmp/running_config.{}".format(file_extension)
    local_file = st.mktemp()
    for _ in range(0,3):
        actual_cmd = "{} > {}".format(command, remote_file)
        st.config(dut, actual_cmd)
        delete_file(local_file)
        st.download_file_from_dut(dut, remote_file, local_file)
        if os.path.exists(local_file):
            if not os.stat(local_file).st_size == 0:
                break
    try:
        with open(local_file) as file:
            if type == "json":
                data = do_eval(json.dumps(json.load(file), indent=4, sort_keys=True))
            else:
                data = file.read().replace('\n', '')
        delete_file(local_file)
    except Exception as e:
        st.error("Exception occured: {}".format(e))
    st.debug(data)
    return data

def check_sonic_branding(build_name, cli_type= ""):
    """
    Author1: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    Author2: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Function to verify the build version is in correct format or not
    :param build_name:
    :return:
    """
    cli_type = st.get_ui_type(cli_type= cli_type)
    #rest support is blocked due to SONIC-24371. So falling back to klish
    if cli_type in ['rest-put', 'rest-patch']:
        cli_type = 'klish'
    result = True
    st.log("The Given build version string is : {}".format(build_name))
    constants = st.get_datastore(None, "constants", "default")
    if cli_type == "click":
        regex_format = r"^([a-zA-Z]+-[a-zA-Z]+)-((\d+\.\d+\.\d+|\d+\.\d+)_*(\w*))_*(\d+_\d+_\d+)*-*(\S+)*$"
        os_regex = r"^{}".format(constants['NOS_NAME'])
        version_regex = r"(\d+\.\d+\.\d+|\d+\.\d+)"

        if not re.findall(os_regex, build_name):
            st.error('Build OS NAME is not matching with the standard format - {}'.format(constants['NOS_NAME']))
            result = False

        if not re.findall(version_regex, build_name):
            st.error('Build VERSION info is not matching with the standard format')
            result = False

        if not any(ele in build_name for ele in constants['PRODUCT_PACKAGING_OPTIONS']):
            st.error('Build PRODUCT info is not matching with any of the standard Package')
            result = False

        if not re.findall(regex_format, build_name):
            st.error('Build info is not as per the standard Format')
            result = False

        if not result:
            st.log("Output of OS NAME regex : {},  data : {}".format(os_regex, re.findall(os_regex, build_name)))
            st.log("Output of VERSION regex : {}, data : {}".format(version_regex, re.findall(version_regex, build_name)))
            st.log("Output of FORMAT regex : {}, data : {}".format(regex_format, re.findall(regex_format, build_name)))
            st.log("CONSTANTS : {}".format(constants))
    elif cli_type == "klish":
        regex_format = r"^(\S+)((\d+\.\d+\.\d+|\d+\.\d+)_*(\w*))_*(\d+_\d+_\d+)*-*(\S+)*$"
        version_regex = r"(\d+\.\d+\.\d+|\d+\.\d+)"

        if not re.findall(version_regex, build_name):
            st.error('Build VERSION info is not matching with the standard format')
            result = False

        if not any(ele in build_name for ele in constants['PRODUCT_PACKAGING_OPTIONS']):
            st.error('Build PRODUCT info is not matching with any of the standard Package')
            result = False

        if not re.findall(regex_format, build_name):
            st.error('Build info is not as per the standard Format')
            result = False

        if not result:
            st.log("Output of VERSION regex : {}, data : {}".format(version_regex, re.findall(version_regex, build_name)))
            st.log("Output of FORMAT regex : {}, data : {}".format(regex_format, re.findall(regex_format, build_name)))
            st.log("CONSTANTS : {}".format(constants))
    else:
        st.log("unsupported cli type")
        return False
    return result



def copy_file_to_docker(dut, file_name, docker_name):
    """
    API to copy file to any docker
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_name:
    :param docker_name:
    :return:
    """
    command = "docker cp {} {}:{}".format(file_name, docker_name, file_name)
    output = st.config(dut, command)
    if "Error response" in utils_obj.remove_last_line_from_string(output):
        st.log(output)
        return False
    return True

def get_user_group_details(connection_obj, device="server"):
    """
    API to execute id command and parse the output
    :param conn_obj:
    :param type:
    :return:
    """
    command = "id"
    if device == "server":
        output = utils_obj.remove_last_line_from_string(conn_obj.execute_command(connection_obj, command))
    else:
        output = utils_obj.remove_last_line_from_string(st.show(connection_obj, command, skip_tmpl=True, type="click"))
    return output

def verify_user_group_details(connection_obj, uid, group, device="server"):
    """
    API to verify the user group details by executing id.
    :param connection_obj:
    :param search_str:
    :param value:
    :param device:
    :return:
    """
    output = get_user_group_details(connection_obj,device=device)
    if not output:
        st.log("Output not found {}".format(output))
        return False
    if uid:
        user_data = re.findall(r"uid=\d+\({}\)".format(uid), output)
        if not user_data:
            st.log("User data not found -- {}".format(uid))
            return False
    if group:
        group_data = re.findall(r"gid=\d+\({}\)".format(group), output)
        if not group_data:
            st.log("Group data not found -- {}".format(group))
            return False
    return True


def delete_line_using_specific_string(connection_obj, specific_string, file_path, device="server"):
    """
    Author: Santosh Votarikari(santosh.votarikari@broadcom.com)
    API to remove line by using specific string

    COMMAND: sed -i "/DELETE THIS TEXT/d" /var/log/messages
    :param connection_obj:
    :param specific_string:
    :param file_path:
    :param device:
    :return:
    """
    st.log("Specific string is {}".format(specific_string))
    if specific_string:
        command = "sed -i '/{}/d' {}".format(specific_string, file_path)
        st.log("COMMAND-- {}".format(command))
        if device == "server":
            return conn_obj.execute_command(connection_obj, command)
        else:
            return st.config(connection_obj, command)


def cmd_validator(dut, commands, cli_type='klish'):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param commands:
    :param cli_type:
    :return:
    """
    result = True
    errs = ['%Error']
    command_list = commands if isinstance(commands, list) else commands.split('\n')
    out = st.config(dut, command_list, type=cli_type, skip_error_check=True)
    for each in errs:
        if each in out:
            st.error("Error string '{}' found in command execution.".format(each))
            result = False
    return result


def verify_docker_status(dut, status='Exited'):
    """
     Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param status:
    :return:
    """
    if status in st.config(dut, "docker ps --no-trunc -a"):
        return False
    else:
        return True


def get_and_match_docker_count(dut, count=None):
    """
    Get docker count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param count:
    :return:
    """
    command = 'docker ps --no-trunc | wc -l'
    if not count:
        return utils_obj.get_word_count(dut, command)
    else:
        if int(count) == utils_obj.get_word_count(dut, command):
            return True
    return False

def move_file_to_local_path(dut, src_path, dst_path, sudo=True, skip_error_check=False):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Function to copy the file to local path
    :param dut:
    :param src_path:
    :param dst_path:
    :return:
    """
    sucmd = "sudo" if sudo else ""
    command = "{} mv {} {}".format(sucmd, src_path, dst_path)
    st.config(dut, command, skip_error_check=skip_error_check)

def delete_file_from_local_path(dut, filename, sudo=True, skip_error_check=True):
    sucmd = "sudo" if sudo else ""
    command = "{} rm {}".format(sucmd, filename)
    st.config(dut, command, skip_error_check=skip_error_check)

def killall_process(dut, name, skip_error_check=True):
    command = "killall {}".format(name)
    st.config(dut, command, skip_error_check=skip_error_check)

def dhcp_server_config(dut, dhcp_files=['isc-dhcp-server','dhcpd.conf','dhcpd6.conf'], **kwargs):
    '''
    1. Install dhcp package
    2. Update dhcp files - dhcpd6.conf  dhcpd.conf  isc-dhcp-server
    3. create vlan, member and configure IPv4 and IPv6.
    4. Add static routes
    5.Restart dhcp process
    '''
    import apis.switching.vlan as vlan_api
    import apis.routing.ip as ip_api
    vlan = kwargs.get("vlan", "50") # This is hardcoded as 50, because the interface on DHCP server is Vlan50
    server_connected_port = kwargs.get("server_port")
    ipv4_server_ip = kwargs.get("server_ipv4")
    ipv6_server_ip = kwargs.get("server_ipv6")
    ipv4_server_ip_mask = kwargs.get("mask_v4", "24")
    ipv6_server_ip_mask = kwargs.get("mask_v6", "64")
    route_list = kwargs.get("route_list")
    route_list_v6 = kwargs.get("route_list_v6")
    ipv4_relay_agent_ip = kwargs.get("ipv4_relay_agent_ip")
    ipv6_relay_agent_ip = kwargs.get("ipv6_relay_agent_ip")
    dhcp_files_path = kwargs.get("dhcp_files_path")
    service="isc-dhcp-server"
    madatory_fields = [server_connected_port]
    if any(elem is None for elem in madatory_fields):
        st.log("Required interfaces are not provided")
        return False
    vlan_int = 'Vlan{}'.format(vlan) if vlan else server_connected_port
    action = kwargs.get("action", "config")
    route_list =utils_obj.make_list(route_list)
    route_list_v6 =utils_obj.make_list(route_list_v6)
    error_msgs = ["Failed", "Error"]
    if action == "config":
        if not dhcp_files_path:
            st.log("DHCP FILES PATH not provided")
            return False
        dhcp_files_path =utils_obj.make_list(dhcp_files_path)
        # service_status = service_operations_by_systemctl(dut, service=service, operation="status")
        # st.debug(service_status)
        # if "Unit isc-dhcp-server.service could not be found" in service_status:
        deploy_package(dut, mode='update')
        deploy_package(dut, packane_name=service, mode='install')
        # else:
        #     st.log("SKIPPING {} installation, as status show it is already available for operations".format(service.upper()))
        # copy_files_to_dut(st.get_mgmt_ip(dut))
        for dhcp_file in dhcp_files_path:
            st.upload_file_to_dut(dut, dhcp_file, "/tmp/")
        st.config(dut,'sudo mv /tmp/'+dhcp_files[0]+' /etc/default/',skip_error_check=True)
        st.config(dut,'sudo mv /tmp/'+dhcp_files[1]+' /etc/dhcp/',skip_error_check=True)
        st.config(dut,'sudo mv /tmp/'+dhcp_files[2]+' /etc/dhcp/',skip_error_check=True)
        if vlan:
            vlan_api.create_vlan(dut, [vlan])
            vlan_api.add_vlan_member(dut, vlan, server_connected_port)
        if ipv4_server_ip:
            ip_api.config_ip_addr_interface(dut,vlan_int, ipv4_server_ip, ipv4_server_ip_mask)
        else:
            st.log("IP CONFIGURATION SKIPPED AS V4 SERVER IP NOT PROVIDED")
        if ipv6_server_ip:
            ip_api.config_ip_addr_interface(dut, vlan_int, ipv6_server_ip, ipv6_server_ip_mask, family='ipv6')
        else:
            st.log("IPV6 CONFIGURATION SKIPPED AS V6 SERVER IP NOT PROVIDED")
        if route_list:
            for ip in route_list:
                if ipv4_relay_agent_ip:
                    ip_api.create_static_route(dut, next_hop= ipv4_relay_agent_ip,static_ip=ip)
                else:
                    st.log("STATIC ROUTE CREATION SKIPPED AS RELAY AGENT IP NOT PROVIDED")
        else:
            st.log("ROUTE LIST NOT PROVIDED HENCE SKIPPED")
        if route_list_v6:
            for ip6 in route_list_v6:
                if ipv6_relay_agent_ip:
                    ip_api.create_static_route(dut, next_hop= ipv6_relay_agent_ip,static_ip=ip6, family= 'ipv6')
                else:
                    st.log("V6 STATIC ROUTE CREATION SKIPPED AS RELAY AGENT IPV6 NOT PROVIDED")
        else:
            st.log("ROUTE LIST V6 NOT PROVIDED HENCE SKIPPED")
        output = service_operations_by_systemctl(dut, service=service, operation="restart", skip_error_check=True)
        for msg in error_msgs:
            if msg in output:
                st.error("Observerd Error while restarting the {} service".format(service))
                return False
        st.wait(2)
        ps_aux = get_ps_aux(dut, "dhcpd")
        if len(ps_aux) > 1:
            return True
        return False
    else:
        output = service_operations_by_systemctl(dut, service=service, operation="stop")
        for msg in error_msgs:
            if msg in output:
                st.error("Observerd Error while stopping the {} service".format(service))
                return False
        deploy_package(dut, packane_name=service, mode='purge')
        if route_list:
            for ip in route_list:
                if ipv4_relay_agent_ip:
                    ip_api.delete_static_route(dut, next_hop=ipv4_relay_agent_ip, static_ip=ip)
        if route_list_v6:
            for ip6 in route_list_v6:
                if ipv6_relay_agent_ip:
                    ip_api.delete_static_route(dut, next_hop=ipv6_relay_agent_ip, static_ip=ip6, family= 'ipv6')
        if ipv4_server_ip:
            ip_api.delete_ip_interface(dut, vlan_int, ipv4_server_ip, ipv4_server_ip_mask)
        if ipv6_server_ip:
            ip_api.delete_ip_interface(dut, vlan_int, ipv6_server_ip, ipv6_server_ip_mask, family='ipv6')
        if vlan:
            vlan_api.delete_vlan_member(dut, vlan, server_connected_port)
            vlan_api.delete_vlan(dut, [vlan])
        st.log("Rebooting the device after purging of {} service to make the purge affect, "
               "without this isc-dhcp-server installation in other feature/module will fail.".format(service))
        st.reboot(dut, method="fast")
        return True



def get_content_file_number(file_path, search_string_pattern):
    try:
        command = "sed -nE '/^{}/=' {}".format(search_string_pattern, file_path)
        st.log("CMD: {}".format(command))
        line_number = os.popen(command).read()
        st.log("LINE NUMBER: {}".format(line_number))
        if line_number:
            return int(line_number)
    except Exception as e:
        st.log(e)
    return 0


def write_content_to_line_number(file_path, content, line_number):
    command = "sed -i '{} i  {}' {}".format(line_number, content, file_path)
    st.log("CMD: {}".format(command))
    os.popen(command).read()
    return True


def delete_content_from_line_number(file_path, line_number):
    command = "sed -i -e '{}d' {}".format(line_number, file_path)
    st.log("CMD: {}".format(command))
    os.popen(command).read()
    return True


def set_mgmt_ip_gw(dut, ipmask, gw):
    interface = st.get_mgmt_ifname(dut)
    cli_type = st.get_ui_type(dut)
    if cli_type in ['rest-put', 'rest-patch']:
        cli_type = 'klish'
    cmd = ""
    if cli_type in ['click']:
        cmd = ["config interface ip add {} {} {}".format(interface, ipmask, gw)]
    elif cli_type in ['klish']:
        if interface == 'eth0':
            cmd = "interface Management 0"
            cmd = cmd + "\n" + "ip address {} gwaddr {}".format(ipmask, gw)
    else:
        st.log("UNSUPPORTED CLI TYPE ")
        return False
    if cmd:
        st.config(dut, cmd, type=cli_type)
    cmd = "sudo /sbin/ifconfig {} {}".format(interface, ipmask)
    cmd = "{};sudo /sbin/route add default gw {}".format(cmd, gw)
    st.config(dut, cmd)
    return True

def get_ip_route_list(dut, interface):
    # ensure that the interface admin state is up
    command = "/sbin/ip link set dev {} up".format(interface)
    st.config(dut, command, skip_error_check=True)

    # fetch the route list
    command = "/sbin/ip route list dev {}".format(interface)
    output = st.show(dut, command, skip_error_check=True)
    if len(output) <= 0 or "address" not in output[0]:
        return None
    ip_address = output[0]['address']
    return ip_address

def get_mgmt_ip(dut, interface):
    ip_address = get_ip_route_list(dut, interface)
    if ip_address:
        return ip_address
    else:
        msg = "Unable to get the ip address of '{}' from '/sbin/ip route list'. Falling back to 'ifconfig'.."
        st.log(msg.format(interface), dut=dut)
        ipaddr_list = get_ifconfig_inet(dut, interface)
        if ipaddr_list:
            return ipaddr_list[0]
    return None

def renew_mgmt_ip(dut, interface):
    output_1 = st.config(dut, "/sbin/dhclient -v -r {}".format(interface), skip_error_check=True, expect_ipchange=True)
    output_2 = st.config(dut, "/sbin/dhclient -v {}".format(interface), skip_error_check=True, expect_ipchange=True)
    return "\n".join([output_1, output_2])

def set_mgmt_vrf(dut, mgmt_vrf):
    import apis.system.management_vrf as mgmt_vrf_api
    if mgmt_vrf == 1:
        return mgmt_vrf_api.config(dut)
    elif mgmt_vrf == 2:
        return mgmt_vrf_api.config(dut, no_form=True)


def tpcm_operation(dut, action, docker_name, install_method="url",**kwargs ):
    """
    purpose:
            This definition is used to install/upgrade/uninstall third party container image

    Arguments:
    :param dut: device where the install/upgrade/uninstall needs to be done
    :type dut: string
    :param action: install/upgrade/uninstall
    :type action: string
    :param docker_name: docker name to be installed
    :type docker_name: string
    :param install_method: how the installation to be done; scp/sftp/url/pull etc
    :type install_method: string
    :param ser_name: remote server name
    :type ser_name: string
    :param user_name: user name
    :type user_name: string
    :param pwd: password
    :type pwd: string
    :param tag_name: tag name to be used for the image
    :type tag_name: string
    :param image_path: path for the image to be installed
    :type image_path: string
    :param file_name: file name
    :type file_name: string
    :param extra_args: additional arguments for the TPCM
    :type extra_args: string
    :param skip_data: whether to skip backup of data during upgrade
    :type skip_data: string
    :param cli_type: type of user interface
    :type cli_type: string
    :return: None

    usage:
    Install:
        tpcm_operation(dut1, "install","mydocker","url",image_path="http://myserver/path/test.tar.gz")
        tpcm_operation(dut1, "install","mydocker","scp",file_name="/images/test.tar.gz",
                    ser_name="10.10.10.10",user_name="test",pwd="password")
        tpcm_operation(dut1, "install","mydocker","sftp",file_name="/images/test.tar.gz",
                    ser_name="10.10.10.10",user_name="test",pwd="password")
        tpcm_operation(dut1, "install","mydocker","file",image_path="/media/usb/path/test.tar.gz")
        tpcm_operation(dut1, "install","mydocker","image",image_path="test.tar.gz",tag_name="test")
    Upgrade:
        tpcm_operation(dut1, "upgrade","mydocker","url", image_path="http://myserver/path/test.tar.gz")
        tpcm_operation(dut1, "upgrade","mydocker","url",image_path="http://myserver/path/test.tar.gz",skip_data="skip")
    Uninstall:
        tpcm_operation(dut1, "uninstall","mydocker")
    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["tpcm_"+action]
        if action == "uninstall":
            if  "skip_data" in kwargs:
                payload = {"openconfig-system-ext:input" : {"clean-data" : kwargs.get("skip_data", "no"),
                           "docker-name" : docker_name}}
            else:
                payload = {"openconfig-system-ext:input" : {"clean-data" : "no", "docker-name" : docker_name}}
        elif action == "install":
            if install_method == "pull":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "pull",
                            "image-name" : kwargs["image_path"]+ ":" +kwargs["tag_name"],
                            "args" : kwargs["extra_args"]}}
            elif install_method == "url":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "url",
                            "image-name" : kwargs["image_path"]}}
            elif install_method == "scp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "scp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"]}}
            elif install_method == "sftp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "sftp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"]}}
            elif install_method == "image":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "image",
                            "image-name" : kwargs["image_path"]}}
            elif install_method == "file":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "file",
                            "image-name" : kwargs["image_path"]}}
        elif action == "upgrade":
            if install_method == "pull":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "pull",
                            "image-name" : kwargs["image_path"]+ ":" +kwargs["tag_name"],
                            "remote-server" : kwargs["ser_name"], "username" : kwargs["user_name"],
                            "password" : kwargs["pwd"],"args" : kwargs["args"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "url":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name, "image-source": "url",
                            "image-name" : kwargs["image_path"],"skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "scp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "scp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "sftp":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "sftp",
                            "image-name" : kwargs["file_name"],"remote-server" : kwargs["ser_name"],
                            "username" : kwargs["user_name"], "password" : kwargs["pwd"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "image":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "image",
                            "image-name" : kwargs["image_path"],
                            "skip-data-migration" : kwargs.get("skip_data", "no")}}
            elif install_method == "file":
                payload = { "openconfig-system-ext:input" :  {"docker-name" : docker_name,"image-source": "file",
                            "image-name" : kwargs["image_path"],"skip-data-migration" : kwargs.get("skip_data", "no")}}
        result = config_rest(dut, http_method='post', rest_url=url, json_data=payload,timeout=60)
    else:
        if action=="uninstall":
            cmd = 'tpcm {} name {}'.format(action, docker_name)
        else:
            cmd = 'tpcm {} name {} {}'.format(action, docker_name,install_method)

        if "image_path" in kwargs:
            cmd += " {}".format(kwargs["image_path"])
        if "tag_name" in kwargs:
            cmd += ":{}".format(kwargs["tag_name"])
        if "ser_name" in kwargs:
            cmd += " {}".format(kwargs["ser_name"])
        if "user_name" in kwargs:
            cmd += " username {}".format(kwargs["user_name"])
        if "pwd" in kwargs:
            cmd += " password {}".format(kwargs["pwd"])
        if "file_name" in kwargs:
            cmd += " filename {}".format(kwargs["file_name"])
        if "extra_args" in kwargs:
            cmd += " args \"{}\"".format(kwargs["extra_args"])
        if  "skip_data" in kwargs:
            if action == "upgrade":
                cmd += " skip_data_migration {}".format(kwargs.get("skip_data","no"))
            elif action == "uninstall":
                cmd += " clean_data {}".format(kwargs.get("skip_data", "no"))
        if "skip_error" in kwargs:
            skip_error = kwargs["skip_error"]
        else:
            skip_error = False
        output= st.config(dut, cmd,type=cli_type,skip_error_check=skip_error)
        if re.search("failed",output):
            result=False
        else:
            result=True
    return result


def get_free_output(dut):
    command = "free"
    return st.show(dut, command)


def verify_free_memory(dut, mem_diff):
    avail_output = list()
    for i in range(0, 5):
        output = get_free_output(dut)
        avail_output.append(int(output[0]['available']) if output else 0)
        if i < 4:
            st.wait(60)
    st.log("AVAILABLE MEMORY SAMPLES - {}".format(avail_output))
    if (avail_output[4]-avail_output[3]) > int(mem_diff) and (avail_output[3]-avail_output[2]) > int(mem_diff) and (avail_output[2]-avail_output[1]) > int(mem_diff) and (avail_output[1]-avail_output[0]) > int(mem_diff):
        st.log("Observed continous decrement in available memory")
        return False
    return True


def get_techsupport(dut=None, filename='TechSupport'):
    """
    This proc is used for copying the tech support from the DUT.
    :param duts:
    :param file:
    :return:
    """
    dut_list = dut or st.get_dut_names()
    st.banner('Collecting the tech-support on dut {}'.format(dut_list))
    api_list=[]
    for d in make_list(dut_list):
        file_path = filename + str(d)
        api_list.append([st.generate_tech_support, d, file_path])
    exec_all(True, api_list)


def save_docker_image(dut,image,options):
    """
    purpose:
            This definition is used to save existing docker's image

    Arguments:
    :param dut: device where the image needs to be saved
    :type dut: string
    :param image: docker image name
    :type image: string
    :param options: rest all things can be specfied as part of options; for ex |gzip -c > /home/admin/mydocker.tar.gz
    :type options: string
    :return: None

    usage:
        save_docker_image(dut1, "httpd:latest","|gzip -c > /home/admin/mydocker.tar.gz")
    Created by: Julius <julius.mariyan@broadcom.com
    """
    cmd = "docker save {} {}".format(image,options)
    return st.config(dut, cmd)


def verify_tpcm_list(dut, docker_list, image_list,status_list,**kwargs):
    """
    purpose:
            This definition is used to verify tpcm list

    Arguments:
    :param dut: device where the command needs to be executed
    :type dut: string
    :param docker_list: docker name list
    :type docker_list: list
    :param image_list: image name list
    :type image_list: list
    :param status_list: docker status list
    :type status_list: list
    :param cli_type: type of user interface
    :type cli_type: string
    :return: True/False; True for success case and Fail for failure case

    usage:
        verify_tpcm_list(dut1, docker_list=["docker1","docker2"],
                         image_list=["httpd:image1","httpd:image2"],status_list=["Up","Exited"])

	Created by: Julius <julius.mariyan@broadcom.com
    """
    success = True
    cli_type = st.get_ui_type(dut, **kwargs)
    docker_list = list(docker_list) if isinstance(docker_list,list) else [docker_list]
    image_list = list(image_list) if isinstance(image_list, list) else [image_list]
    status_list = list(status_list) if isinstance(status_list, list) else [status_list]
    if cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["tpcm_get"]
        rest_out = get_rest(dut,rest_url=url,timeout=60)
        rest_out = rest_out['output']['openconfig-system-ext:tpcm-image-list']
        for docker, image, status in zip(docker_list, image_list, status_list):
            docker_status = False
            for elem in rest_out:
                temp_out = elem.split('  ')
                temp_out = [x.strip(' ') for x in temp_out]
                out = list(filter(None, temp_out))
                if "CONTAINER NAME" not in out:
                    if docker in out:
                        docker_status = True
                        if out[1] == image and out[2].split(" ")[0] == status:
                            st.log("########## Match found for docker {} with status {} ########"
                                   "##".format(docker, status))
                        else:
                            st.error("########## Match NOT found for docker {}; expected image: {} but got: {};"
                                     "expected status : {} but got: {}".format(docker, image, out[1],
                                                                               status, out[2].split(" ")[0]))
                            success = False
            if not docker_status:
                success = False
    elif cli_type == "klish":
        output = st.show(dut, "show tpcm list",type=cli_type)
        for docker,image,status in zip(docker_list,image_list,status_list):
            fil_out = filter_and_select(output, ["status"], {'image': image,"cont_name" : docker})
            if not fil_out:
                st.error("Docker {} with image {} NOT found in tpcm list output".format(docker,image))
                success = False
            else:
                if fil_out[0]["status"] == status:
                    st.log("########## Match found for docker {} with status {} ########"
                           "##".format(docker,status))
                else:
                    st.error("########## Match NOT found for docker {}; expected status : {}"
                             " but got {}".format(docker,status,fil_out[0]["status"]))
                    success = False
    return success


def config_radius_server(dut, **kwargs):
    """
    API to install / configure free radius server on provided DUT and parameters
    :param dut:
    :param kwargs:
    :return:
    """
    config_files_path = kwargs.get("config_files_path")
    service = kwargs.get("service", "freeradius")
    action = kwargs.get("action", "config")
    require_reboot = kwargs.get("require_reboot", False)
    installed = False
    freeradius_user = "freerad"
    process_id = 0
    if action not in ["config", "unconfig"]:
        st.error("UNSUPPORTED ACTION -- {}".format(action))
        return False
    if action == "config":
        if is_free_radius_installed(dut):
            installed = True
            output = get_ps_aux(dut, search_string="freeradius")
            if output:
                for process in output:
                    if process["user"] == freeradius_user and process["command"] == "freeradius -X":
                        process_id = int(process["pid"])
                        break
        if not installed:
            deploy_package(dut, mode='update')
            deploy_package(dut, packane_name=service, mode='install')
            for config_file in config_files_path:
                st.upload_file_to_dut(dut, config_file, "/tmp/")
                file_name = os.path.basename(config_file)
                st.config(dut, 'sudo mv /tmp/' + file_name + ' /etc/freeradius/3.0/', skip_error_check=True)
                st.config(dut, "sudo cp /etc/freeradius/3.0/users /etc/freeradius/3.0/users1")
                st.config(dut,  "sudo rm -rf /etc/freeradius/3.0/users")
                st.config(dut, "sudo ln -s mods-config/files/authorize /etc/freeradius/3.0/users")
                st.config(dut,  "sudo cp /etc/freeradius/3.0/users1 /etc/freeradius/3.0/users")
        else:
            if process_id:
                st.config(dut, "kill -9 {}".format(process_id))
        st.config(dut, "sudo service freeradius stop")
        st.config(dut, "freeradius -X > freeradius.log &")
        return True
    else:
        if is_free_radius_installed(dut):
            deploy_package(dut, packane_name=service, mode='purge')
            if require_reboot:
                st.log("Rebooting the device after purging of {} service to make the purge affect, "
                       "without this isc-dhcp-server installation in other feature/module will fail.".format(service))
                st.reboot(dut, method="fast")
        return True


def is_free_radius_installed(dut):
    """API to check whether free radius is installed or not"""
    output = st.config(dut, "freeradius -v")
    if "not found" in output:
        return False
    return True


def commit_docker_image(dut,docker,image):
    """
    purpose:
            This definition is used to commit existing docker's image

    Arguments:
    :param dut: device where the image needs to be saved
    :type dut: string
    :param docker: docker name
    :type docker: string
    :param image: image name
    :type image: string
    :return: None

    usage:
        commit_docker_image(dut1, "httpd:latest","image:test")
    Created by: Julius <julius.mariyan@broadcom.com
    """
    cmd = "docker commit {} {}".format(docker,image)
    return st.config(dut, cmd)

def swss_config(dut, data):
    if st.get_args("filemode"): return
    file_path1 = "/tmp/swss_config.json"
    file_path2 = "/swss_config.json"
    local_file = write_to_text_file(data)
    st.upload_file_to_dut(dut, local_file, file_path1)
    st.config(dut, "docker cp {0} swss:{1}".format(file_path1, file_path2))
    st.config(dut, "docker exec -it swss bash -c 'swssconfig {0}'".format(file_path2))


def flush_iptable(dut):
    st.config(dut, "iptables -F")

def execute_linux_cmd(dut, cmd):
    st.show(dut, cmd, skip_tmpl=True)

def ifconfig_eth(dut, interfacenumber):
    command = "sudo ifconfig eth{}".format(interfacenumber)
    print("command", command)
    output = st.show(dut, command)
    return output

def update_presence_in_thermalzone(dut, val):
    """
    update the presence in thermal_zone.yaml
    """
    st.show(dut, 'cp /opt/cisco/etc/thermal_zone.yaml /tmp/', skip_tmpl=True)
    out = st.show(dut, 'cat /tmp/thermal_zone.yaml', skip_tmpl=True)
    out1 = utils_obj.remove_last_line_from_string(out)
    out2= yaml.safe_load(out1)
    out2[val][0]['presence']=0
    out3 = yaml.dump(out2)
    st.show(dut, 'printf "%s" > /tmp/new_thermal_zone.yaml'%out3,  skip_tmpl=True)
    st.show(dut, 'sudo cp /tmp/new_thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)

def get_platform_content_from_pmon(dut):
    """
    get platform json content from pmon container in dut
    """
    out = st.show(dut, 'docker exec -it pmon cat /usr/share/sonic/platform/platform.json', skip_tmpl=True)
    out1 = utils_obj.remove_last_line_from_string(out)
    out2 = json.loads(out1)
    thermal_data = out2['chassis']['thermals']
    temperature_cli_data = get_platform_temperature(dut)
    sensor_data = [row['sensor'] for row in temperature_cli_data]
    platform_json_data = [row['name'].encode('utf-8') for row in thermal_data]
    #Check with Sachin for the comparison for platform.json and show platform temp output 
    check =  all(item in sensor_data for item in platform_json_data)
    return check

def update_fan_tray_faulty_presence_in_thermalzone(dut, val):
    """
    update the faulty fan check  in thermal_zone.yaml
    """
    st.show(dut, 'cp /opt/cisco/etc/thermal_zone.yaml /tmp/', skip_tmpl=True)
    st.show(dut, 'sudo cp /opt/cisco/etc/thermal_zone.yaml /opt/cisco/', skip_tmpl=True)
    out = st.show(dut, 'cat /tmp/thermal_zone.yaml', skip_tmpl=True)
    out1 = utils_obj.remove_last_line_from_string(out)
    out2= yaml.safe_load(out1)
    #Check how to add an attribute in yaml in python 
    #out2[val][0]['fans'][0]['name'] ---- fan
    #out2[val][0]['fans'][0]['faulty'] -- 1
    #out2[val][0]['faulty']= 1
    #out2[val][1]['name'] --- fan tray 
    out2[val][0]['faulty']= 1
    out3 = yaml.dump(out2)
    st.show(dut, 'printf "%s" > /tmp/new_thermal_zone.yaml'%out3,  skip_tmpl=True)
    st.show(dut, 'sudo cp /tmp/new_thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)

def update_fan_faulty_presence_in_thermalzone(dut, val):
    """
    update the faulty fan check  in thermal_zone.yaml
    """
    st.show(dut, 'cp /opt/cisco/etc/thermal_zone.yaml /tmp/', skip_tmpl=True)
    st.show(dut, 'sudo cp /opt/cisco/etc/thermal_zone.yaml /opt/cisco/', skip_tmpl=True)
    out = st.show(dut, 'cat /tmp/thermal_zone.yaml', skip_tmpl=True)
    out1 = utils_obj.remove_last_line_from_string(out)
    out2= yaml.safe_load(out1)
    #Check how to add an attribute in yaml in python 
    #out2[val][0]['fans'][0]['name'] ---- fan
    #out2[val][0]['fans'][0]['faulty'] -- 1
    #out2[val][0]['faulty']= 1
    #out2[val][1]['name'] --- fan tray 
    out2[val][0]['fans'][0]['faulty']= 1
    out2[val][0]['fans'][1]['faulty']= 1
    out2[val][1]['fans'][0]['faulty']= 1
    out3 = yaml.dump(out2)
    st.show(dut, 'printf "%s" > /tmp/new_thermal_zone.yaml'%out3,  skip_tmpl=True)
    st.show(dut, 'sudo cp /tmp/new_thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)


def get_parsed_date_to_capture_syslog(dut):
    """
    Get Parsed date to capture syslog
    """
    #Start time 
    date_string = get_dut_date_time(dut)
    if date_string is None:
        raise Exception("The Parsed Date object retuned None")
    if(date_string[4] == '0'):
        date_string = date_string.replace('0',' ', 1)
    month = date_string[7:11]
    date = date_string[4:7]
    hours = date_string[16:18]
    mins = date_string[18:21]
    if(date_string[25:27] == "PM"):
        hours = str(int(hours)+12)
    result_date = month + date + hours + mins
    return result_date

def get_parsed_temp_output_grep_sensor_name(dut, sensor_name):
    """
    Get Parsed temp output
    """
    cmd = "show platform temperature | grep {}".format(sensor_name)
    temp_data_output = st.show(dut, cmd, skip_tmpl=True)
    if temp_data_output is None:
        raise Exception("show plat temp for the sensor name {} output is not found ".format(sensor_name))
    parsed_sensor_data = [s.strip().encode() for s in temp_data_output.split('  ') if s]
    return parsed_sensor_data

def capture_syslog_between_timestamps(dut, start_point, end_point, filterlog):
    """
    Get the expected match syslog to the filterlog
    """
    cmd = "sudo sed -n '/{}/,/{}/p' /var/log/syslog*|grep \"{}\"".format(start_point, end_point, filterlog)
    syslog_data_output = st.show(dut, cmd, skip_tmpl=True)
    length = syslog_data_output.count('\n')
    if length >= 1:
        return True
    return False

def get_watchdog_status(dut):
    """
    Get the status of watchdog
    """
    output = st.show(dut, "sudo watchdogutil status")
    if len(output) <= 0:
        return None
    return output

def change_watchdog_status_to_arm(dut):
    """
    Get the status of watchdog
    """
    output = st.show(dut, "sudo watchdogutil arm")
    if len(output) <= 0:
        return None
    return output

def get_uptime(dut):
    """
    Get the dut uptime
    """
    output = st.show(dut, "show uptime")
    if len(output) <= 0:
        return None
    return output

def get_system_led_status(dut):
    """
    Author: Deekshitha Kankanala
    Get the show system health summary 
    """
    output = st.show(dut, "sudo show system-health summary")
    if len(output) <= 0:
        return None
    return output

def get_redis_cli_interface(dut):
    """
    Get interface details stored in redisdb
    """
    command = "redis-cli -n 6 keys TRANSCEIVER_INFO*"
    output = st.show(dut, command)
    return output

def get_redis_cli_interface_dom_sensors(dut):
    """
    Get presence of optic thermal sensor 
    """
    command = "redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*"
    output = st.show(dut, command)
    return output

def get_redis_int_dom(dut, number):
    """
    Get thermal sensor data present in redisdb for given optics/interface
    """
    command = "redis-cli -n 6 hgetall 'TRANSCEIVER_DOM_SENSOR|Ethernet{}'".format(number)
    output = st.show(dut, command)
    return output
    