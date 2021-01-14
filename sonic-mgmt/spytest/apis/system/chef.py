# This file contains the list of API's for operations on Chef
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

import json
import pprint

from spytest import st

import apis.system.connection as con_obj
import apis.system.basic as basic_obj
import apis.system.ntp as ntp_obj

import utilities.utils as utils_obj

chef_client_file = r"/etc/chef/client.rb"

def get_chef_cookbook_params(hostname="sonic"):
    """
    :return:
    """
    chef_cookbook = dict()
    chef_cookbook["name"] = hostname
    chef_cookbook["description"] = "This is a sample cookbook file for chef"
    chef_cookbook["json_class"] = "Chef::Role"
    chef_cookbook["default_attributes"] = dict()
    chef_cookbook["default_attributes"]["vlans"] = dict()
    chef_cookbook["default_attributes"]["interfaces"] = dict()
    chef_cookbook["default_attributes"]["fdbs"] = dict()
    chef_cookbook["default_attributes"]["lags"] = dict()
    chef_cookbook["override_attributes"] = dict()
    chef_cookbook["env_run_lists"] = dict()
    chef_cookbook["run_list"] = list()
    chef_cookbook["chef_type"] = "role"
    return chef_cookbook

chef_cookbook = get_chef_cookbook_params()

def generate_certificate(chef_conn_obj, cert_path):
    """

    :param chef_conn_obj:
    :param cert_path:
    :return:
    """
    if not chef_conn_obj:
        return False
    # command = "cd {}".format(cert_path)
    # con_obj.execute_command(chef_conn_obj, command)
    # print(command)
    command = "sudo knife configure client {}".format(cert_path)
    st.log("Remote Command: {}".format(command))
    result = con_obj.execute_command(chef_conn_obj, command)
    st.log("Result: {}".format(result))
    if result.find("Writing validation.pem") < 1:
        return False
    return True


def copy_validation_pem_from_chef_sever_to_client(connection_obj, **kwargs):
    """

    :param connection_obj:
    :param kwargs:
    :return:
    """
    connections_params = kwargs
    command = 'sshpass -p "{}"  scp -o StrictHostKeyChecking=no ' \
              '-o UserKnownHostsFile=/dev/null -q {}@{}:{} ' \
              '{}'.format(connections_params["password"],
                          connections_params["username"], connections_params["ip_address"],
                          connections_params["src_path"], connections_params["dst_path"])
    st.config(connection_obj, command)

def run_chef_client(dut, duration=0, args=''):
    """
    :param dut:
    :param duration:
    :return:
    """
    iterations = ""
    if duration:
        iterations = "-i {}".format(duration)
    command = "chef-client {} {}".format(iterations, args).strip()
    st.log("Remote Command: {}".format(command))
    try:
        st.config(dut, command)
    except ValueError as e:
        st.log(e)
        return False
    return True


def run_chef_client_service(dut, config_mode='enable'):
    """
    :param dut:
    :param config_mode:
    :return:
    """
    command = ""
    try:
        if config_mode.lower() == 'enable':
            command = "systemctl {} chef-client".format(config_mode)
        elif config_mode.lower() == 'disable':
            command = "systemctl {} chef-client".format(config_mode)
        st.config(dut, command)
    except ValueError as e:
        st.log(e)
        return False
    return True


def delete_client_pem_files(dut, files_path):
    """
    :param dut:
    :param files_path:
    :return:
    """
    command = "sudo rm -rf {}".format(files_path)
    print(command)
    result = st.config(dut, command)
    return result


def verify_chef_cookbook_on_server(chef_conn_obj, roles, cookbook="sonic.json"):
    """
    :param chef_conn_obj:
    :param roles:
    :param cookbook:
    :return:
    """
    command = "ls -la {}/{}".format(roles, cookbook)
    st.log("Remote Command: {}".format(command))
    files_list = con_obj.execute_command(chef_conn_obj, command)
    st.log(str(files_list))
    if files_list.find(cookbook) < 1:
        return False
    return True

def bootstrap_chef_node(chef_conn_obj, device_ip, uname, password, node_name):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "cd chef-repo"
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "./gencert.sh"
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    st.wait(5)
    command = "knife bootstrap {} -x {} -P {} --sudo --ssh-verify-host-key never --node-ssl-verify-mode none -N {}"\
                        .format(device_ip, uname, password ,node_name)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)


def delete_chef_node(chef_conn_obj, node_name="testsonic"):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "sudo knife node delete {} -y".format(node_name)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "sudo knife client delete {} -y".format(node_name)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)



def create_chef_cookbook(chef_conn_obj, cookbook_path, file_name="sonic.json"):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "sudo chef generate cookbook {}/{}".format(cookbook_path, file_name)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "chmod 777 {}/{}".format(cookbook_path, file_name)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)


def upload_chef_cookbook(chef_conn_obj, cookbook_path, file_name="sonic.json"):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "cd {}/".format(cookbook_path)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)
    command = "sudo knife upload {}".format(file_name)
    st.log("Remote Command: {}".format(command))
    con_obj.execute_command(chef_conn_obj, command)


def create_chef_role(chef_conn_obj):
    """
    :param chef_conn_obj:
    :return:
    """
    if not chef_conn_obj:
        return False
    # TODO -- Rizwan need to confirm the procedure for chef role create


def upload_role_chef_server(chef_conn_obj, file_name="sonic.json"):
    """
    :param chef_conn_obj:
    :param file_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "sudo knife role from file {}".format(file_name)
    st.log("Remote Command: {}".format(command))
    console_log = utils_obj.remove_last_line_from_string(con_obj.execute_command(chef_conn_obj, command))
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        return False
    return True


def update_node_run_list(chef_conn_obj, client_ip, recipe_role):
    """
    :param chef_conn_obj:
    :param client_ip:
    :param recipe_role:
    :return:
    """
    if not chef_conn_obj:
        return False
    client_ip = client_ip.replace(".", "-")
    command = "sudo knife node run_list add {} '{}'".format(client_ip, recipe_role)
    st.log("Remote Command: {}".format(command))
    console_log = utils_obj.remove_last_line_from_string(con_obj.execute_command(chef_conn_obj, command))
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        return False
    return True


def operations_on_runlist(chef_conn_obj, run_list, action="remove"):
    """
    :param chef_conn_obj:
    :param run_list:
    :param action:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "sudo knife node run_list {} {}".format(action, run_list)
    st.log("Remote Command: {}".format(command))
    out = con_obj.execute_command(chef_conn_obj, command)
    if not out:
        return False
    console_log = utils_obj.remove_last_line_from_string(out)
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        return False
    return True


def show_node_run_list(chef_conn_obj, node_name="sonic"):
    """
    :param chef_conn_obj:
    :param node_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "knife node show {} run_list".format(node_name)
    st.log("Remote Command: {}".format(command))
    console_log = utils_obj.remove_last_line_from_string(con_obj.execute_command(chef_conn_obj, command))
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        st.log(console_log)
        return False
    return True

def create_chef_node(chef_conn_obj, node_name):
    """
    :param chef_conn_obj:
    :param node_name:
    :return:
    """
    if not chef_conn_obj:
        return False
    command = "knife node create {}".format(node_name)
    st.log("Remote Command: {}".format(command))
    console_log = utils_obj.remove_last_line_from_string(con_obj.execute_command(chef_conn_obj, command))
    st.log(console_log)
    if console_log.find("ERROR") > 1:
        st.log(console_log)
        return False
    return True


def reset_cookbook_json():
    """
    :return:
    """
    global chef_cookbook
    st.log("Resetting the cookbook..")
    chef_cookbook = get_chef_cookbook_params()
    st.log("Post reset Cookbook Data: \n {}".format(str(chef_cookbook)))


def generate_cookbook_json(**kwargs):
    """
    :param kwargs:
    :return:
    """
    st.log("Cookbook parms: {}".format(str(kwargs)))
    if "name" in kwargs:
        chef_cookbook["name"] = kwargs["name"]
    if "description" in kwargs:
        chef_cookbook["description"] = kwargs["description"]
    if "json_class" in kwargs:
        chef_cookbook["json_class"] = kwargs["json_class"]
    if "chef_type" in kwargs:
        chef_cookbook["chef_type"] = kwargs["chef_type"]
    if "feature" in kwargs:
        if "config" in kwargs:
            if not chef_cookbook["default_attributes"][kwargs["feature"]]:
                chef_cookbook["default_attributes"][kwargs["feature"]] = kwargs["config"]
            else:
                chef_cookbook["default_attributes"][kwargs["feature"]].update(kwargs["config"])
        if "run_list" in kwargs:
            if kwargs["run_list"] not in chef_cookbook["run_list"]:
                chef_cookbook["run_list"].append(kwargs["run_list"])
    st.log("Cookbook generated: \n {}".format(str(pprint.pformat(chef_cookbook, width=2))))


def write_cookbook_json():
    """
    :return:
    """
    json_dump = json.dumps(chef_cookbook)
    parsed = json.loads(json_dump)
    chef_cookbook_json = json.dumps(parsed, indent=4, sort_keys=True)
    st.log("Cookbook Data: \n{}".format(chef_cookbook_json))
    src_file = st.mktemp()
    src_fp = open(src_file, "w")
    src_fp.write(chef_cookbook_json)
    src_fp.close()
    st.log("File path: {}".format(src_file))
    return src_file


def chef_execute_cli_commands(configuration):
    """
    API to generate sonic cli commands with the provided configuration

    :param configuration:
    :return:
    """
    if not configuration:
        return False
    commands = ""
    action_run = "action:run"

    for module in configuration:
        if module == "vlans":
            member_commands = config_cmd = member_config_cmd = ""
            for action in configuration[module]:
                if action == "add":
                    module_action = "vlan_add"
                    member_action = "vlan_member_add"
                elif action == "del":
                    module_action = "vlan_del"
                    member_action = "vlan_member_del"
                commands += "execute '{}' do\n".format(module_action)
                member_commands += "execute '{}' do\n".format(member_action)
                for vlan_id in configuration[module][action]:
                    config_cmd += "config vlan {} {}".format(action, vlan_id) + " && "
                    if "members" in configuration[module][action][vlan_id]:
                        for member in configuration[module][action][vlan_id]["members"]:
                            untag = "" if member["tagged"] or member["tagged"] == "True" else "-u"
                            member_config_cmd += "config vlan member {} {} {} {}".format(action, vlan_id,
                                                                                         member["port"],
                                                                                         untag).strip() + " && "
                    else:
                        member_commands = ""
                config_cmd = config_cmd.rstrip(" &")
                member_config_cmd = member_config_cmd.rstrip(" &")
                commands += " command '{}'\n".format(config_cmd)
                member_commands += " command '{}'\n".format(member_config_cmd)
                commands += " {}\n".format(action_run)
                commands += "end\n\n"
                if member_commands:
                    member_commands += " {}\n".format(action_run)
                    member_commands += "end\n\n"
                    commands += member_commands
        if module == "fdbs":
            for action in configuration[module]:
                config_cmd = ""
                if action == "add":
                    module_action = "fdb_add"
                elif action == "del":
                    module_action = "fdb_del"
                commands += "execute '{}' do\n".format(module_action)
                for entry in configuration[module][action]:
                    mac = entry["mac"] if "mac" in entry else ""
                    vlan_id = entry["vlan_id"] if "vlan_id" in entry else ""
                    port = entry["port"] if "port" in entry else ""
                    if action == "del":
                        config_cmd += "config mac {} {} {}".format(action, mac, vlan_id)+" && "
                    else:
                        config_cmd += "config mac {} {} {} {}".format(action, mac, vlan_id, port)+" && "
                config_cmd = config_cmd.rstrip(" && ")
                commands += " command '{}'\n".format(config_cmd)
                commands += " {}\n".format(action_run)
                commands += "end\n\n"
        if module == "lags":
            member_commands = ""
            for action in configuration[module]:
                fallback = min_links = config_cmd = member_config_cmd = ""
                if action == "add":
                    module_action = "lag_add"
                    member_action = "lag_member_add"
                elif action == "del":
                    module_action = "lag_del"
                    member_action = "lag_member_del"
                commands += "execute '{}' do\n".format(module_action)
                member_commands += "execute '{}' do\n".format(member_action)
                for portchannel in configuration[module][action]:
                    portchannel_config = configuration[module][action][portchannel]
                    if "fallback" in portchannel_config and (
                            portchannel_config["fallback"] or portchannel_config["fallback"] == "True"):
                        fallback = "--fallback true"
                    if "min-links" in portchannel_config:
                        min_links = "--min-links {}".format(portchannel_config["min-links"])
                    config_cmd += "config portchannel {} {} {} {}".format(action, portchannel, fallback,
                                                                          min_links).strip() + " && "
                    if "links" in configuration[module][action][portchannel]:
                        for member in configuration[module][action][portchannel]["links"]:
                            member_config_cmd += "config portchannel member {} {} {}".format(action, portchannel,
                                                                                             member) + " && "
                    else:
                        member_commands = ""
                config_cmd = config_cmd.rstrip(" && ")
                member_config_cmd = member_config_cmd.rstrip(" && ")
                member_commands += " command '{}'\n".format(member_config_cmd)
                commands += " command '{}'\n".format(config_cmd)
                commands += " {}\n".format(action_run)
                commands += "end\n\n"
                if member_commands:
                    member_commands += " {}\n".format(action_run)
                    member_commands += "end\n\n"
                    commands += member_commands
        if module == "interfaces":
            config_cmd = ""
            commands += "execute 'interface' do\n"
            for interface in configuration[module]:
                if "admin_status" in configuration[module][interface]:
                    operation = "shutdown" if configuration[module][interface]["admin_status"] == "down" else "startup"
                    config_cmd += "config interface {} {}".format(operation, interface) + " && "
                if "speed" in configuration[module][interface]:
                    config_cmd += "config interface {} speed {}".format(interface, configuration[module][interface][
                        "speed"]) + " && "
            config_cmd = config_cmd.rstrip(" && ")
            commands += " command '{}'\n".format(config_cmd)
            commands += " {}\n".format(action_run)
            commands += "end\n\n"
    st.log("complete_command: \n{}".format(commands))
    return commands


def chef_package_install(dut, url, ip, username='admin', password='broadcom', altpassword='YourPaSsWoRd'):
    """
    Install CHEF package to the DUT with CHEF server url.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param url:
    :param ip:
    :param username:
    :param password:
    :return:
    """
    if basic_obj.verify_package(dut, 'chef'):
        return True
    ssh_obj = con_obj.connect_to_device(ip, username, password, 'ssh')
    if not ssh_obj:
        ssh_obj = con_obj.connect_to_device(ip, username, altpassword, 'ssh')
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = "apt-get install chef -y"
        st.log(ssh_obj.send_command(command, expect_string=r"URL of Chef server:\s*"))
        command = "{}".format(url)
        st.log(ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt)))
        con_obj.ssh_disconnect(ssh_obj)
        return True
    else:
        con_obj.ssh_disconnect(ssh_obj)
        st.log("SSH to DUT is failed - Failed to install the chef package ")
        return False


def sync_with_server_time(dut, ip, username, password):
    """
    To Sync DUT with the CHEF server time.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ip:
    :param username:
    :param password:
    :return:
    """
    ssh_obj = con_obj.connect_to_device(ip, username, password, 'ssh')
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = "date"
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        st.log(output)
        date = utils_obj.remove_last_line_from_string(output)
        con_obj.ssh_disconnect(ssh_obj)
        st.log("Server Time : {}".format(date))
        ntp_obj.config_date(dut, date)
        return True
    else:
        con_obj.ssh_disconnect(ssh_obj)
        st.log("SSH to Server is failed - failed to sync time between DUT and CHEF Server")
        return False


def restart_and_verify_chef_client(dut):
    st.log("Stopping chef client")
    basic_obj.service_operations(dut, "chef-client", "stop")
    st.log("Verifying the chef client status")
    if basic_obj.verify_service_status(dut, "chef-client"):
        st.error("Chef client is running.")
        st.report_fail("client_running")
    basic_obj.service_operations(dut, "chef-client")
    st.log("Verifying the chef client status")
    if not basic_obj.verify_service_status(dut, "chef-client"):
        st.error("Chef client is not running.")
        st.report_fail("client_not_running")
