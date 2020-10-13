#!/usr/bin/python

"""
This file is used to apply the configs on DUT.
This fiel will be uploaded to DUT and executed there.
Please be sure before changing the file.
"""

import os
import re
import glob
import json
import socket
import filecmp
import argparse
import subprocess

g_use_config_replace = False
g_community_build = False
g_breakout_native = False
g_breakout_file = None
g_debug = False
syslog_levels=['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug', 'none']

minigraph_file = "/etc/sonic/minigraph.xml"
config_file = "/etc/sonic/config_db.json"
tmp_config_file = "/tmp/config_db.json"

copp_config_file = "/etc/swss/config.d/00-copp.config.json"
tmp_copp_file = "/tmp/copp.json"
frr_config_file = "/etc/sonic/frr/frr.conf"
tmp_frr_file = "/tmp/frr.conf"
syslog_file = "/etc/rsyslog.d/99-default.conf"
tmp_syslog_file = "/tmp/rsyslog-default.conf"

spytest_dir = "/etc/spytest"
init_config_file = spytest_dir + "/init_config_db.json"
base_config_file = spytest_dir + "/base_config_db.json"
module_config_file = spytest_dir + "/module_config_db.json"
init_frr_config_file = spytest_dir + "/init_frr.conf"
base_frr_config_file = spytest_dir + "/base_frr.conf"
module_frr_config_file = spytest_dir + "/module_frr.conf"
init_copp_config_file = spytest_dir + "/init_copp.json"
base_copp_config_file = spytest_dir + "/base_copp.json"
module_copp_config_file = spytest_dir + "/module_copp.json"
init_minigraph_file = spytest_dir + "/init_minigraph.xml"
base_minigraph_file = spytest_dir + "/base_minigraph.xml"
module_minigraph_file = spytest_dir + "/module_minigraph.xml"
tech_support_timestamp = spytest_dir + "/tech_support_timestamp.txt"

port_config_file = "/usr/share/sonic/device"

cores_tar_file_name = "/tmp/allcorefiles.tar.gz"
kdump_tar_file_name = "/tmp/allkdumpfiles.tar.gz"

def trace(msg):
    if g_debug:
        print(msg)

def read_port_inifile():
    """
    This proc is to get the last port number in the file port_config.ini
    :return:
    """
    (Platform, HwSKU) = get_hw_values()
    int_file = port_config_file + '/' + Platform + '/' + HwSKU + '/' + 'port_config.ini'
    int_file = 'cat ' + int_file + ' ' + '| ' + 'tail -1'
    output = execute_check_cmd(int_file)
    port = output.split(" ")[0]
    return port

def get_port_status(port):
    """
    This proc is used to get the given port status.
    :param port:
    :return:
    """
    output =  execute_check_cmd("show interfaces status {}".format(port))
    if output != "":
        return output
    return

def iterdict(d):
    new_dict = {}
    for k, v in d.items():
        if isinstance(v,dict):
            v = iterdict(v)
        try:
            new_dict[k] = int(v)
        except:
            new_dict[k] = v
    return new_dict

def read_lines(file_path, default=None):
    try:
        with open(file_path, "r") as infile:
            return infile.readlines()
    except Exception as exp:
        if default is None:
            raise exp
    return default

def read_offset(file_path):
    lines = read_lines(file_path, [])
    offset = int(lines[0].split()[0]) if lines else 0
    return (file_path, offset)

def write_offset(file_path, retval, add=0):
    try:
        lines = retval.split()
        offset = add + int(lines[0].split()[0])
        with open(file_path, "w") as infile:
            infile.write("{} unused".format(offset))
    except: pass

def execute_from_file(file_path):
    execute_cmds(read_lines(file_path))

def execute_cmds(cmds):
    retval = []
    for cmd in cmds:
        retval.append(execute_check_cmd(cmd))
    return "\n".join(retval)

def execute_check_cmd(cmd, show=True, skip_error=False):
    retval = ""
    try:
        if show:
            print("Remote CMD: '{}'".format(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        proc.wait()
        if not skip_error and proc.returncode != 0:
            retval = "Error: Failed to execute '{}' ('{}')\n".format(cmd, err.strip())
        if out.strip() != "":
            retval = retval + out.strip()
    except:
        retval = "Error: Exception occurred while executing the command '{}'".format(cmd)
    if retval.strip() != "":
        print(retval)
    return retval

def run_as_system_cmd(cmd, show=True):
    retcode = None
    try:
        if show:
            print("Remote CMD: '{}'".format(cmd))
        retcode = os.system(cmd)
        if retcode != 0:
            print("Error: Failed to execute '{}'. Return code is '{}'".format(cmd, retcode))
    except:
        print("Error: Exception occurred while executing the command '{}'".format(cmd))
    return retcode

def get_mac_address():
    syseeprom = execute_check_cmd("show platform syseeprom").split("\n")
    for line in syseeprom:
        match = re.match(r"^Base MAC Address\s+0x\d+\s+6\s+(\S+)", line)
        if match:
            return match.group(1)
    return None

def get_hw_values():
    platform = None
    hwsku = None
    platform_summ = execute_check_cmd("show platform summary").split("\n")
    for line in platform_summ:
        if not platform:
            match = re.match(r"^Platform:\s+(\S+)", line)
            if match:
                platform = match.group(1)
        if not hwsku:
            match = re.match(r"^HwSKU:\s+(\S+)", line)
            if match:
                hwsku = match.group(1)
    return (platform, hwsku)

def read_json(filepath):
    return eval(open(filepath, 'rU').read())

def get_file_diff(file1, file2, show_diff=False):
    if filecmp.cmp(file1, file2):
        # files have same content
        return True

    # compare the dictionaries
    file1_dict = read_json(file1)
    file2_dict = read_json(file2)
    f1_dict = iterdict(dict((k, v) for k, v in file1_dict.items() if v))
    f2_dict = iterdict(dict((k, v) for k, v in file2_dict.items() if v))

    if f1_dict == f2_dict:
        # dictionaries are same
        return True

    # the files have different content
    if show_diff:
        print("Content in the files '{}' '{}' is different".format(file1, file2))

    return False

def json_fix(filepath):
    data = open(filepath, 'rU').read()
    try:
        obj = json.loads(data)
    except:
        print("invalid json - trying to fix")
        # remove trailing object comma
        regex = re.compile(r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
        data = regex.sub("}", data)
        # remove trailing array comma
        regex = re.compile(r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
        data = regex.sub("]", data)
        try:
            obj = json.loads(data)
        except:
            raise ValueError("invalid json data")

    dst_file = "{}.new".format(filepath)
    with open(dst_file, 'w') as outfile:
        json.dump(obj, outfile, indent=4)

    return dst_file

def backup_file(file_path):
    file_name = os.path.basename(file_path)
    golden_file = spytest_dir + "/{}.golden".format(file_name)
    backup_filepath = spytest_dir + "/{}.backup".format(file_name)
    if not os.path.exists(golden_file):
        execute_check_cmd("cp {} {}".format(file_path, golden_file))
    execute_check_cmd("cp {} {}".format(file_path, backup_filepath))

def backup_swss_docker_file(file_path):
    file_name = os.path.basename(file_path)
    golden_file = spytest_dir + "/{}.golden".format(file_name)
    backup_filepath = spytest_dir + "/{}.backup".format(file_name)
    if not os.path.exists(golden_file):
        execute_check_cmd("docker cp swss:{} {}".format(file_path, golden_file))
    execute_check_cmd("docker cp swss:{} {}".format(file_path, backup_filepath))
    return backup_filepath

def apply_file(filepath, method):
    commands_to_execute = []

    if filepath.endswith('.json'):
        filepath = json_fix(filepath)
        if method == "full":
            commands_to_execute.append("cp {} {}".format(filepath, init_config_file))
        else:
            commands_to_execute.append("config load -y {}".format(filepath))
            commands_to_execute.append("config save -y")
    elif filepath.endswith('.copp'):
        filepath = json_fix(filepath)
        if method == "full":
            commands_to_execute.append("cp {} {}".format(filepath, init_copp_config_file))
        else:
            backup_swss_docker_file(copp_config_file)
            commands_to_execute.append("docker cp {} swss:{}".format(filepath, copp_config_file))
    elif filepath.endswith('.xml'):
        if method == "full":
            commands_to_execute.append("cp {} {}".format(filepath, init_minigraph_file))
        else:
            backup_file(minigraph_file)
            commands_to_execute.append("cp {} {}".format(filepath, minigraph_file))
            commands_to_execute.append("config load_minigraph -y")
            commands_to_execute.append("config save -y")
    elif filepath.endswith('.frr'):
        if method == "full":
            commands_to_execute.append("cp {} {}".format(filepath, init_frr_config_file))
        else:
            backup_file(frr_config_file)
            commands_to_execute.append("cp {} {}".format(filepath, frr_config_file))
    elif filepath.endswith('.sh'):
        commands_to_execute.append("bash {}".format(filepath))
    elif filepath.endswith('.py'):
        commands_to_execute.append("python {}".format(filepath))
    elif filepath.endswith('.bcm') or filepath.endswith('.ini') or filepath.endswith('.j2'):
        # Execute the command "show platform summary" and get the Platform and HwSKU values.
        (Platform, HwSKU) = get_hw_values()

        # Construct the path where we can found the Platform and HwSKU details.
        device_files_loc = "/usr/share/sonic/device"
        dut_file_location = "{}/{}/{}/".format(device_files_loc,Platform,HwSKU)
        basename = os.path.basename(filepath)
        old_file = os.path.join(dut_file_location, basename)
        if not os.path.exists(old_file + ".orig"):
            commands_to_execute.append("cp {} {}.orig".format(old_file, old_file))
        commands_to_execute.append("cp {} {}".format(filepath, old_file))

    if commands_to_execute:
        execute_cmds(commands_to_execute)
    else:
        print("Error: Invalid file format {}.".format(filepath))

def parse_and_apply_files(names, method):
    ensure_mac_address(config_file)
    if type(names) is str:
        apply_file(names, method)
    elif type(names) is list:
        for filename in names:
            parse_and_apply_files(filename, method)

def clean_core_files(flag):
    if flag == "YES":
        print("remove core files files")
        execute_check_cmd("rm -f /var/core/*.core.gz")

def clean_dump_files(flag):
    if flag == "YES":
        print("remove techsupport dump files")
        execute_check_cmd("rm -f /var/dump/*.tar.gz")

def clear_techsupport(flag):
    if flag == "YES":
        print("remove core dumps and techsupport till now using CLI command.")
        execute_check_cmd("sonic-clear techsupport till 'now' -y")

def init_clean(flags):
    [core_flag, dump_flag, clear_flag] = flags.split(",")
    # remove core files
    clean_core_files(core_flag)
    # remove techsupport dump files
    clean_dump_files(dump_flag)
    # remove core dumps and techsupport till now using CLI command.
    clear_techsupport(clear_flag)

    # disable syslog messages
    print("disable syslog messages")
    enable_disable_debug(False)

    # clear syslog messages
    execute_check_cmd("rm -f {}/syslog.*".format(spytest_dir))
    execute_check_cmd("rm -f {}/sairedis.*".format(spytest_dir))
    execute_check_cmd("logrotate -f /etc/logrotate.conf", skip_error=True)

def init_ta_config(flags, profile):
    init_clean(flags)

    if profile == "na":
        create_default_base_config()
    elif profile == "l2" or profile == "l3":
        create_profile_base_config(profile)

    # save current timestamp
    run_as_system_cmd("date > {}".format(tech_support_timestamp))

    # remove syslogs and sairedis files
    print("clear syslog and sairedis files")
    execute_check_cmd("logrotate -f /etc/logrotate.conf", skip_error=True)
    execute_check_cmd("rm -f /var/log/syslog.*")
    execute_check_cmd("rm -f /var/log/swss/sairedis.rec.*")

    print("DONE")

def create_default_base_config():
    print("default base config")
    # Clean the spytest directory - copp files are also saved as json
    for extn in ["json", "conf", "xml"]:
        execute_check_cmd("rm -f {}/*.{}".format(spytest_dir, extn))

    # remove init configs
    for filename in [init_copp_config_file, init_minigraph_file, \
                     init_frr_config_file]:
        execute_check_cmd("rm -f {}".format(filename))

    # save the config to init file.
    execute_check_cmd("config save -y {}".format(init_config_file))

    file_dict = read_json(init_config_file)

    # remove all the unnecessary sections from init file
    print("remove all the unnecessary sections")
    retain = ['DEVICE_METADATA', 'PORT', 'FLEX_COUNTER_TABLE', "MGMT_PORT"]
    if os.getenv("SPYTEST_NTP_CONFIG_INIT", "0") != "0":
        retain.append("NTP_SERVER")
    if os.getenv("SPYTEST_CLEAR_MGMT_INTERFACE", "0") == "0":
        retain.append("MGMT_INTERFACE")
    for key in file_dict.keys():
        if key not in retain:
            del file_dict[key]

    # enable docker_routing_config_mode
    print("enable docker_routing_config_mode")
    if "DEVICE_METADATA" in file_dict:
        if "localhost" in file_dict["DEVICE_METADATA"]:
            file_dict["DEVICE_METADATA"]["localhost"]["docker_routing_config_mode"] = "split"
            if os.getenv("SPYTEST_CLEAR_DEVICE_METADATA_HOSTNAME", "0") == "0":
                file_dict["DEVICE_METADATA"]["localhost"]["hostname"] = "sonic"

    # enable all ports
    print("enable all ports")
    if "PORT" in file_dict:
        port_dict = file_dict['PORT']
        for k, v in port_dict.items():
            v["admin_status"] = "up"

    # save the configuration to init file
    with open(init_config_file, 'w') as outfile:
        json.dump(file_dict, outfile, indent=4)

def create_profile_base_config(profile):
    print("{} base config".format(profile))
    # save the config to init file.
    execute_check_cmd("config save -y {}".format(init_config_file))

    print("DONE")

def apply_config_profile(profile):
    if profile == "na":
        print("Skipping the profile config as it is not required for 'NA'.")
    else:
        output = execute_check_cmd("show config profiles")
        match = re.match(r"Factory Default:\s+(\S+)", output)
        if match and profile == match.group(1):
            execute_check_cmd("rm -rf {}".format(config_file))
        execute_check_cmd("config profile factory {} -y".format(profile))
    print("DONE")

def update_reserved_ports(port_list):
    # If no init config_db.json return back.
    if not os.path.exists(init_config_file):
        print("==============================================================================")
        print("===================== DEFAULT INIT CONFIG FILE IS MISSING ====================")
        print("==============================================================================")
        print("NOFILE")
        return

    file_dict = read_json(init_config_file)

    # Change reserved port state
    print("Change the reserved port state to down in config-db")
    if "PORT" in file_dict:
        port_dict = file_dict['PORT']
        for k, v in port_dict.items():
            if k not in port_list:
                continue
            v["admin_status"] = "down"

    # save the configuration to init file
    with open(init_config_file, 'w') as outfile:
        json.dump(file_dict, outfile, indent=4)

    print("DONE")

def wait_for_ports_2(port_init_wait, poll_for_ports):
    # Wait for last port to be available
    port_num = read_port_inifile()
    output = []
    if poll_for_ports == "yes":
        for iter in range(0, port_init_wait/2):
            retval = execute_check_cmd("grep -r PortInitDone /var/log/syslog", skip_error=True)
            port_info = get_port_status(port_num)
            if port_info:
                output.append(port_info)
            if "PortInitDone" in retval:
                output.append(retval)
                break
            if port_info and port_num in port_info:
                break
            execute_check_cmd("sleep 2", False)
    else:
        execute_check_cmd("sleep {}".format(port_init_wait))
    return "\n".join(output)

def wait_for_ports(port_init_wait, poll_for_ports):
    if port_init_wait == 0:
        return

    # use older mechanism for community build
    if g_community_build:
        return wait_for_ports_2(port_init_wait, poll_for_ports)

    if poll_for_ports == "yes":
        # Wait for last port to be available
        port_num = read_port_inifile()
        for iter in range(0, port_init_wait/2):
            port_info = get_port_status(port_num)
            retval = execute_check_cmd("show system status")
            if "System is ready" in retval:
                break
            if port_info and port_num in port_info:
                break
            execute_check_cmd("sleep 2", False)
    else:
        execute_check_cmd("sleep {}".format(port_init_wait))

# check if the MAC address is present in config_db.json
def ensure_mac_address(filepath):
    file_dict = read_json(filepath)
    if "DEVICE_METADATA" in file_dict:
        if "localhost" in file_dict["DEVICE_METADATA"]:
            if "mac" not in file_dict["DEVICE_METADATA"]["localhost"]:
                print("============ Recovering MAC address =======")
                mac = get_mac_address()
                file_dict["DEVICE_METADATA"]["localhost"]["dmac"] = mac
                with open(filepath, 'w') as outfile:
                    json.dump(file_dict, outfile, indent=4)
                print("===========================================")

def do_config_reload(filename=""):
    if g_use_config_replace:
        if filename:
            execute_check_cmd("config_replace -f {}".format(filename))
        else:
            execute_check_cmd("config_replace")
    else:
        execute_check_cmd("config reload -y {}".format(filename))

def dump_click_cmds():
    script = "/etc/spytest/remote/click-helper.py"
    execute_check_cmd("python {}".format(script), show=False)

def set_port_defaults(breakout, speed, port_init_wait, poll_for_ports):
    if g_breakout_native:
        script = "/usr/local/bin/port_breakout.py"
    else:
        script = None

    if not script or not os.path.exists(script):
        script = "/etc/spytest/remote/port_breakout.py"

    if g_breakout_file:
        script = script + " -c " + g_breakout_file
    index = 0
    while index < len(breakout):
        opt = breakout[index+1]
        execute_check_cmd("python {} -p {} -o {}".format(script, breakout[index], opt))
        index = index + 2
    if breakout:
        ensure_mac_address(config_file)
        do_config_reload()

    index = 0
    while index < len(speed):
        opt = speed[index+1]
        retval = execute_check_cmd("portconfig -p {} -s {}".format(speed[index], opt))
        for line in retval.split("\n"):
            match = re.match(r"^Port Ethernet\d+ belongs to port group (\d+)", line)
            if match:
                execute_check_cmd("config portgroup speed {} {}".format(match.group(1), opt))
                break
        index = index + 2
    if speed:
        execute_check_cmd("config save -y")

    wait_for_ports(port_init_wait, poll_for_ports)

def config_reload(save, port_init_wait, poll_for_ports):
    if save == "yes":
        execute_check_cmd("config save -y")

    ensure_mac_address(config_file)

    do_config_reload()

    wait_for_ports(port_init_wait, poll_for_ports)

def copy_or_delete(from_file, to_file):
    if os.path.exists(from_file):
        execute_check_cmd("cp {} {}".format(from_file, to_file))
    else:
        execute_check_cmd("rm -f {}".format(to_file))

def show_file_content(filename, msg=""):
    if g_debug:
        print("======================== {} ====================".format(msg))
        if os.path.exists(filename):
            execute_check_cmd("cat {}".format(filename))
        else:
            print("File {} does not exist".format(filename))
        print("================================================")

def save_base_config():
    # Save init_config_db.json and copy to base_config_db.json
    execute_check_cmd("cp {} {}".format(init_config_file, base_config_file))

    # Copy all init files as base files
    copy_or_delete(init_frr_config_file, base_frr_config_file)
    copy_or_delete(init_copp_config_file, base_copp_config_file)
    copy_or_delete(init_minigraph_file, base_minigraph_file)

    print("DONE")

def save_module_config():
    # Save current DB configuration to config_db.json and copy it as module config file.
    execute_check_cmd("config save -y")
    execute_check_cmd("cp {} {}".format(config_file, module_config_file))

    # save the FRR configuration applied in module init
    execute_check_cmd("touch {}".format(frr_config_file))
    execute_check_cmd("vtysh -c write file")
    show_file_content(frr_config_file, "save_module_config FRR")

    # Copy all the actual files as module files.
    copy_or_delete(frr_config_file, module_frr_config_file)
    copy_or_delete(minigraph_file, module_minigraph_file)

    # Copy copp config file to ta location.
    execute_check_cmd("docker cp swss:{} {}".format(copp_config_file, module_copp_config_file))

    print("DONE")

def apply_ta_config(method, port_init_wait, poll_for_ports, is_module_cfg):

    ta_config_file = module_config_file if is_module_cfg else base_config_file
    ta_frr_config_file = module_frr_config_file if is_module_cfg else base_frr_config_file
    ta_copp_config_file = module_copp_config_file if is_module_cfg else base_copp_config_file
    ta_minigraph_file = module_minigraph_file if is_module_cfg else base_minigraph_file

    # If no base/module config_db.json return back. No need to check for other file formats.
    if not os.path.exists(ta_config_file):
        print("==============================================================================")
        print("======================= TA DEFAULT CONFIG FILE IS MISSING ====================")
        print("==============================================================================")
        print("NOFILE")
        return

    changed_files = []

    # Save current config in DB to temp file to and compare it with base/module config_db.json file
    # If there is a change, add config to list.
    execute_check_cmd("config save -y {}".format(tmp_config_file))
    if not get_file_diff(tmp_config_file, ta_config_file, g_debug):
        trace("TA Config File Differs")
        changed_files.append("config")

    # Compare the minigraph.xml file with base/module minigraph.xml
    # If there is a change, add xml to list.
    if os.path.exists(minigraph_file) and os.path.exists(ta_minigraph_file):
        if not filecmp.cmp(minigraph_file, ta_minigraph_file):
            trace("TA Minigraph File Differs")
            changed_files.append("minigraph")

    # When frr.conf file is not present, write file creates 3 different config files.
    # Touch the frr.conf, this allows to create a empty file is it is not present.
    # Write the current running configuration to frr.conf file
    # Compare the generated frr.conf with base/module frr.conf file.
    # If there is a change or no base/module/actual frr.conf file exists, add frr to list.
    show_file_content(frr_config_file, "existing FRR")
    execute_check_cmd("touch {}".format(frr_config_file))
    execute_check_cmd("vtysh -c write file")
    show_file_content(frr_config_file, "generated FRR")
    show_file_content(ta_frr_config_file, "TA FRR")
    if not os.path.exists(ta_frr_config_file) and not os.path.exists(frr_config_file):
        pass
    elif not os.path.exists(ta_frr_config_file):
        trace("TA FRR File Missing")
        changed_files.append("frr")
    elif not filecmp.cmp(frr_config_file, ta_frr_config_file):
        trace("FRR File Differs")
        changed_files.append("frr")

    # Save and compare the copp.json file
    execute_check_cmd("docker cp swss:{} {}".format(copp_config_file, tmp_copp_file))
    if not os.path.exists(tmp_copp_file) and os.path.exists(ta_copp_config_file):
        trace("SWSS COPP File Missing")
        changed_files.append("copp")
    elif os.path.exists(tmp_copp_file) and not os.path.exists(ta_copp_config_file):
        trace("TA COPP File Missing")
        changed_files.append("copp")
    elif os.path.exists(tmp_copp_file) and os.path.exists(ta_copp_config_file):
        if not get_file_diff(tmp_copp_file, ta_copp_config_file, g_debug):
            trace("COPP File Differs")
            changed_files.append("copp")

    # If a force method is *NOT* used, check for any entries in changed list
    # If no entries are present(Means no change in configs), Return back.
    if method not in ["force_reload", "force_reboot"]:
        if not changed_files:
            print("Config, FRR, COPP are same as TA files")
            print("DONE")
            return

        print("The current config differs from TA config, {}".format(changed_files))

    # Check for each entry in changed list and copy the base/module files to the actual files.
    # Copy base/module config file to actual file if config entry exists.
    # If base/module frr file not exists, remove the actual file.
    # Copy base/module frr file to actual file if frr entry exists.
    # COPP
    if "config" in changed_files:
        execute_check_cmd("cp {} {}".format(ta_config_file, config_file))
    if os.path.exists(ta_minigraph_file) and "minigraph" in changed_files:
        execute_check_cmd("cp -f {} {}".format(ta_minigraph_file, minigraph_file))
    if not os.path.exists(ta_frr_config_file) and "frr" in changed_files:
        execute_check_cmd("rm -f {}".format(frr_config_file))
    if os.path.exists(ta_frr_config_file) and "frr" in changed_files:
        execute_check_cmd("cp -f {} {}".format(ta_frr_config_file, frr_config_file))
    if os.path.exists(ta_copp_config_file) and "copp" in changed_files:
        execute_check_cmd("docker cp {} swss:{}".format(ta_copp_config_file, copp_config_file))
        method = "force_reboot"

    # We copied the changed files to actual files.
    # If reboot related method is used, return back asking for reboot required.
    if method in ["force_reboot", "reboot"]:
        print("REBOOT REQUIRED")
        return

    # Following code is required for reload related methods.
    # Create an empty frr.conf file. This will allow to write the running config to single file.
    execute_check_cmd("touch {}".format(frr_config_file))

    # Depending on the entries in the changed list, perform the operations.
    if "minigraph" in changed_files:
        execute_check_cmd("config load_minigraph -y")
        execute_check_cmd("config save -y")

    # If config entry is present, perform config reload, this will take care of frr too.
    # If frr enry is present, perform bgp docker restart.
    if "config" in changed_files or method in ["force_reload"]:
        ensure_mac_address(ta_config_file)
        #execute_check_cmd("echo before reload;date")
        do_config_reload(ta_config_file)
        #execute_check_cmd("echo after reload;date")
    if "frr" in changed_files or method in ["force_reload"]:
        execute_cmds(["systemctl restart bgp"])
        execute_cmds(["sleep 10"])

    # Re-Write the base/module frr.conf, this is to allow the hook level code to get saved in frr.conf.
    execute_check_cmd("vtysh -c write file")
    if os.path.exists(frr_config_file):
        execute_check_cmd("cp -f {} {}".format(frr_config_file, ta_frr_config_file))
        show_file_content(ta_frr_config_file, "rewrite TA FRR")

    # Wait for last port to be available
    wait_for_ports(port_init_wait, poll_for_ports)

def run_test(script_fullpath, proc_args):
    if os.path.exists(script_fullname):
        execute_check_cmd("chmod 755 {}".format(script_fullpath))
        args_to_script = " ".join(proc_args)
        cmd = "{} {}".format(script_fullpath, args_to_script)
        execute_check_cmd(cmd)
        return
    print("Script '{}' not exists".format(script_fullpath))

def enable_disable_debug(flag):
    if not os.path.exists(syslog_file):
        print("==============================================================================")
        print("============================= SYSLOG FILE IS MISSING =========================")
        print("==============================================================================")
        print("NOFILE")
        return

    backup_file(syslog_file)
    execute_check_cmd("cp {} {}".format(syslog_file, tmp_syslog_file))

    cmd = ""
    if flag:
        cmd = '''sed -i '$ a :msg, contains, "(core dumped)"   /dev/console' {}'''.format(syslog_file)
    else:
        cmd = '''sed '/core dumped/d' -i {}'''.format(syslog_file)
    execute_check_cmd(cmd, False)

    if not filecmp.cmp(syslog_file, tmp_syslog_file):
        # files have different content
        execute_check_cmd("systemctl restart rsyslog")
        print("DONE")
        return

    print("NOCHANGE")

def read_messages(file_path, all_file, var_file, our_file):
    (offset_file, offset) = read_offset(file_path)
    execute_check_cmd("tail --lines=+{} {} > {}".format(offset, all_file, our_file))
    execute_check_cmd("ls -l {}*".format(var_file))
    retval = execute_check_cmd("wc -l {}".format(our_file))
    write_offset(file_path, retval, offset)

def syslog_read_msgs(lvl, phase):
    if phase: execute_check_cmd("sudo echo {}".format(phase))
    file_path = "{}/syslog.offset".format(spytest_dir)
    var_file = "/var/log/syslog"
    our_file = "{}/syslog.txt".format(spytest_dir)
    read_messages(file_path, var_file, var_file, our_file)
    if lvl != "none" and lvl in syslog_levels:
        index = syslog_levels.index(lvl)
        needed = "|".join(syslog_levels[:index+1])
        cmd = r"""grep -E "^\S+\s+[0-9]+\s+[0-9]+:[0-9]+:[0-9]+(\.[0-9]+){{0,1}}\s+\S+\s+({})" {}"""
        execute_check_cmd(cmd.format(needed.upper(), our_file), False, True)

def do_sairedis(op):
    if op == "clean":
        execute_check_cmd("rm -f {}/sairedis.*".format(spytest_dir))
        execute_check_cmd("rm -f /var/log/swss/sairedis.rec.*")
    file_path = "{}/sairedis.offset".format(spytest_dir)
    var_file = "/var/log/swss/sairedis.rec"
    our_file = "{}/sairedis.txt".format(spytest_dir)
    all_file = "{}/sairedis.all".format(spytest_dir)
    execute_check_cmd("rm -f {0};ls -1tr {1}* | xargs zcat -f >> {0}".format(all_file, var_file))
    read_messages(file_path, all_file, var_file, our_file)
    if op == "read":
        print("SAI-REDIS-FILE: /etc/spytest/sairedis.txt")

def invalid_ip(addr):
    try:
        socket.inet_aton(addr)
    except:
        return True
    return False

def mgmt_ip_setting(mgmt_type, ip_addr_mask, gw_addr):
    # Validate the ip/gw for static
    if mgmt_type == "static":
        if ip_addr_mask and gw_addr:
            try:
                (ipaddr, mask_str) = ip_addr_mask.split("/")
            except:
                print("IP and Mask should be provided with '/' delimited.")
                return
            try:
                mask = int(mask_str)
                if mask < 0 or mask > 32:
                    print("Invalid MASK provided.")
                    return
            except:
                print("Invalid MASK provided.")
                return
            if invalid_ip(ipaddr) or invalid_ip(gw_addr):
                print("Invalid IP/Gateway provided.")
                return
        else:
            print("IP or Gateway details not provided.")
            return

    file_dict = read_json(config_file)

    if mgmt_type == "dhcp" and 'MGMT_INTERFACE' not in file_dict.keys():
        print("DONE-NOCHANGE-DHCP")
        return

    print("Remove the required ip setting sections")
    if 'MGMT_INTERFACE' in file_dict.keys():
        del file_dict['MGMT_INTERFACE']

    if mgmt_type == "static":
        print("Adding new data")
        mgmt_key = "eth0|{}".format(ip_addr_mask)
        mgmt_dict = {mgmt_key: {"gwaddr": gw_addr}}
        file_dict['MGMT_INTERFACE'] = mgmt_dict

    # save the configuration
    with open(config_file, 'w') as outfile:
        json.dump(file_dict, outfile, indent=4)

    print("DONE")

def fetch_core_files():
    # Create a tar file for using the files  /var/core/*.core.gz
    core_files_list = glob.glob("/var/core/*.core.gz")
    if len(core_files_list) == 0:
        print("NO-CORE-FILES")
        return
    if os.path.exists(cores_tar_file_name):
        execute_check_cmd("rm -f {}".format(cores_tar_file_name))
    tar_cmd = "cd /var/core/ && tar -cf {} *.core.gz && cd -".format(cores_tar_file_name)
    execute_check_cmd(tar_cmd)
    if os.path.exists(cores_tar_file_name):
        execute_check_cmd("rm -f /var/core/*.core.gz")
        print("CORE-FILES: {}".format(cores_tar_file_name))
        return
    print("NO-CORE-FILES: No tar file is generated for core.gz files")

def get_tech_support():
    # read last time stamp
    lines = read_lines(tech_support_timestamp, [])
    since = "--since='{}'".format(lines[0].strip()) if lines else ""

    # Create a tar file for using the the command show techsupport
    retcode = run_as_system_cmd("show techsupport {} > /tmp/show_tech_support.log 2>&1".format(since))
    if retcode != 0:
        print("NO-DUMP-FILES: 'show techsupport' command failed")
        return
    tech_support_tarlist = sorted(glob.glob("/var/dump/*.tar.gz"))
    if len(tech_support_tarlist) == 0:
        print("NO-DUMP-FILES: No techsupport tar file is generated in /var/dump/")
        return
    retval = "DUMP-FILES: {}".format(tech_support_tarlist[-1])
    print(retval)

    # save current time stamp
    run_as_system_cmd("date > {}".format(tech_support_timestamp))

def fetch_kdump_files():
    # Create a tar file for using the files  /var/crash/datestamp & and the kexec_dump
    kdump_files_type1 = execute_check_cmd("find /var/crash -name dmesg* | wc -l")
    kdump_files_type2 = execute_check_cmd("find /var/crash -name kdump* | wc -l")
    if kdump_files_type1 == '0' and kdump_files_type2 == '0':
        print("NO-KDUMP-FILES")
        return
    if os.path.exists(kdump_tar_file_name):
        execute_check_cmd("rm -f {}".format(kdump_tar_file_name))
    tar_cmd = "cd /var/crash/ && tar -cf {} * && cd -".format(kdump_tar_file_name)
    execute_check_cmd(tar_cmd)
    if os.path.exists(kdump_tar_file_name):
        execute_check_cmd("sudo rm -rf /var/crash/*")
        print("KDUMP-FILES: {}".format(kdump_tar_file_name))
        return
    print("NO-KDUMP-FILES: No tar file is generated for kdump files")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SpyTest Helper script.')

    parser.add_argument("--env", action="append", default=[],
                        nargs=2, help="environment variables")
    parser.add_argument("--apply-configs", action="store", default=None,
            nargs="+", help="list of files that need to apply on dut.")
    parser.add_argument("--apply-file-method", action="store",
            choices=['full', 'incremental'],
            help="method to apply files.")
    parser.add_argument("--run-test", action="store", default=None, nargs="+",
            help="execute the given script with given arguments.")
    parser.add_argument("--save-base-config", action="store_true", default=False,
            help="save the current config as base config.")
    parser.add_argument("--save-module-config", action="store_true", default=False,
            help="save the current config as module config.")
    parser.add_argument("--init-ta-config", action="store", default=None,
            help="save the current config as ta default config.")
    parser.add_argument("--port-init-wait", action="store", type=int, default=0,
            help="Wait time in seconds for ports to come up -- default: 0")
    parser.add_argument("--poll-for-ports", action="store", default="no",
            choices=['yes', 'no'],
            help="Poll for the ports status after the DUT reload")
    parser.add_argument("--apply-base-config", action="store",
            choices=['reload', 'replace', 'reboot', 'force_reload', 'force_reboot'],
            help="apply base config as current config.")
    parser.add_argument("--apply-module-config", action="store",
            choices=['reload', 'replace', 'reboot', 'force_reload', 'force_reboot'],
            help="apply module config as current config.")
    parser.add_argument("--json-diff", action="store", nargs=2, default=None,
            help="dump the difference between json files.")
    parser.add_argument("--enable-debug", action="store_true", default=False,
            help="enable debug messages onto the console.")
    parser.add_argument("--disable-debug", action="store_true", default=False,
            help="disable debug messages onto the console.")
    parser.add_argument("--syslog-check", action="store", default=None,
            choices=syslog_levels,
            help="read syslog messages of given level and clear all syslog messages.")
    parser.add_argument("--phase", action="store", default=None,
            help="phase for checks.")
    parser.add_argument("--sairedis", action="store", default="none",
            choices=['clear', 'read', 'none', 'clean'], help="read sairedis messages.")
    parser.add_argument("--execute-from-file", action="store", default=None,
            help="execute commands from file.")
    parser.add_argument("--set-mgmt-ip", action="store", default=None,
            choices=['dhcp', 'static', None], help="Management(eth0) address type.")
    parser.add_argument("--ip-addr-mask", action="store", default=None,
            help="IP address to set for management port(eth0).")
    parser.add_argument("--gw-addr", action="store", default=None,
            help="Gateway address to set for management port(eth0).")
    parser.add_argument("--fetch-core-files", action="store", default=None,
            choices=['collect_kdump', 'none'],
            help="Fetch the core files from DUT to logs location.")
    parser.add_argument("--get-tech-support", action="store_true", default=False,
            help="Get the tech-support information from DUT to logs location.")
    parser.add_argument("--init-clean", action="store", default=None,
            help="Clear the core files, dump files, syslog data etc.")
    parser.add_argument("--update-reserved-ports", action="store", default=None,
            nargs="+", help="list of reserved ports that need to be shutdown on dut.")
    parser.add_argument("--breakout", action="store", default=[],
            nargs="+", help="breakout operations to be performed.")
    parser.add_argument("--speed", action="store", default=[],
            nargs="+", help="speed operations to be performed.")
    parser.add_argument("--port-defaults", action="store_true", default=None,
            help="apply breakout/speed defaults.")
    parser.add_argument("--dump-click-cmds", action="store_true", default=None,
            help="dump all click commnds.")
    parser.add_argument("--config-reload", action="store", default=None,
            choices=['yes', 'no'],
            help="perform config reload operation: yes=save+reload no=reload")
    parser.add_argument("--wait-for-ports", action="store_true", default=None,
            help="wait for ports to comeup.")
    parser.add_argument("--config-profile", action="store", default="na",
            choices=['l2', 'l3', 'na'], help="Profile name to load.")
    parser.add_argument("--community-build", action="store_true", default=False,
            help="use community build options.")
    parser.add_argument("--breakout-native", action="store_true", default=False,
            help="Use port breakout script from device.")
    parser.add_argument("--breakout-file", action="store", default=None,
            help="Use port breakout options from file.")
    parser.add_argument("--use-config-replace", action="store_true", default=False,
            help="use config replace where ever config reload is needed.")
    parser.add_argument("--debug", action="store_true", default=False)

    args, unknown = parser.parse_known_args()

    if unknown:
        print("IGNORING unknown arguments", unknown)

    #g_debug = args.debug
    g_community_build = args.community_build
    g_breakout_native = args.breakout_native
    g_breakout_file = args.breakout_file
    g_use_config_replace = args.use_config_replace

    for name, value in args.env:
        os.environ[name] = value

    if args.apply_configs:
        parse_and_apply_files(args.apply_configs, args.apply_file_method)
    elif args.run_test:
        script_fullname = args.run_test[0]
        script_arguments = args.run_test[1:]
        run_test(script_fullname, script_arguments)
    elif args.init_ta_config:
        init_ta_config(args.init_ta_config, args.config_profile)
    elif args.save_base_config:
        save_base_config()
    elif args.save_module_config:
        save_module_config()
    elif args.apply_base_config:
        apply_ta_config(args.apply_base_config, args.port_init_wait, args.poll_for_ports, False)
    elif args.apply_module_config:
        apply_ta_config(args.apply_module_config, args.port_init_wait, args.poll_for_ports, True)
    elif args.json_diff:
        retval = get_file_diff(args.json_diff[0], args.json_diff[1], True)
        print(retval)
    elif args.enable_debug:
        enable_disable_debug(True)
    elif args.disable_debug:
        enable_disable_debug(False)
    elif args.syslog_check:
        syslog_read_msgs(args.syslog_check, args.phase)
    elif args.sairedis != "none":
        do_sairedis(args.sairedis)
    elif args.execute_from_file:
        execute_from_file(args.execute_from_file)
    elif args.set_mgmt_ip:
        mgmt_ip_setting(args.set_mgmt_ip, args.ip_addr_mask, args.gw_addr)
    elif args.fetch_core_files:
        fetch_core_files()
        if args.fetch_core_files == "collect_kdump":
            fetch_kdump_files()
    elif args.get_tech_support:
        get_tech_support()
    elif args.init_clean:
        init_clean(args.init_clean)
    elif args.update_reserved_ports:
        update_reserved_ports(args.update_reserved_ports)
    elif args.port_defaults:
        set_port_defaults(args.breakout, args.speed, args.port_init_wait, args.poll_for_ports)
    elif args.dump_click_cmds:
        dump_click_cmds()
    elif args.config_reload:
        config_reload(args.config_reload, args.port_init_wait, args.poll_for_ports)
    elif args.wait_for_ports:
        wait_for_ports(args.port_init_wait, args.poll_for_ports)
    elif args.config_profile:
        apply_config_profile(args.config_profile)
    else:
       print("Error: Invalid/Unknown arguments provided for the script.")
