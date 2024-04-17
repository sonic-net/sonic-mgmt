#!/usr/bin/env python3

import logging
import os
import sys
import paramiko
import glob
import re
import yaml
import jinja2

from functools import lru_cache

from tests.common.connections.console_host import ConsoleHost
from paramiko.ssh_exception import AuthenticationException
from constants import RC_SSH_FAILED, RC_PASSWORD_FAILED

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, "../.."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

logger = logging.getLogger(__name__)


@lru_cache
def creds_on_dut(sonichost):
    groups = sonichost.im.get_host(sonichost.hostname).get_vars()['group_names']
    groups.append("fanout")
    logger.info("dut {} belongs to groups {}".format(sonichost.hostname, groups))
    exclude_regex_patterns = [
        r'topo_.*\.yml',
        r'breakout_speed\.yml',
        r'lag_fanout_ports_test_vars\.yml',
        r'qos\.yml',
        r'sku-sensors-data\.yml',
        r'mux_simulator_http_port_map\.yml'
    ]
    files = glob.glob("group_vars/all/*.yml")
    files += glob.glob("vars/*.yml")
    for group in groups:
        files += glob.glob("group_vars/{}/*.yml".format(group))
    filtered_files = [
        f for f in files if not re.search('|'.join(exclude_regex_patterns), f)
    ]

    creds = {}
    for f in filtered_files:
        with open(f) as stream:
            v = yaml.safe_load(stream)
            if v is not None:
                creds.update(v)
            else:
                logger.info("skip empty var file {}".format(f))

    cred_vars = [
        "sonicadmin_user",
        "sonicadmin_password",
        "docker_registry_host",
        "docker_registry_username",
        "docker_registry_password",
        "public_docker_registry_host"
    ]

    hostvars = sonichost.vm._hostvars[sonichost.hostname]

    for cred_var in cred_vars:
        if cred_var in creds:
            creds[cred_var] = jinja2.Template(creds[cred_var]).render(**hostvars)

    if "console_login" not in list(hostvars.keys()):
        console_login_creds = {}
    else:
        console_login_creds = hostvars["console_login"]

    creds["console_user"] = {}
    creds["console_password"] = {}
    for k, v in list(console_login_creds.items()):
        creds["console_user"][k] = v["user"]
        creds["console_password"][k] = v["passwd"]
    return creds


def get_console_info(sonichost, conn_graph_facts):
    console_host = conn_graph_facts['device_console_info'][sonichost.hostname]['ManagementIp']
    console_port = conn_graph_facts['device_console_link'][sonichost.hostname]['ConsolePort']['peerport']
    console_type = conn_graph_facts['device_console_link'][sonichost.hostname]['ConsolePort']['type']

    return console_host, console_port, console_type


def get_ssh_info(sonichost):
    creds = creds_on_dut(sonichost)
    sonic_username = creds['sonicadmin_user']
    sonicadmin_alt_password = sonichost.vm.get_vars(
        host=sonichost.im.get_hosts(pattern='sonic')[0]).get("ansible_altpassword")
    sonic_password = [creds['sonicadmin_password'], sonicadmin_alt_password]
    sonic_ip = sonichost.im.get_host(sonichost.hostname).vars['ansible_host']
    return sonic_username, sonic_password, sonic_ip


def duthost_console(sonichost, conn_graph_facts):
    console_host, console_port, console_type = get_console_info(sonichost, conn_graph_facts)
    console_type = "console_" + console_type
    if "/" in console_host:
        console_host = console_host.split("/")[0]

    # console password and sonic_password are lists, which may contain more than one password
    sonicadmin_alt_password = sonichost.vm.get_vars(
        host=sonichost.im.get_hosts(pattern='sonic')[0]).get("ansible_altpassword")
    creds = creds_on_dut(sonichost)

    host = ConsoleHost(console_type=console_type,
                       console_host=console_host,
                       console_port=console_port,
                       sonic_username=creds['sonicadmin_user'],
                       sonic_password=[creds['sonicadmin_password'], sonicadmin_alt_password],
                       console_username=creds['console_user'][console_type],
                       console_password=creds['console_password'][console_type])

    return host


def duthost_ssh(sonichost):
    sonic_username, sonic_passwords, sonic_ip = get_ssh_info(sonichost)
    for password in sonic_passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(sonic_ip, username=sonic_username, password=password,
                        allow_agent=False, look_for_keys=False, timeout=10)
            ssh.close()
            return sonic_username, password, sonic_ip
        except AuthenticationException:
            continue
        # Errors such like timeout, connection fails
        except Exception as e:
            logger.info("Cannot access DUT {} via ssh, error: {}".format(sonichost.hostname, e))
            return RC_SSH_FAILED
    return RC_PASSWORD_FAILED
