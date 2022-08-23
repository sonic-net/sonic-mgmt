"""
    Helpful utilities for writing tests for the COPP feature.

    Todo:
        Refactor ptfadapter so it can be leveraged in these test cases.
"""
import re
import logging
import json

from tests.common.config_reload import config_reload

DEFAULT_NN_TARGET_PORT = 3

_REMOVE_IP_SCRIPT = "scripts/remove_ip.sh"
_ADD_IP_SCRIPT = "scripts/add_ip.sh"
_ADD_IP_BACKEND_SCRIPT = "scripts/add_ip_backend.sh"
_UPDATE_COPP_SCRIPT = "copp/scripts/update_copp_config.py"

_BASE_COPP_CONFIG = "/tmp/base_copp_config.json"
_APP_DB_COPP_CONFIG = ":/etc/swss/config.d/00-copp.config.json"
_CONFIG_DB_COPP_CONFIG = "/etc/sonic/copp_cfg.json"
_TEMP_COPP_CONFIG = "/tmp/copp_config.json"
_TEMP_COPP_TEMPLATE = "/tmp/copp.json.j2"
_COPP_TEMPLATE_PATH = "/usr/share/sonic/templates/copp.json.j2"
_SWSS_COPP_TEMPLATE = ":" + _COPP_TEMPLATE_PATH
_DEFAULT_COPP_TEMPLATE = "/usr/share/sonic/templates/copp_cfg.j2"
_BASE_COPP_TEMPLATE = "/home/admin/copp_cfg_base.j2"

_PTF_NN_TEMPLATE = "templates/ptf_nn_agent.conf.ptf.j2"
_PTF_NN_DEST = "/etc/supervisor/conf.d/ptf_nn_agent.conf"

_SYNCD_NN_TEMPLATE = "templates/ptf_nn_agent.conf.dut.j2"
_SYNCD_NN_DEST = "/tmp/ptf_nn_agent.conf"
_SYNCD_NN_FILE = "ptf_nn_agent.conf"

_CONFIG_DB = "/etc/sonic/config_db.json"
_TEMP_CONFIG_DB = "/home/admin/config_db_copp_backup.json"


def limit_policer(dut, pps_limit, nn_target_namespace):
    """
        Updates the COPP configuration in the SWSS container to respect a given rate limit.

        Note:
            The SWSS container must be restarted for the config change to take effect.

        Args:
            dut (SonicHost): The target device.
            pps_limit (int): The rate limit for COPP to enforce on ALL trap groups.
    """

    asichost = dut.asic_instance_from_namespace(nn_target_namespace)

    swss_docker_name = asichost.get_docker_name("swss")

    if "201811" in dut.os_version or "201911" in dut.os_version:
        dut.command("docker cp {} {}".format(swss_docker_name + _APP_DB_COPP_CONFIG, _BASE_COPP_CONFIG))
        config_format = "app_db"
    else:
        dut.command("cp {} {}".format(_DEFAULT_COPP_TEMPLATE, _BASE_COPP_TEMPLATE))
        dut.command("cp {} {}".format(_CONFIG_DB_COPP_CONFIG, _BASE_COPP_CONFIG))
        config_format = "config_db"

    dut.script(
        cmd="{} {} {} {} {}".format(_UPDATE_COPP_SCRIPT,
                                    pps_limit,
                                    _BASE_COPP_CONFIG,
                                    _TEMP_COPP_CONFIG,
                                    config_format)
    )

    if config_format == "app_db":
        dut.command("docker cp {} {}".format(_TEMP_COPP_CONFIG, swss_docker_name + _APP_DB_COPP_CONFIG))

        # As copp config is regenerated each time swss starts need to replace the template with
        # config updated above. But before doing that need store the original template in a
        # temporary file for restore after test.
        dut.command("docker cp {} {}".format(swss_docker_name + _SWSS_COPP_TEMPLATE, _TEMP_COPP_TEMPLATE))
        dut.command("docker cp {} {}".format(_TEMP_COPP_CONFIG, swss_docker_name + _SWSS_COPP_TEMPLATE))
    else:
        dut.command("cp {} {}".format(_TEMP_COPP_CONFIG, _DEFAULT_COPP_TEMPLATE))

def restore_policer(dut, nn_target_namespace):
    """
        Reloads the default COPP configuration in the SWSS container.

        Notes:
            This method should only be used after limit_policer.

            The SWSS container must be restarted for the config change to take effect.
    """
    asichost = dut.asic_instance_from_namespace(nn_target_namespace)

    swss_docker_name = asichost.get_docker_name("swss")

    # Restore the copp template in swss
    if "201811" in dut.os_version or "201911" in dut.os_version:
        dut.command("docker cp {} {}".format(_BASE_COPP_CONFIG, swss_docker_name + _APP_DB_COPP_CONFIG))
        dut.command("docker cp {} {}".format(_TEMP_COPP_TEMPLATE, swss_docker_name + _SWSS_COPP_TEMPLATE))
    else:
        dut.command("cp {} {}".format(_BASE_COPP_TEMPLATE, _DEFAULT_COPP_TEMPLATE))


def configure_ptf(ptf, test_params, is_backend_topology=False):
    """
        Configures the PTF to run the NN agent on the specified port.

        Args:
            ptf (PTFHost): The target PTF.
            test_params (_COPPTestParameters): test parameters set.
            is_backend_topology (bool): Whether it's a backend topology testbed.
    """

    ptf.script(cmd=_REMOVE_IP_SCRIPT)
    if is_backend_topology:
        ip_command = "ip address add %s/31 dev \"eth%s.%s\"" % (test_params.myip, test_params.nn_target_port, test_params.nn_target_vlanid)
    else:
        ip_command = "ip address add %s/31 dev eth%s" % (test_params.myip, test_params.nn_target_port)

    logging.debug("ip_command is: %s" % ip_command)
    ptf.command(ip_command)

    facts = {
        "nn_target_port": test_params.nn_target_port,
        "nn_target_vlanid": test_params.nn_target_vlanid
    }
    ptf.host.options["variable_manager"].extra_vars.update(facts)
    ptf.template(src=_PTF_NN_TEMPLATE, dest=_PTF_NN_DEST)

    ptf.supervisorctl(name="ptf_nn_agent", state="restarted")

def restore_ptf(ptf):
    """
        Restores the PTF and the NN agent to default settings.

        Args:
            ptf (PTFHost): The target PTF.
    """

    ptf.script(cmd=_REMOVE_IP_SCRIPT)

    facts = {
        "nn_target_port": DEFAULT_NN_TARGET_PORT,
        "nn_target_vlanid": None
    }
    ptf.host.options["variable_manager"].extra_vars.update(facts)

    ptf.template(src=_PTF_NN_TEMPLATE, dest=_PTF_NN_DEST)

    ptf.supervisorctl(name="ptf_nn_agent", state="restarted")

def configure_syncd(dut, nn_target_port, nn_target_interface, nn_target_namespace, nn_target_vlanid, swap_syncd, creds):
    """
        Configures syncd to run the NN agent on the specified port.

        Note:
            The DUT must be running an RPC syncd image in order for the
            NN agent to be available.

        Args:
            dut (SonicHost): The target device.
            nn_target_port (int): The port to run NN agent on.
            nn_target_interface (str): The Interface remote NN agents listen to
            nn_target_namespace (str): The namespace remote NN agents listens
            nn_target_vlanid (str): The vlan id of the port to run NN agent on
            creds (dict): Credential information according to the dut inventory
    """

    facts = {
        "nn_target_port": nn_target_port,
        "nn_target_interface": nn_target_interface,
        "nn_target_vlanid": nn_target_vlanid
    }
    dut.host.options["variable_manager"].extra_vars.update(facts)

    asichost = dut.asic_instance_from_namespace(nn_target_namespace)

    syncd_docker_name = asichost.get_docker_name("syncd")

    if not swap_syncd:
        _install_nano(dut, creds, syncd_docker_name)

    dut.template(src=_SYNCD_NN_TEMPLATE, dest=_SYNCD_NN_DEST)

    dut.command("docker cp {} {}:/etc/supervisor/conf.d/".format(_SYNCD_NN_DEST, syncd_docker_name))

    dut.command("docker exec {} supervisorctl reread".format(syncd_docker_name))
    dut.command("docker exec {} supervisorctl update".format(syncd_docker_name))

def restore_syncd(dut, nn_target_namespace):
    asichost = dut.asic_instance_from_namespace(nn_target_namespace)

    syncd_docker_name = asichost.get_docker_name("syncd")

    dut.command("docker exec {} rm -rf /etc/supervisor/conf.d/{}".format(syncd_docker_name, _SYNCD_NN_FILE))
    dut.command("docker exec {} supervisorctl reread".format(syncd_docker_name))
    dut.command("docker exec {} supervisorctl update".format(syncd_docker_name))


def _install_nano(dut, creds,  syncd_docker_name):
    """
        Install nanomsg package to syncd container.

        Args:
            dut (SonicHost): The target device.
            creds (dict): Credential information according to the dut inventory
    """
    output = dut.command("docker exec {} bash -c '[ -d /usr/local/include/nanomsg ] && [ -d /opt/ptf ] || echo copp'".format(syncd_docker_name))

    if output["stdout"] == "copp":
        http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
        https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
        check_cmd = "docker exec -i {} bash -c 'cat /etc/os-release'".format(syncd_docker_name)

        if "bullseye" in dut.shell(check_cmd)['stdout'].lower():
            cmd = '''docker exec -e http_proxy={} -e https_proxy={} {} bash -c " \
                    rm -rf /var/lib/apt/lists/* \
                    && apt-get update \
                    && apt-get install -y python3-pip build-essential libssl-dev libffi-dev python3-dev python-setuptools wget cmake python-is-python3 \
                    && wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz \
                    && tar xzf 1.0.0.tar.gz && cd nanomsg-1.0.0 \
                    && mkdir -p build && cmake . && make install && ldconfig && cd .. && rm -rf nanomsg-1.0.0 \
                    && rm -f 1.0.0.tar.gz && pip3 install cffi && pip3 install --upgrade cffi && pip3 install nnpy \
                    && mkdir -p /opt && cd /opt && wget https://raw.githubusercontent.com/p4lang/ptf/master/ptf_nn/ptf_nn_agent.py \
                    && mkdir ptf && cd ptf && wget https://raw.githubusercontent.com/p4lang/ptf/master/src/ptf/afpacket.py && touch __init__.py \
                    " '''.format(http_proxy, https_proxy, syncd_docker_name)
        else:
            cmd = '''docker exec -e http_proxy={} -e https_proxy={} {} bash -c " \
                    rm -rf /var/lib/apt/lists/* \
                    && apt-get update \
                    && apt-get install -y python-pip build-essential libssl-dev libffi-dev python-dev python-setuptools wget cmake \
                    && wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz \
                    && tar xzf 1.0.0.tar.gz && cd nanomsg-1.0.0 \
                    && mkdir -p build && cmake . && make install && ldconfig && cd .. && rm -rf nanomsg-1.0.0 \
                    && rm -f 1.0.0.tar.gz && pip2 install cffi==1.7.0 && pip2 install --upgrade cffi==1.7.0 && pip2 install nnpy \
                    && mkdir -p /opt && cd /opt && wget https://raw.githubusercontent.com/p4lang/ptf/master/ptf_nn/ptf_nn_agent.py \
                    && mkdir ptf && cd ptf && wget https://raw.githubusercontent.com/p4lang/ptf/master/src/ptf/afpacket.py && touch __init__.py \
                    " '''.format(http_proxy, https_proxy, syncd_docker_name)

        try:
            # Stop bgp sessions
            dut.command("sudo config feature autorestart bgp disabled")
            dut.command("sudo config feature state bgp disabled")
            dut.command(cmd)
        finally:
            dut.command("sudo config feature state bgp enabled")
            dut.command("sudo config feature autorestart bgp enabled")

def _map_port_number_to_interface(dut, nn_target_port):
    """
        Retrieves the correct interface for a given port number.
    """

    interfaces = dut.command("portstat")["stdout_lines"][2:]
    return interfaces[nn_target_port].split()[0]

def _get_http_and_https_proxy_ip(creds):
    """
       Get the http and https proxy ip.

       Args:
           creds (dict): Credential information according to the dut inventory
    """

    return (re.findall(r'[0-9]+(?:\.[0-9]+){3}', creds.get('proxy_env', {}).get('http_proxy', ''))[0],
            re.findall(r'[0-9]+(?:\.[0-9]+){3}', creds.get('proxy_env', {}).get('https_proxy', ''))[0])


def configure_always_enabled_for_trap(dut, trap_id, always_enabled):
    """
    Configure the always_enabled to true or false for the specified trap id.
    Args:
        dut (SonicHost): The target device
        trap_id (str): The trap id (e.g. bgp)
        always_enabled (str): true or false
    """
    copp_trap_config_json = "/tmp/copp_{}.json".format(trap_id)
    cmd_copp_trap_always_enabled_config = """
cat << EOF >  %s
{
   "COPP_TRAP": {
       "%s": {
       "always_enabled": "%s"
       }
    }
}
EOF
""" % (copp_trap_config_json, trap_id, always_enabled)

    dut.shell(cmd_copp_trap_always_enabled_config)
    dut.command("sudo config load {} -y".format(copp_trap_config_json))


def get_config_db_json_obj(dut):
    """
    Get config_db content from dut
    Args:
        dut (SonicHost): The target device
    """
    config_db_json = dut.shell("sudo sonic-cfggen -d --print-data")["stdout"]
    return json.loads(config_db_json)


def remove_feature_entry(dut, feature_name):
    """
    Remove feature entry from dut
    Args:
        dut (SonicHost): The target device
        feature_name (str): feature name (e.g bgp)
    """
    dut.command('redis-cli -n 4 del "FEATURE|{}"'.format(feature_name))


def disable_feature_entry(dut, feature_name):
    """
    Disable feature entry on dut
    Args:
        dut (SonicHost): The target device
        feature_name (str): feature name (e.g bgp)
    """
    dut.command(' sudo config feature state {} disabled'.format(feature_name))


def enable_feature_entry(dut, feature_name):
    """
    Enabled feature entry dut
    Args:
        dut (SonicHost): The target device
        feature_name (str): feature name (e.g bgp)
    """
    dut.command(' sudo config feature state {} enabled'.format(feature_name))


def backup_config_db(dut):
    """
    Backup config db to /home/admin/
    Args:
        dut (SonicHost): The target device
    """
    dut.command("sudo cp {} {}".format(_CONFIG_DB, _TEMP_CONFIG_DB))


def restore_config_db(dut):
    """
    Restore config db
    Args:
        dut (SonicHost): The target device
    """
    dut.command("sudo cp {} {}".format(_TEMP_CONFIG_DB, _CONFIG_DB))
    dut.command("sudo rm -f {}".format(_TEMP_CONFIG_DB))
    config_reload(dut)


def uninstall_trap(dut, feature_name, trap_id):
    """
    Uninstall trap by disabling feature and set always_enable to false

    Args:
        dut (SonicHost): The target device
        feature_name (str): feature name corresponding to the trap
        trap_id (str): trap id
    """
    disable_feature_entry(dut, feature_name)
    configure_always_enabled_for_trap(dut, trap_id, "false")


def verify_always_enable_value(dut, trap_id, always_enable_value):
    """
    Verify the value of always_enable for the specified trap is expected one

    Args:
        dut (SonicHost): The target device
        trap_id (str): trap id
        always_enable_value (str): true or false
    """
    config_db_json = get_config_db_json_obj(dut)
    assert config_db_json["COPP_TRAP"][trap_id]["always_enabled"] == always_enable_value, \
        "The value of always_enable not match. The expected value is:{}, the actual value is :{}".format(
            always_enable_value, config_db_json["COPP_TRAP"][trap_id]["always_enabled"])


def install_trap(dut, feature_name):
    """
    Install trap by enabling feature status
    Args:
        dut (SonicHost): The target device
        feature_name (str): feature name
    """
    enable_feature_entry(dut, feature_name)
