"""
    Helpful utilities for writing tests for the COPP feature.

    Todo:
        Refactor ptfadapter so it can be leveraged in these test cases.
"""

DEFAULT_NN_TARGET_PORT = 3

_REMOVE_IP_SCRIPT = "scripts/remove_ip.sh"
_ADD_IP_SCRIPT = "scripts/add_ip.sh"
_UPDATE_COPP_SCRIPT = "copp/scripts/update_copp_config.py"

_BASE_COPP_CONFIG = "/tmp/base_copp_config.json"
_APP_DB_COPP_CONFIG = "swss:/etc/swss/config.d/00-copp.config.json"
_CONFIG_DB_COPP_CONFIG = "/etc/sonic/copp_cfg.json"
_TEMP_COPP_CONFIG = "/tmp/copp_config.json"
_TEMP_COPP_TEMPLATE = "/tmp/copp.json.j2"
_COPP_TEMPLATE_PATH = "/usr/share/sonic/templates/copp.json.j2"
_SWSS_COPP_TEMPLATE = "swss:" + _COPP_TEMPLATE_PATH

_PTF_NN_TEMPLATE = "templates/ptf_nn_agent.conf.ptf.j2"
_PTF_NN_DEST = "/etc/supervisor/conf.d/ptf_nn_agent.conf"

_SYNCD_NN_TEMPLATE = "templates/ptf_nn_agent.conf.dut.j2"
_SYNCD_NN_DEST = "/tmp/ptf_nn_agent.conf"

def limit_policer(dut, pps_limit):
    """
        Updates the COPP configuration in the SWSS container to respect a given rate limit.

        Note:
            The SWSS container must be restarted for the config change to take effect.

        Args:
            dut (SonicHost): The target device.
            pps_limit (int): The rate limit for COPP to enforce on ALL trap groups.
    """

    if "201811" in dut.os_version or "201911" in dut.os_version:
        dut.command("docker cp {} {}".format(_APP_DB_COPP_CONFIG, _BASE_COPP_CONFIG))
        config_format = "app_db"
    else:
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
        dut.command("docker cp {} {}".format(_TEMP_COPP_CONFIG, _APP_DB_COPP_CONFIG))

        # As copp config is regenerated each time swss starts need to replace the template with
        # config updated above. But before doing that need store the original template in a
        # temporary file for restore after test.
        dut.command("docker cp {} {}".format(_SWSS_COPP_TEMPLATE, _TEMP_COPP_TEMPLATE))
        dut.command("docker cp {} {}".format(_TEMP_COPP_CONFIG, _SWSS_COPP_TEMPLATE))
    else:
        dut.command("cp {} {}".format(_TEMP_COPP_CONFIG, _CONFIG_DB_COPP_CONFIG))

def restore_policer(dut):
    """
        Reloads the default COPP configuration in the SWSS container.

        Notes:
            This method should only be used after limit_policer.

            The SWSS container must be restarted for the config change to take effect.
    """
    # Restore the copp template in swss
    if "201811" in dut.os_version or "201911" in dut.os_version:
        dut.command("docker cp {} {}".format(_BASE_COPP_CONFIG, _APP_DB_COPP_CONFIG))
        dut.command("docker cp {} {}".format(_TEMP_COPP_TEMPLATE, _SWSS_COPP_TEMPLATE))
    else:
        dut.command("cp {} {}".format(_BASE_COPP_CONFIG, _CONFIG_DB_COPP_CONFIG))

def configure_ptf(ptf, nn_target_port):
    """
        Configures the PTF to run the NN agent on the specified port.

        Args:
            ptf (PTFHost): The target PTF.
            nn_target_port (int): The port to run NN agent on.
    """

    ptf.script(cmd=_REMOVE_IP_SCRIPT)
    ptf.script(cmd=_ADD_IP_SCRIPT)

    facts = {"nn_target_port": nn_target_port}
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

    facts = {"nn_target_port": DEFAULT_NN_TARGET_PORT}
    ptf.host.options["variable_manager"].extra_vars.update(facts)

    ptf.template(src=_PTF_NN_TEMPLATE, dest=_PTF_NN_DEST)

    ptf.supervisorctl(name="ptf_nn_agent", state="restarted")

def configure_syncd(dut, nn_target_port, nn_target_interface, creds):
    """
        Configures syncd to run the NN agent on the specified port.

        Note:
            The DUT must be running an RPC syncd image in order for the
            NN agent to be available.

        Args:
            dut (SonicHost): The target device.
            nn_target_port (int): The port to run NN agent on.
            nn_target_interface (str): The Interface remote NN agents listens.
            creds (dict): Credential information according to the dut inventory
    """

    facts = {"nn_target_port": nn_target_port, "nn_target_interface": nn_target_interface}
    dut.host.options["variable_manager"].extra_vars.update(facts)

    _install_nano(dut, creds)

    dut.template(src=_SYNCD_NN_TEMPLATE, dest=_SYNCD_NN_DEST)
    dut.command("docker cp {} syncd:/etc/supervisor/conf.d/".format(_SYNCD_NN_DEST))

    dut.command("docker exec syncd supervisorctl reread")
    dut.command("docker exec syncd supervisorctl update")

def _install_nano(dut, creds):
    """
        Install nanomsg package to syncd container.

        Args:
            dut (SonicHost): The target device.
            creds (dict): Credential information according to the dut inventory
    """

    output = dut.command("docker exec syncd bash -c '[ -d /usr/local/include/nanomsg ] || echo copp'")

    if output["stdout"] == "copp":
        http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
        https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')

        cmd = '''docker exec -e http_proxy={} -e https_proxy={} syncd bash -c " \
                rm -rf /var/lib/apt/lists/* \
                && apt-get update \
                && apt-get install -y python-pip build-essential libssl-dev python-dev python-setuptools wget cmake \
                && wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz \
                && tar xzf 1.0.0.tar.gz && cd nanomsg-1.0.0 \
                && mkdir -p build && cmake . && make install && ldconfig && cd .. && rm -rf nanomsg-1.0.0 \
                && rm -f 1.0.0.tar.gz && pip2 install cffi==1.7.0 && pip2 install --upgrade cffi==1.7.0 && pip2 install nnpy \
                && mkdir -p /opt && cd /opt && wget https://raw.githubusercontent.com/p4lang/ptf/master/ptf_nn/ptf_nn_agent.py \
                && mkdir ptf && cd ptf && wget https://raw.githubusercontent.com/p4lang/ptf/master/src/ptf/afpacket.py && touch __init__.py \
                " '''.format(http_proxy, https_proxy)
        dut.command(cmd)

def _map_port_number_to_interface(dut, nn_target_port):
    """
        Retrieves the correct interface for a given port number.
    """

    interfaces = dut.command("portstat")["stdout_lines"][2:]
    return interfaces[nn_target_port].split()[0]
