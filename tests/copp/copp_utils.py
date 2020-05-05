"""
    Helpful utilities for writing tests for the COPP feature.

    Todo:
        Refactor ptfadapter so it can be leveraged in these test cases.
"""

DEFAULT_NN_TARGET_PORT = 3

_REMOVE_IP_SCRIPT = "scripts/remove_ip.sh"
_ADD_IP_SCRIPT = "scripts/add_ip.sh"
_UPDATE_COPP_SCRIPT = "copp/scripts/update_copp_config.py"

_BASE_COPP_CONFIG = "/tmp/00-copp.config.json"
_SWSS_COPP_CONFIG = "swss:/etc/swss/config.d/00-copp.config.json"
_TEMP_COPP_CONFIG = "/tmp/copp_config.json"

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

    dut.command("docker cp {} {}".format(_SWSS_COPP_CONFIG, _BASE_COPP_CONFIG))
    dut.script(cmd="{} {} {} {}".format(_UPDATE_COPP_SCRIPT, pps_limit,
                                        _BASE_COPP_CONFIG, _TEMP_COPP_CONFIG))
    dut.command("docker cp {} {}".format(_TEMP_COPP_CONFIG, _SWSS_COPP_CONFIG))

def restore_policer(dut):
    """
        Reloads the default COPP configuration in the SWSS container.

        Notes:
            This method should only be used after limit_policer.

            The SWSS container must be restarted for the config change to take effect.
    """
    dut.command("docker cp {} {}".format(_BASE_COPP_CONFIG, _SWSS_COPP_CONFIG))

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
    ptf.host.options['variable_manager'].extra_vars.update(facts)
    ptf.template(src=_PTF_NN_TEMPLATE, dest=_PTF_NN_DEST)

    ptf.supervisorctl(name="ptf_nn_agent", state="restarted")

    ptf.copy(src="ptftests", dest="/root")

def restore_ptf(ptf):
    """
        Restores the PTF and the NN agent to default settings.

        Args:
            ptf (PTFHost): The target PTF.
    """

    ptf.script(cmd=_REMOVE_IP_SCRIPT)

    facts = {"nn_target_port": DEFAULT_NN_TARGET_PORT}
    ptf.host.options['variable_manager'].extra_vars.update(facts)

    ptf.template(src=_PTF_NN_TEMPLATE, dest=_PTF_NN_DEST)

    ptf.supervisorctl(name="ptf_nn_agent", state="restarted")

def configure_syncd(dut, nn_target_port):
    """
        Configures syncd to run the NN agent on the specified port.

        Note:
            The DUT must be running an RPC syncd image in order for the
            NN agent to be available.

        Args:
            dut (SonicHost): The target device.
            nn_target_port (int): The port to run NN agent on.
    """

    facts = {"nn_target_port": nn_target_port,
             "nn_target_interface": _map_port_number_to_interface(dut, nn_target_port)}
    dut.host.options['variable_manager'].extra_vars.update(facts)

    dut.template(src=_SYNCD_NN_TEMPLATE, dest=_SYNCD_NN_DEST)
    dut.command("docker cp {} syncd:/etc/supervisor/conf.d/".format(_SYNCD_NN_DEST))

    dut.command("docker exec syncd supervisorctl reread")
    dut.command("docker exec syncd supervisorctl update")

def _map_port_number_to_interface(dut, nn_target_port):
    """
        Retrieves the correct interface for a given port number.
    """

    interfaces = dut.command("portstat")["stdout_lines"][2:]
    return interfaces[nn_target_port].split()[0]
