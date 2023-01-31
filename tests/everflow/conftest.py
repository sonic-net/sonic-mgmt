import pytest
import logging


@pytest.fixture(autouse=True, scope="module")
def setup_recycle_port(duthosts, tbinfo):
    """Setup recycle port ip address on t2 topo"""
    rec_intf = {}
    if "t2" in tbinfo['topo']['name']:
        for duthost in duthosts.frontend_nodes:
            rec_intf[duthost.hostname] = {}
            for asic in duthost.asics:
                output = duthost.command("show ip interfaces {} -d all".format(asic.cli_ns_option))['stdout_lines']
                if 'Ethernet-Rec' not in output:
                    rec_intf[duthost.hostname][asic.namespace] = 1
                    cmd = "sudo config interface {ns} ip add Ethernet-Rec{rec} 1.1.1.{an}/32".format(
                        ns=asic.cli_ns_option,
                        rec=asic.asic_index,
                        an=asic.asic_index + 1)
                    logging.info(cmd)
                    duthost.command(cmd)
            duthost.command("sudo config save -y")
    yield
    if "t2" in tbinfo['topo']['name']:
        for duthost in duthosts.frontend_nodes:
            for asic in duthost.asics:
                if rec_intf[duthost.hostname][asic.namespace]:
                    cmd = "sudo config interface {ns} ip remove Ethernet-Rec{rec} 1.1.1.{an}/32".format(
                        ns=asic.cli_ns_option,
                        rec=asic.asic_index,
                        an=asic.asic_index + 1)
                    logging.info(cmd)
                    duthost.command(cmd)
            duthost.command("sudo config save -y")

