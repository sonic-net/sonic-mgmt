import pytest
import logging


@pytest.fixture(autouse=True, scope="package")
def setup_recycle_port(duthosts, tbinfo):
    """Setup recycle port ip address on t2 topo"""
    if "t2" not in tbinfo['topo']['name']:
        return
    for duthost in duthosts.frontend_nodes:
        for asic in duthost.asics:
            cmd = "sudo config interface -n {ns} ip add Ethernet-Rec{rec} 1.1.1.{an}/32".format(ns=asic.namespace,
                                                                                                rec=asic.asic_index,
                                                                                                an=asic.asic_index+1)
            logging.info(cmd)
            duthost.command(cmd)
        duthost.command("sudo config save -y")
    yield
    for duthost in duthosts.frontend_nodes:
        for asic in duthost.asics:
            cmd = "sudo config interface -n {ns} ip remove Ethernet-Rec{rec} 1.1.1.{an}/32".format(ns=asic.namespace,
                                                                                                   rec=asic.asic_index,
                                                                                                   an=asic.asic_index+1)
            logging.info(cmd)
            duthost.command(cmd)
        duthost.command("sudo config save -y")
