import pytest
import ipaddress
import utils
import pdb


pytestmark = [
    pytest.mark.topology("any"),
    # pytest.mark.disable_loganalyzer
]


def test_static_routes(duthost):
    add_command = "sudo config interface ip add Ethernet0 {}/{}".format(utils.gw_ip, utils.mask)
    duthost.shell(add_command)
    utils.config_routes(duthost, utils.num_dest)
    remove_command = "sudo config interface ip remove Ethernet0 {}/{}".format(utils.gw_ip, utils.mask)
    duthost.shell(remove_command)





