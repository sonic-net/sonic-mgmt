import pytest

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

RADV_CONF_FILE = '/etc/radvd.conf'


def test_radv_managed_flag(duthosts, rand_one_dut_hostname):

    duthost = duthost = duthosts[rand_one_dut_hostname]
    cmd = "grep -q 'AdvManagedFlag on' {}; echo $?".format(RADV_CONF_FILE)
    output = duthost.shell("docker exec radv {}".format(cmd))["stdout"]

    assert(output == '0')



def test_radv_other_flag(duthosts, rand_one_dut_hostname):

    duthost = duthost = duthosts[rand_one_dut_hostname]
    cmd = "grep -q 'AdvOtherConfigFlag off' {}; echo $?".format(RADV_CONF_FILE)
    output = duthost.shell("docker exec radv {}".format(cmd))["stdout"]

    assert(output == '0')

