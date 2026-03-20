import logging
import pytest

from tests.acms.helper import container_name

from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

DOCKER_EXEC_CMD = "docker exec {} bash -c "
CA_PEM = "/etc/sonic/credentials/AME_ROOT_CERTIFICATE.pem"


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)

    yield

    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)


def test_acms_multi_root_ca_pem(duthosts,
                                enum_rand_one_per_hwsku_hostname,
                                setup_ca_pem_cert):
    """
    Validates the Root CA PEM bundle has at least one unexpired cert
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    cmd = f"""while :; do out=$(openssl x509 -noout -checkend 0 2>/dev/null || true); [ -z "$out" ] && break; \
              printf "%s\n" "$out"; done < {CA_PEM}"""
    output = duthost.shell(cmd)["stdout"]

    pytest_assert("Certificate will not expire" in output, f"FAIL no unexpired certificate found in {CA_PEM}")
