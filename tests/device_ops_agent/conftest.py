import pytest
import logging
import os

logger = logging.getLogger(__name__)

GEN_CERT_SCRIPT = os.path.join(
    os.path.dirname(__file__), "scripts", "gen-server-cert.sh"
)
REMOTE_SCRIPT_PATH = "/tmp/gen-server-cert.sh"
CONTAINER_NAME = "device-ops-agent"


def pytest_addoption(parser):
    parser.addoption(
        "--device-ops-agent-image",
        action="store",
        default=None,
        help="Full image URL for device-ops-agent"
    )


@pytest.fixture(scope="module", autouse=True)
def generate_device_ops_agent_certs(
    duthosts, enum_rand_one_per_hwsku_hostname
):
    """Generate TLS certs for device-ops-agent on the DUT.

    Copies gen-server-cert.sh to the DUT and runs it to mint a fresh
    server certificate signed by the on-disk dsmsroot CA. Certs are
    written to /etc/sonic/telemetry which is already bind-mounted into
    the container.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logger.info("Copying gen-server-cert.sh to DUT")
    duthost.copy(src=GEN_CERT_SCRIPT, dest=REMOTE_SCRIPT_PATH, mode="0755")

    logger.info("Running gen-server-cert.sh on DUT")
    cert_result = duthost.shell(
        "sudo bash {}".format(REMOTE_SCRIPT_PATH),
        module_ignore_errors=True,
    )
    if cert_result.get("rc", 1) != 0:
        pytest.fail(
            "gen-server-cert.sh failed: {}".format(
                cert_result.get("stderr", "")
            )
        )
    logger.info("Certs generated: %s", cert_result.get("stdout", ""))

    yield
