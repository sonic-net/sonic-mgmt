import logging
import pytest

from tests.acms.helper import container_name
from tests.acms.helper import create_acms_conf
from tests.acms.helper import create_dsms_conf
from tests.acms.helper import generate_pfx_cert
from tests.common.utilities import wait_until
from dateutil import parser


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def check_state_db(duthost):
    dut_command = "sonic-db-cli STATE_DB keys 'ACMS_BOOTSTRAP_CERT|localhost'"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    output = result['stdout'].strip()
    return len(output) != 0


def clean_state_db(duthost):
    dut_command = "sonic-db-cli STATE_DB hdel 'ACMS_BOOTSTRAP_CERT|localhost', region"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sonic-db-cli STATE_DB hdel 'ACMS_BOOTSTRAP_CERT|localhost', date"
    duthost.shell(dut_command, module_ignore_errors=True)


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop bootstrap_monitor" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    clean_state_db(duthost)

    yield

    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    clean_state_db(duthost)


def test_bootstrap_monitor_01(duthosts, rand_one_dut_hostname):
    """
    Test ACMS bootstrap_monitor.py functionality.
    Downloaded bootstrap certificate is newer than current bootstrap certificate
    """
    duthost = duthosts[rand_one_dut_hostname]
    region = "useast"
    client_path = "/var/opt/msft/client/"
    cred_path = "/etc/sonic/credentials/"
    dut_command = "mkdir -p %s" % (client_path + "dsms/sonic-prod/adhocsecrets")
    duthost.shell(dut_command, module_ignore_errors=True)
    create_dsms_conf(duthost, client_path + "dsms.conf")
    create_acms_conf(region, "Public", duthost, client_path + "acms_secrets.ini")
    # Generate the bootstrap certificate will expire in 30 days
    generate_pfx_cert(duthost, "acms", 30)
    int_command = "openssl pkcs12 -in /tmp/acms.pfx -nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date_30 = result['stdout']
    logger.info("The first expire date: " + expire_date_30)
    dut_command = "docker exec %s cp /tmp/acms.pfx %ssonic_acms_bootstrap-%s.pfx" % (container_name, cred_path, region)
    duthost.shell(dut_command, module_ignore_errors=True)
    # Generate the bootstrap certificate will expire in 60 days
    generate_pfx_cert(duthost, "acms", 60)
    int_command = "openssl pkcs12 -in /tmp/acms.pfx -nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date_60 = result['stdout']
    logger.info("The second expire date: " + expire_date_60)
    int_command = "base64 /tmp/acms.pfx > /tmp/acms.b64"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    duthost.shell(dut_command, module_ignore_errors=True)
    # openssl 3.0
    download_cert_path = client_path + "dsms/sonic-prod/adhocsecrets/bootstrap_3_0.10"
    notify_path = client_path + "dsms/sonic-prod/adhocsecrets/bootstrap_3_0.notify"
    dut_command = "docker exec %s cp /tmp/acms.b64 %s" % (container_name, download_cert_path)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "echo -n %s > %s" % (download_cert_path, notify_path)
    duthost.shell(dut_command, module_ignore_errors=True)
    # Start bootstrap_monitor and check result
    dut_command = "docker exec %s supervisorctl start bootstrap_monitor" % (container_name)
    duthost.shell(dut_command, module_ignore_errors=True)
    wait_until(30, 1, 0, check_state_db, duthost)
    dut_command = "sonic-db-cli STATE_DB hget 'ACMS_BOOTSTRAP_CERT|localhost' region"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    db_region = result['stdout']
    assert db_region == region, "Invalid region: " + db_region
    dut_command = "sonic-db-cli STATE_DB hget 'ACMS_BOOTSTRAP_CERT|localhost' date"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    db_date = result['stdout']
    logger.info("db date: " + db_date)
    int_command = "openssl pkcs12 -in %ssonic_acms_bootstrap-%s.pfx " % (cred_path, region)
    int_command += "-nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date = result['stdout']
    logger.info("expire date: " + expire_date)
    assert expire_date == expire_date_60, "Invalid expire date: " + expire_date
    poll_time = parser.parse(expire_date, fuzzy=True)
    assert str(poll_time) == db_date, "ACMS_BOOTSTRAP_CERT date does not match: " + str(poll_time)

def test_bootstrap_monitor_02(duthosts, rand_one_dut_hostname):
    """
    Test ACMS bootstrap_monitor.py functionality.
    Downloaded bootstrap certificate is older than current bootstrap certificate
    """
    duthost = duthosts[rand_one_dut_hostname]
    region = "useast"
    client_path = "/var/opt/msft/client/"
    cred_path = "/etc/sonic/credentials/"
    dut_command = "mkdir -p %s" % (client_path + "dsms/sonic-prod/adhocsecrets")
    duthost.shell(dut_command, module_ignore_errors=True)
    create_dsms_conf(duthost, client_path + "dsms.conf")
    create_acms_conf(region, "Public", duthost, client_path + "acms_secrets.ini")
    # Generate the bootstrap certificate will expire in 60 days
    generate_pfx_cert(duthost, "acms", 60)
    int_command = "openssl pkcs12 -in /tmp/acms.pfx -nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date_60 = result['stdout']
    logger.info("The first expire date: " + expire_date_60)
    dut_command = "docker exec %s cp /tmp/acms.pfx %ssonic_acms_bootstrap-%s.pfx" % (container_name, cred_path, region)
    duthost.shell(dut_command, module_ignore_errors=True)
    # Generate the bootstrap certificate will expire in 30 days
    generate_pfx_cert(duthost, "acms", 30)
    int_command = "openssl pkcs12 -in /tmp/acms.pfx -nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date_30 = result['stdout']
    logger.info("The second expire date: " + expire_date_30)
    int_command = "base64 /tmp/acms.pfx > /tmp/acms.b64"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    duthost.shell(dut_command, module_ignore_errors=True)
    # openssl 3.0
    download_cert_path = client_path + "dsms/sonic-prod/adhocsecrets/bootstrap_3_0.10"
    notify_path = client_path + "dsms/sonic-prod/adhocsecrets/bootstrap_3_0.notify"
    dut_command = "docker exec %s cp /tmp/acms.b64 %s" % (container_name, download_cert_path)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "echo -n %s > %s" % (download_cert_path, notify_path)
    duthost.shell(dut_command, module_ignore_errors=True)
    # Start bootstrap_monitor and check result
    dut_command = "docker exec %s supervisorctl start bootstrap_monitor" % (container_name)
    duthost.shell(dut_command, module_ignore_errors=True)
    wait_until(30, 1, 0, check_state_db, duthost)
    dut_command = "sonic-db-cli STATE_DB hget 'ACMS_BOOTSTRAP_CERT|localhost' region"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    db_region = result['stdout']
    assert db_region == region, "Invalid region: " + db_region
    dut_command = "sonic-db-cli STATE_DB hget 'ACMS_BOOTSTRAP_CERT|localhost' date"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    db_date = result['stdout']
    logger.info("db date: " + db_date)
    int_command = "openssl pkcs12 -in %ssonic_acms_bootstrap-%s.pfx " % (cred_path, region)
    int_command += "-nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date = result['stdout']
    logger.info("expire date: " + expire_date)
    assert expire_date == expire_date_60, "Invalid expire date: " + expire_date
    poll_time = parser.parse(expire_date, fuzzy=True)
    assert str(poll_time) == db_date, "ACMS_BOOTSTRAP_CERT date does not match: " + str(poll_time)

def test_bootstrap_monitor_03(duthosts, rand_one_dut_hostname):
    """
    Test ACMS bootstrap_monitor.py functionality.
    There's no downloaded bootstrap certificate
    """
    duthost = duthosts[rand_one_dut_hostname]
    region = "useast"
    client_path = "/var/opt/msft/client/"
    cred_path = "/etc/sonic/credentials/"
    dut_command = "mkdir -p %s" % (client_path + "dsms/sonic-prod/adhocsecrets")
    duthost.shell(dut_command, module_ignore_errors=True)
    create_dsms_conf(duthost, client_path + "dsms.conf")
    create_acms_conf(region, "Public", duthost, client_path + "acms_secrets.ini")
    # Generate the bootstrap certificate will expire in 30 days
    generate_pfx_cert(duthost, "acms", 30)
    int_command = "openssl pkcs12 -in /tmp/acms.pfx -nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date_30 = result['stdout']
    logger.info("The first expire date: " + expire_date_30)
    dut_command = "docker exec %s cp /tmp/acms.pfx %ssonic_acms_bootstrap-%s.pfx" % (container_name, cred_path, region)
    duthost.shell(dut_command, module_ignore_errors=True)
    # Start bootstrap_monitor and check result
    dut_command = "docker exec %s supervisorctl start bootstrap_monitor" % (container_name)
    duthost.shell(dut_command, module_ignore_errors=True)
    wait_until(30, 1, 0, check_state_db, duthost)
    dut_command = "sonic-db-cli STATE_DB hget 'ACMS_BOOTSTRAP_CERT|localhost' region"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    db_region = result['stdout']
    assert db_region == region, "Invalid region: " + db_region
    dut_command = "sonic-db-cli STATE_DB hget 'ACMS_BOOTSTRAP_CERT|localhost' date"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    db_date = result['stdout']
    logger.info("db date: " + db_date)
    int_command = "openssl pkcs12 -in %ssonic_acms_bootstrap-%s.pfx " % (cred_path, region)
    int_command += "-nodes -out /dev/stdout -passin pass: "
    int_command += "| openssl x509 -in /dev/stdin -enddate -noout"
    dut_command = "docker exec %s bash -c \"%s\"" % (container_name, int_command)
    result = duthost.shell(dut_command, module_ignore_errors=True)
    expire_date = result['stdout']
    logger.info("expire date: " + expire_date)
    assert expire_date == expire_date_30, "Invalid expire date: " + expire_date
    poll_time = parser.parse(expire_date, fuzzy=True)
    assert str(poll_time) == db_date, "ACMS_BOOTSTRAP_CERT date does not match: " + str(poll_time)
