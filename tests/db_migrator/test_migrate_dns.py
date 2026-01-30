import pytest
import logging
import json
import random
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.utilities import backup_config, restore_config

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer
]

GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_BACKUP = "/etc/sonic/golden_config_db.json_before_override"
CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json_before_override"
MINIGRAPH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP = "/etc/sonic/minigraph.xml_before_override"
DNS_TEMPLATE = "/usr/share/sonic/templates/dns.j2"
DNS_TEMPLATE_BACKUP = "/usr/share/sonic/templates/dns.j2_before_override"

logger = logging.getLogger(__name__)


minigraph_dns = "1.1.1.1"
golden_config_dns = "2.2.2.2"


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)


@pytest.fixture(scope="module", autouse=True)
def setup_env(duthost):
    """
    Setup/teardown
    Args:
        duthost: DUT.
        golden_config_exists_on_dut: Check if golden config exists on DUT.
    """
    if duthost.is_multi_asic:
        pytest.skip("Skip test on multi-asic platforms as it is designed for single asic.")

    # Backup configDB
    backup_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    if file_exists_on_dut(duthost, GOLDEN_CONFIG):
        backup_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)
    # Backup minigraph
    backup_config(duthost, MINIGRAPH, MINIGRAPH_BACKUP)
    # Backup dns template
    backup_config(duthost, DNS_TEMPLATE, DNS_TEMPLATE_BACKUP)

    yield

    # Restore configDB after test.
    restore_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    if file_exists_on_dut(duthost, GOLDEN_CONFIG_BACKUP):
        restore_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)
    else:
        duthost.file(path=GOLDEN_CONFIG, state='absent')
    # Restore minigraph
    restore_config(duthost, MINIGRAPH, MINIGRAPH_BACKUP)
    # Restore dns template
    restore_config(duthost, DNS_TEMPLATE, DNS_TEMPLATE_BACKUP)

    # Restore config
    config_reload(duthost, safe_reload=True)


def get_nameserver_from_config_db(duthost):
    """
    Get the DNS nameserver configured in the config db
    :param duthost: DUT host object
    :return: DNS nameserver list
    """
    nameservers = duthost.show_and_parse("show dns nameserver")
    return [str(nameserver["nameserver"]) for nameserver in nameservers]


def del_dns_nameserver(duthost, ip_addr):
    return duthost.shell(f"config dns nameserver del {ip_addr}", module_ignore_errors=True)


def update_minigraph(duthost, minigraph_file, profile=None):
    """
    Update the minigraph file on the DUT
    :param duthost: DUT host object
    :param minigraph_file: Path to the minigraph file
    :param profile: Optional QoS profile to be added to the minigraph
    :return: None
    """

    if not profile:
        profile = random.choice(["RDMA-CENTRIC", "TCP-CENTRIC", "BALANCED"])

    new_device_property = f'''
    <a:DeviceProperty>
        <a:Name>SonicQosProfile</a:Name>
        <a:Reference i:nil="true"/>
        <a:Value>{profile}</a:Value>
    </a:DeviceProperty>
'''
    # Read the minigraph file
    ret = duthost.command(f"cat {minigraph_file}", module_ignore_errors=True)
    if ret["rc"] != 0:
        pytest.fail("Failed to read minigraph file")

    # Check if the minigraph file already contains "SonicQosProfile" property
    if "<a:Name>SonicQosProfile</a:Name>" in ret["stdout"]:
        logger.info("SonicQosProfile property already exists in the minigraph file, exiting update_minigraph.")
        return

    minigraph_data = ret["stdout"]
    # Insert the SonicQosProfile property into the minigraph file
    position = minigraph_data.find('</a:DeviceProperty>')
    if position == -1:
        pytest.fail("Closing tag '</a:DeviceProperty>' not found in minigraph file")
    else:
        new_data = minigraph_data[:position + len('</a:DeviceProperty>')]
        new_data += new_device_property
        new_data += minigraph_data[position + len('</a:DeviceProperty>'):]
        # Update the minigraph file on the DUT
        duthost.copy(content=new_data, dest=minigraph_file)


def test_migrate_dns_01(duthost):
    """Minigraph exists, and golden config exists
    db_migrator should use DNS_NAMESERVER from golden config

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Restore minigraph
    backup_config(duthost, MINIGRAPH_BACKUP, MINIGRAPH)
    # Update the DNS template to include the DNS server specified by minigraph_dns
    file_content = json.dumps({
        "DNS_NAMESERVER": {
            minigraph_dns: {}
        }
    }, indent=2)
    duthost.copy(content=file_content, dest=DNS_TEMPLATE)
    # Update the golden config to include the DNS server specified by golden_config_dns
    file_content = json.dumps({
        "DNS_NAMESERVER": {
            golden_config_dns: {}
        }
    }, indent=2)
    duthost.copy(content=file_content, dest=GOLDEN_CONFIG)

    # Update database VERSIONS
    origin_version = "version_202305_01"
    cmd = f"sonic-db-cli CONFIG_DB hset 'VERSIONS|DATABASE' VERSION {origin_version}"
    duthost.command(cmd, module_ignore_errors=True)
    # Cleanup DNS_NAMESERVER from config db
    dns_servers = get_nameserver_from_config_db(duthost)
    for dns_server in dns_servers:
        del_dns_nameserver(duthost, dns_server)

    # Run db_migrator
    result = duthost.command("db_migrator.py -o migrate", module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, f"db_migrator failed with error: {result.get('stderr', '')}")

    # Check if the DNS server from golden config is present in config db
    dns_servers = get_nameserver_from_config_db(duthost)
    pytest_assert(golden_config_dns in dns_servers,
                  "DNS server from golden config is not present in config db")
    pytest_assert(minigraph_dns not in dns_servers,
                  "DNS server from minigraph is present in config db")


def test_migrate_dns_02(duthost):
    """Minigraph exists, and golden config does not exist
    db_migrator should use DNS_NAMESERVER from minigraph

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Restore minigraph
    backup_config(duthost, MINIGRAPH_BACKUP, MINIGRAPH)
    # Update the DNS template to include the DNS server specified by minigraph_dns
    file_content = json.dumps({
        "DNS_NAMESERVER": {
            minigraph_dns: {}
        }
    }, indent=2)
    duthost.copy(content=file_content, dest=DNS_TEMPLATE)
    # Remove golden config if it exists
    if file_exists_on_dut(duthost, GOLDEN_CONFIG):
        duthost.file(path=GOLDEN_CONFIG, state='absent')

    # Update database VERSIONS
    origin_version = "version_202305_01"
    cmd = f"sonic-db-cli CONFIG_DB hset 'VERSIONS|DATABASE' VERSION {origin_version}"
    duthost.command(cmd, module_ignore_errors=True)
    # Cleanup DNS_NAMESERVER from config db
    dns_servers = get_nameserver_from_config_db(duthost)
    for dns_server in dns_servers:
        del_dns_nameserver(duthost, dns_server)

    # Run db_migrator
    result = duthost.command("db_migrator.py -o migrate", module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, f"db_migrator failed with error: {result.get('stderr', '')}")

    # Check if the DNS server from minigraph is present in config db
    dns_servers = get_nameserver_from_config_db(duthost)
    pytest_assert(golden_config_dns not in dns_servers,
                  "DNS server from golden config is present in config db")
    pytest_assert(minigraph_dns in dns_servers,
                  "DNS server from minigraph is present in config db")


def test_migrate_dns_03(duthost):
    """Minigraph exists, and golden config does not exist.
    The minigraph contains the SonicQosProfile property.

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Create test minigraph
    backup_config(duthost, MINIGRAPH_BACKUP, MINIGRAPH)
    update_minigraph(duthost, MINIGRAPH)
    # Update the DNS template to include the DNS server specified by minigraph_dns
    file_content = json.dumps({
        "DNS_NAMESERVER": {
            minigraph_dns: {}
        }
    }, indent=2)
    duthost.copy(content=file_content, dest=DNS_TEMPLATE)
    # Remove golden config if it exists
    if file_exists_on_dut(duthost, GOLDEN_CONFIG):
        duthost.file(path=GOLDEN_CONFIG, state='absent')

    # Update database VERSIONS
    origin_version = "version_202305_01"
    cmd = f"sonic-db-cli CONFIG_DB hset 'VERSIONS|DATABASE' VERSION {origin_version}"
    duthost.command(cmd, module_ignore_errors=True)
    # Cleanup DNS_NAMESERVER from config db
    dns_servers = get_nameserver_from_config_db(duthost)
    for dns_server in dns_servers:
        del_dns_nameserver(duthost, dns_server)

    # Run db_migrator
    result = duthost.command("db_migrator.py -o migrate", module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, f"db_migrator failed with error: {result.get('stderr', '')}")

    # Check if the DNS server from minigraph is present in config db
    dns_servers = get_nameserver_from_config_db(duthost)
    pytest_assert(golden_config_dns not in dns_servers,
                  "DNS server from golden config is present in config db")
    pytest_assert(minigraph_dns in dns_servers,
                  "DNS server from minigraph is not present in config db")


def test_migrate_dns_04(duthost):
    """Minigraph does not exist, and golden config exists
    db_migrator should use DNS_NAMESERVER from golden config

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Remove MINIGRAPH
    if file_exists_on_dut(duthost, MINIGRAPH):
        duthost.file(path=MINIGRAPH, state='absent')
    # Update the golden config to include the DNS server specified by golden_config_dns
    file_content = json.dumps({
        "DNS_NAMESERVER": {
            golden_config_dns: {}
        }
    }, indent=2)
    duthost.copy(content=file_content, dest=GOLDEN_CONFIG)

    # Update database VERSIONS
    origin_version = "version_202305_01"
    cmd = f"sonic-db-cli CONFIG_DB hset 'VERSIONS|DATABASE' VERSION {origin_version}"
    duthost.command(cmd, module_ignore_errors=True)
    # Cleanup DNS_NAMESERVER from config db
    dns_servers = get_nameserver_from_config_db(duthost)
    for dns_server in dns_servers:
        del_dns_nameserver(duthost, dns_server)

    # Run db_migrator
    result = duthost.command("db_migrator.py -o migrate", module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, f"db_migrator failed with error: {result.get('stderr', '')}")

    # Check if the DNS server from golden config is present in config db
    dns_servers = get_nameserver_from_config_db(duthost)
    pytest_assert(golden_config_dns in dns_servers,
                  "DNS server from golden config is not present in config db")
    pytest_assert(minigraph_dns not in dns_servers,
                  "DNS server from minigraph is present in config db")
