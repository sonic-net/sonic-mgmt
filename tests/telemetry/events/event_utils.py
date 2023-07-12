import logging
from tests.common.utilities import wait_until 
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def backup_monit_config(duthost):
    logger.info("Backing up monit config files")
    duthost.shell("cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("cp -f /etc/monit/conf.d/sonic-host /tmp/")


def restore_monit_config(duthost):
    logger.info("Restoring monit config files")
    duthost.shell("mv -f /tmp/monitrc /etc/monit/monitrc")
    duthost.shell("mv -f /tmp/sonic-host /etc/monit/conf.d/sonic-host")
    restart_monit(duthost)


def customize_monit_config(duthost, regex_pairs):
    logger.info("Customizing monit files")
    # Modifying monitrc to reduce monit start delay time
    logger.info("Modifying monit config to eliminate start delay")
    duthost.replace(path="/etc/monit/monitrc", regexp='with start delay 300', replace='#')
    for pair in regex_pairs:
        original_line = pair[0]
        new_line = pair[1]
        if original_line != "":
            duthost.replace(path="/etc/monit/conf.d/sonic-host", regexp=original_line, replace=new_line)
    restart_monit(duthost)


def restart_monit(duthost):
    duthost.shell("systemctl restart monit")
    is_monit_active = wait_until(300, 5, 0, is_monit_running, duthost)
    pytest_assert(is_monit_active, "Monit is not active after restarting")


def is_monit_running(duthost):
    monit_services_status = duthost.get_monit_services_status()
    if not monit_services_status:
        return False
    return True
