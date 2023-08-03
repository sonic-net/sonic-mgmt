import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def backup_monit_config(duthost):
    logger.info("Backing up monit config files")
    duthost.shell("cp -f /etc/monit/monitrc ~/")
    duthost.shell("cp -f /etc/monit/conf.d/sonic-host ~/")


def restore_monit_config(duthost):
    logger.info("Restoring monit config files")
    duthost.shell("mv -f ~/monitrc /etc/monit/monitrc")
    duthost.shell("mv -f ~/sonic-host /etc/monit/conf.d/sonic-host")
    duthost.shell("systemctl restart monit")


def customize_monit_config(duthost, regex_pair):
    logger.info("Customizing monit files")
    # Modifying monitrc to reduce monit start delay time
    logger.info("Modifying monit config to eliminate start delay")
    duthost.replace(path="/etc/monit/monitrc", regexp='set daemon 60', replace='set daemon 10')
    duthost.replace(path="/etc/monit/monitrc", regexp='with start delay 300')
    original_line = regex_pair[0]
    new_line = regex_pair[1]
    if original_line != "":
        duthost.replace(path="/etc/monit/conf.d/sonic-host", regexp=original_line, replace=new_line)
    restart_monit(duthost)


def restart_monit(duthost):
    duthost.shell("systemctl restart monit")
    is_monit_running = wait_until(320,
                                  5,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")


def check_monit_running(duthost):
    monit_services_status = duthost.get_monit_services_status()
    return monit_services_status
