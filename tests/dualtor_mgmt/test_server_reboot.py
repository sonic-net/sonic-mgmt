import logging
import pytest

from tests.common.dualtor.icmp_responder_control import shutdown_icmp_responder    # noqa: F401

pytestmark = [
    pytest.mark.topology('dualtor')
]


def test_server_reboot(shutdown_icmp_responder, tbinfo, vmhost):    # noqa: F811

    # shutdown the icmp responder
    logging.info('shutting down icmp_responder')
    shutdown_icmp_responder()

    # shutting down ptf container to simulate
    # server restart
    logging.info('shutting down server')
    group_name = tbinfo['group-name']
    ptf_container = f'ptf_{group_name}'
    # vmhost shutdown ptf container
    vmhost.shell(f'docker stop {ptf_container}')
