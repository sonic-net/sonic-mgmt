import pytest
import logging
import functools
import re
import os
import time

from datetime import datetime
from tests.common.helpers.assertions import pytest_assert
from isis_helpers import get_device_systemid
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_lsp_gen_interval(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_generation_interval"
    config_dict = {config_key: '20'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def isis_change_config(duthost):

    config_key = "wide_metric"
    config_dict = {config_key: '0'}
    add_dev_isis_attr(duthost, config_dict)
    config_device_isis(duthost)
    config_key = "wide_metric"
    config_dict = {config_key: '1'}
    add_dev_isis_attr(duthost, config_dict)
    config_device_isis(duthost)
    config_key = "wide_metric"
    config_dict = {config_key: '0'}
    add_dev_isis_attr(duthost, config_dict)
    config_device_isis(duthost)


def to_seconds(date):
    return time.mktime(date.timetuple())


def test_isis_lsp_gen_interval(isis_common_setup_teardown, isis_setup_teardown_lsp_gen_interval):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    cmd = "tcpdump -i {} isis -w /var/tmp/isis.pcap -Z root".format(dut_port)
    start = "nohup {} &".format(cmd)
    dut_host.shell(start)

    isis_change_config(dut_host)
    time.sleep(10)
    dut_host.shell("pkill -f '{}'".format(cmd), module_ignore_errors=True)

    dut_host.fetch(src="/var/tmp/isis.pcap", dest="/var/tmp/isis.pcap", flat=True)
    dut_host.file(path="/var/tmp/isis.pcap", state="absent")
    stream = os.popen('sudo tcpdump -ttttnnr /var/tmp/isis.pcap')

    output = stream.readlines()
    regex = \
        re.compile(r'(\d+-\d+-\d+\s*\d+:\d+:\d+)\.\d+\s*.*lsp-id\s*{}.*'.format(get_device_systemid(dut_host)))

    lsp = []
    for line in output:
        match = regex.match(line)
        if match:
            lsp.append(match.group(1))

    time_new = to_seconds(datetime.strptime(lsp[-1], '%Y-%m-%d %H:%M:%S'))
    time_old = to_seconds(datetime.strptime(lsp[-2], '%Y-%m-%d %H:%M:%S'))

    pytest_assert((time_new - time_old) == 20, "LSP generate interval is not 20s!")
