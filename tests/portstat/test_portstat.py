
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat
from tests.common.utilities import wait

logger = logging.getLogger('__name__')

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture(scope='function', autouse=True)
def reset_portstat(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info('Clear out all tags')
    duthost.command('portstat -D', become=True, module_ignore_errors=True)

    yield

    logger.info("Reset portstate ")
    duthost.command('portstat -D', become=True, module_ignore_errors=True)


@pytest.mark.parametrize('command', ['portstat -c', 'portstat --clear'])
def test_portstat_clear(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait(30, 'Wait for DUT to receive/send some packets')
    before_portstat = parse_portstat(duthost.command('portstat')['stdout_lines'])
    pytest_assert(before_portstat, 'No parsed command output')

    duthost.command(command)
    wait(1, 'Wait for portstat counters to refresh')

    after_portstat = parse_portstat(duthost.command('portstat')['stdout_lines'])
    pytest_assert(after_portstat, 'No parsed command output')

    """
    Assert only when rx/tx count is no smaller than COUNT_THRES because DUT may send or receive
    some packets during test after port status are clear
    """
    COUNT_THRES = 10
    for intf in before_portstat:
        tmp_ok_cnt = before_portstat[intf]['rx_ok'].replace(',','')
        rx_ok_before = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        tmp_ok_cnt = after_portstat[intf]['rx_ok'].replace(',','')
        rx_ok_after = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        tmp_ok_cnt = before_portstat[intf]['tx_ok'].replace(',','')
        tx_ok_before = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        tmp_ok_cnt = after_portstat[intf]['tx_ok'].replace(',','')
        tx_ok_after = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        if int(rx_ok_before >= COUNT_THRES):
            pytest_assert(rx_ok_before >= rx_ok_after,
                          'Value of RX_OK after clear should be lesser')
        if int(tx_ok_before >= COUNT_THRES):
            pytest_assert(tx_ok_before >= tx_ok_after,
                          'Value of TX_OK after clear should be lesser')

@pytest.mark.parametrize('command', ['portstat -D', 'portstat --delete-all'])
def test_portstat_delete_all(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    stats_files = ('test_1', 'test_2', 'test_test')

    logger.info('Create several test stats files')
    for stats_file in stats_files:
        duthost.command('portstat -c -t {}'.format(stats_file))

    logger.info('Verify that the file names are in the /tmp directory')
    uid = duthost.command('id -u')['stdout'].strip()
    for stats_file in stats_files:
        pytest_assert(duthost.stat(path='/tmp/portstat-{uid}/{uid}-{filename}'\
                      .format(uid=uid, filename=stats_file))['stat']['exists'])

    logger.info('Run the command to be tested "{}"'.format(command))
    duthost.command(command)

    logger.info('Verify that the file names are not in the /tmp directory')
    for stats_file in stats_files:
        pytest_assert(not duthost.stat(path='/tmp/portstat-{uid}/{uid}-{filename}'\
                      .format(uid=uid, filename=stats_file))['stat']['exists'])


@pytest.mark.parametrize('command',
                         ['portstat -d -t', 'portstat -d --tag', 'portstat --delete -t', 'portstat --delete --tag'])
def test_portstat_delete_tag(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    stats_files = ('test_1', 'test_2', 'test_delete_me')
    file_to_delete = stats_files[2]
    files_not_deleted = stats_files[:2]

    logger.info('Create several test stats files')
    for stats_file in stats_files:
        duthost.command('portstat -c -t {}'.format(stats_file))

    logger.info('Verify that the file names are in the /tmp directory')
    uid = duthost.command('id -u')['stdout'].strip()
    for stats_file in stats_files:
        pytest_assert(duthost.stat(path='/tmp/portstat-{uid}/{uid}-{filename}'\
                      .format(uid=uid, filename=stats_file))['stat']['exists'])

    full_delete_command = command + ' ' + file_to_delete
    logger.info('Run the command to be tested "{}"'.format(full_delete_command))
    duthost.command(full_delete_command)

    logger.info('Verify that the deleted file name is not in the directory')
    pytest_assert(not duthost.stat(path='/tmp/portstat-{uid}/{uid}-{filename}'\
                  .format(uid=uid, filename=file_to_delete))['stat']['exists'])

    logger.info('Verify that the remaining file names are in the directory')
    for stats_file in files_not_deleted:
        pytest_assert(duthost.stat(path='/tmp/portstat-{uid}/{uid}-{filename}'\
                      .format(uid=uid, filename=stats_file))['stat']['exists'])


@pytest.mark.parametrize('command', ['portstat -a', 'portstat --all'])
def test_portstat_display_all(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    base_portstat = parse_portstat(duthost.command('portstat')['stdout_lines'])
    all_portstats = parse_portstat(duthost.command(command)['stdout_lines'])
    pytest_assert(base_portstat and all_portstats, 'No parsed command output')

    logger.info('Verify the all number of columns is greater than the base number of columns')
    for intf in all_portstats.keys():
        pytest_assert(len(all_portstats[intf].keys()) > len(base_portstat[intf].keys()))


@pytest.mark.parametrize('command', ['portstat -p 1', 'portstat --period 1'])
def test_portstat_period(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    output = duthost.command(command)
    pytest_assert('The rates are calculated within 1 seconds period' in output['stdout_lines'][0])


@pytest.mark.parametrize('command', ['portstat -h', 'portstat --help', 'portstat', 'portstat -v',
                                     'portstat --version', 'portstat -j', 'portstat --json',
                                     'portstat -r', 'portstat --raw'])
def test_portstat_no_exceptions(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logger.info('Verify that the commands do not cause tracebacks')
    duthost.command(command)
