
import logging
import re
import pytest
from natsort import natsorted

from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat
from tests.common.utilities import wait

logger = logging.getLogger('__name__')

pytestmark = [
    pytest.mark.topology('any')
]

# Ingress packets dropped for lack of buffers, polled by the PORT_BUFFER_DROP flex counter group
IN_DROPPED_PKTS = 'SAI_PORT_STAT_IN_DROPPED_PKTS'
# IPv4 packets received, which 'Overruns Received' used to show
IP_IN_RECEIVES = 'SAI_PORT_STAT_IP_IN_RECEIVES'
OVERRUNS_RECEIVED_RE = re.compile(r'^Overruns Received\.+\s+(\S+)\s*$', re.MULTILINE)


@pytest.fixture(scope='function', autouse=True)
def reset_portstat(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info('Clear out all tags')
    duthost.command('portstat -D')

    yield

    logger.info("Reset portstate ")
    duthost.command('portstat -D', module_ignore_errors=True)


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
        tmp_ok_cnt = before_portstat[intf]['rx_ok'].replace(',', '')
        rx_ok_before = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        tmp_ok_cnt = after_portstat[intf]['rx_ok'].replace(',', '')
        rx_ok_after = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        tmp_ok_cnt = before_portstat[intf]['tx_ok'].replace(',', '')
        tx_ok_before = int(0 if tmp_ok_cnt == 'N/A' else tmp_ok_cnt)
        tmp_ok_cnt = after_portstat[intf]['tx_ok'].replace(',', '')
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
        pytest_assert(get_tmp_portstat_file_existing_status(duthost, uid, stats_file))

    logger.info('Run the command to be tested "{}"'.format(command))
    duthost.command(command)

    logger.info('Verify that the file names are not in the /tmp directory')
    for stats_file in stats_files:
        pytest_assert(not get_tmp_portstat_file_existing_status(duthost, uid, stats_file))


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
        pytest_assert(get_tmp_portstat_file_existing_status(duthost, uid, stats_file))

    full_delete_command = command + ' ' + file_to_delete
    logger.info('Run the command to be tested "{}"'.format(full_delete_command))
    duthost.command(full_delete_command)

    logger.info('Verify that the deleted file name is not in the directory')
    pytest_assert(not get_tmp_portstat_file_existing_status(duthost, uid, file_to_delete))

    logger.info('Verify that the remaining file names are in the directory')
    for stats_file in files_not_deleted:
        pytest_assert(get_tmp_portstat_file_existing_status(duthost, uid, stats_file))


def get_tmp_portstat_file_existing_status(duthost, uid, stats_file):
    return duthost.stat(path='/tmp/cache/portstat/{uid}-{filename}'.format(
        uid=uid, filename=stats_file))['stat']['exists']


@pytest.mark.parametrize('command', ['portstat -a', 'portstat --all'])
def test_portstat_display_all(duthosts, enum_rand_one_per_hwsku_frontend_hostname, command):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    base_portstat = parse_portstat(duthost.command('portstat')['stdout_lines'])
    all_portstats = parse_portstat(duthost.command(command)['stdout_lines'])
    pytest_assert(base_portstat and all_portstats, 'No parsed command output')

    logger.info('Verify the all number of columns is greater than the base number of columns')
    for intf in list(all_portstats.keys()):
        pytest_assert(len(list(all_portstats[intf].keys())) > len(list(base_portstat[intf].keys())))


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


def get_overruns_received(duthost, port):
    """Return the 'Overruns Received' value printed by 'show interfaces counters detailed <port>'"""
    output = duthost.command('show interfaces counters detailed {}'.format(port))['stdout']
    match = OVERRUNS_RECEIVED_RE.search(output)
    pytest_assert(match, "No 'Overruns Received' line in 'show interfaces counters detailed {}':\n{}"
                  .format(port, output))
    return match.group(1)


def get_port_counter(asic, port_oid, counter):
    """Return a port counter from COUNTERS_DB, or None if the port doesn't have it"""
    cmd = 'COUNTERS_DB HGET COUNTERS:{} {}'.format(port_oid, counter)
    return asic.run_sonic_db_cli_cmd(cmd)['stdout'].strip() or None


def set_port_counter(asic, port_oid, counter, value):
    """Write a port counter to COUNTERS_DB, or remove it if value is None"""
    if value is None:
        asic.run_sonic_db_cli_cmd('COUNTERS_DB HDEL COUNTERS:{} {}'.format(port_oid, counter))
    else:
        asic.run_sonic_db_cli_cmd('COUNTERS_DB HSET COUNTERS:{} {} {}'.format(port_oid, counter, value))


def sample_overruns_received(duthost, asic, port, port_oid):
    """
    Return 'Overruns Received' and the SAI_PORT_STAT_IN_DROPPED_PKTS value it should show.
    PORT_BUFFER_DROP polling can update the counter while the CLI runs, so retry until it stays the same.
    """
    for _ in range(3):
        before = get_port_counter(asic, port_oid, IN_DROPPED_PKTS)
        overruns = get_overruns_received(duthost, port)
        after = get_port_counter(asic, port_oid, IN_DROPPED_PKTS)
        if before == after:
            return overruns, after
        logger.info('%s on %s changed from %s to %s while reading the CLI, retrying',
                    IN_DROPPED_PKTS, port, before, after)
    pytest.fail('{} on {} kept changing while reading the CLI'.format(IN_DROPPED_PKTS, port))


def format_counter(value):
    """Format a COUNTERS_DB value the way portstat prints it when no snapshot is saved"""
    return 'N/A' if value is None else '{:,}'.format(int(float(value)))


@pytest.fixture
def overruns_port(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Pick a front-panel port, preferably oper up, and find its ASIC and COUNTERS_DB OID"""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    intf_status = duthost.get_interfaces_status()
    ports = natsorted(intf for intf in intf_status if intf.startswith('Ethernet'))
    pytest_assert(ports, "No Ethernet ports in 'show interfaces status'")
    up_ports = [port for port in ports if intf_status[port].get('oper') == 'up']
    port = (up_ports or ports)[0]

    asic = duthost.get_port_asic_instance(port)
    port_oid = asic.run_sonic_db_cli_cmd('COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP {}'.format(port))['stdout'].strip()
    pytest_assert(port_oid, 'No {} in COUNTERS_PORT_NAME_MAP'.format(port))
    logger.info('Checking %s (%s, namespace %s)', port, port_oid, asic.namespace)
    return duthost, asic, port, port_oid


@pytest.fixture
def buffer_drop_polling_paused(overruns_port):
    """
    Pause PORT_BUFFER_DROP polling on the port's ASIC, so that counters the test writes to COUNTERS_DB stay put.
    Afterwards, restore the port's SAI_PORT_STAT_IN_DROPPED_PKTS and the polling.
    """
    duthost, asic, _, port_oid = overruns_port
    status = asic.run_sonic_db_cli_cmd(
        'CONFIG_DB HGET "FLEX_COUNTER_TABLE|PORT_BUFFER_DROP" FLEX_COUNTER_STATUS')['stdout'].strip()
    polling_enabled = status == 'enable'
    if polling_enabled:
        duthost.command('{}counterpoll port-buffer-drop disable'.format(asic.ns_arg))
    try:
        if polling_enabled:
            wait(5, 'Let an in-flight PORT_BUFFER_DROP poll finish')
        original_value = get_port_counter(asic, port_oid, IN_DROPPED_PKTS)

        yield

        set_port_counter(asic, port_oid, IN_DROPPED_PKTS, original_value)
    finally:
        if polling_enabled:
            duthost.command('{}counterpoll port-buffer-drop enable'.format(asic.ns_arg))


def test_portstat_overruns_received_matches_counters_db(overruns_port):
    """
    Verify that 'Overruns Received' in 'show interfaces counters detailed' shows the port's ingress buffer drops,
    SAI_PORT_STAT_IN_DROPPED_PKTS in COUNTERS_DB, or N/A if the port doesn't have that counter.
    The reset_portstat fixture removes saved snapshots, so the CLI shows the counter itself.
    """
    duthost, asic, port, port_oid = overruns_port
    overruns, buffer_drops = sample_overruns_received(duthost, asic, port, port_oid)
    ip_in_receives = get_port_counter(asic, port_oid, IP_IN_RECEIVES)
    logger.info("%s: 'Overruns Received' %s, %s %s, %s %s",
                port, overruns, IN_DROPPED_PKTS, buffer_drops, IP_IN_RECEIVES, ip_in_receives)
    pytest_assert(overruns == format_counter(buffer_drops),
                  "'Overruns Received' on {} is {}, but {} is {} ({} is {})".format(
                      port, overruns, IN_DROPPED_PKTS, buffer_drops, IP_IN_RECEIVES, ip_in_receives))


def test_portstat_overruns_received_counts_buffer_drops(overruns_port, buffer_drop_polling_paused):
    """
    Verify that 'Overruns Received' follows SAI_PORT_STAT_IN_DROPPED_PKTS rather than SAI_PORT_STAT_IP_IN_RECEIVES.
    With PORT_BUFFER_DROP polling paused, set the counter in COUNTERS_DB and check that the CLI shows:
    1. the counter, when no snapshot is saved
    2. how much the counter grew since 'sonic-clear counters'
    3. N/A once the counter is removed, as on ports that don't support it
    """
    duthost, asic, port, port_oid = overruns_port
    ip_in_receives = get_port_counter(asic, port_oid, IP_IN_RECEIVES)
    buffer_drops = 123456789
    new_buffer_drops = 4321

    def check_overruns_received(counter_value, expected):
        set_port_counter(asic, port_oid, IN_DROPPED_PKTS, counter_value)
        overruns, db_value = sample_overruns_received(duthost, asic, port, port_oid)
        pytest_assert(db_value == counter_value,
                      '{} on {} is {} instead of {}: was it updated by PORT_BUFFER_DROP polling?'.format(
                          IN_DROPPED_PKTS, port, db_value, counter_value))
        pytest_assert(overruns == expected,
                      "'Overruns Received' on {} is {}, expected {} with {} set to {} ({} is {})".format(
                          port, overruns, expected, IN_DROPPED_PKTS, counter_value, IP_IN_RECEIVES, ip_in_receives))

    logger.info('With no snapshot, Overruns Received shows %s', IN_DROPPED_PKTS)
    check_overruns_received(str(buffer_drops), '123,456,789')

    logger.info("After 'sonic-clear counters', Overruns Received shows how much %s grew", IN_DROPPED_PKTS)
    duthost.command('sonic-clear counters')
    check_overruns_received(str(buffer_drops + new_buffer_drops), '4,321')

    logger.info('Without %s, Overruns Received shows N/A', IN_DROPPED_PKTS)
    check_overruns_received(None, 'N/A')
