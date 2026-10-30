"""BMC-initiated graceful shutdown and restart of the switch-host.

Test plan: docs/testplan/bmc/BMC_Graceful_Restart_Testplan.md

Every case here removes power from the paired switch-host, so they are disruptive and serial.
The BMC-link gNOI provisioning these cases need is installed by the module fixture and removed
on teardown; see tests/common/platform/bmc_graceful_utils.py.
"""

import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.bmc_graceful_utils import (
    CHASSIS_STATUS_BASE_COLUMNS,
    CHASSIS_STATUS_REQUEST_ID_COLUMN,
    CHASSIS_STATUS_RESULT_COLUMN,
    CLI_DEFAULT_GRACEFUL_TIMEOUT,
    CMD_GRACEFUL_RESTART,
    CMD_GRACEFUL_SHUT,
    CMD_POWER_ON,
    CMD_RESULT_CRITICAL_LEAK_PRESENT,
    CMD_RESULT_PREEMPTED,
    CMD_RESULT_SUCCESS,
    CMD_STATUS_DONE,
    CMD_STATUS_FAILED,
    DEFAULT_GRACEFUL_TIMEOUT,
    OP_REASON_ALREADY_OFF,
    OP_REASON_CHECK_FAILED,
    OP_REASON_DEADLINE,
    OP_REASON_NONE,
    OP_REASON_NOT_QUALIFIED,
    OP_REASON_PREEMPTED,
    OP_REASON_RPC_FAILURE,
    OP_REASON_TIMEOUT_ZERO,
    OP_RESULT_OFF_LEAK_BLOCKED,
    OP_RESULT_PREEMPTED,
    OP_RESULT_SUCCESS_FORCED,
    OP_RESULT_SUCCESS_GRACEFUL,
    POWER_STATE_GRACEFUL_SHUTTING_DOWN,
    POWER_STATE_POWERED_OFF,
    POWER_STATE_POWERED_ON,
    RESTART_PAUSE_SECS,
    TRIGGER_CLI_SHUTDOWN,
    BmcGracefulEnv,
    rack_manager_trigger,
)
from tests.common.platform.bmc_utils import (
    BMC_EVENT_LOG,
    CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC,
    CAUSE_POWER_DOWN_FROM_BMC,
)
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status

logger = logging.getLogger(__name__)

# Both ends of the measured leg duration are polled, so it can fall short of the real one by
# about one poll interval. The failure this bound is here to catch -- a wait that was never
# really waited -- misses by far more than that.
ELAPSED_POLL_SLACK_SECS = 5

# Budget for a case to act on an operation that is still in flight. Kept under the graceful
# timeout, so an injection that has not landed by then is late rather than merely slow.
MID_FLIGHT_WAIT_SECS = 20

pytestmark = [
    pytest.mark.topology('bmc'),
    pytest.mark.disable_loganalyzer,
]


@pytest.fixture(scope='module')
def bmc_graceful_env(duthosts, enum_rand_one_per_hwsku_hostname, tmp_path_factory):
    """Install the BMC-link fixture for the module and remove it afterwards."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if not duthost.is_bmc():
        pytest.skip("Device is not a BMC system")
    if not check_pmon_daemon_enable_status(duthost, 'bmcctld'):
        pytest.skip("bmcctld is not enabled on {}".format(duthost.facts['platform']))

    env = BmcGracefulEnv.create(duthost, tmp_path_factory.mktemp('bmc-link-pki'))
    try:
        env.setup()
        yield env
    finally:
        env.teardown()


@pytest.fixture
def graceful_case(bmc_graceful_env):
    """Per-case guard: start from a provisioned, online host and leave one behind."""
    bmc_graceful_env.ensure_host_provisioned()
    bmc_graceful_env.clear_hook_flags()
    bmc_graceful_env.reset_hook_count()
    bmc_graceful_env.set_timeout(DEFAULT_GRACEFUL_TIMEOUT)
    try:
        yield bmc_graceful_env
    finally:
        bmc_graceful_env.recover()


def _assert_operation_record(env, request_id, expected_result, expected_reason,
                             expected_trigger, expected_power_state):
    """Assert one operation's terminal record, in STATE_DB and in the BMC event log.

    bmcctld writes the two records from different code paths, so checking both is not a
    duplicated assertion: a disagreement between them is itself a defect.
    """
    state = env.wait_op_done(request_id)
    pytest_assert(state.get('op_result') == expected_result,
                  "op_result is {!r}, expected {!r}. HOST_STATE={}".format(
                      state.get('op_result'), expected_result, state))
    pytest_assert(state.get('op_reason') == expected_reason,
                  "op_reason is {!r}, expected {!r}. HOST_STATE={}".format(
                      state.get('op_reason'), expected_reason, state))
    pytest_assert(state.get('op_trigger') == expected_trigger,
                  "op_trigger is {!r}, expected {!r}".format(state.get('op_trigger'), expected_trigger))
    pytest_assert(state.get('device_power_state') == expected_power_state,
                  "device_power_state is {!r}, expected {!r}".format(
                      state.get('device_power_state'), expected_power_state))

    record = env.op_done_log(request_id)
    pytest_assert(record, "no OP_DONE record in the BMC event log for request {}".format(request_id))
    pytest_assert(record['result'] == expected_result and record['reason'] == expected_reason
                  and record['trigger'] == expected_trigger,
                  "BMC event log disagrees with HOST_STATE: {}".format(record))
    return state


def _assert_graceful_record(env, request_id, expected_trigger, expected_power_state):
    """Assert one operation was recorded graceful.

    A host that never confirmed its pre-shutdown is recorded forced, so a broken handshake
    shows up as the wrong op_result here rather than as a missing record.
    """
    return _assert_operation_record(env, request_id, OP_RESULT_SUCCESS_GRACEFUL, OP_REASON_NONE,
                                    expected_trigger, expected_power_state)


def _assert_forced_record(env, request_id, expected_reason):
    """Assert one Rack-Manager shutdown degraded to forced for the reason under test.

    Power is removed either way and every case in this group ends in the same op_result, so
    op_reason is the only record of why the graceful leg was skipped or failed.
    """
    return _assert_operation_record(env, request_id, OP_RESULT_SUCCESS_FORCED, expected_reason,
                                    rack_manager_trigger(CMD_GRACEFUL_SHUT), POWER_STATE_POWERED_OFF)


def _assert_chassis_status_shows(env, request_id, expected_result):
    status = env.chassis_status_text()
    pytest_assert(expected_result in status and request_id in status,
                  "'show chassis modules status' does not expose result {!r} and request id {} "
                  "in its new columns:\n{}".format(expected_result, request_id, status))


def _assert_graceful_reboot_cause(env):
    cause = env.host_reboot_cause()
    pytest_assert(CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC in cause,
                  "switch-host reboot cause is {!r}, expected it to contain {!r}. The graceful "
                  "cause is written only after the host's own completion check passed.".format(
                      cause, CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC))


def _assert_host_was_asked(env):
    """Assert the pre-shutdown request did reach the switch-host.

    This is what separates a broken transport or an unanswered wait from the preconditions
    that skip the graceful leg outright: there, the hook never runs at all.
    """
    pytest_assert(env.hook_count() >= 1,
                  "the switch-host never ran its pre-shutdown, so the BMC never reached it; "
                  "this case is about what happens after it did")


def _assert_host_was_never_asked(env):
    """Assert no pre-shutdown request ever reached the switch-host.

    The test plan proves this with a packet capture on the BMC's side of the link. The host's
    pre-shutdown counter is the same fact read from the other end -- the hook runs only when a
    request arrived -- and it does not depend on a capture tool being present in the BMC image.
    Read it after the host is back: the counter lives on /host and survives the power cut.
    """
    ran = env.hook_count()
    pytest_assert(ran == 0,
                  "the switch-host ran its pre-shutdown {} time(s); with the precondition under "
                  "test the BMC should not have sent a request at all".format(ran))


def _run_graceful_shutdown_pass(env, entry_point):
    """Run one graceful shutdown end to end and leave the switch-host back in service."""
    logger.info("Graceful shutdown pass via %s", entry_point)
    previous_id = env.host_state().get('op_request_id')
    pre_boot = env.host_boot_time()

    if entry_point == 'CLI':
        result = env.shutdown_cli()
        pytest_assert(result.get('rc') == 0,
                      "'config chassis modules shutdown SWITCH-HOST' failed: {}".format(result))
        expected_trigger = TRIGGER_CLI_SHUTDOWN
        command_key = None
    else:
        command_key = env.submit(CMD_GRACEFUL_SHUT)
        expected_trigger = rack_manager_trigger(CMD_GRACEFUL_SHUT)

    request_id = env.wait_new_request_id(previous_id)
    _assert_graceful_record(env, request_id, expected_trigger, POWER_STATE_POWERED_OFF)

    pytest_assert(env.wait_host_powered_off(),
                  "switch-host did not become OFFLINE and unreachable after the {} shutdown".format(
                      entry_point))
    _assert_chassis_status_shows(env, request_id, OP_RESULT_SUCCESS_GRACEFUL)

    if command_key is not None:
        row = env.wait_command(command_key)
        pytest_assert(row.get('status') == CMD_STATUS_DONE and row.get('result') == CMD_RESULT_SUCCESS,
                      "Rack-Manager command row is {}, expected status={} result={}".format(
                          row, CMD_STATUS_DONE, CMD_RESULT_SUCCESS))
        pytest_assert(row.get('request_id') == request_id,
                      "Rack-Manager command carries request id {!r}, expected {!r}".format(
                          row.get('request_id'), request_id))

    env.recover()
    pytest_assert(env.host_boot_time() != pre_boot,
                  "switch-host boot time did not advance, so it never really lost power")
    _assert_graceful_reboot_cause(env)


def _run_forced_shutdown(env, expected_reason, mid_flight=None):
    """Trigger GRACEFUL_SHUT through the Rack Manager and assert the degraded record.

    mid_flight, when given, is called with the request id while the operation is still in
    flight, for the cases that have to act on a live graceful wait.

    Leaves the switch-host powered off; the caller recovers it. Returns the seconds between
    the operation being admitted and its terminal result being observed. Both ends are polled,
    so that figure is an approximation and only safe to use as a lower bound.
    """
    logger.info("Forced shutdown pass, expecting op_reason %s", expected_reason)
    previous_id = env.host_state().get('op_request_id')

    command_key = env.submit(CMD_GRACEFUL_SHUT)
    request_id = env.wait_new_request_id(previous_id)
    admitted_at = time.monotonic()
    if mid_flight is not None:
        mid_flight(request_id)
    _assert_forced_record(env, request_id, expected_reason)
    elapsed = time.monotonic() - admitted_at

    pytest_assert(env.wait_host_powered_off(),
                  "switch-host is still reachable; a graceful leg that could not run must not "
                  "stop the BMC from removing power")
    row = env.wait_command(command_key)
    pytest_assert(row.get('status') == CMD_STATUS_DONE and row.get('result') == CMD_RESULT_SUCCESS,
                  "Rack-Manager command row is {}, expected status={} result={}. The operation "
                  "itself succeeded; only its graceful leg was skipped or failed.".format(
                      row, CMD_STATUS_DONE, CMD_RESULT_SUCCESS))
    _assert_chassis_status_shows(env, request_id, OP_RESULT_SUCCESS_FORCED)
    return elapsed


def test_graceful_shutdown_records_proven_completion(graceful_case):
    """Graceful shutdown from the chassis CLI and from the Rack Manager.

    Both entry points run the same flow, the operation is positively attributed with a request
    id, and the next boot reports the graceful cause rather than the BMC power-down cause.
    """
    for entry_point in ('CLI', 'Rack Manager'):
        _run_graceful_shutdown_pass(graceful_case, entry_point)


def test_graceful_restart_returns_host_under_one_request(graceful_case):
    """GRACEFUL_RESTART takes the switch-host down and back up as one operation.

    There is no CLI verb for restart in this release, so the Rack Manager is the only entry
    point. What separates a restart from a shutdown followed by a startup is that no operator
    action happens in between and admin_status is left alone.
    """
    env = graceful_case
    previous_id = env.host_state().get('op_request_id')
    pre_boot = env.host_boot_time()
    admin_config_before = env.admin_status_config()
    admin_runtime_before = env.admin_status_runtime()

    command_key = env.submit(CMD_GRACEFUL_RESTART)
    request_id = env.wait_new_request_id(previous_id)
    _assert_graceful_record(env, request_id,
                            rack_manager_trigger(CMD_GRACEFUL_RESTART), POWER_STATE_POWERED_ON)

    row = env.wait_command(command_key)
    pytest_assert(row.get('status') == CMD_STATUS_DONE and row.get('result') == CMD_RESULT_SUCCESS,
                  "Rack-Manager command row is {}, expected status={} result={}".format(
                      row, CMD_STATUS_DONE, CMD_RESULT_SUCCESS))

    # One request id across both power legs. A second id on the power-on leg would mean the two
    # legs were not run as one operation.
    pytest_assert(row.get('request_id') == request_id,
                  "Rack-Manager command carries request id {!r}, expected {!r}".format(
                      row.get('request_id'), request_id))
    pytest_assert(env.host_state().get('op_request_id') == request_id,
                  "a second operation was admitted during the restart; the power-on leg must "
                  "run under the same request id")

    pytest_assert(env.admin_status_config() == admin_config_before,
                  "graceful restart changed the persisted admin_status: {!r} -> {!r}".format(
                      admin_config_before, env.admin_status_config()))
    pytest_assert(env.admin_status_runtime() == admin_runtime_before,
                  "graceful restart changed the runtime admin_status mirror: {!r} -> {!r}".format(
                      admin_runtime_before, env.admin_status_runtime()))

    # The host has to come back by itself: recover() only waits here, it does not power anything.
    env.recover()
    pytest_assert(env.host_boot_time() != pre_boot,
                  "switch-host boot time did not advance, so the restart never cycled power")
    _assert_graceful_reboot_cause(env)


def test_forced_when_bmc_is_not_qualified(graceful_case):
    """Forced shutdown: the BMC client certificate is not in place.

    bmcctld re-reads the BMC-link certificates on every operation, so moving one aside is
    enough to take the BMC out of qualification without restarting the daemon.
    """
    env = graceful_case
    with env.no_client_cert():
        _run_forced_shutdown(env, OP_REASON_NOT_QUALIFIED)
    env.recover()
    _assert_host_was_never_asked(env)


def test_forced_when_graceful_timeout_is_zero(graceful_case):
    """Forced shutdown: graceful_shutdown_timeout is 0.

    A zero timeout leaves no window to wait in, so the handshake is skipped rather than
    attempted and immediately abandoned.
    """
    env = graceful_case
    with env.timeout(0):
        _run_forced_shutdown(env, OP_REASON_TIMEOUT_ZERO)
    env.recover()
    _assert_host_was_never_asked(env)


def test_forced_when_host_is_already_off(graceful_case):
    """Forced shutdown: the switch-host is already OFFLINE.

    There is nothing to ask and nothing to shut down, so the operation still has to complete
    and be attributed rather than hang or report a failure.
    """
    env = graceful_case
    env.power_off_host()
    _run_forced_shutdown(env, OP_REASON_ALREADY_OFF)
    env.recover()
    _assert_host_was_never_asked(env)


def test_forced_when_host_pre_shutdown_fails(graceful_case):
    """Forced shutdown: the host runs its pre-shutdown and reports it did not complete.

    This is the one degraded path where the handshake works end to end -- the request is sent,
    the host answers, and the answer is a failure. An op_reason of 'backend_answered' here
    would mean the host attached a status message to its report and bmcctld classified on that
    instead, which is a different classification of the same working handshake.
    """
    env = graceful_case
    with env.fail_hook():
        _run_forced_shutdown(env, OP_REASON_CHECK_FAILED)
    env.recover()
    pytest_assert(env.hook_count() >= 1,
                  "the switch-host never ran its pre-shutdown, so it cannot have reported the "
                  "failure this case is about; {!r} would have been recorded for the wrong "
                  "reason".format(OP_REASON_CHECK_FAILED))


def test_forced_when_gnmi_stops_mid_wait(graceful_case):
    """Forced shutdown: the gNMI service is gone while the BMC is waiting on it.

    Recording 'rpc_failure' rather than 'deadline' is itself the proof that the wait was not
    left to run out: bmcctld reaches the two from mutually exclusive branches. The forced
    power-off must still happen -- a dead transport cannot leave the host powered.
    """
    env = graceful_case

    def break_the_channel(request_id):
        # Both waits are bounded well inside the graceful timeout: spending longer than that
        # here would stop gNMI after the wait rather than during it, and the case would record
        # 'deadline'. That is also the signal if this ordering ever slips.
        pytest_assert(env.wait_power_state(request_id, POWER_STATE_GRACEFUL_SHUTTING_DOWN,
                                           timeout=MID_FLIGHT_WAIT_SECS),
                      "the operation never entered {}, so there was no graceful wait to "
                      "interrupt".format(POWER_STATE_GRACEFUL_SHUTTING_DOWN))
        pytest_assert(env.wait_hook_running(timeout=MID_FLIGHT_WAIT_SECS),
                      "the switch-host never entered its pre-shutdown hook; stopping gNMI now "
                      "would break the channel before the request rather than during the wait")
        env.stop_host_gnmi()

    with env.hold_hook():
        _run_forced_shutdown(env, OP_REASON_RPC_FAILURE, mid_flight=break_the_channel)
    env.recover()
    _assert_host_was_asked(env)


def test_forced_when_host_never_answers(graceful_case):
    """Forced shutdown: the host is held in its pre-shutdown until the deadline passes.

    The hook is held past the graceful timeout, so the host is alive and reachable throughout
    and simply never reports completion. Beyond the recorded reason, the elapsed time is
    checked independently of bmcctld's own accounting: an operation that gave up early would
    come back well under the configured timeout.
    """
    env = graceful_case
    with env.hold_hook():
        elapsed = _run_forced_shutdown(env, OP_REASON_DEADLINE)
    env.recover()
    _assert_host_was_asked(env)

    logger.info("Operation reached its terminal result %.0fs after it was admitted", elapsed)
    floor = DEFAULT_GRACEFUL_TIMEOUT - ELAPSED_POLL_SLACK_SECS
    pytest_assert(elapsed >= floor,
                  "the operation reached its terminal result {:.0f}s after it was admitted, "
                  "short of the {}s timeout it was supposed to wait out (allowing {}s of "
                  "polling slack)".format(elapsed, DEFAULT_GRACEFUL_TIMEOUT,
                                          ELAPSED_POLL_SLACK_SECS))


def test_critical_leak_preempts_graceful_wait(graceful_case):
    """A critical leak lands while the BMC is waiting on the host's pre-shutdown.

    A leak outranks an operator's restart, so the restart has to give way rather than finish.
    The recorded result is read from the BMC event log: the leak's own power-off is admitted
    about a second after the preemption and overwrites HOST_STATE's terminal fields, so they
    cannot be read back reliably.
    """
    env = graceful_case
    previous_id = env.host_state().get('op_request_id')

    with env.leak_window():
        with env.hold_hook():
            command_key = env.submit(CMD_GRACEFUL_RESTART)
            request_id = env.wait_new_request_id(previous_id)
            pytest_assert(env.wait_power_state(request_id, POWER_STATE_GRACEFUL_SHUTTING_DOWN,
                                               timeout=MID_FLIGHT_WAIT_SECS),
                          "the restart never entered {}, so there was no wait to preempt".format(
                              POWER_STATE_GRACEFUL_SHUTTING_DOWN))
            pytest_assert(env.wait_hook_running(timeout=MID_FLIGHT_WAIT_SECS),
                          "the switch-host never entered its pre-shutdown, so the operation was "
                          "not yet waiting on it when the leak was published")
            env.publish_critical_leak()
            record = env.wait_op_done_log(request_id)

        pytest_assert(record['result'] == OP_RESULT_PREEMPTED,
                      "the restart was recorded {!r}, expected {!r}: a critical leak has to "
                      "take the operation away, not let it run to completion. Record={}".format(
                          record['result'], OP_RESULT_PREEMPTED, record))
        pytest_assert(record['reason'] == OP_REASON_PREEMPTED,
                      "op_reason is {!r}, expected {!r}. Record={}".format(
                          record['reason'], OP_REASON_PREEMPTED, record))

        row = env.wait_command(command_key)
        pytest_assert(row.get('status') == CMD_STATUS_FAILED
                      and row.get('result') == CMD_RESULT_PREEMPTED,
                      "Rack-Manager command row is {}, expected status={} result={}; the "
                      "submitter has to be told its restart did not happen".format(
                          row, CMD_STATUS_FAILED, CMD_RESULT_PREEMPTED))

        pytest_assert(env.wait_host_powered_off(),
                      "the switch-host is still up; the leak's own power-off has to follow the "
                      "preemption")
    env.recover()


def test_critical_leak_preempts_restart_pause(graceful_case):
    """A critical leak lands in the restart's powered-off pause.

    This is the only wait where a preemption is visible as power that never comes back, so it
    is a separate injection point rather than a repeat of the leak landing in the graceful
    wait. The graceful timeout is set to zero to make the shutdown leg immediate, which keeps
    the pause the only thing the injection has to hit.
    """
    env = graceful_case

    with env.leak_window():
        with env.timeout(0):
            command_key = env.submit_with_leak_at(CMD_GRACEFUL_RESTART, POWER_STATE_POWERED_OFF)
            row = env.wait_command(command_key)

        request_id = row.get('request_id')
        pytest_assert(request_id,
                      "the Rack-Manager command row carries no request id, so the operation "
                      "cannot be attributed: {}".format(row))
        record = env.wait_op_done_log(request_id)
        pytest_assert(record['result'] == OP_RESULT_PREEMPTED,
                      "the restart was recorded {!r}, expected {!r}. Record={}".format(
                          record['result'], OP_RESULT_PREEMPTED, record))

        # The point of this injection point: the power-on leg must never run.
        time.sleep(RESTART_PAUSE_SECS * 2)
        pytest_assert(not env.host_is_online(),
                      "the switch-host came back up after the restart was preempted; a preempted "
                      "restart must not raise power")
    env.recover()


def test_critical_leak_blocks_every_power_raise(graceful_case):
    """While a critical leak stands, every way of raising power is refused.

    Three entry points reach the power-on path, and they report the refusal differently: the
    Rack Manager fails the command outright, the chassis CLI is blocked before an operation is
    even admitted, and a restart is admitted and then records OFF_LEAK_BLOCKED. All three have
    to leave the switch-host down.
    """
    env = graceful_case

    with env.leak_window():
        mark = env.event_log_mark()
        env.publish_critical_leak()
        pytest_assert(env.wait_host_powered_off(),
                      "the critical leak did not take the switch-host down, so there is no "
                      "refused power raise to test")

        power_on_key = env.submit(CMD_POWER_ON)
        row = env.wait_command(power_on_key)
        pytest_assert(row.get('status') == CMD_STATUS_FAILED
                      and row.get('result') == CMD_RESULT_CRITICAL_LEAK_PRESENT,
                      "Rack-Manager {} row is {}, expected status={} result={}".format(
                          CMD_POWER_ON, row, CMD_STATUS_FAILED, CMD_RESULT_CRITICAL_LEAK_PRESENT))

        env.shutdown_cli()
        env.startup_cli()
        blocked = env.wait_event_log_since(mark, 'CHASSIS_MODULE admin_up')
        pytest_assert(CMD_RESULT_CRITICAL_LEAK_PRESENT in blocked,
                      "the BMC event log does not record the chassis startup being blocked by "
                      "the leak; last matching line was {!r}".format(blocked))

        restart_key = env.submit(CMD_GRACEFUL_RESTART)
        row = env.wait_command(restart_key)
        pytest_assert(row.get('result') == CMD_RESULT_CRITICAL_LEAK_PRESENT,
                      "Rack-Manager {} row is {}, expected result={}".format(
                          CMD_GRACEFUL_RESTART, row, CMD_RESULT_CRITICAL_LEAK_PRESENT))
        record = env.wait_op_done_log(row.get('request_id'))
        # The command row and the operation record use different words for the same refusal.
        pytest_assert(record['result'] == OP_RESULT_OFF_LEAK_BLOCKED,
                      "the restart was recorded {!r}, expected {!r}. Record={}".format(
                          record['result'], OP_RESULT_OFF_LEAK_BLOCKED, record))

        pytest_assert(not env.host_is_online(),
                      "the switch-host is up again; no power raise may succeed while a critical "
                      "leak stands")
    env.recover()


def test_shutdown_timeout_configuration_boundaries(graceful_case):
    """The shutdown-timeout this feature adds takes valid values and refuses the rest.

    The only case in the suite that removes no power. It is about the CLI's own validation, so
    a refusal has to be visible in the command's exit status rather than only in a log, and it
    has to leave the configured value alone.
    """
    env = graceful_case

    # set_timeout() asserts the command succeeded and reads the value back from CONFIG_DB.
    # 0 is the lower boundary: bmcctld reads it as 'skip the graceful leg'.
    for seconds in (0, 1, DEFAULT_GRACEFUL_TIMEOUT, CLI_DEFAULT_GRACEFUL_TIMEOUT):
        env.set_timeout(seconds)

    # The test plan also asks for a value above the upper limit to be refused. This release
    # declares the argument click.IntRange(min=0), so there is no upper limit to cross yet;
    # that half belongs here once the CLI grows one.
    accepted = env.configured_timeout()
    for rejected in ('-1', 'abc', '1.5'):
        result = env.set_timeout_cli(rejected)
        pytest_assert(result.get('rc') != 0,
                      "'shutdown-timeout SWITCH-HOST {}' was accepted; a value that is not a "
                      "whole number of seconds has to be refused. Result={}".format(
                          rejected, result))
        pytest_assert(env.configured_timeout() == accepted,
                      "the refused shutdown-timeout {!r} still changed CONFIG_DB: {!r} -> "
                      "{!r}".format(rejected, accepted, env.configured_timeout()))


def test_operation_record_is_complete_and_visible(graceful_case):
    """Everything an operator can see once a graceful shutdown has finished.

    The same operation is recorded in four places written by different code paths -- HOST_STATE,
    the BMC event log, the chassis CLI and the Rack Manager's receipt. This case is about them
    agreeing, and about the CLI's pre-existing columns not having been disturbed to make room
    for the two the feature adds.
    """
    env = graceful_case
    previous_id = env.host_state().get('op_request_id')

    command_key = env.submit(CMD_GRACEFUL_SHUT)
    request_id = env.wait_new_request_id(previous_id)
    # Asserts HOST_STATE's terminal fields and that the event log's OP_DONE record agrees.
    state = _assert_graceful_record(env, request_id, rack_manager_trigger(CMD_GRACEFUL_SHUT),
                                    POWER_STATE_POWERED_OFF)

    for field in ('op_request_id', 'op_trigger', 'op_result', 'op_reason'):
        pytest_assert(state.get(field),
                      "HOST_STATE has no {}, so the finished operation cannot be read back in "
                      "full: {}".format(field, state))
    pytest_assert(state['op_request_id'] == request_id,
                  "HOST_STATE is attributed to request {!r}, expected {!r}".format(
                      state['op_request_id'], request_id))

    pytest_assert(env.wait_host_powered_off(),
                  "switch-host did not become OFFLINE and unreachable after the shutdown")

    columns = env.chassis_status_columns()
    leading = columns[:len(CHASSIS_STATUS_BASE_COLUMNS)]
    pytest_assert(leading == list(CHASSIS_STATUS_BASE_COLUMNS),
                  "'show chassis modules status' no longer leads with {}; the columns that "
                  "predate this feature have to keep their order. Columns={}".format(
                      list(CHASSIS_STATUS_BASE_COLUMNS), columns))
    added = columns[len(CHASSIS_STATUS_BASE_COLUMNS):]
    for column in (CHASSIS_STATUS_RESULT_COLUMN, CHASSIS_STATUS_REQUEST_ID_COLUMN):
        pytest_assert(column in added,
                      "'show chassis modules status' does not add a {} column. Columns={}".format(
                          column, columns))
    _assert_chassis_status_shows(env, request_id, OP_RESULT_SUCCESS_GRACEFUL)

    row = env.wait_command(command_key)
    pytest_assert(row.get('request_id') == request_id and row.get('result') == CMD_RESULT_SUCCESS,
                  "the Rack-Manager receipt is {}, expected request_id={} result={}".format(
                      row, request_id, CMD_RESULT_SUCCESS))

    # The test plan collects a support bundle and looks for HOST_STATE and the event log inside
    # it. 'show techsupport' takes minutes on this platform and would only prove that these two
    # sources were copied, so they are read where they are written instead.
    pytest_assert(env.op_done_log(request_id),
                  "the BMC event log at {} keeps no record of request {}, so the operation "
                  "cannot be reconstructed after the fact".format(BMC_EVENT_LOG, request_id))

    env.recover()

    # Reboot-cause history can only be read once the host is back up. The graceful cause lands
    # in the Cause column; the BMC power-down behind it is the comment.
    latest = env.host_reboot_cause_history_latest()
    pytest_assert(CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC in latest,
                  "the newest reboot-cause history row is {!r}, expected it to name {!r}".format(
                      latest, CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC))
    pytest_assert(CAUSE_POWER_DOWN_FROM_BMC in latest,
                  "the newest reboot-cause history row is {!r}, expected its comment to carry "
                  "the hardware cause {!r}".format(latest, CAUSE_POWER_DOWN_FROM_BMC))
