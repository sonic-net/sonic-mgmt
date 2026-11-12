"""BMC-initiated graceful shutdown of the switch-host.

Test plan: docs/testplan/bmc/BMC_Graceful_Restart_Testplan.md

GRACEFUL_RESTART is deferred by the HLD, so this release has no graceful restart to test: a
restart is a shutdown followed by a startup.

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
    CHASSIS_STATUS_RESULT_COLUMN,
    CLI_DEFAULT_GRACEFUL_TIMEOUT,
    CMD_GRACEFUL_SHUT,
    CMD_POWER_ON,
    CMD_RESULT_ERROR,
    CMD_RESULT_POWER_ON_BLOCKED,
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
    OP_RESULT_PREEMPTED,
    OP_RESULT_SUCCESS_FORCED,
    OP_RESULT_SUCCESS_GRACEFUL,
    POWER_STATE_GRACEFUL_SHUTTING_DOWN,
    POWER_STATE_POWERED_OFF,
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

# A shutdown-timeout far above the default. The CLI sets no upper limit, so a value this large
# has to be taken like any other.
FAR_ABOVE_DEFAULT_TIMEOUT = 3600

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
        pytest.skip(f"bmcctld is not enabled on {duthost.facts['platform']}")

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
    bmc_graceful_env.clear_pre_check_flags()
    bmc_graceful_env.reset_pre_check_count()
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
                  f"op_result is {state.get('op_result')!r}, expected {expected_result!r}. HOST_STATE={state}")
    pytest_assert(state.get('op_reason') == expected_reason,
                  f"op_reason is {state.get('op_reason')!r}, expected {expected_reason!r}. HOST_STATE={state}")
    pytest_assert(state.get('op_trigger') == expected_trigger,
                  f"op_trigger is {state.get('op_trigger')!r}, expected {expected_trigger!r}")
    pytest_assert(state.get('device_power_state') == expected_power_state,
                  f"device_power_state is {state.get('device_power_state')!r}, expected {expected_power_state!r}")

    record = env.op_done_log(request_id)
    pytest_assert(record, f"no OP_DONE record in the BMC event log for request {request_id}")
    pytest_assert(record['result'] == expected_result and record['reason'] == expected_reason
                  and record['trigger'] == expected_trigger,
                  f"BMC event log disagrees with HOST_STATE: {record}")
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


def _assert_chassis_status_shows(env, expected_result):
    shown = env.chassis_status_result()
    pytest_assert(shown == expected_result,
                  f"'show chassis modules status' reports {CHASSIS_STATUS_RESULT_COLUMN}={shown!r} for "
                  f"SWITCH-HOST, expected {expected_result!r}:\n{env.chassis_status_text()}")


def _assert_graceful_reboot_cause(env):
    cause = env.host_reboot_cause()
    pytest_assert(CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC in cause,
                  f"switch-host reboot cause is {cause!r}, expected it to contain "
                  f"{CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC!r}. The graceful cause is written only after the "
                  f"host's own completion check passed.")


def _assert_pre_check_entered(env):
    """Assert the switch-host entered its pre-check once during the operation.

    This is what separates a broken transport, an unanswered wait or a failed pre-shutdown from
    the preconditions that skip the graceful leg outright: there, the pre-check never runs.
    The count lives on /host and survives the power cut, so it is read once the host is back.
    """
    ran = env.pre_check_count()
    pytest_assert(ran == 1,
                  f"the switch-host entered its pre-check {ran} time(s) during the operation, expected "
                  f"once; this case is about what happens after the BMC's request reached it")


def _assert_host_was_never_asked(env):
    """Assert no pre-shutdown request ever reached the switch-host.

    The test plan proves this with a packet capture on the BMC's side of the link. The
    pre-check's invocation count is the same fact read from the other end -- 'reboot -p' runs
    the pre-check only when a request arrived -- and it does not depend on a capture tool being
    present in the BMC image. Read it after the host is back: the count lives on /host and
    survives the power cut.
    """
    ran = env.pre_check_count()
    pytest_assert(ran == 0,
                  f"the switch-host ran its pre-check {ran} time(s); with the precondition under test "
                  f"the BMC should not have sent a request at all")


def _run_graceful_shutdown_pass(env, entry_point):
    """Run one graceful shutdown end to end and leave the switch-host back in service."""
    logger.info(f"Graceful shutdown pass via {entry_point}")
    previous_id = env.host_state().get('op_request_id')
    pre_boot = env.host_boot_time()

    if entry_point == 'CLI':
        result = env.shutdown_cli()
        pytest_assert(result.get('rc') == 0,
                      f"'config chassis modules shutdown SWITCH-HOST' failed: {result}")
        expected_trigger = TRIGGER_CLI_SHUTDOWN
        command_key = None
    else:
        command_key = env.submit(CMD_GRACEFUL_SHUT)
        expected_trigger = rack_manager_trigger(CMD_GRACEFUL_SHUT)

    request_id = env.wait_new_request_id(previous_id)
    _assert_graceful_record(env, request_id, expected_trigger, POWER_STATE_POWERED_OFF)

    pytest_assert(env.wait_host_powered_off(),
                  f"switch-host did not become OFFLINE and unreachable after the {entry_point} shutdown")
    _assert_chassis_status_shows(env, OP_RESULT_SUCCESS_GRACEFUL)

    if command_key is not None:
        row = env.wait_command(command_key)
        pytest_assert(row.get('status') == CMD_STATUS_DONE and row.get('result') == CMD_RESULT_SUCCESS,
                      f"Rack-Manager command row is {row}, expected status={CMD_STATUS_DONE} "
                      f"result={CMD_RESULT_SUCCESS}")

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
    logger.info(f"Forced shutdown pass, expecting op_reason {expected_reason}")
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
                  f"Rack-Manager command row is {row}, expected status={CMD_STATUS_DONE} "
                  f"result={CMD_RESULT_SUCCESS}. The operation itself succeeded; only its graceful leg "
                  f"was skipped or failed.")
    _assert_chassis_status_shows(env, OP_RESULT_SUCCESS_FORCED)
    return elapsed


def test_graceful_shutdown_records_proven_completion(graceful_case):
    """Graceful shutdown from the chassis CLI and from the Rack Manager.

    Both entry points run the same flow, the operation is positively attributed with a request
    id, and the next boot reports the graceful cause rather than the BMC power-down cause.
    """
    for entry_point in ('CLI', 'Rack Manager'):
        _run_graceful_shutdown_pass(graceful_case, entry_point)


def test_forced_when_bmc_is_not_qualified(graceful_case):
    """Forced shutdown: the BMC client certificate is not where GNMI_CLIENT|certs points.

    bmcctld resolves its credential paths again for every operation and falls back to nothing
    else, so pointing client_crt at a file that does not exist is enough to take the BMC out of
    qualification without restarting the daemon.
    """
    env = graceful_case
    with env.missing_client_cert():
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
    """Forced shutdown: the host runs its pre-check and the pre-check fails.

    This is the one degraded path where the handshake works end to end -- the request is sent,
    the host answers, and the answer is a failure. An op_reason of 'backend_answered' here
    would mean the host attached a status message to its report and bmcctld classified on that
    instead, which is a different classification of the same working handshake.
    """
    env = graceful_case
    with env.fail_pre_check():
        _run_forced_shutdown(env, OP_REASON_CHECK_FAILED)
    env.recover()
    _assert_pre_check_entered(env)


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
                      f"the operation never entered {POWER_STATE_GRACEFUL_SHUTTING_DOWN}, so there was no "
                      f"graceful wait to interrupt")
        pytest_assert(env.wait_pre_check_entered(timeout=MID_FLIGHT_WAIT_SECS),
                      "the switch-host never entered its pre-check; stopping gNMI now would break the "
                      "channel before the request rather than during the wait")
        env.stop_host_gnmi()

    with env.hold_pre_check():
        _run_forced_shutdown(env, OP_REASON_RPC_FAILURE, mid_flight=break_the_channel)
    env.recover()
    _assert_pre_check_entered(env)


def test_forced_when_host_never_answers(graceful_case):
    """Forced shutdown: the host is held in its pre-check until the deadline passes.

    Runs at the production timeout. The pre-check is held past it, so the host is alive and
    reachable throughout and simply never reports completion. Beyond the recorded reason, the
    elapsed time is checked independently of bmcctld's own accounting: an operation that gave
    up early would come back well under the configured timeout.
    """
    env = graceful_case
    timeout = CLI_DEFAULT_GRACEFUL_TIMEOUT

    def held_in_pre_check(_request_id):
        pytest_assert(env.wait_pre_check_entered(timeout=MID_FLIGHT_WAIT_SECS),
                      "the switch-host never entered its pre-check, so there is no unanswered wait to "
                      "run out")

    with env.timeout(timeout):
        with env.hold_pre_check():
            elapsed = _run_forced_shutdown(env, OP_REASON_DEADLINE, mid_flight=held_in_pre_check)
    env.recover()
    _assert_pre_check_entered(env)

    logger.info(f"Operation reached its terminal result {elapsed:.0f}s after it was admitted")
    floor = timeout - ELAPSED_POLL_SLACK_SECS
    pytest_assert(elapsed >= floor,
                  f"the operation reached its terminal result {elapsed:.0f}s after it was admitted, short "
                  f"of the {timeout}s timeout it was supposed to wait out (allowing "
                  f"{ELAPSED_POLL_SLACK_SECS}s of polling slack)")


def test_critical_leak_preempts_graceful_wait(graceful_case):
    """A critical leak lands while the BMC is waiting on the host's pre-shutdown.

    A leak outranks an operator's shutdown, so the operation has to give way rather than
    finish. The recorded result is read from the BMC event log: the leak's own power-off is
    admitted about a second after the preemption and overwrites HOST_STATE's terminal fields,
    so they cannot be read back reliably. The Rack Manager row does not carry PREEMPTED: like
    any command whose operation did not complete, it is closed FAILED with ERROR.
    """
    env = graceful_case
    previous_id = env.host_state().get('op_request_id')

    with env.leak_window():
        with env.hold_pre_check():
            command_key = env.submit(CMD_GRACEFUL_SHUT)
            request_id = env.wait_new_request_id(previous_id)
            pytest_assert(env.wait_power_state(request_id, POWER_STATE_GRACEFUL_SHUTTING_DOWN,
                                               timeout=MID_FLIGHT_WAIT_SECS),
                          f"the shutdown never entered {POWER_STATE_GRACEFUL_SHUTTING_DOWN}, so there was no "
                          f"wait to preempt")
            pytest_assert(env.wait_pre_check_entered(timeout=MID_FLIGHT_WAIT_SECS),
                          "the switch-host never entered its pre-check, so the operation was not yet "
                          "waiting on it when the leak was published")
            env.publish_critical_leak()
            record = env.wait_op_done_log(request_id)

        pytest_assert(record['result'] == OP_RESULT_PREEMPTED,
                      f"the shutdown was recorded {record['result']!r}, expected {OP_RESULT_PREEMPTED!r}: a "
                      f"critical leak has to take the operation away, not let it run to completion. "
                      f"Record={record}")
        pytest_assert(record['reason'] == OP_REASON_PREEMPTED,
                      f"op_reason is {record['reason']!r}, expected {OP_REASON_PREEMPTED!r}. Record={record}")

        row = env.wait_command(command_key)
        pytest_assert(row.get('status') == CMD_STATUS_FAILED and row.get('result') == CMD_RESULT_ERROR,
                      f"Rack-Manager command row is {row}, expected status={CMD_STATUS_FAILED} "
                      f"result={CMD_RESULT_ERROR}; the submitter has to be told its shutdown did not complete")

        pytest_assert(env.wait_host_powered_off(),
                      "the switch-host is still up; the leak's own power-off has to follow the preemption")
    env.recover()


def test_critical_leak_blocks_every_power_raise(graceful_case):
    """While a critical leak stands, every way of raising power is refused.

    Two entry points reach the power-on path, and they report the refusal in different places:
    the Rack Manager fails the command outright, and the chassis CLI is blocked before an
    operation is even admitted, which only the event log records. Both name the same reason and
    both have to leave the switch-host down.
    """
    env = graceful_case

    with env.leak_window():
        mark = env.event_log_mark()
        env.publish_critical_leak()
        pytest_assert(env.wait_host_powered_off(),
                      "the critical leak did not take the switch-host down, so there is no refused "
                      "power raise to test")

        power_on_key = env.submit(CMD_POWER_ON)
        row = env.wait_command(power_on_key)
        pytest_assert(row.get('status') == CMD_STATUS_FAILED
                      and row.get('result') == CMD_RESULT_POWER_ON_BLOCKED,
                      f"Rack-Manager {CMD_POWER_ON} row is {row}, expected status={CMD_STATUS_FAILED} "
                      f"result={CMD_RESULT_POWER_ON_BLOCKED}")

        env.shutdown_cli()
        env.startup_cli()
        blocked = env.wait_event_log_since(mark, 'CHASSIS_MODULE admin_up')
        pytest_assert(CMD_RESULT_POWER_ON_BLOCKED in blocked,
                      f"the BMC event log does not record the chassis startup being blocked by the leak; "
                      f"last matching line was {blocked!r}")

        pytest_assert(not env.host_is_online(),
                      "the switch-host is up again; no power raise may succeed while a critical leak stands")
    env.recover()


def test_shutdown_timeout_configuration_boundaries(graceful_case):
    """The shutdown-timeout this feature adds takes any non-negative integer and refuses the rest.

    The only case in the suite that removes no power. It is about the CLI's own validation, so
    a refusal has to be visible in the command's exit status rather than only in a log, and it
    has to leave the configured value alone.
    """
    env = graceful_case

    # set_timeout() asserts the command succeeded and reads the value back from CONFIG_DB.
    # 0 is the lower boundary: bmcctld reads it as 'skip the graceful leg'. There is no upper
    # one, so a value far above the default has to be taken as well.
    for seconds in (0, 1, CLI_DEFAULT_GRACEFUL_TIMEOUT, FAR_ABOVE_DEFAULT_TIMEOUT):
        env.set_timeout(seconds)

    accepted = env.configured_timeout()
    for rejected in ('-1', 'abc', '1.5'):
        result = env.set_timeout_cli(rejected)
        pytest_assert(result.get('rc') != 0,
                      f"'shutdown-timeout SWITCH-HOST {rejected}' was accepted; a value that is not a "
                      f"non-negative whole number of seconds has to be refused. Result={result}")
        pytest_assert(env.configured_timeout() == accepted,
                      f"the refused shutdown-timeout {rejected!r} still changed CONFIG_DB: {accepted!r} -> "
                      f"{env.configured_timeout()!r}")


def test_operation_record_is_complete_and_visible(graceful_case):
    """Everything an operator can see once a graceful shutdown has finished.

    The same operation is recorded in four places written by different code paths -- HOST_STATE,
    the BMC event log, the chassis CLI and the Rack Manager's receipt. This case is about them
    agreeing, and about the CLI's pre-existing columns not having been disturbed to make room
    for the one the feature adds. The receipt carries only a status and a result; the request
    id lives in HOST_STATE and the event log.
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
                      f"HOST_STATE has no {field}, so the finished operation cannot be read back in full: "
                      f"{state}")
    pytest_assert(state['op_request_id'] == request_id,
                  f"HOST_STATE is attributed to request {state['op_request_id']!r}, expected {request_id!r}")

    pytest_assert(env.wait_host_powered_off(),
                  "switch-host did not become OFFLINE and unreachable after the shutdown")

    columns = env.chassis_status_columns()
    leading = columns[:len(CHASSIS_STATUS_BASE_COLUMNS)]
    pytest_assert(leading == list(CHASSIS_STATUS_BASE_COLUMNS),
                  f"'show chassis modules status' no longer leads with {list(CHASSIS_STATUS_BASE_COLUMNS)}; "
                  f"the columns that predate this feature have to keep their order. Columns={columns}")
    added = columns[len(CHASSIS_STATUS_BASE_COLUMNS):]
    pytest_assert(CHASSIS_STATUS_RESULT_COLUMN in added,
                  f"'show chassis modules status' does not add a {CHASSIS_STATUS_RESULT_COLUMN} column. "
                  f"Columns={columns}")
    _assert_chassis_status_shows(env, OP_RESULT_SUCCESS_GRACEFUL)

    row = env.wait_command(command_key)
    pytest_assert(row.get('status') == CMD_STATUS_DONE and row.get('result') == CMD_RESULT_SUCCESS,
                  f"the Rack-Manager receipt is {row}, expected status={CMD_STATUS_DONE} "
                  f"result={CMD_RESULT_SUCCESS}")

    # The test plan collects a support bundle and looks for HOST_STATE and the event log inside
    # it. 'show techsupport' takes minutes on this platform and would only prove that these two
    # sources were copied, so they are read where they are written instead.
    pytest_assert(env.op_done_log(request_id),
                  f"the BMC event log at {BMC_EVENT_LOG} keeps no record of request {request_id}, so the "
                  f"operation cannot be reconstructed after the fact")

    env.recover()

    # Reboot-cause history can only be read once the host is back up. The graceful cause lands
    # in the Cause column; the BMC power-down behind it is the comment.
    latest = env.host_reboot_cause_history_latest()
    pytest_assert(CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC in latest,
                  f"the newest reboot-cause history row is {latest!r}, expected it to name "
                  f"{CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC!r}")
    pytest_assert(CAUSE_POWER_DOWN_FROM_BMC in latest,
                  f"the newest reboot-cause history row is {latest!r}, expected its comment to carry the "
                  f"hardware cause {CAUSE_POWER_DOWN_FROM_BMC!r}")
