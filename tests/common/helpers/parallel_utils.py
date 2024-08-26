import fcntl
import logging

from datetime import datetime
from enum import Enum
from threading import Lock
from typing import Tuple

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def config_reload_parallel_compatible(node, results, *args, **kwargs):
    return config_reload(node, *args, **kwargs)


def is_initial_checks_active(request):
    parallel_state_file = request.config.getoption("--parallel_state_file")
    try:
        last_line = read_last_line_of_file(parallel_state_file)
        if not last_line:
            return False

        return last_line.split(',')[1].endswith("started")
    except FileNotFoundError:
        logger.info("State file {} not found".format(parallel_state_file))
        return False


def read_last_line_of_file(file, lock_type=fcntl.LOCK_SH):
    try:
        with open(file, 'r') as f:
            fcntl.flock(f, lock_type)
            lines = f.readlines()
            fcntl.flock(f, fcntl.LOCK_UN)
            return lines[-1].strip() if lines else ""
    except FileNotFoundError as e:
        raise e


class InitialCheckStatus(Enum):
    IDLE = "idle"
    SETUP_STARTED = "setup_started"
    SETUP_COMPLETED = "setup_completed"
    TESTS_COMPLETED = "tests_completed"
    TEARDOWN_STARTED = "teardown_started"
    TEARDOWN_COMPLETED = "teardown_completed"
    SANITY_CHECK_FAILED = "sanity_check_failed"


class ParallelRole(Enum):
    LEADER = "leader"
    FOLLOWER = "follower"
    UNKNOWN = "unknown"


class InitialCheckState:
    _instance = None
    _lock = Lock()

    def __new__(cls, num_followers: int, state_file: str) -> 'InitialCheckState':
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(InitialCheckState, cls).__new__(cls)
                    cls._instance._initialize(num_followers, state_file)

        return cls._instance

    def _initialize(self, num_followers: int, state_file: str) -> None:
        self.num_followers = num_followers
        self.should_wait = num_followers > 0
        self.state_file = state_file
        self._set_initial_status()

    def _set_initial_status(self) -> None:
        with open(self.state_file, 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            content = f.readlines()
            # only set the initial status if the file is empty
            if not content:
                f.write("{},{},{},{},{}\n".format(
                    datetime.utcnow(),
                    InitialCheckStatus.IDLE.value,
                    0,
                    ParallelRole.UNKNOWN.value,
                    "unknown",
                ))

                f.flush()
            else:
                logger.info("State file already contains data, skipping initial status setup")

            fcntl.flock(f, fcntl.LOCK_UN)

    def _read_state(self) -> Tuple[str, int]:
        try:
            content = read_last_line_of_file(self.state_file)
            if not content:
                logger.warning("State file is empty, returning IDLE status")
                return InitialCheckStatus.IDLE.value, 0

            _, status_value, acknowledgments, _, _ = content.split(',')
            return status_value, int(acknowledgments)
        except FileNotFoundError:
            logger.warning("State file not found, returning IDLE status")
            return InitialCheckStatus.IDLE.value, 0

    def _is_expected_status(self, expected_status: InitialCheckStatus) -> bool:
        status_value, _ = self._read_state()
        if status_value == InitialCheckStatus.SANITY_CHECK_FAILED.value:
            pt_assert(False, "Leader node sanity check failed. Exiting the test.")

        return status_value == expected_status.value

    def _acknowledge_status(self, ack_status: InitialCheckStatus, is_leader: bool, hostname: str) -> None:
        with open(self.state_file, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            lines = f.readlines()
            if not lines:
                raise Exception("State file is empty")

            last_line = lines[-1].strip()
            _, status_value, acknowledgments, _, _ = last_line.split(',')
            if status_value != ack_status.value:
                raise Exception("Cannot acknowledge status {} when status is {}".format(ack_status, status_value))

            f.write("{},{},{},{},{}\n".format(
                datetime.utcnow(),
                ack_status.value,
                int(acknowledgments) + 1,
                ParallelRole.LEADER.value if is_leader else ParallelRole.FOLLOWER.value,
                hostname,
            ))

            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def _is_all_acknowledged(self, ack_status: InitialCheckStatus) -> bool:
        status_value, acknowledgments = self._read_state()
        return status_value == ack_status.value and acknowledgments >= self.num_followers

    def mark_tests_completed_for_follower(self, hostname: str) -> None:
        with open(self.state_file, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            lines = f.readlines()
            if not lines:
                raise Exception("State file is empty")

            last_line = lines[-1].strip()
            _, status_value, acknowledgments, _, _ = last_line.split(',')
            f.write("{},{},{},{},{}\n".format(
                datetime.utcnow(),
                InitialCheckStatus.TESTS_COMPLETED.value,
                int(acknowledgments) + 1 if status_value == InitialCheckStatus.TESTS_COMPLETED.value else 1,
                ParallelRole.FOLLOWER.value,
                hostname,
            ))

            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def set_new_status(self, new_status: InitialCheckStatus, is_leader: bool, hostname: str) -> None:
        with open(self.state_file, 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write("{},{},{},{},{}\n".format(
                datetime.utcnow(),
                new_status.value,
                0,
                ParallelRole.LEADER.value if is_leader else ParallelRole.FOLLOWER.value,
                hostname,
            ))

            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def wait_and_acknowledge_status(self, expected_status: InitialCheckStatus, is_leader: bool, hostname: str) -> None:
        if not self.should_wait:
            status_value, _ = self._read_state()
            if status_value == InitialCheckStatus.SANITY_CHECK_FAILED.value:
                pt_assert(False, "Leader node sanity check failed. Exiting the test.")

            logger.info("Skip waiting and acknowledging status")
            return

        if wait_until(
            432000,
            10,
            0,
            self._is_expected_status, expected_status,
        ):
            self._acknowledge_status(expected_status, is_leader, hostname)
        else:
            pt_assert(False, "Timed out waiting for status {}".format(expected_status))

    def wait_for_all_acknowledgments(self, ack_status: InitialCheckStatus) -> None:
        if not self.should_wait:
            logger.info("Skip waiting for all acknowledgments")
            return

        status_to_timeout = {
            InitialCheckStatus.SETUP_COMPLETED: 1200,
            InitialCheckStatus.TESTS_COMPLETED: 432000,
            InitialCheckStatus.TEARDOWN_COMPLETED: 1200,
        }

        if not wait_until(
            status_to_timeout.get(ack_status, 120),
            5,
            0,
            self._is_all_acknowledged, ack_status,
        ):
            pt_assert(False, "Timed out waiting for all acknowledgments for status {}".format(ack_status))
