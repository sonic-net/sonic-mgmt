import fcntl
import logging
import time

from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from threading import Lock
from typing import Tuple

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def is_initial_checks_active(request):
    parallel_state_file = request.config.getoption("--parallel_state_file")
    try:
        last_line = read_last_line_of_file(parallel_state_file)
        if not last_line:
            return False

        return last_line.split(',')[1] in (
            ParallelStatus.SETUP_STARTED.value,
            ParallelStatus.TEARDOWN_STARTED.value,
        )
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


class ParallelStatus(Enum):
    IDLE = "idle"
    SETUP_READY = "setup_ready"
    SETUP_STARTED = "setup_started"
    SETUP_COMPLETED = "setup_completed"
    TESTS_COMPLETED = "tests_completed"
    TEARDOWN_STARTED = "teardown_started"
    TEARDOWN_COMPLETED = "teardown_completed"
    SANITY_CHECK_FAILED = "sanity_check_failed"
    CONFIG_RELOAD_READY = "config_reload_ready"
    CONFIG_RELOAD_COMPLETED = "config_reload_completed"
    REBOOT_READY = "reboot_ready"
    REBOOT_COMPLETED = "reboot_completed"


class ParallelRole(Enum):
    LEADER = "leader"
    FOLLOWER = "follower"
    UNKNOWN = "unknown"


class ParallelMode(Enum):
    FULL_PARALLEL = "FULL_PARALLEL"
    RP_FIRST = "RP_FIRST"


class ParallelCoordinator:
    _instance = None
    _lock = Lock()

    def __new__(cls, num_followers: int, state_file: str, mode: str) -> 'ParallelCoordinator':
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ParallelCoordinator, cls).__new__(cls)
                    cls._instance._initialize(num_followers, state_file, mode)

        return cls._instance

    def _initialize(self, num_followers: int, state_file: str, mode: str) -> None:
        self.num_followers = num_followers
        self.state_file = state_file
        self.mode = mode
        self._set_initial_status()

    def _set_initial_status(self) -> None:
        with open(self.state_file, 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            content = f.readlines()
            # only set the initial status if the file is empty
            if not content:
                f.write("{},{},{},{},{}\n".format(
                    datetime.now(timezone.utc),
                    ParallelStatus.IDLE.value,
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
                return ParallelStatus.IDLE.value, 0

            _, status_value, acknowledgments, _, _ = content.split(',')
            return status_value, int(acknowledgments)
        except FileNotFoundError:
            logger.warning("State file not found, returning IDLE status")
            return ParallelStatus.IDLE.value, 0

    def _is_expected_status(self, expected_status: ParallelStatus) -> bool:
        status_value = self.exit_if_failed_status()
        return status_value == expected_status.value

    def _acknowledge_status(self, ack_status: ParallelStatus, is_leader: bool, hostname: str) -> None:
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
                datetime.now(timezone.utc),
                ack_status.value,
                int(acknowledgments) + 1,
                ParallelRole.LEADER.value if is_leader else ParallelRole.FOLLOWER.value,
                hostname,
            ))

            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def _is_all_acknowledged(self, ack_status: ParallelStatus, required_ack: int) -> bool:
        if ack_status in {ParallelStatus.CONFIG_RELOAD_READY, ParallelStatus.REBOOT_READY}:
            self.exit_if_early_complete()

        status_value, acknowledgments = self._read_state()
        return status_value == ack_status.value and acknowledgments >= required_ack

    def _mark_status(self, status_to_mark: ParallelStatus, is_leader: bool, hostname: str) -> None:
        with open(self.state_file, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            lines = f.readlines()
            if not lines:
                raise Exception("State file is empty")

            last_line = lines[-1].strip()
            _, status_value, acknowledgments, _, _ = last_line.split(',')
            f.write("{},{},{},{},{}\n".format(
                datetime.now(timezone.utc),
                status_to_mark.value,
                int(acknowledgments) + 1 if status_value == status_to_mark.value else 1,
                ParallelRole.LEADER.value if is_leader else ParallelRole.FOLLOWER.value,
                hostname,
            ))

            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def mark_and_wait_for_status(self, status_to_mark: ParallelStatus, hostname: str, is_leader: bool) -> None:
        if (self.num_followers > 0 and
                status_to_mark in {ParallelStatus.CONFIG_RELOAD_READY, ParallelStatus.REBOOT_READY}):
            self.exit_if_early_complete()

        self._mark_status(status_to_mark, is_leader, hostname)
        if self.num_followers == 0:
            logger.info("Skip waiting for all hosts to be ready for setup")
            return

        status_to_timeout = {
            ParallelStatus.SETUP_READY: 600,  # 10 minutes
            ParallelStatus.CONFIG_RELOAD_READY: 7200,  # 2 hours
            ParallelStatus.CONFIG_RELOAD_COMPLETED: 7200,  # 2 hours
            ParallelStatus.REBOOT_READY: 10800,  # 3 hours
            ParallelStatus.REBOOT_COMPLETED: 10800,  # 3 hours
            ParallelStatus.TESTS_COMPLETED: 25200,  # 7 hours
        }

        status_timeout = status_to_timeout.get(status_to_mark, 600)
        wait_interval = 2
        required_ack = self.num_followers if self.mode == ParallelMode.RP_FIRST.value else self.num_followers + 1
        if not wait_until(
            status_timeout,
            wait_interval,
            0,
            self._is_all_acknowledged, status_to_mark, required_ack,
        ):
            pt_assert(False, "Timed out waiting for all hosts to be ready for status {}".format(status_to_mark))

        # Wait longer than the interval to prevent the situation where a host starts writing new status to the file
        # while others are still within the waiting interval for the status_to_mark
        time.sleep(wait_interval * 5)

    def set_new_status(self, new_status: ParallelStatus, is_leader: bool, hostname: str, ack: int = 0) -> None:
        with open(self.state_file, 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write("{},{},{},{},{}\n".format(
                datetime.now(timezone.utc),
                new_status.value,
                ack,
                ParallelRole.LEADER.value if is_leader else ParallelRole.FOLLOWER.value,
                hostname,
            ))

            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def wait_and_ack_status_for_followers(self, expected_status: ParallelStatus, is_leader: bool,
                                          hostname: str) -> None:
        if self.num_followers == 0 or self.mode == ParallelMode.RP_FIRST.value:
            self.exit_if_failed_status()
            logger.info("Skip waiting and acknowledging status {} for followers".format(expected_status))
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

    def wait_for_all_followers_ack(self, ack_status: ParallelStatus) -> None:
        if self.num_followers == 0 or self.mode == ParallelMode.RP_FIRST.value:
            logger.info("Skip waiting for all followers' ACK for status {}".format(ack_status))
            return

        status_to_timeout = {
            ParallelStatus.SETUP_COMPLETED: 1200,  # 20 minutes
            ParallelStatus.TEARDOWN_COMPLETED: 1200,  # 20 minutes
        }

        status_timeout = status_to_timeout.get(ack_status, 120)
        logger.info("Waiting for all followers' ACK for status {} with timeout {}".format(ack_status, status_timeout))
        if not wait_until(
            status_timeout,
            5,
            0,
            self._is_all_acknowledged, ack_status, self.num_followers
        ):
            pt_assert(False, "Timed out waiting for all followers' ACK for status {}".format(ack_status))

    def set_failed_status(self, failed_status: ParallelStatus, is_leader: bool, hostname: str) -> None:
        self.set_new_status(failed_status, is_leader, hostname, ack=-1)

    def exit_if_failed_status(self) -> str:
        status_value, _ = self._read_state()
        if status_value in {ParallelStatus.SANITY_CHECK_FAILED.value}:
            pt_assert(False, "Exiting test due to failed status: {}".format(status_value))

        return status_value

    def exit_if_early_complete(self) -> str:
        status_value, _ = self._read_state()
        if status_value == ParallelStatus.TESTS_COMPLETED.value:
            pt_assert(
                False,
                "Exiting test due to early complete status on other hosts: {}".format(status_value)
            )

        return status_value


def synchronized_config_reload(func):
    """Decorator that adds parallel-run feature around config_reload."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.info("Running config_reload via synchronized_config_reload decorator")
        # Expect callers to pass parallel_run_context as a kwarg.
        parallel_run_context = kwargs.pop("parallel_run_context", (False, "", False, -1, "", ""))
        if not parallel_run_context:
            logger.info("Running original config_reload as parallel_run_context is falsy")
            return func(*args, **kwargs)

        is_par_run, target_hostname, is_par_leader, par_followers, par_state_file, par_mode = parallel_run_context
        if par_followers == -1:
            logger.info("Running original config_reload as par_followers is -1")
            return func(*args, **kwargs)

        if not is_par_run:
            logger.info("Running original config_reload as is_par_run is False")
            return func(*args, **kwargs)

        logger.info("Running config_reload in parallel")
        parallel_coordinator = ParallelCoordinator(par_followers, par_state_file, par_mode)
        parallel_coordinator.mark_and_wait_for_status(
            ParallelStatus.CONFIG_RELOAD_READY,
            target_hostname,
            is_par_leader,
        )

        try:
            logger.info("Starting config reload in parallel for host: {}".format(target_hostname))
            result = func(*args, **kwargs)
            logger.info("Config reload in parallel completed successfully for host: {}".format(target_hostname))
        except BaseException:
            logger.error("Config reload in parallel failed for host: {}".format(target_hostname))
            raise
        finally:
            parallel_coordinator.mark_and_wait_for_status(
                ParallelStatus.CONFIG_RELOAD_COMPLETED,
                target_hostname,
                is_par_leader,
            )

        return result

    return wrapper


def synchronized_reboot(func):
    """Decorator that adds parallel-run feature around reboot."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.info("Running reboot via synchronized_reboot decorator")
        # Expect callers to pass parallel_run_context as a kwarg.
        parallel_run_context = kwargs.pop("parallel_run_context", (False, "", False, -1, "", ""))
        if not parallel_run_context:
            logger.info("Running original reboot as parallel_run_context is falsy")
            return func(*args, **kwargs)

        is_par_run, target_hostname, is_par_leader, par_followers, par_state_file, par_mode = parallel_run_context
        if par_followers == -1:
            logger.info("Running original reboot as par_followers is -1")
            return func(*args, **kwargs)

        if not is_par_run:
            logger.info("Running original reboot as is_par_run is False")
            return func(*args, **kwargs)

        logger.info("Running reboot in parallel")
        parallel_coordinator = ParallelCoordinator(par_followers, par_state_file, par_mode)
        parallel_coordinator.mark_and_wait_for_status(ParallelStatus.REBOOT_READY, target_hostname, is_par_leader)
        try:
            logger.info("Starting reboot in parallel for host: {}".format(target_hostname))
            result = func(*args, **kwargs)
            logger.info("Reboot in parallel completed successfully for host: {}".format(target_hostname))
        except BaseException:
            logger.error("Reboot in parallel failed for host: {}".format(target_hostname))
            raise
        finally:
            parallel_coordinator.mark_and_wait_for_status(
                ParallelStatus.REBOOT_COMPLETED,
                target_hostname,
                is_par_leader,
            )

        return result

    return wrapper
