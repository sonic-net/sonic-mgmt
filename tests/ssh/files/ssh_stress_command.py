#!/usr/bin/env python3
"""Run and fence SSH-stress commands by unique ownership token."""

import argparse
import base64
import fcntl
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager

TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")
TERMINATE_GRACE = 2
CANCEL_WAIT = 5
WRAPPER_WAIT = 2 * (TERMINATE_GRACE + CANCEL_WAIT) + 1


def _validate_token(token):
    if not TOKEN_PATTERN.match(token):
        raise ValueError("Invalid command token")


def _token_dir(state_root, token):
    _validate_token(token)
    return os.path.join(state_root, token)


def _atomic_write(path, data):
    temporary = path + ".tmp.{}".format(os.getpid())
    with open(temporary, "w") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


@contextmanager
def _locked_state(state_root, token):
    directory = _token_dir(state_root, token)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    lock_path = os.path.join(directory, "lock")
    with open(lock_path, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield directory


def _parse_process_start_time(stat_line):
    closing_parenthesis = stat_line.rfind(")")
    if closing_parenthesis < 0:
        raise ValueError("Invalid /proc stat data")
    # Fields after the command name start at proc(5) field 3; starttime is 22.
    fields = stat_line[closing_parenthesis + 1:].split()
    return fields[19]


def _process_start_time(pid):
    try:
        with open("/proc/{}/stat".format(pid)) as stream:
            return _parse_process_start_time(stream.read())
    except (FileNotFoundError, IndexError, ProcessLookupError, ValueError):
        return None


def _owned_process_alive(pid, start_time):
    return _process_start_time(pid) == start_time


def _process_group_alive(process_group):
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False


def _signal_owned_process(pid, start_time, signum):
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        try:
            pidfd = os.pidfd_open(pid)
        except ProcessLookupError:
            return False
        try:
            if not _owned_process_alive(pid, start_time):
                return False
            signal.pidfd_send_signal(pidfd, signum)
            return True
        finally:
            os.close(pidfd)
    if not _owned_process_alive(pid, start_time):
        return False
    os.kill(pid, signum)
    return True


def _read_owner(directory):
    try:
        with open(os.path.join(directory, "owner.json")) as stream:
            owner = json.load(stream)
        parsed = {
            "pid": int(owner["pid"]),
            "start_time": str(owner["start_time"]),
        }
        if "wrapper_pid" in owner:
            parsed.update({
                "wrapper_pid": int(owner["wrapper_pid"]),
                "wrapper_start_time": str(owner["wrapper_start_time"]),
            })
        return parsed
    except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _mark_done(directory, return_code):
    _atomic_write(
        os.path.join(directory, "done.json"),
        json.dumps({"return_code": return_code}),
    )
    try:
        os.unlink(os.path.join(directory, "owner.json"))
    except FileNotFoundError:
        # Cancellation may have already removed ownership metadata.
        pass


def _terminate_process_group(process_group):
    if not _process_group_alive(process_group):
        return
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.monotonic() + TERMINATE_GRACE
    while time.monotonic() < deadline:
        if not _process_group_alive(process_group):
            return
        time.sleep(0.05)

    if _process_group_alive(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            return

    deadline = time.monotonic() + CANCEL_WAIT
    while time.monotonic() < deadline:
        if not _process_group_alive(process_group):
            return
        time.sleep(0.05)
    raise RuntimeError("Owned command process group did not terminate")


def _terminate_child_process(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=TERMINATE_GRACE)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The process group exited between the timeout and escalation.
            pass
        process.wait(timeout=CANCEL_WAIT)
    _terminate_process_group(process.pid)


def _terminate_owned_process(pid, start_time):
    if not _owned_process_alive(pid, start_time):
        if not _process_group_alive(pid):
            return
    _terminate_process_group(pid)


def reserve_command(state_root, token):
    with _locked_state(state_root, token) as directory:
        _atomic_write(os.path.join(directory, "reserved"), "1")


def cancel_command(state_root, token):
    with _locked_state(state_root, token) as directory:
        _atomic_write(os.path.join(directory, "cancelled"), "1")
        owner = _read_owner(directory)

    if owner is not None:
        wrapper_pid = owner.get("wrapper_pid")
        if wrapper_pid is not None:
            _signal_owned_process(
                wrapper_pid,
                owner["wrapper_start_time"],
                signal.SIGTERM,
            )
            deadline = time.monotonic() + WRAPPER_WAIT
            done_path = os.path.join(directory, "done.json")
            while time.monotonic() < deadline:
                if os.path.exists(done_path):
                    break
                time.sleep(0.05)
            if not os.path.exists(done_path):
                raise RuntimeError(
                    "Command wrapper did not confirm process-tree termination"
                )
        else:
            _terminate_owned_process(
                owner["pid"], owner["start_time"]
            )

    with _locked_state(state_root, token) as directory:
        _mark_done(directory, 124)


def run_command(
    state_root,
    token,
    encoded_command,
    run_user=None,
    stdout=None,
    stderr=None,
):
    stdout = stdout or sys.stdout.buffer
    stderr = stderr or sys.stderr.buffer
    command = base64.b64decode(encoded_command).decode("utf-8")
    process = None
    directory = None

    def terminate_child(_signum, _frame):
        if process is not None:
            _terminate_child_process(process)
        raise SystemExit(143)

    install_handlers = threading.current_thread() is threading.main_thread()
    previous_term = None
    previous_int = None
    try:
        if install_handlers:
            previous_term = signal.signal(signal.SIGTERM, terminate_child)
            previous_int = signal.signal(signal.SIGINT, terminate_child)
        with _locked_state(state_root, token) as directory:
            if os.path.exists(os.path.join(directory, "cancelled")):
                _mark_done(directory, 124)
                return 124
            child_setup = None
            start_new_session = True
            child_env = dict(
                os.environ, SSH_STRESS_COMMAND_TOKEN=token
            )
            if os.geteuid() == 0 and run_user is not None:
                account = pwd.getpwnam(run_user)

                def demote_and_start_session():
                    os.setsid()
                    os.initgroups(account.pw_name, account.pw_gid)
                    os.setgid(account.pw_gid)
                    os.setuid(account.pw_uid)

                child_setup = demote_and_start_session
                start_new_session = False
                child_env.update({
                    "HOME": account.pw_dir,
                    "LOGNAME": account.pw_name,
                    "USER": account.pw_name,
                })
            process = subprocess.Popen(
                ["/bin/bash", "-lc", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=start_new_session,
                preexec_fn=child_setup,
                env=child_env,
            )
            start_time = _process_start_time(process.pid)
            if start_time is None:
                raise RuntimeError("Could not identify command process")
            owner = {"pid": process.pid, "start_time": start_time}
            if install_handlers:
                owner.update({
                    "wrapper_pid": os.getpid(),
                    "wrapper_start_time": _process_start_time(os.getpid()),
                })
            _atomic_write(
                os.path.join(directory, "owner.json"),
                json.dumps(owner),
            )

        command_stdout, command_stderr = process.communicate()
        # A synchronous stress command must not leave detached work in its
        # uniquely owned process group after its leader exits.
        _terminate_process_group(process.pid)
        stdout.write(command_stdout)
        stdout.flush()
        stderr.write(command_stderr)
        stderr.flush()
        return_code = process.returncode
        with _locked_state(state_root, token) as directory:
            _mark_done(directory, return_code)
        return return_code
    finally:
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)
        if previous_int is not None:
            signal.signal(signal.SIGINT, previous_int)
        if directory is not None and process is not None:
            done_path = os.path.join(directory, "done.json")
            if not os.path.exists(done_path):
                if process.poll() is None:
                    _terminate_child_process(process)
                else:
                    # A leader exit does not prove that the owned process group
                    # is empty; retain owner.json if fencing cannot be proved.
                    _terminate_process_group(process.pid)
                with _locked_state(state_root, token) as directory:
                    if not os.path.exists(done_path):
                        _mark_done(directory, process.returncode)


def control(state_root):
    print("READY", flush=True)
    for line in sys.stdin:
        parts = line.strip().split()
        if not parts:
            continue
        if parts == ["QUIT"]:
            return 0
        if len(parts) != 2 or parts[0] not in ("RESERVE", "CANCEL"):
            print("ERROR invalid-request", flush=True)
            continue
        action, token = parts
        try:
            if action == "RESERVE":
                reserve_command(state_root, token)
                print("RESERVED {}".format(token), flush=True)
                continue
            cancel_command(state_root, token)
            print("CANCELLED {}".format(token), flush=True)
        except Exception as error:  # noqa: B902 - remote protocol must report
            print(
                "ERROR {} {}".format(token, str(error).replace("\n", " ")),
                flush=True,
            )
    return 0


def cancel_all(state_root):
    if not os.path.isdir(state_root):
        return 0
    failures = []
    for token in os.listdir(state_root):
        if not TOKEN_PATTERN.match(token):
            continue
        try:
            cancel_command(state_root, token)
        except Exception as error:  # noqa: B902 - report every owned command
            failures.append("{}: {}".format(token, error))
    if failures:
        print("; ".join(failures), file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", required=True)
    subparsers = parser.add_subparsers(dest="action", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--run-user", required=True)
    run_parser.add_argument("token")
    run_parser.add_argument("encoded_command")
    subparsers.add_parser("control")
    cancel_parser = subparsers.add_parser("cancel")
    cancel_parser.add_argument("token")
    subparsers.add_parser("cancel-all")
    args = parser.parse_args()

    os.makedirs(args.state_root, mode=0o700, exist_ok=True)
    if args.action == "run":
        return run_command(
            args.state_root,
            args.token,
            args.encoded_command,
            run_user=args.run_user,
        )
    if args.action == "control":
        return control(args.state_root)
    if args.action == "cancel":
        cancel_command(args.state_root, args.token)
        return 0
    return cancel_all(args.state_root)


if __name__ == "__main__":
    sys.exit(main())
