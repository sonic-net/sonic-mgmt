"""PTF-local fence for one HFT run's in-memory InfluxDB process."""

import fcntl
import os
import re
import select
import signal
import stat
import sys
import time
from pathlib import Path


ROOT = Path("/tmp")


def stop_pid(pid, node):
    # Pin the process before checking argv: the numeric PID may have been reused.
    try:
        handle = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            return
        if (argv[0].rsplit(b"/", 1)[-1] != b"influxdb3" or
                argv[1:6] != [b"serve", b"--object-store", b"memory", b"--node-id", node.encode()]):
            return  # Original exited; never signal a different process.
        exited = select.poll()
        exited.register(handle, select.POLLIN)
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                signal.pidfd_send_signal(handle, sig)
            except ProcessLookupError:
                return
            if exited.poll(10000):
                return
        raise RuntimeError(f"InfluxDB for {node} has not exited")
    finally:
        os.close(handle)


def lifecycle(action, node, port):
    if not re.fullmatch(r"sonic-mgmt-hft-[A-Za-z0-9_-]+", node):
        raise ValueError("Invalid HFT run name")
    work = ROOT / (node + "-sink")
    if action == "prepare":
        # Check kernel/runtime support before arming the DUT journal.
        probe = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(probe, 0)
        finally:
            os.close(probe)
        work.mkdir(mode=0o700)
        (work / "ready").touch(mode=0o600)
        return
    try:
        fd = os.open(work, os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if action == "stop":
            return
        raise
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"PTF sink {node} still has an in-flight operation; retry cleanup")
                time.sleep(0.1)
        st = os.fstat(fd)
        if not work.exists() and action == "stop":
            return
        if (not os.path.samestat(st, work.lstat()) or stat.S_IMODE(st.st_mode) != 0o700 or
                st.st_uid != os.geteuid()):
            raise RuntimeError("PTF sink reservation changed")
        ready, pidfile, pending, log = (work / name for name in ("ready", "pid", "pid.tmp", "influx.log"))
        if action == "start":
            ready.unlink()  # One-shot permit. A retry or delayed launch cannot recreate it.
            # This helper becomes influxdb3. Its non-inheritable flock descriptor
            # closes at exec, not between fork and PID publication.
            with pending.open("x") as f:
                f.write(str(os.getpid()))
            pending.replace(pidfile)
            with log.open("xb") as f:
                os.dup2(f.fileno(), 1)
                os.dup2(f.fileno(), 2)
            os.execvp("influxdb3", ["influxdb3", "serve", "--object-store", "memory", "--node-id", node,
                                    f"--http-bind=0.0.0.0:{int(port)}", "--without-auth"])
        elif action == "stop":
            ready.unlink(missing_ok=True)
            if pidfile.exists():
                stop_pid(int(pidfile.read_text()), node)
                pidfile.unlink()
            log.unlink(missing_ok=True)
            pending.unlink(missing_ok=True)
            work.rmdir()  # Still locked. A queued start cannot recreate or reuse this directory.
        else:
            raise ValueError(f"Unknown PTF sink action: {action}")
    finally:
        os.close(fd)


if __name__ == "__main__":
    lifecycle(*sys.argv[1:])
