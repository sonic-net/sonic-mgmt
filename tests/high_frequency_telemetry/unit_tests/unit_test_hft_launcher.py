"""The generated launcher must stay fenced when its DUT helper dies before Docker create."""
import fcntl
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

import pytest


FILES = Path(__file__).resolve().parents[1] / "files"


def test_launcher_preserves_inherited_flock(tmp_path):
    launcher = tmp_path / "hft.sh"
    launcher.write_text('echo ready >&2\nread -r permit || exit 1\necho creating >"$CREATED"\n'
                        'docker create --name=hft docker-hft:latest\n')
    docker = tmp_path / "docker"
    docker.symlink_to('/bin/true')  # also works on CI's noexec temporary filesystem
    created = tmp_path / "created"
    # Use the same command wrapper as the DUT, with the real directory flock deliberately on fd 3.
    helper = '''import fcntl, os, sys
from hft_container import FENCE_FDS, command
work, adapter, launcher = sys.argv[1:]
fd = os.open(work, os.O_DIRECTORY)
if fd != 3:
    os.dup2(fd, 3); os.close(fd)
fcntl.flock(3, fcntl.LOCK_EX)
FENCE_FDS.set((3,))
command("bash", adapter, "hft", "test=owner", launcher, "--enable-otel")
'''
    env = {**os.environ, "PYTHONPATH": str(FILES), "PATH": f"{tmp_path}:{os.environ['PATH']}", "CREATED": str(created)}
    with subprocess.Popen([sys.executable, "-B", "-c", helper, str(tmp_path), str(FILES / "create_container.sh"),
                           str(launcher)], stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True, env=env) as proc:
        contender = os.open(tmp_path, os.O_DIRECTORY)
        try:
            assert select.select([proc.stderr], [], [], 5)[0] and proc.stderr.readline() == b"ready\n"
            proc.kill()
            assert proc.wait(timeout=5) == -signal.SIGKILL
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            proc.stdin.write(b"go\n")
            proc.stdin.flush()
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            assert created.read_text().strip() == "creating"
        finally:
            os.close(contender)
            if proc.poll() is None:
                proc.kill()
            proc.stdin.close()  # release a stand-in launcher if an assertion failed before the gate
