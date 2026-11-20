"""Controller ownership of a durable HFT fixture transaction on one DUT."""

import base64
import fcntl
import hashlib
import json
import os
import socket
import uuid
from pathlib import Path

import pytest


ACTIVE = Path("/var/lib/sonic-mgmt-hft")


def active_work(dut):
    info = dut.stat(path=str(ACTIVE), follow=False, get_checksum=False, get_mime=False)["stat"]
    if not info["exists"]:
        return None
    target = Path(info.get("lnk_target", ""))
    if not info["islnk"] or target.parent != ACTIVE.parent or not target.name.startswith("sonic-mgmt-hft-"):
        raise RuntimeError(f"Unexpected HFT transaction link: {ACTIVE}")
    directory = dut.stat(path=str(target), follow=False, get_checksum=False, get_mime=False)["stat"]
    if not directory.get("isdir") or directory.get("uid") != 0 or directory.get("mode") != "0700":
        raise RuntimeError(f"HFT recovery directory is not private and root-owned: {target}")
    return target


def read_record(dut, path):
    encoded = dut.slurp(src=str(path), verbose=False)["content"]
    return json.loads(base64.b64decode(encoded))


class HftTransaction:
    def __init__(self, dut, work, owner):
        self.dut, self.work, self.owner = dut, work, owner

    def call(self, action, *args):
        return self.dut.command(argv=["python3", str(self.work / "hft_container.py"), action,
                                      str(self.work), self.owner, *args])["stdout"].strip()

    def record(self, name, data):
        pending = self.work / (name + "." + self.owner)
        self.dut.copy(content=json.dumps(data), dest=str(pending), mode="0600", verbose=False)
        self.call("record", name)

    def load(self, name):
        path = self.work / name
        if self.dut.stat(path=str(path), get_checksum=False, get_mime=False)["stat"]["exists"]:
            return read_record(self.dut, path)
        return None

    def configure_otel(self, config):
        self.dut.copy(content=config, dest=str(self.work / ("config." + self.owner)), mode="0600", verbose=False)
        self.call("configure")


def claim(dut, request, recover):
    # flock is released by the kernel on controller death (including SIGKILL).
    # Matching the private token is what permits automatic recovery; never infer
    # death from a lock's age, a hostname or a reused container/PID.
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sonic-mgmt" / "hft"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = cache / hashlib.sha256(dut.hostname.encode()).hexdigest()
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    local = os.fdopen(fd, "r+")
    request.addfinalizer(local.close)  # registered first: held through remote cleanup
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pytest.fail(f"Another HFT test on this controller owns {dut.hostname}")

    def remember(token):
        local.write(token + "\n")
        local.flush()
        os.fsync(fd)

    previous_tokens = local.read().splitlines()
    previous = active_work(dut)
    controller = f"{socket.gethostname()}:{os.getpid()}"
    if previous is None and dut.stat(path="/run/lock/sonic-mgmt-hft", follow=False,
                                     get_checksum=False, get_mime=False)["stat"]["exists"]:
        pytest.fail("A legacy HFT run holds /run/lock/sonic-mgmt-hft; verify its owner and journal before retrying")
    if previous:
        owner = read_record(dut, previous / "owner.json")
        if owner.get("version") != 2:
            raise RuntimeError(f"Unrecognized HFT journal version at {previous}; use its matching recovery code")
        if owner["id"] not in previous_tokens and os.environ.get("SONIC_MGMT_HFT_RECOVER_OWNER") != owner["id"]:
            pytest.fail(f"HFT run {previous.name} is owned by {owner['controller']}. If that job is confirmed dead, "
                        f"rerun with SONIC_MGMT_HFT_RECOVER_OWNER={owner['id']}. Do not delete the journal.")
        old = HftTransaction(dut, previous, owner["id"])
        successor = uuid.uuid4().hex
        remember(successor)  # retain both tokens if interrupted during the handoff
        old.call("take", successor, controller)
        recover(HftTransaction(dut, previous, successor))

    local.seek(0)
    local.truncate()
    token = uuid.uuid4().hex
    remember(token)  # before publishing the reservation on the DUT
    work = Path(dut.tempfile(state="directory", path=str(ACTIVE.parent), prefix="sonic-mgmt-hft-")["path"])
    tx = HftTransaction(dut, work, token)
    try:
        for name in ("hft_container.py", "create_container.sh"):
            dut.copy(src=str(Path(__file__).parent / "files" / name), dest=str(work / name), mode="0600")
    except Exception:
        dut.file(path=str(work), state="absent")  # not yet published or used
        raise
    tx.call("claim", controller)
    request.addfinalizer(lambda: recover(tx))
    return tx
