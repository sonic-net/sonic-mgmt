"""Controller ownership of a durable HFT fixture transaction on one DUT."""

import base64
import fcntl
import hashlib
import json
import os
import socket
import uuid
from contextlib import contextmanager
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

    def call(self, action, *args, payload=None):
        options = {} if payload is None else {"stdin": json.dumps(payload), "verbose": False}
        return self.dut.command(argv=["python3", "-B", str(self.work / "hft_container.py"), action,
                                      str(self.work), self.owner, *args], **options)["stdout"].strip()

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


class HftProfile:
    """Function-scoped profile handle. The DUT journals the actual run-unique CONFIG_DB name."""
    def __init__(self, tx):
        self.tx = tx
        self.case = uuid.uuid4().hex
        self.active = False

    def create(self, group, objects, counters, poll_interval=10000, stream_state="enabled"):
        self.active = True  # A lost reply does not prove the create failed.
        return self.tx.call("profile-create", self.case, payload={"group": group, "objects": list(objects),
                            "counters": list(counters), "poll_interval": poll_interval, "state": stream_state})

    def set_state(self, state):
        self.tx.call("profile-state", self.case, state)

    def remove(self):
        if self.active:
            self.tx.call("profile-remove", self.case)
            self.active = False


@contextmanager
def controller_lock(dut):
    """Keep the descriptor open through DUT teardown, including exceptional exits."""
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sonic-mgmt" / "hft"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = cache / hashlib.sha256(dut.hostname.encode()).hexdigest()
    with open(path, "a+", opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW, 0o600)) as local:
        try:
            fcntl.flock(local.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pytest.fail(f"Another HFT test on this controller owns {dut.hostname}")
        local.seek(0)
        yield local


@contextmanager
def claim(dut, recover):
    # Keep the kernel lock through setup, use and rollback in a single lexical
    # scope. A dead controller releases it even on SIGKILL.
    with controller_lock(dut) as local:
        tx = _claim_locked(dut, local, recover)
        try:
            yield tx
        finally:
            recover(tx)


def _claim_locked(dut, local, recover):
    def remember(token):
        local.write(token + "\n")
        local.flush()
        os.fsync(local.fileno())

    previous_tokens = local.read().splitlines()
    previous = active_work(dut)
    controller = f"{socket.gethostname()}:{os.getpid()}"
    if previous is None and dut.stat(path="/run/lock/sonic-mgmt-hft", follow=False,
                                     get_checksum=False, get_mime=False)["stat"]["exists"]:
        pytest.fail("A legacy HFT run holds /run/lock/sonic-mgmt-hft; verify its owner and journal before retrying")
    if previous:
        owner = read_record(dut, previous / "owner.json")
        if owner.get("version") != 5:
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
        for name in ("hft_container.py", "hft_profiles.py", "create_container.sh"):
            dut.copy(src=str(Path(__file__).parent / "files" / name), dest=str(work / name), mode="0600")
    except Exception:
        dut.file(path=str(work), state="absent")  # not yet published or used
        raise
    tx.call("claim", controller)
    return tx
