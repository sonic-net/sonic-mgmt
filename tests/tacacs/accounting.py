"""Scenario-local accounting log observation (no DUT/testbed dependencies)."""

import json
import re
import shlex
import time
from collections import Counter
from threading import Event


POLL_INTERVAL = 1
POSITIVE_TIMEOUT = 80
LOCAL_TIMEOUT = 120
ABSENCE_WINDOW = 80
LOG_READ_TIMEOUT = 80

# One open file descriptor provides identity and contents together. Verify the
# previous prefix, not just its length: copytruncate followed by regrowth must
# not turn old offsets into evidence of absence. Logs are small after cleanup.
READ_LOG = '''import hashlib, json, os, sys
with open(sys.argv[1], "rb") as stream:
    stat = os.fstat(stream.fileno())
    data = stream.read()
offset = int(sys.argv[2])
print(json.dumps({"identity": [stat.st_dev, stat.st_ino], "size": len(data),
    "prefix": hashlib.sha256(data[:offset]).hexdigest(),
    "digest": hashlib.sha256(data).hexdigest(),
    "text": data[offset:].decode("utf-8", errors="strict")}))
'''


class MissingAccounting(AssertionError):
    """Only a missing positive may trigger the existing local-accounting retry."""


class LogCursor:
    def __init__(self, host, path, local=False):
        self.host = host
        self.path = path
        self.local = local
        self.snapshot = None
        self.pending = ""
        self.lines = []

    def read(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("Accounting log read budget exhausted: {}".format(self.path))
        offset = self.snapshot["size"] if self.snapshot else 0
        # GNU timeout bounds the remote subprocess, NOT Ansible/SSH transport.
        # Reopen syslog as before; combine flush and read in one remote call.
        flush = "kill -HUP $(cat /var/run/rsyslogd.pid) && " if self.local else ""
        script = "{}sync {} && python3 -c {} {} {}".format(
            flush, shlex.quote(self.path), shlex.quote(READ_LOG), shlex.quote(self.path), offset)
        result = self.host.shell("timeout --signal=KILL {:.6f}s sh -c {}".format(
            remaining, shlex.quote(script)), module_ignore_errors=True)
        if result.get("rc") != 0 or result.get("failed"):
            raise AssertionError("Accounting log read failed for {}: {}".format(self.path, result))
        snapshot = json.loads(result["stdout"])
        if self.snapshot:
            if (snapshot["identity"] != self.snapshot["identity"] or snapshot["size"] < offset or
                    snapshot["prefix"] != self.snapshot["digest"]):
                raise AssertionError("Accounting log rotated/truncated/rewritten: {}".format(self.path))
            text = self.pending + snapshot["text"]
            complete = text.split("\n")
            self.pending = complete.pop()
            self.lines.extend(complete)
        else:
            # Never accept a record which began before the scenario boundary.
            if snapshot["text"] and not snapshot["text"].endswith("\n"):
                raise AssertionError("Accounting log boundary contains an incomplete record: {}".format(self.path))
        self.snapshot = snapshot
        return self.lines

    def counts(self, username, commands):
        counts = Counter()
        forbidden = []
        for line in self.lines:
            if self.local:
                # Identify accounting records before inspecting their payload.
                # Command arguments may contain strings also found in reader or
                # Ansible noise; they must never bypass username validation.
                if not re.search(r"INFO audisp-tacplus: (?:Audisp-tacplus: )?Accounting:", line):
                    continue
                match = re.search(
                    r"INFO audisp-tacplus: (?:Audisp-tacplus: )?Accounting: user: ([^,]*),.*?, "
                    r"command: (.*), type: [0-9]+, task ID: [0-9]+\s*$", line)
                if not match:
                    raise AssertionError("Malformed accounting record in {}: {}".format(self.path, line))
                record_user, record_command = match.groups()
                if record_user != username:
                    forbidden.append(line)
                    continue
            else:
                if not any("\t{}\t".format(user) in line for user in (username, "admin")):
                    forbidden.append(line)
                match = re.search(r"\t{}\t.*\tcmd=([^\t]*)".format(re.escape(username)), line)
                record_command = match.group(1) if match else None
            if match:
                # Match a command token, not e.g. 'grep' in 'pgrep'. Each record
                # belongs to at most one command; repeated commands need N records.
                for command in commands:
                    if re.fullmatch(r"(?:\S*/)?{}\s*".format(re.escape(command)), record_command):
                        counts[command] += 1
                        break
        if forbidden:
            raise AssertionError("Unexpected accounting records in {}: {}".format(self.path, forbidden))
        return counts


def capture_logs(cursors, timeout=POSITIVE_TIMEOUT):
    deadline = time.monotonic() + timeout
    for cursor in cursors:
        cursor.read(deadline)
        if time.monotonic() > deadline:
            raise AssertionError("Accounting log boundary capture exceeded elapsed budget")


def _positive_deadline_expired(cursors, username, required, missing):
    # Before a retry can clean the logs, reconcile ALL sources, including ones
    # not sampled near expiry. This is one bounded sweep, not positive grace:
    # late positives cannot rescue the expired attempt. Read/integrity errors
    # and incomplete records must fail hard rather than discard evidence.
    read_deadline = time.monotonic() + LOG_READ_TIMEOUT
    for cursor in cursors:
        cursor.read(read_deadline)
        cursor.counts(username, required)
        if time.monotonic() > read_deadline:
            raise AssertionError("Accounting expiry reconciliation exceeded elapsed budget")
    if any(cursor.pending for cursor in cursors):
        raise AssertionError("Incomplete accounting record prevents retry")
    raise MissingAccounting("Accounting elapsed deadline exceeded; missing: {}".format(missing))


def verify_accounting(cursors, username, commands, timeout=POSITIVE_TIMEOUT,
                      absence_window=ABSENCE_WINDOW, interval=POLL_INTERVAL):
    """One positive budget, followed by one shared, full absence window.

    The positive deadline limits acceptance, not read completion. Each sample
    has a separate bounded subprocess budget; transport can overrun it. Expiry
    requires one bounded all-source reconciliation before retry, never accepting
    late positives. Absence still requires an end-of-window read.
    No config changes or command execution occur inside this observation loop.
    """
    if not cursors or not commands or timeout <= 0 or absence_window < 0 or interval <= 0:
        raise ValueError("Accounting observation needs logs, commands and positive polling budgets")
    required = Counter(commands)
    deadline = time.monotonic() + timeout
    absence_deadline = None
    missing = {}
    while True:
        if absence_deadline is None and time.monotonic() >= deadline:
            _positive_deadline_expired(cursors, username, required, missing)
        missing = {}
        final_sample = absence_deadline is not None and time.monotonic() >= absence_deadline
        for cursor in cursors:
            if absence_deadline is None and time.monotonic() >= deadline:
                _positive_deadline_expired(cursors, username, required, missing)
            if absence_deadline is not None and not final_sample and time.monotonic() >= absence_deadline:
                break  # Start a complete final sweep; do not omit an earlier source.
            # Do not kill a healthy read just because positive acceptance ends:
            # rc137 cannot distinguish that from an unrelated kill/read failure.
            # Bound each read separately and check elapsed acceptance below.
            # Absence still needs a complete sweep STARTING after the window.
            read_deadline = time.monotonic() + LOG_READ_TIMEOUT
            cursor.read(read_deadline)
            counts = cursor.counts(username, required)
            remaining = required - counts
            if remaining:
                missing[cursor.path] = dict(remaining)
            if absence_deadline is None and time.monotonic() > deadline:
                _positive_deadline_expired(cursors, username, required, missing)
        now = time.monotonic()
        if absence_deadline is None:
            if not missing:
                absence_deadline = now + absence_window
            elif now >= deadline:
                _positive_deadline_expired(cursors, username, required, missing)
        elif final_sample:
            if any(cursor.pending for cursor in cursors):
                raise AssertionError("Incomplete accounting record at end of observation")
            return
        target = deadline if absence_deadline is None else absence_deadline
        # Unlike wait_until(), keep exceptions visible and use a monotonic clock.
        Event().wait(min(interval, max(0, target - time.monotonic())))
