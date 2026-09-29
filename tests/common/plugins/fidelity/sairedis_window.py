"""
Inode-aware sairedis.rec windowing for SAI fidelity scoring.

Handles logrotate rename (sairedis.rec -> sairedis.rec.1) by stitching the
remainder of the old inode with the new active file. When history cannot be
reconstructed, returns an explicit status so callers can set score=None
instead of reporting a false "no SAI activity".

Statuses
--------
OK              Same inode; read new lines only.
STITCHED        Inode changed; recovered via .1 / older rotates.
HISTORY_LOST    Start inode not found (archives deleted / wiped).
TRUNCATED       Same inode but fewer lines than snapshot (unexpected).
MISSING         Active path missing at snapshot or collect time.
RECORDER_RESET  New file with recording-on marker and no recoverable history.
TOO_LARGE       Stitched delta exceeds size cap (refuse to pull).
ERROR           Unexpected failure.
"""

from __future__ import annotations

import gzip
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Soft cap on stitched text pulled over SSH (~32 MiB)
DEFAULT_MAX_BYTES = 32 * 1024 * 1024

STATUS_OK = "OK"
STATUS_STITCHED = "STITCHED"
STATUS_HISTORY_LOST = "HISTORY_LOST"
STATUS_TRUNCATED = "TRUNCATED"
STATUS_MISSING = "MISSING"
STATUS_RECORDER_RESET = "RECORDER_RESET"
STATUS_TOO_LARGE = "TOO_LARGE"
STATUS_ERROR = "ERROR"

# Statuses where scoring with empty/missing text must not claim "no SAI activity"
UNRELIABLE_EMPTY = frozenset(
    (
        STATUS_HISTORY_LOST,
        STATUS_TRUNCATED,
        STATUS_MISSING,
        STATUS_RECORDER_RESET,
        STATUS_TOO_LARGE,
        STATUS_ERROR,
    )
)


@dataclass
class RecSnapshot:
    """File identity at test start."""

    path: str
    inode: Optional[int] = None
    size: int = 0
    lines: int = 0


@dataclass
class FileMeta:
    path: str
    inode: int
    size: int
    # Rotation index: 0 = active file, 1 = .1, 2 = .2.gz, ...
    rot_index: int = 0


@dataclass
class DeltaResult:
    status: str
    text: str = ""
    reason: str = ""
    bytes_read: int = 0


def rotation_index(active_path: str, candidate_path: str) -> int:
    """
    Map a path in the sairedis.rec family to a rotation index.
    active -> 0, .1 -> 1, .2 / .2.gz -> 2, etc.
    """
    if candidate_path == active_path:
        return 0
    prefix = active_path + "."
    if not candidate_path.startswith(prefix):
        return -1
    suffix = candidate_path[len(prefix) :]
    # strip .gz
    if suffix.endswith(".gz"):
        suffix = suffix[: -len(".gz")]
    if suffix.isdigit():
        return int(suffix)
    return -1


def list_rec_family_local(active_path: str) -> List[FileMeta]:
    """Local filesystem: list active + rotates with inodes."""
    directory = os.path.dirname(active_path) or "."
    base = os.path.basename(active_path)
    found: List[FileMeta] = []
    try:
        names = os.listdir(directory)
    except OSError:
        return found

    for name in names:
        full = os.path.join(directory, name)
        if name != base and not name.startswith(base + "."):
            continue
        if not os.path.isfile(full):
            continue
        idx = rotation_index(active_path, full)
        if idx < 0 and full != active_path:
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        found.append(
            FileMeta(
                path=full,
                inode=int(st.st_ino),
                size=int(st.st_size),
                rot_index=0 if full == active_path else idx,
            )
        )
    return found


def read_text_file(path: str) -> str:
    """Read a rec file; transparently gunzip *.gz."""
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _lines_from(text: str, start_line: int) -> str:
    """Return text from 0-based start_line to EOF (start_line == wc -l means empty)."""
    if start_line <= 0:
        return text
    lines = text.splitlines(keepends=True)
    if start_line >= len(lines):
        return ""
    return "".join(lines[start_line:])


def collect_delta_local(
    snap: RecSnapshot,
    max_bytes: int = DEFAULT_MAX_BYTES,
    family: Optional[List[FileMeta]] = None,
    readers: Optional[Dict[str, str]] = None,
) -> DeltaResult:
    """
    Pure collect: stitch using local files or an in-memory family.

    ``family``: optional precomputed FileMeta list (for unit tests).
    ``readers``: optional path -> full file text (for unit tests without disk).
    """
    if snap.inode is None and snap.lines == 0 and snap.size == 0:
        # Snapshot failed / missing at start
        if not os.path.exists(snap.path) and not (family or readers):
            return DeltaResult(STATUS_MISSING, reason="active path missing at snapshot")

    metas = family if family is not None else list_rec_family_local(snap.path)
    by_inode = {m.inode: m for m in metas}
    active = next((m for m in metas if m.rot_index == 0 and m.path == snap.path), None)
    if active is None:
        active = next((m for m in metas if m.path == snap.path), None)

    def _read(path: str) -> str:
        if readers is not None and path in readers:
            return readers[path]
        return read_text_file(path)

    if active is None:
        return DeltaResult(STATUS_MISSING, reason="active path missing at collect")

    # --- same inode ---
    if snap.inode is not None and active.inode == snap.inode:
        text = _read(active.path)
        line_count = len(text.splitlines())

        if line_count < snap.lines:
            return DeltaResult(
                STATUS_TRUNCATED,
                reason="same inode but fewer lines than snapshot ({} < {})".format(
                    line_count, snap.lines
                ),
            )
        delta = _lines_from(text, snap.lines)
        if len(delta.encode("utf-8", errors="replace")) > max_bytes:
            return DeltaResult(
                STATUS_TOO_LARGE,
                reason="delta exceeds {} bytes".format(max_bytes),
                bytes_read=len(delta),
            )
        return DeltaResult(STATUS_OK, text=delta, bytes_read=len(delta))

    # --- inode changed: find start inode among family ---
    if snap.inode is None:
        # No inode from snapshot — try active-only from line 0 as last resort?
        return DeltaResult(
            STATUS_HISTORY_LOST,
            reason="snapshot had no inode; cannot verify identity",
        )

    start_meta = by_inode.get(snap.inode)
    if start_meta is None:
        # Check for recorder reset hint on new active file
        try:
            head = _read(active.path)[:500]
        except Exception:
            head = ""
        if "recording on:" in head or "logrotate on:" in head:
            return DeltaResult(
                STATUS_RECORDER_RESET,
                reason="start inode {} not found; new recorder file".format(snap.inode),
            )
        return DeltaResult(
            STATUS_HISTORY_LOST,
            reason="start inode {} not found in {}".format(
                snap.inode, [m.path for m in metas]
            ),
        )

    # Stitch: remainder of start file, then all newer rotates (lower rot_index),
    # rot_index 0 = active is newest. Higher rot_index = older.
    # Order: start_meta (from offset), then files with rot_index < start_meta.rot_index
    # sorted descending by rot_index (older among "newer than start"? Wait)
    #
    # Example: started on active (ino 100). After rotate: .1 has ino 100, active ino 200.
    # start_meta.rot_index = 1, active rot_index = 0.
    # Newer than start = rot_index < 1, i.e. active (0).
    # Order: tail(.1) + cat(active). Good.
    #
    # Two rotates: started on active. Now .2.gz=old, .1=middle, active=new.
    # start inode on .2.gz (rot 2). Newer: rot 1 and 0. Order: .1 then active.
    # Sort newer by rot_index descending: 1 then 0. Good.

    parts: List[str] = []
    try:
        start_text = _read(start_meta.path)
    except Exception as exc:
        return DeltaResult(
            STATUS_ERROR,
            reason="failed to read {}: {}".format(start_meta.path, exc),
        )
    parts.append(_lines_from(start_text, snap.lines))

    newer = [
        m
        for m in metas
        if m.rot_index < start_meta.rot_index and m.inode != start_meta.inode
    ]
    newer.sort(key=lambda m: m.rot_index, reverse=True)
    for meta in newer:
        try:
            parts.append(_read(meta.path))
        except Exception as exc:
            return DeltaResult(
                STATUS_ERROR,
                reason="failed to read {}: {}".format(meta.path, exc),
            )

    delta = "".join(parts)
    nbytes = len(delta.encode("utf-8", errors="replace"))
    if nbytes > max_bytes:
        return DeltaResult(
            STATUS_TOO_LARGE,
            reason="stitched delta exceeds {} bytes".format(max_bytes),
            bytes_read=nbytes,
        )
    return DeltaResult(
        STATUS_STITCHED,
        text=delta,
        reason="stitched from {} + {} newer file(s)".format(
            start_meta.path, len(newer)
        ),
        bytes_read=nbytes,
    )


def snapshot_rec(host, rec_path: str) -> RecSnapshot:
    """SSH: snapshot inode/size/lines for a sairedis path."""
    # Single shell: inode size on one line, wc -l on next
    cmd = (
        "if [ -f {p} ]; then "
        "stat -c '%i %s' {p}; "
        "wc -l < {p}; "
        "else echo MISSING; fi"
    ).format(p=rec_path)
    result = host.shell(cmd, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        logger.warning(
            "sairedis snapshot failed for %s: %s",
            rec_path,
            result.get("stderr"),
        )
        return RecSnapshot(path=rec_path)

    out = (result.get("stdout") or "").strip().splitlines()
    if not out or out[0].strip() == "MISSING":
        return RecSnapshot(path=rec_path)

    try:
        inode_s, size_s = out[0].split()[:2]
        inode = int(inode_s)
        size = int(size_s)
    except (ValueError, IndexError):
        return RecSnapshot(path=rec_path)

    lines = 0
    if len(out) > 1 and out[1].strip().isdigit():
        lines = int(out[1].strip())

    return RecSnapshot(path=rec_path, inode=inode, size=size, lines=lines)


def collect_delta(host, snap: RecSnapshot, max_bytes: int = DEFAULT_MAX_BYTES) -> DeltaResult:
    """
    SSH: collect delta for a snapshot using inode-aware stitching on the DUT.

    Runs a small Python script on the DUT so stitching happens remotely;
    only status + delta text are returned.
    """
    inode_arg = "None" if snap.inode is None else str(snap.inode)
    cmd = (
        "START_PATH={path} START_INODE={inode} START_LINES={lines} MAX_BYTES={maxb} "
        "python3 - <<'PY'\n"
        "import gzip, os, sys\n"
        "active = os.environ['START_PATH']\n"
        "si = os.environ.get('START_INODE', 'None')\n"
        "start_inode = int(si) if si != 'None' else None\n"
        "start_lines = int(os.environ['START_LINES'])\n"
        "max_bytes = int(os.environ['MAX_BYTES'])\n"
        + _DUT_COLLECTOR_BODY
        + "\nPY"
    ).format(
        path=_shell_quote(snap.path),
        inode=inode_arg,
        lines=snap.lines,
        maxb=max_bytes,
    )

    result = host.shell(cmd, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return DeltaResult(
            STATUS_ERROR,
            reason="collect shell failed: {}".format(
                (result.get("stderr") or "")[:300]
            ),
        )
    return _parse_collector_stdout(result.get("stdout") or "")


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


_DUT_COLLECTOR_BODY = r'''
def rot_index(active, path):
    if path == active:
        return 0
    pref = active + "."
    if not path.startswith(pref):
        return -1
    suf = path[len(pref):]
    if suf.endswith(".gz"):
        suf = suf[:-3]
    return int(suf) if suf.isdigit() else -1

def read_text(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

def lines_from(text, start):
    if start <= 0:
        return text
    ls = text.splitlines(keepends=True)
    if start >= len(ls):
        return ""
    return "".join(ls[start:])

directory = os.path.dirname(active) or "."
base = os.path.basename(active)
metas = []
try:
    names = os.listdir(directory)
except OSError:
    print("STATUS=MISSING")
    print("REASON=cannot list directory")
    raise SystemExit(0)

for name in names:
    full = os.path.join(directory, name)
    if name != base and not name.startswith(base + "."):
        continue
    if not os.path.isfile(full):
        continue
    idx = rot_index(active, full)
    if idx < 0 and full != active:
        continue
    try:
        st = os.stat(full)
    except OSError:
        continue
    metas.append((full, int(st.st_ino), 0 if full == active else idx))

active_meta = None
for full, ino, idx in metas:
    if full == active:
        active_meta = (full, ino, idx)
        break

if active_meta is None:
    print("STATUS=MISSING")
    print("REASON=active missing")
    raise SystemExit(0)

afull, aino, aidx = active_meta

if start_inode is not None and aino == start_inode:
    text = read_text(afull)
    nlines = len(text.splitlines())
    if nlines < start_lines:
        print("STATUS=TRUNCATED")
        print("REASON=same inode fewer lines")
        raise SystemExit(0)
    delta = lines_from(text, start_lines)
    if len(delta.encode("utf-8", errors="replace")) > max_bytes:
        print("STATUS=TOO_LARGE")
        print("REASON=delta too large")
        raise SystemExit(0)
    print("STATUS=OK")
    print("REASON=")
    print("---DATA---")
    sys.stdout.write(delta)
    raise SystemExit(0)

if start_inode is None:
    print("STATUS=HISTORY_LOST")
    print("REASON=no snapshot inode")
    raise SystemExit(0)

start_meta = None
for full, ino, idx in metas:
    if ino == start_inode:
        start_meta = (full, ino, idx)
        break

if start_meta is None:
    head = ""
    try:
        head = read_text(afull)[:500]
    except Exception:
        pass
    if "recording on:" in head or "logrotate on:" in head:
        print("STATUS=RECORDER_RESET")
        print("REASON=start inode gone; new recorder")
    else:
        print("STATUS=HISTORY_LOST")
        print("REASON=start inode not found")
    raise SystemExit(0)

sfull, sino, sidx = start_meta
parts = [lines_from(read_text(sfull), start_lines)]
newer = [(f, i, x) for f, i, x in metas if x < sidx and i != sino]
newer.sort(key=lambda t: t[2], reverse=True)
for f, i, x in newer:
    parts.append(read_text(f))
delta = "".join(parts)
if len(delta.encode("utf-8", errors="replace")) > max_bytes:
    print("STATUS=TOO_LARGE")
    print("REASON=stitched too large")
    raise SystemExit(0)
print("STATUS=STITCHED")
print("REASON=stitched from %s + %d newer" % (sfull, len(newer)))
print("---DATA---")
sys.stdout.write(delta)
'''


def _parse_collector_stdout(stdout: str) -> DeltaResult:
    lines = stdout.splitlines(keepends=True)
    status = STATUS_ERROR
    reason = ""
    data_idx = None
    for i, line in enumerate(lines):
        raw = line.rstrip("\n")
        if raw.startswith("STATUS="):
            status = raw.split("=", 1)[1].strip() or STATUS_ERROR
        elif raw.startswith("REASON="):
            reason = raw.split("=", 1)[1]
        elif raw.strip() == "---DATA---":
            data_idx = i + 1
            break
    text = ""
    if data_idx is not None:
        text = "".join(lines[data_idx:])
    return DeltaResult(status=status, text=text, reason=reason, bytes_read=len(text))
