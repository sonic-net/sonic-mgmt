"""Rotation-safe byte markers for the managed gNMI service log."""

import base64
from dataclasses import dataclass


MARK_LOG_SCRIPT = r"""
import base64
import os
import sys

path = sys.argv[1]
with open(path, "rb") as log_file:
    stat = os.fstat(log_file.fileno())
    anchor_start = max(0, stat.st_size - 128)
    log_file.seek(anchor_start)
    anchor = base64.b64encode(log_file.read()).decode("ascii") or "-"
print("{} {} {}".format(stat.st_ino, stat.st_size, anchor))
"""


READ_LOG_SCRIPT = r"""
import base64
import glob
import gzip
import os
import re
import sys

current_path = sys.argv[1]
marker_inode = int(sys.argv[2])
marker_offset = int(sys.argv[3])
marker_anchor = b"" if sys.argv[4] == "-" else base64.b64decode(sys.argv[4])
max_generations = 4
max_scan_bytes = 16 * 1024 * 1024
max_output_bytes = 1024 * 1024

def generation(path):
    if path == current_path:
        return 0
    match = re.fullmatch(re.escape(current_path) + r"\.(\d+)(?:\.gz)?", path)
    return int(match.group(1)) if match else None

def open_log(path):
    opener = gzip.open if path.endswith(".gz") else open
    return opener(path, "rb")

def anchor_matches(path, offset):
    if not marker_anchor:
        return True
    anchor_start = max(0, offset - len(marker_anchor))
    try:
        with open_log(path) as log_file:
            log_file.seek(anchor_start)
            return log_file.read(len(marker_anchor)) == marker_anchor
    except (FileNotFoundError, OSError):
        return False

def find_anchor(path):
    if not marker_anchor:
        return None
    overlap = b""
    scanned = 0
    try:
        with open_log(path) as log_file:
            while scanned < max_scan_bytes:
                chunk = log_file.read(min(65536, max_scan_bytes - scanned))
                if not chunk:
                    break
                data = overlap + chunk
                position = data.find(marker_anchor)
                if position >= 0:
                    return scanned - len(overlap) + position + len(marker_anchor)
                overlap = data[-max(0, len(marker_anchor) - 1):]
                scanned += len(chunk)
    except (FileNotFoundError, OSError):
        return None
    return None

def append_tail(output, path, start, scan_budget):
    try:
        with open_log(path) as log_file:
            log_file.seek(start)
            while scan_budget[0] > 0:
                chunk = log_file.read(min(65536, scan_budget[0]))
                if not chunk:
                    break
                output.extend(chunk)
                scan_budget[0] -= len(chunk)
                if len(output) > max_output_bytes:
                    del output[:-max_output_bytes]
    except (FileNotFoundError, OSError):
        pass

paths = []
for path in glob.glob(current_path + "*"):
    item_generation = generation(path)
    if item_generation is not None and item_generation <= max_generations:
        paths.append((item_generation, path))
paths.sort(reverse=True)

marker_index = None
marker_start = 0
truncated_current_index = None
for index, (_, path) in enumerate(paths):
    try:
        same_inode = not path.endswith(".gz") and os.stat(path).st_ino == marker_inode
    except OSError:
        same_inode = False
    if same_inode:
        size = os.stat(path).st_size
        if size >= marker_offset and anchor_matches(path, marker_offset):
            marker_start = marker_offset
        elif generation(path) == 0:
            # Search rotated generations before treating this as truncate.
            truncated_current_index = index
            continue
        else:
            continue
        marker_index = index
        break

if marker_index is None and marker_anchor:
    for index in range(len(paths) - 1, -1, -1):
        path = paths[index][1]
        if anchor_matches(path, marker_offset):
            marker_index = index
            marker_start = marker_offset
            break
        anchor_end = find_anchor(path)
        if anchor_end is not None:
            marker_index = index
            marker_start = anchor_end
            break

if marker_index is None and truncated_current_index is not None:
    marker_index = truncated_current_index
    marker_start = 0

if marker_index is not None:
    output = bytearray()
    scan_budget = [max_scan_bytes]
    append_tail(output, paths[marker_index][1], marker_start, scan_budget)
    for _, path in paths[marker_index + 1:]:
        if scan_budget[0] <= 0:
            break
        append_tail(output, path, 0, scan_budget)
else:
    sys.stderr.write("gNMI log marker no longer identifies retained log bytes")
    sys.exit(2)

sys.stdout.write(base64.b64encode(bytes(output)).decode("ascii"))
"""


@dataclass(frozen=True)
class GnmiLogMarker:
    """Identity and byte offset for a point in the managed gNMI log."""

    inode: int
    offset: int
    anchor: str


def parse_log_marker(output):
    """Parse MARK_LOG_SCRIPT output into a GnmiLogMarker."""
    values = output.strip().split(" ", 2)
    if len(values) != 3:
        raise ValueError("Invalid gNMI log marker: {!r}".format(output))
    return GnmiLogMarker(int(values[0]), int(values[1]), values[2])


def decode_log_bytes(output):
    """Decode READ_LOG_SCRIPT output as UTF-8 while preserving bad bytes."""
    return base64.b64decode(output.strip(), validate=True).decode(
        "utf-8", errors="replace"
    )
