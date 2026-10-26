"""
Test cases for console mirror feature.

These test cases verify:
- Valid `consutil mirror start`, `show`, `timeout`, and `stop` operations
- RX, TX, and bidirectional recording without console-session interference
- SCM-Text v1 format, payload escaping, file rotation, and successful ZIP packaging
- STATE_DB state management, automatic stop, session cleanup, and resource stability

Testbed Architecture: c0-lo
"""

import ast
import json
import logging
import os
import re
import shlex
import threading
import time
import uuid
from dataclasses import dataclass, field

import pexpect
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import (
    check_target_line_status,
    create_ssh_client,
    disconnect_console_client,
    ensure_console_session_up,
    get_dut_console_lines,
    get_host_ip_and_creds,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("c0-lo")]


# ==================== Constants ===========================

MIRROR_BASE_DIR = "/var/log/sonic/console-mirror"
MIRROR_ACTIVE_FIELDS = {
    "owner_pid",
    "started_by",
    "start_time",
    "timeout",
    "file_path",
    "direction",
}
MIRROR_IDLE_TIMEOUT_SEC = 30
ROTATION_PAYLOAD_BYTES_PER_DIRECTION = 160 * 1024
AUTO_STOP_TIMEOUT_SEC = 5
RESOURCE_LOAD_DURATION_SEC = 180
RESOURCE_SAMPLE_INTERVAL_SEC = 1

_PREFIX_RE = re.compile(
    r"^/var/log/sonic/console-mirror/line(?P<line>[0-9]+)/"
    r"console-mirror-line(?P=line)-(?P<direction>rx|tx|both)-(?P<timestamp>[0-9]{8}T[0-9]{12}Z)$"
)
_PART_RE = re.compile(r"^(?P<prefix>.+)-part(?P<part>[0-9]{4})\.log$")
_RECORD_RE = re.compile(
    r"^(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+Z) "
    r"\+(?P<delta>[0-9]{12})ms (?P<seq>[0-9]{8}) "
    r"(?P<direction>RX|TX|EVENT) (?P<length>[0-9]{8}) (?P<payload>.*)$"
)


# ==================== Type Definitions ====================


@dataclass(frozen=True)
class MirrorPort:
    line: str
    baud_rate: int
    flow_control: bool


@dataclass
class MirrorTestContext:
    port: MirrorPort
    clients: list[pexpect.spawn] = field(default_factory=list)
    recording_prefixes: set[str] = field(default_factory=set)

    def register_recording_file(self, file_path: str) -> str:
        prefix = _recording_prefix(file_path)
        self.recording_prefixes.add(prefix)
        return prefix


@dataclass(frozen=True)
class ScmRecord:
    seq: int
    direction: str
    original_length: int
    payload: bytes
    event: dict | None = None


# ==================== Helper Functions ====================


def _mirror_command(duthost, arguments: str, expect_success: bool = True) -> dict:
    result = duthost.shell(
        f"sudo consutil mirror {arguments}",
        module_ignore_errors=True,
    )
    if expect_success:
        pytest_assert(
            result["rc"] == 0,
            "consutil mirror {} failed: {}".format(
                arguments, result.get("stderr") or result.get("stdout")
            ),
        )
    return result


def _start_mirror(
    duthost,
    context: MirrorTestContext,
    direction: str = "both",
    timeout: str = "2m",
    max_file_size: int | None = None,
) -> tuple[dict, str, str]:
    arguments = (
        f"start {context.port.line} --direction {direction} --timeout {timeout}"
    )
    if max_file_size is not None:
        arguments += f" --max-file-size {max_file_size}"
    result = _mirror_command(duthost, arguments)
    match = re.search(r"^Recording file:\s*(\S+)\s*$", result["stdout"], re.MULTILINE)
    pytest_assert(
        match is not None,
        "Start output did not contain a recording file: {}".format(result["stdout"]),
    )
    assert match is not None
    file_path = match.group(1)
    prefix = context.register_recording_file(file_path)
    pytest_assert(f"Started mirror on line [{context.port.line}]" in result["stdout"])
    pytest_assert(f"Auto-stop timeout: {timeout}" in result["stdout"])
    return result, file_path, prefix


def _stop_mirror(
    duthost, context: MirrorTestContext, archive: bool = False
) -> tuple[dict, str]:
    arguments = "stop {}{}".format(context.port.line, " --archive" if archive else "")
    result = _mirror_command(duthost, arguments)
    if archive:
        match = re.search(
            r"^Recording archive:\s*(\S+)\s*$", result["stdout"], re.MULTILINE
        )
        pytest_assert(
            match is not None,
            "Archive stop output did not contain the final ZIP: {}".format(
                result["stdout"]
            ),
        )
        assert match is not None
        archive_path = match.group(1)
        prefix = archive_path[:-4] if archive_path.endswith(".zip") else ""
        pytest_assert(
            prefix in context.recording_prefixes,
            f"Archive path does not match the active test recording: {archive_path}",
        )
        return result, archive_path

    match = re.search(
        r"^(/var/log/sonic/console-mirror/\S+)\s*$", result["stdout"], re.MULTILINE
    )
    pytest_assert(
        match is not None,
        "Stop output did not contain the retained prefix: {}".format(result["stdout"]),
    )
    assert match is not None
    prefix = match.group(1)
    pytest_assert(
        prefix in context.recording_prefixes,
        f"Retained prefix does not match the active test recording: {prefix}",
    )
    return result, prefix


def _get_state_db(duthost, line: str) -> dict[str, str]:
    result = duthost.shell(
        f"sonic-db-cli STATE_DB HGETALL 'CONSOLE_MIRROR|{line}'",
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0, f"Failed to read Console Mirror STATE_DB for line {line}"
    )
    stdout = result.get("stdout", "")
    # return directly if is a dict
    if isinstance(stdout, dict):
        return {str(key): str(value) for key, value in stdout.items()}
    # parse str
    stripped = stdout.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            values_dict = ast.literal_eval(stripped)
        except (SyntaxError, ValueError):
            values_dict = None
        if isinstance(values_dict, dict):
            return {str(key): str(value) for key, value in values_dict.items()}
    # values used for checking
    values = stdout.splitlines()
    pytest_assert(
        len(values) % 2 == 0,
        f"Unexpected STATE_DB HGETALL output for line {line}: {stdout}",
    )
    return dict(zip(values[0::2], values[1::2]))


def _get_cli_status(duthost, line: str) -> dict[str, str]:
    result = _mirror_command(duthost, f"show {line}")
    for output_line in result["stdout"].splitlines():
        columns = output_line.split()
        if len(columns) >= 2 and columns[0] == str(line):
            columns += ["-"] * (7 - len(columns))  # pad to 7 columns
            return {
                "line": columns[0],
                "state": columns[1],
                "start_time": columns[2],
                "direction": columns[3],
                "timeout": columns[4],
                "remaining": columns[5],
                "file_path": columns[6],
            }
    raise AssertionError(
        "Could not parse line {} from consutil mirror show output: {}".format(
            line, result["stdout"]
        )
    )


def _duration_seconds(value: str) -> int:
    matches = list(re.finditer(r"[0-9]+([dhms])", value))
    units = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    pytest_assert(matches and "".join(m.group(0) for m in matches) == value)
    return sum(int(m.group(0)[:-1]) * units[m.group(1)] for m in matches)


def _wait_for_mirror_idle(
    duthost, line: str, timeout: int = MIRROR_IDLE_TIMEOUT_SEC
) -> bool:
    def check_idle():
        try:
            result = (_get_cli_status(duthost, line).get("state") == "idle") and (
                _get_state_db(duthost, line).get("state") == "idle"
            )
            return result
        except Exception:  # noqa: BLE001
            return False

    return wait_until(condition=check_idle, timeout=timeout, interval=1, delay=1)


def _recording_prefix(file_path: str) -> str:
    part_match = _PART_RE.fullmatch(file_path)
    pytest_assert(
        part_match is not None, f"Unexpected Console Mirror file path: {file_path}"
    )
    assert part_match is not None
    prefix = part_match.group("prefix")
    pytest_assert(
        _PREFIX_RE.fullmatch(prefix) is not None,
        f"Unsafe or malformed Console Mirror recording prefix: {prefix}",
    )
    return prefix


def _validate_prefix(prefix: str) -> re.Match:
    match = _PREFIX_RE.fullmatch(prefix)
    pytest_assert(
        match is not None,
        f"Unsafe or malformed Console Mirror recording prefix: {prefix}",
    )
    assert match is not None
    return match


def _recording_is_open(duthost, prefix: str) -> bool:
    _validate_prefix(prefix)
    line_dir = os.path.dirname(prefix)
    result = duthost.shell(
        f"sudo lsof +D {shlex.quote(line_dir)}", module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] in (0, 1),
        "Failed to inspect open recording files in {}: {}".format(
            line_dir, result.get("stderr")
        ),
    )
    return prefix in result.get("stdout", "")


def _remove_test_recording(duthost, prefix: str) -> None:
    _validate_prefix(prefix)
    line_dir = os.path.dirname(prefix)
    pattern = os.path.basename(prefix) + "*"
    result = duthost.shell(
        f"sudo find {shlex.quote(line_dir)} -maxdepth 1 -type f -name {shlex.quote(pattern)} -delete",
        module_ignore_errors=True,
    )
    pytest_assert(result["rc"] == 0, f"Failed to delete test recording {prefix}")


def _list_recording_parts(duthost, prefix: str) -> list[str]:
    _validate_prefix(prefix)
    line_dir = os.path.dirname(prefix)
    pattern = os.path.basename(prefix) + "-part????.log"
    result = duthost.shell(
        f"sudo find {shlex.quote(line_dir)} -maxdepth 1 -type f -name {shlex.quote(pattern)} -printf '%p\\n'",
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0, f"Failed to enumerate recording parts for {prefix}"
    )
    return sorted(path for path in result["stdout"].splitlines() if path)


def _unescape_payload(payload: str) -> bytes:
    output = bytearray()
    index = 0
    named = {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\"}
    while index < len(payload):
        if payload[index] != "\\":
            output.extend(payload[index].encode("utf-8"))
            index += 1
            continue
        pytest_assert(
            index + 1 < len(payload), "Trailing backslash in SCM-Text payload"
        )
        escape = payload[index + 1]
        if escape in named:
            output.extend(named[escape])
            index += 2
            continue
        if escape == "x":
            hex_value = payload[index + 2: index + 4]
            pytest_assert(
                len(hex_value) == 2 and re.fullmatch(r"[0-9a-fA-F]{2}", hex_value),
                f"Invalid hexadecimal SCM-Text escape in {payload!r}",
            )
            output.append(int(hex_value, 16))
            index += 4
            continue
        pytest.fail(f"Unknown SCM-Text escape in {payload!r}")
    return bytes(output)


def _parse_scm_content(
    content: str, line: str, direction: str, part_number: int
) -> list[ScmRecord]:
    lines = content.splitlines()
    pytest_assert(len(lines) >= 3, "SCM-Text part has fewer than three header lines")
    pytest_assert(
        lines[0] == "# SONIC_CONSOLE_MIRROR_TEXT version=1",
        f"Invalid SCM-Text version header: {lines[0]}",
    )
    metadata = lines[1]
    pytest_assert(
        metadata.startswith("# "), f"Invalid SCM-Text metadata header: {metadata}"
    )
    metadata_fields = dict(field.split("=", 1) for field in metadata[2:].split())
    expected_metadata = {
        "line": line,
        "direction": direction,
        "part": f"part{part_number:04d}",
        "encoding": "printable-escape",
    }
    for name, expected in expected_metadata.items():
        pytest_assert(
            metadata_fields.get(name) == expected,
            f"SCM-Text metadata {name} is invalid: expected {expected}, got {metadata_fields.get(name)}",
        )
    pytest_assert(
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+Z", metadata_fields.get("start_time", "")
        ),
        f"SCM-Text start_time is missing or invalid: {metadata}",
    )
    pytest_assert(
        re.fullmatch(r"[0-9]+[smhd]", metadata_fields.get("timeout", "")),
        f"SCM-Text timeout is missing or invalid: {metadata}",
    )
    pytest_assert(
        lines[2] == "# fields=timestamp delta seq direction length payload",
        f"Invalid SCM-Text fields header: {lines[2]}",
    )

    records = []
    for record_line in lines[3:]:
        if not record_line:
            continue
        pytest_assert(
            all(
                ord(char) >= 0x20 and not 0x7F <= ord(char) <= 0x9F
                for char in record_line
            ),
            "SCM-Text contains a literal terminal-control character",
        )
        match = _RECORD_RE.fullmatch(record_line)
        pytest_assert(match is not None, f"Malformed SCM-Text record: {record_line}")
        assert match is not None
        original_length = int(match.group("length"))
        record_direction = match.group("direction")
        payload_text = match.group("payload")
        if record_direction == "EVENT":
            event = json.loads(payload_text)
            payload = payload_text.encode("utf-8")
            pytest_assert(
                isinstance(event, dict), "SCM-Text EVENT payload is not a JSON object"
            )
        else:
            event = None
            payload = _unescape_payload(payload_text)
        pytest_assert(
            len(payload) == original_length,
            f"SCM-Text length mismatch: header={original_length}, decoded={len(payload)}",
        )
        records.append(
            ScmRecord(
                seq=int(match.group("seq")),
                direction=record_direction,
                original_length=original_length,
                payload=payload,
                event=event,
            )
        )
    return records


def _read_remote_file(duthost, path: str) -> str:
    result = duthost.shell(
        f"sudo cat -- {shlex.quote(path)}", module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] == 0, "Failed to read {}: {}".format(path, result.get("stderr"))
    )
    return result["stdout"]


def _read_scm_parts(
    duthost, prefix: str, direction: str
) -> tuple[list[str], list[ScmRecord]]:
    prefix_match = _validate_prefix(prefix)
    parts = _list_recording_parts(duthost, prefix)
    pytest_assert(parts, f"No recording parts found for {prefix}")
    records = []
    for expected_part, path in enumerate(parts, 1):
        match = _PART_RE.fullmatch(path)
        pytest_assert(
            match is not None and int(match.group("part")) == expected_part,
            f"Recording parts are missing or non-contiguous: {parts}",
        )
        records.extend(
            _parse_scm_content(
                _read_remote_file(duthost, path),
                prefix_match.group("line"),
                direction,
                expected_part,
            )
        )
    sequences = [record.seq for record in records]
    pytest_assert(
        sequences == list(range(1, len(sequences) + 1)),
        f"SCM-Text sequence numbers are not contiguous: {sequences}",
    )
    return parts, records


def _drain_console(client: pexpect.spawn) -> None:
    while True:
        try:
            client.read_nonblocking(size=8192, timeout=0.05)
        except pexpect.TIMEOUT:
            return
        except pexpect.EOF:
            pytest.fail("Console session closed while draining pending data")


def _send_all(client: pexpect.spawn, payload: bytes, baud_rate: int) -> None:
    chunk_size = 256
    remaining = memoryview(payload)
    while remaining:
        chunk = remaining[:chunk_size]
        written = client.send(chunk.tobytes())
        pytest_assert(written, "Console session accepted zero bytes while sending")
        remaining = remaining[written:]
        if remaining:
            time.sleep(written * 10.0 / baud_rate)  # 8N1


def _extract_frame(captured: bytes, start_marker: bytes, end_marker: bytes) -> bytes:
    start = captured.find(start_marker)
    end = captured.find(end_marker, start + len(start_marker) if start >= 0 else 0)
    pytest_assert(
        start >= 0 and end >= 0,
        f"Did not receive Console Mirror traffic frame (captured {len(captured)} bytes)",
    )
    return captured[start + len(start_marker): end]


def _transfer_payload(
    client: pexpect.spawn,
    payload: bytes,
    baud_rate: int,
) -> tuple[bytes, float]:
    token = uuid.uuid4().hex.encode(encoding="ascii")
    start_marker = b"CM_START_" + token + b"_"
    end_marker = b"_CM_END_" + token + b"\n"
    frame = start_marker + payload + end_marker
    _drain_console(client)

    captured = bytearray()
    reader_errors = []
    done = threading.Event()
    timeout = max(30.0, len(frame) * 10.0 / baud_rate * 3.0 + 30.0)

    def reader():
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline and not done.is_set():
                try:
                    data = client.read_nonblocking(size=8192, timeout=0.2)
                except pexpect.TIMEOUT:
                    continue
                if isinstance(data, str):
                    data = data.encode("latin-1")
                captured.extend(data)
                if end_marker in captured:
                    return
            reader_errors.append(f"Timed out receiving {len(frame)} serial bytes")
        # Propagate reader-thread errors in the test thread.
        except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
            reader_errors.append(str(error))

    reader_thread = threading.Thread(
        target=reader, name="console-mirror-reader", daemon=True
    )
    started = time.monotonic()
    reader_thread.start()
    _send_all(client, frame, baud_rate)
    reader_thread.join(timeout)
    elapsed = time.monotonic() - started
    done.set()
    pytest_assert(not reader_thread.is_alive(), "Console receive thread did not finish")
    pytest_assert(not reader_errors, f"Console receive failed: {reader_errors}")
    pytest_assert(
        _extract_frame(bytes(captured), start_marker, end_marker) == payload,
        "Console Mirror changed, lost, or duplicated bytes in the active console session",
    )
    return frame, elapsed


def _open_console_client(
    duthost, creds: dict, context: MirrorTestContext
) -> pexpect.spawn:
    dut_ip, dut_user, dut_password = get_host_ip_and_creds(duthost, creds)
    line = context.port.line
    client = create_ssh_client(dut_ip, f"{dut_user}:{line}", dut_password)
    context.clients.append(client)
    ensure_console_session_up(client, line)
    client.delaybeforesend = None
    client.delayafterread = None
    _drain_console(client)
    return client


def _generate_rotation(
    duthost, creds, context: MirrorTestContext, prefix: str
) -> list[str]:
    client = _open_console_client(duthost, creds, context)
    payload = b"\x80" * ROTATION_PAYLOAD_BYTES_PER_DIRECTION
    _transfer_payload(client, payload, context.port.baud_rate)
    pytest_assert(
        wait_until(30, 1, 0, lambda: len(_list_recording_parts(duthost, prefix)) >= 2),
        "Recording did not rotate after escaped traffic exceeded the 1 MB part limit",
    )
    return _list_recording_parts(duthost, prefix)


def _records_by_direction(records: list[ScmRecord]) -> dict[str, bytes]:
    return {
        direction: b"".join(
            record.payload for record in records if record.direction == direction
        )
        for direction in ("RX", "TX")
    }


def _remote_file_exists(duthost, path: str) -> bool:
    result = duthost.shell(
        f"sudo test -f {shlex.quote(path)}", module_ignore_errors=True
    )
    return result["rc"] == 0


def _remote_stat(duthost, path: str) -> dict[str, object]:
    result = duthost.shell(
        f"sudo stat -c '%a|%U|%G|%F|%s' -- {shlex.quote(path)}",
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0, "Failed to stat {}: {}".format(path, result.get("stderr"))
    )
    mode, user, group, file_type, size = result["stdout"].strip().split("|", 4)
    return {
        "mode": mode,
        "user": user,
        "group": group,
        "type": file_type,
        "size": int(size),
    }


def _remote_sha256(duthost, path: str) -> str:
    result = duthost.shell(
        f"sudo sha256sum -- {shlex.quote(path)}", module_ignore_errors=True
    )
    digest = result.get("stdout", "").split(maxsplit=1)[0]  # <sha256>  <filename>
    pytest_assert(
        result["rc"] == 0 and re.fullmatch(r"[0-9a-f]{64}", digest),
        "Failed to calculate SHA-256 for {}: {}".format(
            path, result.get("stderr") or result.get("stdout")
        ),
    )
    return digest


def _zip_information(duthost, archive_path: str, include_content: bool = False) -> dict:
    _validate_prefix(archive_path[:-4] if archive_path.endswith(".zip") else "")
    entry_value = (
        "z.read(name).decode('utf-8')"
        if include_content
        else "z.read(name).decode('utf-8').splitlines()[:3]"
    )
    script = (
        "import hashlib,json,sys,zipfile;"
        "z=zipfile.ZipFile(sys.argv[1]);"
        "names=z.namelist();"
        f"print(json.dumps({{'bad':z.testzip(),'entries':[{{'name':name,'size':z.getinfo(name).file_size,"
        f"'sha256':hashlib.sha256(z.read(name)).hexdigest(),'value':{entry_value}}} for name in names]}}))"
    )
    result = duthost.shell(
        f"sudo python3 -c {shlex.quote(script)} {shlex.quote(archive_path)}",
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0,
        "Failed to inspect archive {}: {}".format(archive_path, result.get("stderr")),
    )
    return json.loads(result["stdout"])


def _assert_archive_part_names(prefix: str, names: list[str]) -> None:
    _validate_prefix(prefix)
    prefix_name = re.escape(os.path.basename(prefix))
    pattern = re.compile(rf"^{prefix_name}-part([0-9]{{4}})\.log$")
    part_numbers = []
    for name in names:
        match = pattern.fullmatch(name)
        pytest_assert(
            match is not None, f"ZIP contains a foreign or malformed entry: {name}"
        )
        assert match is not None
        part_numbers.append(int(match.group(1)))
    pytest_assert(
        part_numbers == list(range(1, len(names) + 1)),
        f"ZIP recording parts are missing or duplicated: {names}",
    )


def _systemd_counter(duthost, service: str, property_name: str):
    result = duthost.shell(
        f"sudo systemctl show {service} --property={property_name} --value",
        module_ignore_errors=True,
    )
    value = result.get("stdout", "").strip()
    pytest_assert(
        result["rc"] == 0 and value.isdigit(),
        f"Could not read {property_name} for {service}: {value}",
    )
    return value


def _get_proxy_memory_usage(duthost, service: str) -> int:
    return int(_systemd_counter(duthost, service, "MemoryCurrent"))


def _get_proxy_cpu_usage(
    duthost, service: str, sample_state: dict[str, float]
) -> float:
    last_time = sample_state.get("time")
    last_value = sample_state.get("value")
    if last_time is None or last_value is None:
        last_time = time.monotonic()
        last_value = float(_systemd_counter(duthost, service, "CPUUsageNSec"))
        time.sleep(2)
    current_time = time.monotonic()
    current_value = float(_systemd_counter(duthost, service, "CPUUsageNSec"))
    elapsed_time = current_time - last_time
    elapsed_cpu_nsec = current_value - last_value
    sample_state.update(time=current_time, value=current_value)
    elapsed_cpu_sec = elapsed_cpu_nsec / 1e9
    cpu_percent = (elapsed_cpu_sec / elapsed_time) * 100
    return cpu_percent


# ==================== Fixtures ============================


@pytest.fixture(scope="module")
def mirror_port(setup_c0, duthost, conn_graph_facts, console_facts) -> MirrorPort:  # noqa: F811
    """Select one c0-lo console port."""
    setup_dut, console_fanout = setup_c0
    pytest_assert(
        setup_dut is duthost and console_fanout is duthost,
        "Console Mirror tests require a c0-lo DUT with local loopback wiring",
    )

    lines = get_dut_console_lines(conn_graph_facts, duthost)
    pytest_assert(
        lines,
        f"Console Mirror requires at least one console line for DUT '{duthost.hostname}' in *_serial_links.csv",
    )
    line = str(lines[0])
    line_facts = console_facts["lines"][line]
    port = MirrorPort(
        line=line,
        baud_rate=int(line_facts["baud_rate"]),
        flow_control=bool(line_facts["flow_control"]),
    )
    logger.info(
        "Selected Console Mirror loopback port: line %s, baud=%s, flow_control=%s",
        port.line,
        port.baud_rate,
        port.flow_control,
    )
    return port


@pytest.fixture(scope="function")
def mirror_test_context(duthost, mirror_port: MirrorPort):
    """Provide strict per-test teardown for mirror and interactive sessions."""
    # 1. Check proxy service and socket
    line = mirror_port.line
    service = f"console-monitor-proxy@{line}.service"
    result = duthost.shell(
        f"sudo systemctl is-active --quiet {service}", module_ignore_errors=True
    )
    pytest_assert(result["rc"] == 0, f"{service} is not active")
    pytest_assert(
        check_target_line_status(duthost, line, "IDLE"),
        f"Console line {line} is busy before the test starts",
    )

    socket_path = f"/run/console-monitor/mirror/line{line}.sock"
    result = duthost.shell(
        f"sudo test -S {shlex.quote(socket_path)}", module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] == 0, f"Console Mirror control socket is missing: {socket_path}"
    )

    # 2. Check initial CLI and DB are idle
    initial_cli = _get_cli_status(duthost, line)
    initial_db = _get_state_db(duthost, line)
    pytest_assert(
        initial_cli.get("state") == "idle" and initial_db.get("state") == "idle",
        f"Console line {line} is not idle at test start, CLI={initial_cli}, DB={initial_db}",
    )

    # 3. Create context
    context: MirrorTestContext = MirrorTestContext(port=mirror_port)

    yield context

    teardown_errors = []
    # 4. Stop any active mirror sessions
    try:
        cli_status = _get_cli_status(duthost, line)
        db_status = _get_state_db(duthost, line)
        if cli_status.get("file_path") and cli_status["file_path"] != "-":
            try:
                context.register_recording_file(cli_status["file_path"])
            except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
                teardown_errors.append(str(error))
        if cli_status.get("state") == "active" or db_status.get("state") == "active":
            result = _mirror_command(
                duthost,
                f"stop {line}",
                expect_success=False,
            )
            if result["rc"] != 0:
                teardown_errors.append(
                    "Failed to stop active mirror during teardown: {}".format(
                        result.get("stderr") or result.get("stdout")
                    )
                )
    except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
        teardown_errors.append(
            f"Failed to inspect/stop mirror during teardown: {error}"
        )

    # 5. Wait for cli and db idle
    # 6. Check cleared
    try:
        if not _wait_for_mirror_idle(duthost, line):
            teardown_errors.append(
                f"Mirror line {line} did not become idle in CLI and STATE_DB"
            )
        state = _get_state_db(duthost, line)
        uncleared = sorted(MIRROR_ACTIVE_FIELDS.intersection(state))
        if state.get("state") != "idle" or uncleared:
            teardown_errors.append(
                f"STATE_DB teardown state is invalid: state={state}, uncleared_fields={uncleared}"
            )
    except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
        teardown_errors.append(f"Failed to verify idle mirror state: {error}")

    # 7. Delete
    for prefix in sorted(context.recording_prefixes):
        try:
            if _recording_is_open(duthost, prefix):
                teardown_errors.append(
                    f"Target proxy still has a recording file open for {prefix}"
                )
        except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
            teardown_errors.append(
                f"Failed to check open recording files for {prefix}: {error}"
            )

    for client in context.clients:
        disconnect_console_client(client)
        try:
            client.close(force=True)
        except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
            teardown_errors.append(f"Failed to close console client: {error}")

    try:
        if not wait_until(
            15, 1, 0, check_target_line_status, duthost, line, "IDLE"
        ):
            teardown_errors.append(f"Console line {line} did not return to IDLE")
    except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
        teardown_errors.append(
            f"Failed to verify console line {line} cleanup: {error}"
        )

    for prefix in sorted(context.recording_prefixes):
        try:
            _remove_test_recording(duthost, prefix)
        except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
            teardown_errors.append(f"Failed to remove test recording {prefix}: {error}")

    if teardown_errors:
        pytest.fail(
            "Console Mirror teardown failed: {}".format("; ".join(teardown_errors))
        )


# ==================== Test Cases ==========================


def test_console_mirror_cli_and_state(duthost, mirror_test_context: MirrorTestContext):
    """Verify start/show/timeout/stop output and STATE_DB runtime metadata."""
    # Mirror start
    # Start a mirror
    context = mirror_test_context
    _, file_path, prefix = _start_mirror(
        duthost, context, direction="both", timeout="30s"
    )

    # Check state in CLI and STATE_DB
    cli_status = _get_cli_status(duthost, context.port.line)
    state = _get_state_db(duthost, context.port.line)
    pytest_assert(cli_status["state"] == "active" and cli_status["direction"] == "both")
    pytest_assert(
        cli_status["timeout"] == "30s"
        and 0 < _duration_seconds(cli_status["remaining"]) <= 30
    )
    pytest_assert(cli_status["file_path"] == file_path)
    pytest_assert(state.get("state") == "active" and state.get("direction") == "both")
    pytest_assert(state.get("timeout") == "30" and state.get("file_path") == file_path)
    pytest_assert(state.get("owner_pid", "").isdigit() and int(state["owner_pid"]) > 0)
    pytest_assert(
        state.get("started_by", "") != "" and state.get("start_time", "").isdigit()
    )
    original_start_time = state["start_time"]

    # Mirror timeout
    result = _mirror_command(duthost, f"timeout {context.port.line} 1m")
    pytest_assert(
        f"Updated mirror timeout on line [{context.port.line}]" in result["stdout"]
    )
    pytest_assert("Timeout: 1m" in result["stdout"])
    remaining_match = re.search(r"^Remaining:\s*(\S+)", result["stdout"], re.MULTILINE)
    pytest_assert(remaining_match is not None, result["stdout"])
    assert remaining_match is not None
    pytest_assert(0 < _duration_seconds(remaining_match.group(1)) <= 60)

    cli_status = _get_cli_status(duthost, context.port.line)
    state = _get_state_db(duthost, context.port.line)
    pytest_assert(
        cli_status["timeout"] == "1m"
        and 0 < _duration_seconds(cli_status["remaining"]) <= 60
    )
    pytest_assert(
        state.get("timeout") == "60" and state.get("start_time") == original_start_time
    )
    pytest_assert(state.get("file_path") == file_path)

    # Mirror stop
    result, retained_prefix = _stop_mirror(duthost, context)
    pytest_assert(f"Stopped mirror on line [{context.port.line}]" in result["stdout"])
    pytest_assert(retained_prefix == prefix)
    # Wait for the mirror to become idle
    pytest_assert(_wait_for_mirror_idle(duthost, context.port.line))
    idle_state = _get_state_db(duthost, context.port.line)
    pytest_assert(
        idle_state == {"state": "idle"}, f"Active fields were not cleared: {idle_state}"
    )
    _, records = _read_scm_parts(duthost, prefix, "both")
    pytest_assert(
        any(
            record.event == {"event": "timeout_update", "timeout": "1m"}
            for record in records
        ),
        "Timeout update was not recorded in SCM-Text",
    )


@pytest.mark.parametrize("direction", ["rx", "tx", "both"])
def test_console_mirror_traffic_recording(
    duthost,
    creds,
    mirror_test_context: MirrorTestContext,
    direction: str,
):
    """Verify direction filtering, escaping, byte integrity, and non-interference."""
    context = mirror_test_context
    client = _open_console_client(duthost, creds, context)
    _, _, prefix = _start_mirror(duthost, context, direction=direction, timeout="2m")

    control_bytes = b"\x02\t\n\r\x1b\x7f\x80\\"
    payload = (
        b"loopback-" + uuid.uuid4().hex.encode("ascii") + b"-" + control_bytes
    )
    loopback_frame, _ = _transfer_payload(client, payload, context.port.baud_rate)

    _stop_mirror(duthost, context)
    _, records = _read_scm_parts(duthost, prefix, direction)
    streams = _records_by_direction(records)
    expected_directions = {
        "rx": {"RX"},
        "tx": {"TX"},
        "both": {"RX", "TX"},
    }[direction]
    actual_directions = {
        record.direction for record in records if record.direction in ("RX", "TX")
    }
    pytest_assert(
        actual_directions == expected_directions,
        f"Direction labels do not match {direction} filtering: {actual_directions}",
    )

    if "TX" in expected_directions:
        pytest_assert(
            streams["TX"].count(loopback_frame) == 1,
            "Loopback frame was not recorded exactly once as TX",
        )
    else:
        pytest_assert(
            loopback_frame not in streams["TX"],
            "TX payload leaked into an excluded direction",
        )
    if "RX" in expected_directions:
        pytest_assert(
            streams["RX"].count(loopback_frame) == 1,
            "Looped-back frame was not recorded exactly once as RX",
        )
    else:
        pytest_assert(
            loopback_frame not in streams["RX"],
            "RX payload leaked into an excluded direction",
        )


def test_console_mirror_recording_files(
    duthost, creds, mirror_test_context: MirrorTestContext
):
    """Verify SCM-Text rotation, retention, ownership, and permissions."""
    context = mirror_test_context
    _, _, prefix = _start_mirror(
        duthost, context, direction="both", timeout="10m", max_file_size=1
    )
    active_parts = _generate_rotation(duthost, creds, context, prefix)
    pytest_assert(
        wait_until(
            10,
            1,
            0,
            lambda: (
                _get_state_db(duthost, context.port.line).get("file_path")
                == active_parts[-1]
            ),
        ),
        f"STATE_DB did not follow the current rotated part: {_get_state_db(duthost, context.port.line)}",
    )

    _stop_mirror(duthost, context)
    parts, records = _read_scm_parts(duthost, prefix, "both")
    pytest_assert(len(parts) >= 2, "Expected at least two retained recording parts")
    pytest_assert(
        set(active_parts).issubset(set(parts)),
        f"Manual stop lost recording parts: active={active_parts}, retained={parts}",
    )
    pytest_assert(
        parts == _list_recording_parts(duthost, prefix),
        "Manual stop did not retain every recording part",
    )
    pytest_assert(
        not _remote_file_exists(duthost, prefix + ".zip"),
        "Manual stop without --archive unexpectedly created a ZIP",
    )
    pytest_assert(
        any(
            record.event == {"event": "stop", "reason": "manual"} for record in records
        ),
        "Manual stop event is missing from SCM-Text",
    )

    prefix_match = _validate_prefix(prefix)
    directory_stats = [
        _remote_stat(duthost, MIRROR_BASE_DIR),
        _remote_stat(
            duthost,
            os.path.join(MIRROR_BASE_DIR, "line{}".format(prefix_match.group("line"))),
        ),
    ]
    for stat_info in directory_stats:
        pytest_assert(
            stat_info["mode"] == "700"
            and stat_info["user"] == "root"
            and stat_info["group"] == "root"
            and stat_info["type"] == "directory",
            f"Recording directory permissions/ownership are invalid: {stat_info}",
        )
    for path in parts:
        stat_info = _remote_stat(duthost, path)
        pytest_assert(
            stat_info["mode"] == "600"
            and stat_info["user"] == "root"
            and stat_info["group"] == "root"
            and stat_info["type"] == "regular file",
            f"Recording part permissions/ownership are invalid: {path} -> {stat_info}",
        )
        size = stat_info["size"]
        assert isinstance(size, int)
        pytest_assert(
            size <= 1024 * 1024,
            "Rotated part exceeded the requested 1 MB limit: {} -> {}".format(
                path, stat_info["size"]
            ),
        )


def test_console_mirror_archive_success(
    duthost, creds, mirror_test_context: MirrorTestContext
):
    """Verify all rotated parts are packaged and sources are removed after success."""
    context = mirror_test_context
    _, _, prefix = _start_mirror(
        duthost, context, direction="both", timeout="10m", max_file_size=1
    )
    source_parts = _generate_rotation(duthost, creds, context, prefix)
    pytest_assert(len(source_parts) >= 2)

    # Keep a hard link to each source inode.
    source_copies = {}
    for source_path in source_parts:
        source_copy = source_path + ".source-copy"
        result = duthost.shell(
            f"sudo ln -- {shlex.quote(source_path)} {shlex.quote(source_copy)}",
            module_ignore_errors=True,
        )
        pytest_assert(
            result["rc"] == 0,
            "Failed to preserve source log {}: {}".format(
                source_path, result.get("stderr") or result.get("stdout")
            ),
        )
        source_copies[os.path.basename(source_path)] = source_copy

    result, archive_path = _stop_mirror(duthost, context, archive=True)
    pytest_assert("packaging recording" in result["stdout"])
    pytest_assert("Waiting for packaging to complete" in result["stdout"])
    pytest_assert(
        _remote_file_exists(duthost, archive_path), "Completed ZIP does not exist"
    )
    pytest_assert(
        not _list_recording_parts(duthost, prefix),
        "Source log parts were not removed after successful packaging",
    )
    pytest_assert(
        not _remote_file_exists(duthost, archive_path + ".tmp"),
        "Temporary ZIP remains after successful packaging",
    )

    stat_info = _remote_stat(duthost, archive_path)
    pytest_assert(
        stat_info["mode"] == "600"
        and stat_info["user"] == "root"
        and stat_info["group"] == "root"
        and stat_info["type"] == "regular file",
        f"Archive permissions/ownership are invalid: {stat_info}",
    )
    archive = _zip_information(duthost, archive_path)
    pytest_assert(
        archive["bad"] is None,
        "ZIP CRC validation failed for {}".format(archive["bad"]),
    )
    names = [entry["name"] for entry in archive["entries"]]
    _assert_archive_part_names(prefix, names)
    pytest_assert(
        set(names) == set(source_copies),
        f"ZIP entries do not match the source logs: source={sorted(source_copies)}, archive={names}",
    )
    pytest_assert(
        len(names) >= 2, f"ZIP does not contain all rotated recording parts: {names}"
    )
    for entry in archive["entries"]:
        source_copy = source_copies[entry["name"]]
        source_stat = _remote_stat(duthost, source_copy)
        pytest_assert(
            entry["size"] == source_stat["size"],
            "Archived content size differs from source {}: archive={}, source={}".format(
                entry["name"], entry["size"], source_stat["size"]
            ),
        )
        pytest_assert(
            entry["sha256"] == _remote_sha256(duthost, source_copy),
            f"Archived content differs from source log {entry['name']}",
        )
        pytest_assert(entry["value"][0] == "# SONIC_CONSOLE_MIRROR_TEXT version=1")
        pytest_assert(
            entry["value"][2] == "# fields=timestamp delta seq direction length payload"
        )


def test_console_mirror_automatic_stop(duthost, mirror_test_context: MirrorTestContext):
    """Verify timeout finalization records its reason and creates a ZIP."""
    context = mirror_test_context
    _, _, prefix = _start_mirror(
        duthost,
        context,
        direction="both",
        timeout=f"{AUTO_STOP_TIMEOUT_SEC}s",
    )
    archive_path = prefix + ".zip"

    pytest_assert(
        _wait_for_mirror_idle(duthost, context.port.line),
        message=f"Mirror did not automatically stop after {AUTO_STOP_TIMEOUT_SEC}s",
    )
    pytest_assert(
        wait_until(30, 1, 1, _remote_file_exists, duthost, archive_path),
        "Automatic stop did not create a ZIP",
    )
    pytest_assert(
        wait_until(30, 1, 1, lambda: not _list_recording_parts(duthost, prefix)),
        "Source log parts were not removed after automatic stop",
    )

    archive = _zip_information(duthost, archive_path, include_content=True)
    pytest_assert(
        archive["bad"] is None,
        "ZIP CRC validation failed for {}".format(archive["bad"]),
    )
    names = [entry["name"] for entry in archive["entries"]]
    _assert_archive_part_names(prefix, names)
    records = []
    prefix_match = _validate_prefix(prefix)
    for part_number, entry in enumerate(archive["entries"], 1):
        records.extend(
            _parse_scm_content(
                entry["value"], prefix_match.group("line"), "both", part_number
            )
        )
    pytest_assert(
        any(
            record.event == {"event": "stop", "reason": "timeout"} for record in records
        ),
        "Automatic archive does not contain reason=timeout",
    )


def test_console_mirror_resource_usage(
    duthost, creds, record_property, mirror_test_context: MirrorTestContext
):
    """Measure proxy CPU/memory at maximum configured serial throughput."""
    context = mirror_test_context
    client = _open_console_client(duthost, creds, context)
    service = f"console-monitor-proxy@{context.port.line}.service"

    # record baseline
    cpu_sample_state: dict[str, float] = {}
    baseline_cpu = _get_proxy_cpu_usage(duthost, service, cpu_sample_state)
    baseline_mem = _get_proxy_memory_usage(duthost, service)

    _start_mirror(duthost, context, direction="both", timeout="5m")

    payload_size = max(
        4096, int(context.port.baud_rate / 10.0 * RESOURCE_LOAD_DURATION_SEC)
    )
    payload = b"S" * payload_size
    transfer_result = {}
    transfer_errors = []

    def transfer():
        try:
            frame, elapsed = _transfer_payload(
                client, payload, context.port.baud_rate
            )
            transfer_result.update(frame=frame, elapsed=elapsed)
        except (Exception, pytest.fail.Exception) as error:  # noqa: BLE001
            transfer_errors.append(error)

    transfer_thread = threading.Thread(
        target=transfer, name="console-mirror-transfer", daemon=True
    )
    transfer_thread.start()

    mem_samples = []
    cpu_samples = []
    while transfer_thread.is_alive():
        time.sleep(RESOURCE_SAMPLE_INTERVAL_SEC)
        mem_samples.append(_get_proxy_memory_usage(duthost, service))
        cpu_samples.append(_get_proxy_cpu_usage(duthost, service, cpu_sample_state))

    transfer_thread.join(timeout=1.0)
    pytest_assert(
        not transfer_errors, f"Maximum-rate console transfer failed: {transfer_errors}"
    )
    pytest_assert(transfer_result, "Maximum-rate console transfer produced no result")
    _stop_mirror(duthost, context)

    # check actual throughput
    throughput = payload_size / transfer_result["elapsed"]
    expected_throughput = context.port.baud_rate / 10.0
    pytest_assert(
        throughput >= expected_throughput * 0.75,
        f"Console throughput {throughput:.1f} B/s is below 75% of baud-limited {expected_throughput:.1f} B/s",
    )

    post_limit = baseline_mem + int(baseline_mem * 0.25)
    pytest_assert(
        wait_until(
            30,
            3,
            0,
            lambda: _get_proxy_memory_usage(duthost, service) <= post_limit,
        ),
        f"Proxy memory did not return near its idle baseline (baseline={baseline_mem}, allowed={post_limit})",
    )

    post_memory = _get_proxy_memory_usage(duthost, service)
    peak_memory = max(mem_samples or [baseline_mem])
    peak_cpu = max(cpu_samples or [0.0])

    metrics = {
        "line": context.port.line,
        "baud_rate": context.port.baud_rate,
        "payload_bytes": payload_size,
        "throughput_bytes_per_sec": round(throughput, 2),
        "idle_cpu_percent": round(baseline_cpu, 3),
        "peak_cpu_percent": round(peak_cpu, 3),
        "idle_memory_bytes": baseline_mem,
        "peak_memory_bytes": peak_memory,
        "post_stop_memory_bytes": post_memory,
    }
    logger.info("Console Mirror resource metrics: %s", metrics)
    for name, value in metrics.items():
        record_property(f"console_mirror_{name}", value)
