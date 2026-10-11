import importlib.util
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "generate_hosts.py"

spec = importlib.util.spec_from_file_location("generate_hosts", SCRIPT_PATH)
generate_hosts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate_hosts)


class TtyInput(io.StringIO):
    def isatty(self):
        return True


def write_csv(path, rows):
    path.write_text("ManagementIp,Hostname\n" + "\n".join(rows) + "\n")


def host_pairs(contents):
    pairs = set()
    for line in contents.splitlines():
        ip, hostnames = generate_hosts.parse_hosts_line(line)
        pairs.update((ip, hostname) for hostname in hostnames)
    return pairs


def test_main_preserves_multi_hostname_entries_and_rejects_changed_ip(
        tmp_path, capsys):
    base_hosts = tmp_path / "hosts"
    base_hosts.write_text(
        "127.0.0.1 localhost localhost.localdomain\n"
        "10.0.0.1 old-device\n"
    )
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["127.0.0.1,new-device", "10.0.0.2,localhost"])
    output_file = tmp_path / "hosts.out"

    result = generate_hosts.main(
        str(base_hosts), str(output_file), str(csv_file), override=True
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert (
        "Hostname localhost already exists with IP 127.0.0.1"
        in captured.err
    )
    assert not output_file.exists()


def test_load_csv_devices_strips_values_and_validates_ip(tmp_path):
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, [" 10.0.0.1/24 , host1 "])

    assert generate_hosts.load_csv_devices(str(csv_file)) == {
        "host1": "10.0.0.1"
    }


@pytest.mark.parametrize(
    "row, message",
    [
        ("not-an-ip,host1", "invalid ManagementIp 'not-an-ip'"),
        ("10.0.0.1,   ", "ManagementIp and Hostname must not be empty"),
        ("   ,host1", "ManagementIp and Hostname must not be empty"),
        ("10.0.0.1,bad_host", "invalid Hostname 'bad_host'"),
    ],
)
def test_load_csv_devices_rejects_invalid_values(tmp_path, row, message):
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, [row])

    with pytest.raises(ValueError, match=message):
        generate_hosts.load_csv_devices(str(csv_file))


def test_load_csv_devices_reports_missing_columns(tmp_path):
    csv_file = tmp_path / "devices.csv"
    csv_file.write_text("ManagementIp,Name\n10.0.0.1,host1\n")

    with pytest.raises(ValueError, match="missing required CSV column.*Hostname"):
        generate_hosts.load_csv_devices(str(csv_file))


def test_load_csv_devices_rejects_unmatched_glob(tmp_path):
    pattern = str(tmp_path / "missing-*.csv")

    with pytest.raises(ValueError, match="No CSV files matched pattern"):
        generate_hosts.load_csv_devices(pattern)


def test_load_csv_devices_rejects_conflicting_mappings(tmp_path):
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,Host1.", "10.0.0.2,host1"])

    message = (
        "Hostname host1 is mapped to multiple IPs: "
        "10.0.0.1 and 10.0.0.2"
    )
    with pytest.raises(ValueError, match=message):
        generate_hosts.load_csv_devices(str(csv_file))


def test_write_hosts_file_adds_missing_newline_and_warns_once(tmp_path):
    output_file = tmp_path / "hosts.out"
    hosts_map = {
        "127.0.0.1": ["localhost"],
        "10.0.0.1": ["host1", "host2", "host3"],
    }

    generate_hosts.write_hosts_file(
        str(output_file), hosts_map, ["127.0.0.1 localhost"]
    )

    output = output_file.read_text()
    warning = (
        "# Warning: IP 10.0.0.1 is mapped to multiple hostnames: "
        "host1, host2, host3\n"
    )
    assert output.startswith("127.0.0.1 localhost\n")
    assert output.count(warning) == 1
    assert host_pairs(output) == {
        ("127.0.0.1", "localhost"),
        ("10.0.0.1", "host1"),
        ("10.0.0.1", "host2"),
        ("10.0.0.1", "host3"),
    }


@pytest.mark.parametrize("stdin", [io.StringIO(), None])
def test_main_rejects_non_interactive_conflict(
        tmp_path, capsys, monkeypatch, stdin):
    base_hosts = tmp_path / "hosts"
    base_hosts.write_text("10.0.0.1 old-host\n")
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,new-host"])
    output_file = tmp_path / "hosts.out"
    output_file.write_text("unchanged\n")
    monkeypatch.setattr(generate_hosts.sys, "stdin", stdin)

    result = generate_hosts.main(
        str(base_hosts), str(output_file), str(csv_file), override=False
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert (
        "Cannot prompt to add new-host in non-interactive mode"
        in captured.err
    )
    assert output_file.read_text() == "unchanged\n"


def test_main_accepts_interactive_conflict(tmp_path, capsys, monkeypatch):
    base_hosts = tmp_path / "hosts"
    base_hosts.write_text("10.0.0.1 old-host\n")
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,new-host"])
    output_file = tmp_path / "hosts.out"
    monkeypatch.setattr(generate_hosts.sys, "stdin", TtyInput("y\n"))

    result = generate_hosts.main(
        str(base_hosts), str(output_file), str(csv_file), override=False
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == ""
    assert "Do you want to add hostname new-host" in captured.err
    assert ("10.0.0.1", "new-host") in host_pairs(output_file.read_text())


def test_main_atomically_updates_base_file_in_place(tmp_path):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")
    hosts_file.chmod(0o640)
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,host1"])

    result = generate_hosts.main(
        str(hosts_file), str(hosts_file), str(csv_file), override=False
    )

    assert result == 0
    assert host_pairs(hosts_file.read_text()) == {
        ("127.0.0.1", "localhost"),
        ("10.0.0.1", "host1"),
    }
    assert hosts_file.stat().st_mode & 0o777 == 0o640


def test_main_updates_symlink_target_without_replacing_link(tmp_path):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")
    hosts_link = tmp_path / "hosts.link"
    hosts_link.symlink_to(hosts_file.name)
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,host1"])

    result = generate_hosts.main(
        str(hosts_link), str(hosts_link), str(csv_file), override=False
    )

    assert result == 0
    assert hosts_link.is_symlink()
    assert ("10.0.0.1", "host1") in host_pairs(hosts_file.read_text())


def test_main_rejects_non_regular_output(tmp_path, capsys):
    base_hosts = tmp_path / "hosts"
    base_hosts.write_text("127.0.0.1 localhost\n")
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,host1"])
    output_file = tmp_path / "hosts.fifo"
    os.mkfifo(str(output_file))

    result = generate_hosts.main(
        str(base_hosts), str(output_file), str(csv_file), override=False
    )

    assert result == 1
    assert output_file.is_fifo()
    assert "is not a regular file" in capsys.readouterr().err


def test_main_rejects_cyclic_output_symlink(tmp_path, capsys):
    base_hosts = tmp_path / "hosts"
    base_hosts.write_text("127.0.0.1 localhost\n")
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,host1"])
    output_file = tmp_path / "hosts.link"
    output_file.symlink_to(output_file.name)

    result = generate_hosts.main(
        str(base_hosts), str(output_file), str(csv_file), override=False
    )

    assert result == 1
    assert output_file.is_symlink()
    assert "broken or cyclic symlink" in capsys.readouterr().err


def test_atomic_write_preserves_output_when_replace_fails(
        tmp_path, monkeypatch):
    output_file = tmp_path / "hosts"
    output_file.write_text("original\n")

    def fail_replace(source, destination):
        raise OSError("replace failed")

    monkeypatch.setattr(generate_hosts.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        generate_hosts.write_hosts_file(
            str(output_file), {"10.0.0.1": ["host1"]}, []
        )

    assert output_file.read_text() == "original\n"
    assert list(tmp_path.iterdir()) == [output_file]


def test_main_rejects_missing_base_file(tmp_path, capsys):
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,host1"])
    output_file = tmp_path / "hosts"

    result = generate_hosts.main(
        str(tmp_path / "missing-hosts"),
        str(output_file),
        str(csv_file),
        override=False,
    )

    assert result == 1
    assert "Base hosts file" in capsys.readouterr().err
    assert not output_file.exists()


def test_load_csv_devices_reports_malformed_csv(tmp_path):
    csv_file = tmp_path / "devices.csv"
    write_csv(csv_file, ["10.0.0.1,hostname-longer-than-limit"])
    original_limit = generate_hosts.csv.field_size_limit()

    try:
        generate_hosts.csv.field_size_limit(20)
        with pytest.raises(ValueError, match="invalid CSV data"):
            generate_hosts.load_csv_devices(str(csv_file))
    finally:
        generate_hosts.csv.field_size_limit(original_limit)


def test_cli_returns_nonzero_for_unmatched_glob(tmp_path):
    output_file = tmp_path / "hosts"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--base-hosts", "",
            "--output", str(output_file),
            "--csv-pattern", str(tmp_path / "missing-*.csv"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "No CSV files matched pattern" in result.stderr
    assert not output_file.exists()
