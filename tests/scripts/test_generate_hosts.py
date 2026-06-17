import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "ansible" / "scripts" / "generate_hosts.py"


spec = importlib.util.spec_from_file_location("generate_hosts", SCRIPT_PATH)
generate_hosts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate_hosts)


def test_main_preserves_multi_hostname_entries_and_warns_on_changed_ip(tmp_path, capsys):
    base_hosts = tmp_path / "hosts"
    base_hosts.write_text("127.0.0.1 localhost localhost.localdomain\n10.0.0.1 old-device\n")

    csv_file = tmp_path / "devices.csv"
    csv_file.write_text("ManagementIp,Hostname\n127.0.0.1,new-device\n10.0.0.2,localhost\n")
    output_file = tmp_path / "hosts.out"

    generate_hosts.main(str(base_hosts), str(output_file), str(csv_file), override=True)

    captured = capsys.readouterr().out
    output = output_file.read_text()

    assert "Adding hostname new-device to existing IP 127.0.0.1." in captured
    assert "Warning: Hostname localhost already exists with IP 127.0.0.1, skipping new IP 10.0.0.2." in captured
    warning = "# Warning: IP 127.0.0.1 is mapped to multiple hostnames: localhost, localhost.localdomain, new-device\n"
    assert warning in output
    assert "127.0.0.1 new-device\n" in output
    assert "10.0.0.2 localhost" not in output


def test_load_csv_devices_warns_and_skips_missing_fields(tmp_path, capsys):
    csv_file = tmp_path / "devices.csv"
    csv_file.write_text("ManagementIp,Hostname\n10.0.0.1,host1\n10.0.0.2,\n")

    devices = generate_hosts.load_csv_devices(str(csv_file))

    assert devices == {"host1": "10.0.0.1"}
    assert f"Warning: Skipping {csv_file} line 3, missing ManagementIp or Hostname." in capsys.readouterr().out


def test_write_hosts_file_emits_duplicate_ip_warning_once(tmp_path):
    output_file = tmp_path / "hosts.out"
    hosts_map = {"10.0.0.1": ["host1", "host2", "host3"]}

    generate_hosts.write_hosts_file(str(output_file), hosts_map, [])

    output = output_file.read_text()

    assert output.count("# Warning: IP 10.0.0.1 is mapped to multiple hostnames: host1, host2, host3\n") == 1
    assert "10.0.0.1 host1\n" in output
    assert "10.0.0.1 host2\n" in output
    assert "10.0.0.1 host3\n" in output
