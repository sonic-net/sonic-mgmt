"""Offline regressions for the selected-device MGFX persistence helper."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


SPEC = importlib.util.spec_from_file_location(
    "repair_mgfx_config", Path(__file__).resolve().parents[1] / "repair_mgfx_config.py"
)
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)

GRUB = """serial --port=0x3f8 --speed=115200 --word=8 --parity=no --stop=1
terminal_input console serial
terminal_output console serial
menuentry 'SONiC-OS-20220531.45' {
    linux /image-20220531.45/boot/vmlinuz-5.10 root=UUID=example ro console=tty0 console=ttyS0,115200n8
}
menuentry 'SONiC-OS-previous' {
    linux /image-previous/boot/vmlinuz ro console=ttyS0,115200n8
}
menuentry ONIE {
    chainloader /EFI/onie/grubx64.efi
}
# preserve unrelated --speed=115200 and console=ttyS0,115200n8
"""


def config():
    """Include both address families and unrelated configuration that must survive."""
    return {
        "DEVICE_METADATA": {"localhost": {"hostname": "dut"}},
        "MGMT_INTERFACE": {
            "eth0|10.3.146.209/24": {"gwaddr": "10.3.146.1"},
            "eth0|2001:db8::2/64": {"gwaddr": "2001:db8::1"},
            "eth1|192.0.2.2/24": {"gwaddr": "192.0.2.1"},
        },
        "BGP_NEIGHBOR": {"192.0.2.4": {"asn": "65001"}},
    }


@pytest.fixture
def dut(tmp_path, monkeypatch):
    """Replace only device I/O while executing the real orchestration."""
    config_path = tmp_path / "config_db.json"
    grub_path = tmp_path / "grub.cfg"
    original = config()
    config_path.write_text(json.dumps(original), encoding="utf-8")
    grub_path.write_text(GRUB, encoding="utf-8")
    state = {"running": copy.deepcopy(original), "commands": [], "fail_save": False}

    def command(arguments):
        state["commands"].append(arguments)
        if arguments == ["sonic-cfggen", "-d", "--print-data"]:
            return json.dumps(state["running"])
        if arguments[:5] == ["config", "interface", "ip", "add", "eth0"]:
            state["running"] = repair.management_config(state["running"], [tuple(arguments[5:])])
            return ""
        if arguments == ["config", "save", "-y"]:
            if state["fail_save"]:
                raise subprocess.CalledProcessError(1, arguments)
            config_path.write_text(json.dumps(state["running"]), encoding="utf-8")
            return ""
        raise AssertionError("Unexpected command: {}".format(arguments))

    monkeypatch.setattr(repair, "CONFIG_PATH", config_path)
    monkeypatch.setattr(repair, "GRUB_PATH", grub_path)
    monkeypatch.setattr(repair, "run_command", command)
    monkeypatch.setattr(repair.socket, "gethostname", lambda: "dut")
    return config_path, grub_path, state


def test_screenshot_example_replaces_old_ipv4_and_preserves_other_configuration():
    """The exact reported /27 and gateway replace only the stale eth0 IPv4 entry."""
    original = config()
    desired = repair.management_config(original, [("10.3.144.70/27", "10.3.144.65")])
    assert desired["MGMT_INTERFACE"]["eth0|10.3.144.70/27"] == {"gwaddr": "10.3.144.65"}
    assert "eth0|10.3.146.209/24" not in desired["MGMT_INTERFACE"]
    for key in ("eth0|2001:db8::2/64", "eth1|192.0.2.2/24"):
        assert desired["MGMT_INTERFACE"][key] == original["MGMT_INTERFACE"][key]
    assert desired["BGP_NEIGHBOR"] == original["BGP_NEIGHBOR"]
    assert original == config()


@pytest.mark.parametrize("prefix,gateway,version", [
    ("10.3.144.70", "10.3.144.65", 4),
    ("10.3.144.70/27", "10.3.146.1", 4),
    ("10.3.144.70/27", "10.3.144.70", 4),
    ("10.3.144.64/27", "10.3.144.65", 4),
    ("10.3.144.70/27", "10.3.144.95", 4),
    ("10.3.144.70/27", "2001:db8::1", 4),
    ("2001:db8::2/64", "2001:db8::1", 4),
    ("10.3.144.70/27", "169.254.0.1", 4),
    ("2001:db8::70/64", "2001:db8:1::1", 6),
    ("fe80::70/64", "fe80::70", 6),
    ("2001:db8::70/64", "ff02::1", 6),
    ("2001:db8::70/64", "::", 6),
])
def test_invalid_address_pair_rejected(prefix, gateway, version):
    """Reject ambiguous prefixes and unusable gateways before any device write."""
    with pytest.raises(ValueError):
        repair.address_pair(prefix, gateway, version)


def test_valid_address_pairs():
    """Accept the screenshot and an explicit IPv6 configuration."""
    assert repair.address_pair("10.3.144.70/27", "10.3.144.65", 4) == ("10.3.144.70/27", "10.3.144.65")
    assert repair.address_pair("2001:db8::2/64", "2001:db8::1", 6) == ("2001:db8::2/64", "2001:db8::1")


def test_ipv6_link_local_gateway_with_global_prefix_is_persisted(dut):
    """Accept and save an eth0 link-local router for a global IPv6 management prefix."""
    cfg, _, state = dut
    pair = repair.address_pair("2001:db8::70/64", "fe80::1", 6)
    assert pair == ("2001:db8::70/64", "fe80::1")
    repair.repair("dut", [pair], apply=True, console_access=True)
    saved = json.loads(cfg.read_bytes())
    assert saved == state["running"]
    assert saved["MGMT_INTERFACE"]["eth0|2001:db8::70/64"] == {"gwaddr": "fe80::1"}
    assert "eth0|2001:db8::2/64" not in saved["MGMT_INTERFACE"]
    assert saved["MGMT_INTERFACE"]["eth0|10.3.146.209/24"] == {"gwaddr": "10.3.146.1"}
    assert ["config", "interface", "ip", "add", "eth0", "2001:db8::70/64", "fe80::1"] in state["commands"]


def test_bootloader_and_all_sonic_kernel_entries_are_changed():
    """Align both boot stages while retaining the ONIE entry and comments verbatim."""
    updated = repair.console_9600(GRUB)
    assert "--speed=9600 --word=8" in updated
    assert updated.count("console=ttyS0,9600n8") == 2
    assert "root=UUID=example ro console=tty0" in updated
    assert "# preserve unrelated --speed=115200 and console=ttyS0,115200n8" in updated
    assert "chainloader /EFI/onie/grubx64.efi" in updated
    assert repair.console_9600(updated) == updated


@pytest.mark.parametrize("text", [
    GRUB.replace("--speed=115200", "--speed=57600"),
    GRUB.replace("console=ttyS0,115200n8", "console=ttyS1,115200n8"),
    GRUB.replace("serial --port", "# serial --port"),
    "serial --speed=115200\nmenuentry ONIE {\n chainloader /EFI/onie/grubx64.efi\n}\n",
])
def test_unknown_console_layout_rejected(text):
    """Do not guess a baud rate or edit a boot layout the helper cannot verify."""
    with pytest.raises(ValueError):
        repair.console_9600(text)


def test_preview_has_no_side_effects(dut):
    """Preview creates neither changed device state nor backup artifacts."""
    cfg, grub, state = dut
    before = cfg.read_bytes(), grub.read_bytes()
    plan = repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], True)
    assert plan["save_required"] and plan["grub_update_required"]
    assert (cfg.read_bytes(), grub.read_bytes()) == before
    assert state["running"] == config()
    assert list(cfg.parent.glob("*.mgfx*")) == []
    assert all(cmd[0] == "sonic-cfggen" for cmd in state["commands"])


def test_apply_persists_correct_settings_and_is_idempotent(dut):
    """Running CONFIG_DB, saved JSON, and both boot stages agree after application."""
    cfg, grub, state = dut
    addresses = [("10.3.144.70/27", "10.3.144.65")]
    before = cfg.read_bytes(), grub.read_bytes()
    repair.repair("dut", addresses, True, True, True)
    saved = json.loads(cfg.read_bytes())
    assert saved == state["running"] == repair.management_config(config(), addresses)
    assert grub.read_text(encoding="utf-8") == repair.console_9600(GRUB)
    assert next(cfg.parent.glob("config_db.json.mgfx-backup-*")).read_bytes() == before[0]
    assert next(cfg.parent.glob("grub.cfg.mgfx-backup-*")).read_bytes() == before[1]
    state["commands"].clear()
    plan = repair.repair("dut", addresses, True, True, True)
    assert not plan["save_required"] and not plan["grub_update_required"]
    assert len(list(cfg.parent.glob("*.mgfx-backup-*"))) == 2
    assert all(cmd[0] == "sonic-cfggen" for cmd in state["commands"])


def test_runtime_already_correct_but_startup_stale_is_saved(dut):
    """Saving is still required when only the persisted configuration is stale."""
    cfg, _, state = dut
    addresses = [("10.3.144.70/27", "10.3.144.65")]
    state["running"] = repair.management_config(config(), addresses)
    repair.repair("dut", addresses, apply=True, console_access=True)
    assert json.loads(cfg.read_bytes()) == state["running"]
    assert ["config", "save", "-y"] in state["commands"]
    assert not any(cmd[:3] == ["config", "interface", "ip"] for cmd in state["commands"])


def test_unrelated_unsaved_changes_block_save(dut):
    """A management repair must not silently save somebody else's BGP changes."""
    cfg, grub, state = dut
    state["running"]["BGP_NEIGHBOR"]["192.0.2.4"]["asn"] = "65002"
    before = cfg.read_bytes(), grub.read_bytes()
    with pytest.raises(ValueError, match="unrelated"):
        repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], True, True, True)
    assert (cfg.read_bytes(), grub.read_bytes()) == before
    assert all(cmd[0] == "sonic-cfggen" for cmd in state["commands"])


def test_expected_hostname_and_console_confirmation_are_required(dut):
    """Refuse the wrong DUT and an unconfirmed management-session write."""
    with pytest.raises(ValueError, match="hostname"):
        repair.repair("another-dut", [("10.3.144.70/27", "10.3.144.65")])
    with pytest.raises(ValueError, match="confirm-console-access"):
        repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], apply=True)


def test_save_failure_is_not_reported_as_success(dut, capsys):
    """Keep startup and boot files intact if saving fails; expose the recovery backups."""
    cfg, grub, state = dut
    state["fail_save"] = True
    before = cfg.read_bytes(), grub.read_bytes()
    with pytest.raises(subprocess.CalledProcessError):
        repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], True, True, True)
    assert (cfg.read_bytes(), grub.read_bytes()) == before
    output = capsys.readouterr().out
    assert "backups" in output
    assert "Persisted settings verified" not in output


def test_additional_management_attributes_require_manual_reconciliation():
    """Do not delete forced routes or platform-specific management attributes."""
    current = config()
    current["MGMT_INTERFACE"]["eth0|10.3.146.209/24"]["forced_mgmt_routes"] = ["192.0.2.0/24"]
    with pytest.raises(ValueError, match="additional management attributes"):
        repair.management_config(current, [("10.3.144.70/27", "10.3.144.65")])


def test_ipv6_and_ipv4_can_be_persisted_together(dut):
    """Explicitly selected families get their own gateways without changing other interfaces."""
    cfg, _, state = dut
    addresses = [
        ("10.3.144.70/27", "10.3.144.65"),
        ("2001:db8:1::70/64", "2001:db8:1::1"),
    ]
    repair.repair("dut", addresses, apply=True, console_access=True)
    table = json.loads(cfg.read_bytes())["MGMT_INTERFACE"]
    assert table == state["running"]["MGMT_INTERFACE"] == {
        "eth0|10.3.144.70/27": {"gwaddr": "10.3.144.65"},
        "eth0|2001:db8:1::70/64": {"gwaddr": "2001:db8:1::1"},
        "eth1|192.0.2.2/24": {"gwaddr": "192.0.2.1"},
    }


def test_unrequested_ipv6_drift_blocks_ipv4_only_save(dut):
    """Do not let a global config save overwrite an unrequested family's saved settings."""
    cfg, _, state = dut
    state["running"]["MGMT_INTERFACE"]["eth0|2001:db8::2/64"]["gwaddr"] = "2001:db8::3"
    before = cfg.read_bytes()
    with pytest.raises(ValueError, match="Unrequested management"):
        repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], apply=True, console_access=True)
    assert cfg.read_bytes() == before
    assert all(cmd[0] == "sonic-cfggen" for cmd in state["commands"])


def test_grub_validation_precedes_any_writes(dut):
    """An unsupported boot layout prevents a half-applied combined repair."""
    cfg, grub, state = dut
    grub.write_text("unknown bootloader\n", encoding="utf-8")
    before = cfg.read_bytes()
    with pytest.raises(ValueError, match="Expected one GRUB"):
        repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], True, True, True)
    assert cfg.read_bytes() == before
    assert list(cfg.parent.glob("*.mgfx*")) == []
    assert all(cmd[0] == "sonic-cfggen" for cmd in state["commands"])


def test_concurrent_change_during_preflight_refused(dut, monkeypatch):
    """Retain a concurrent writer's changes rather than overwrite a stale snapshot."""
    cfg, _, state = dut
    original_backup = repair.backup

    def concurrent_backup(path, content):
        name = original_backup(path, content)
        state["running"]["BGP_NEIGHBOR"]["192.0.2.4"]["asn"] = "65002"
        return name

    monkeypatch.setattr(repair, "backup", concurrent_backup)
    with pytest.raises(ValueError, match="changed during preflight"):
        repair.repair("dut", [("10.3.144.70/27", "10.3.144.65")], apply=True, console_access=True)
    assert json.loads(cfg.read_bytes()) == config()
    assert all(cmd[0] == "sonic-cfggen" for cmd in state["commands"])


@pytest.mark.parametrize("content", ['[]', '{"MGMT_INTERFACE":[]}', '{"DEVICE_METADATA":{"localhost":[]}}'])
def test_invalid_config_shape_rejected(content):
    """Invalid source documents are explicit errors, never empty configuration defaults."""
    with pytest.raises(ValueError, match="JSON object"):
        repair.parse_config(content)
