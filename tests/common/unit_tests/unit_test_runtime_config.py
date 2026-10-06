"""Exercise runtime-managed config comparison without testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_runtime_config.py -v
"""

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "helpers" / "runtime_config.py"


def _load_runtime_config():
    spec = importlib.util.spec_from_file_location("runtime_config", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNTIME_CONFIG = _load_runtime_config()


def test_refreshes_core_inventory_after_runtime_readiness_window():
    snapshots = iter([
        ["existing.core", "early.core"],
        ["existing.core", "late.core"],
    ])

    current, new = RUNTIME_CONFIG.refresh_core_dump_inventory(
        ["existing.core"],
        lambda: next(snapshots),
    )
    assert current == ["existing.core", "early.core"]
    assert new == ["early.core"]

    current, new = RUNTIME_CONFIG.refresh_core_dump_inventory(
        ["existing.core"],
        lambda: next(snapshots),
        new,
    )
    assert current == ["existing.core", "late.core"]
    assert new == ["early.core", "late.core"]


def test_selects_only_runtime_managed_entries():
    config = {
        "LOGGER": {
            "DomInfoUpdateTask": {
                "LOGLEVEL": "NOTICE",
                "require_manual_refresh": "true",
            },
            "xcvrd": {
                "LOGLEVEL": "NOTICE",
                "require_manual_refresh": True,
            },
            "orchagent": {
                "LOGLEVEL": "NOTICE",
                "LOGOUTPUT": "SYSLOG",
            },
        }
    }

    assert RUNTIME_CONFIG.get_runtime_managed_entries(config) == {
        "DomInfoUpdateTask": config["LOGGER"]["DomInfoUpdateTask"],
        "xcvrd": config["LOGGER"]["xcvrd"],
    }


def test_reports_missing_and_changed_runtime_entries():
    expected = {
        "LOGGER": {
            "DomInfoUpdateTask": {
                "LOGLEVEL": "NOTICE",
                "require_manual_refresh": "true",
            },
            "SfpStateUpdateTask": {
                "LOGLEVEL": "NOTICE",
                "require_manual_refresh": "true",
            },
        }
    }
    current = {
        "LOGGER": {
            "SfpStateUpdateTask": {
                "LOGLEVEL": "DEBUG",
                "require_manual_refresh": "true",
            }
        }
    }

    assert RUNTIME_CONFIG.get_unrestored_runtime_managed_entries(expected, current) == {
        "DomInfoUpdateTask": {
            "expected": expected["LOGGER"]["DomInfoUpdateTask"],
            "current": None,
        },
        "SfpStateUpdateTask": {
            "expected": expected["LOGGER"]["SfpStateUpdateTask"],
            "current": current["LOGGER"]["SfpStateUpdateTask"],
        },
    }


def test_ignores_static_and_extra_runtime_entries_for_readiness():
    expected = {
        "LOGGER": {
            "orchagent": {
                "LOGLEVEL": "NOTICE",
                "LOGOUTPUT": "SYSLOG",
            }
        }
    }
    current = {
        "LOGGER": {
            "ExtraTask": {
                "LOGLEVEL": "NOTICE",
                "require_manual_refresh": "true",
            }
        }
    }

    assert RUNTIME_CONFIG.get_unrestored_runtime_managed_entries(expected, current) == {}


def test_tracks_runtime_entries_per_namespace_context():
    expected = {
        None: {
            "LOGGER": {
                "DomInfoUpdateTask": {
                    "LOGLEVEL": "NOTICE",
                    "require_manual_refresh": "true",
                }
            }
        },
        "asic0": {
            "LOGGER": {
                "NamespaceTask": {
                    "LOGLEVEL": "INFO",
                    "require_manual_refresh": "true",
                }
            }
        },
    }
    current = {
        None: expected[None],
        "asic0": {"LOGGER": {}},
    }

    assert RUNTIME_CONFIG.get_unrestored_runtime_managed_entries_by_context(expected, current) == {
        "asic0": {
            "NamespaceTask": {
                "expected": expected["asic0"]["LOGGER"]["NamespaceTask"],
                "current": None,
            }
        }
    }
