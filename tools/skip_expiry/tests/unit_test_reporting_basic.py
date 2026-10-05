from typing import Any, Dict, List

from tools.skip_expiry.skip_issue_expiry_impl.reporting import (
    _cap_backoff,
    _is_rate_limit_graphql_error,
    _parse_retry_after,
    ProjectV2Reporter,
)


def _make_reporter() -> ProjectV2Reporter:
    reporter = ProjectV2Reporter.__new__(ProjectV2Reporter)
    reporter.token = "token"
    reporter.project_id = "project"
    reporter.dry_run = False
    reporter.existing_items = {}
    reporter.existing_field_values = {}
    reporter.field_map = {}
    reporter.created_count = 0
    reporter.updated_count = 0
    reporter.skipped_count = 0
    return reporter


def test_cap_backoff_caps_to_max() -> None:
    assert _cap_backoff(3.0, 60.0) == 3.0
    assert _cap_backoff(120.0, 60.0) == 60.0


def test_parse_retry_after_seconds_and_fallback() -> None:
    assert _parse_retry_after("2.5", 1.0) == 2.5
    assert _parse_retry_after("", 1.0) == 1.0
    assert _parse_retry_after("not-a-date", 1.0) == 1.0


def test_is_rate_limit_graphql_error_detects_rate_limit_signals() -> None:
    errors: List[object] = [
        {"type": "RATE_LIMITED", "message": "too many requests"},
    ]
    assert _is_rate_limit_graphql_error(errors) is True
    assert _is_rate_limit_graphql_error([{"type": "OTHER", "message": "failed"}]) is False


def test_apply_field_update_if_changed_updates_cache_only_on_change() -> None:
    reporter = _make_reporter()
    reporter.existing_field_values = {"test/a.py::test_x": {"owner": "alice"}}

    calls: List[Dict[str, Any]] = []

    def updater(item_id: str, field_name: str, value: object) -> None:
        calls.append({"item_id": item_id, "field": field_name, "value": value})

    changed = reporter._apply_field_update_if_changed(
        item_id="item1",
        test_id="test/a.py::test_x",
        field_name="owner",
        value="alice",
        updater=updater,
    )
    assert changed is False
    assert calls == []

    changed = reporter._apply_field_update_if_changed(
        item_id="item1",
        test_id="test/a.py::test_x",
        field_name="owner",
        value="bob",
        updater=updater,
    )
    assert changed is True
    assert len(calls) == 1
    assert reporter.existing_field_values["test/a.py::test_x"]["owner"] == "bob"


def test_update_single_select_field_clears_when_option_missing() -> None:
    reporter = _make_reporter()
    reporter.field_map = {
        "current_status": {
            "id": "field-1",
            "name": "current_status",
            "dataType": "SINGLE_SELECT",
            "options": [{"id": "opt-1", "name": "expired"}],
        }
    }

    cleared: List[Dict[str, str]] = []

    def fake_clear(item_id: str, field_name: str) -> None:
        cleared.append({"item_id": item_id, "field_name": field_name})

    reporter._clear_field_value = fake_clear  # type: ignore[method-assign]

    reporter._update_single_select_field("item1", "current_status", "not-expired")

    assert cleared == [{"item_id": "item1", "field_name": "current_status"}]
