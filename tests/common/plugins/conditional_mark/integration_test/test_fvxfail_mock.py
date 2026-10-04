"""Integration tests for the Failure-Validated xfail feature.

Tests go through the real collection phase via mark conditions entries in
tests_mark_conditions_fvxfail_integration.yaml (copied to the plugin dir
by conftest.py). The pytest_runtest_makereport hook from the conditional_mark
plugin processes failures and decides whether to xfail or fail.

Run directly to see raw pytest results:
    pytest common/plugins/conditional_mark/integration_test/test_fvxfail_mock.py ...

Or run the wrapper test to validate results automatically:
    pytest common/plugins/conditional_mark/integration_test/test_fvxfail_mock_wrapper.py ...
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import time
import pytest

from tests.common.plugins.conditional_mark import failure_signature
from tests.common.plugins.conditional_mark.integration_test.conftest import load_mocked_failure

pytestmark = [pytest.mark.disable_memory_utilization, pytest.mark.skip_check_dut_health,
              pytest.mark.disable_loganalyzer]


# ---------------------------------------------------------------------------
# Mock AI agent server
# ---------------------------------------------------------------------------

_mock_ai_responses = []
_mock_ai_request_count = 0
_mock_ai_lock = threading.Lock()


class _MockAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global _mock_ai_request_count
        if self.path != "/api/v1/compare-failures":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)

        with _mock_ai_lock:
            idx = _mock_ai_request_count
            _mock_ai_request_count += 1

        if idx < len(_mock_ai_responses):
            resp_config = _mock_ai_responses[idx]
        else:
            resp_config = _mock_ai_responses[-1] if _mock_ai_responses else {}

        delay = resp_config.get("delay", 0)
        if delay:
            time.sleep(delay)

        status = resp_config.get("status", 200)
        body = resp_config.get("body", {})

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_ai(request, monkeypatch):
    """Fixture that starts a mock AI server and patches the URL."""
    servers = []

    def _setup(responses):
        global _mock_ai_responses, _mock_ai_request_count
        _mock_ai_responses = responses
        _mock_ai_request_count = 0

        server = HTTPServer(("127.0.0.1", 0), _MockAIHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)

        url = f"http://127.0.0.1:{port}/api/v1"
        monkeypatch.setattr(failure_signature, "XFAIL_AI_AGENT_URL", url)

    yield _setup

    for server in servers:
        server.shutdown()


# ---------------------------------------------------------------------------
# Fixtures for setup/teardown phase tests
# ---------------------------------------------------------------------------

@pytest.fixture
def setup_failure_fixture():
    """Fixture that fails during setup with a known message."""
    msg = load_mocked_failure("setup_teardown_failure.txt")
    pytest.fail(msg)
    yield


@pytest.fixture
def teardown_failure_fixture():
    """Fixture that fails during teardown with a known message."""
    yield
    msg = load_mocked_failure("setup_teardown_failure.txt")
    pytest.fail(msg)


# ============================= TEST CASES =====================================

# --- Core Decision Logic ---

def test_same_failure_high_similarity():
    """TC1: Score >= high threshold -> xfail, no AI triggered."""
    pytest.fail(load_mocked_failure("high_similarity_failure.txt"))


def test_different_failure_low_similarity():
    """TC2: Score <= low threshold -> failed."""
    raise KeyError("completely unrelated error about missing configuration key foobar_xyz")


def test_no_signature_file_no_fvxfail():
    """TC3: No mark conditions entry -> normal failure, no FV-xfail."""
    pytest.fail("some random failure with no FV-xfail involvement")


def test_passed_no_interference():
    """TC4: Test passes -> PASSED."""
    pass


# --- Threshold and Weight Overrides ---

def test_custom_high_threshold():
    """TC5: Per-signature low high_th -> xfail."""
    pytest.fail(load_mocked_failure("custom_high_th_failure.txt"))


def test_custom_low_threshold():
    """TC6: Per-signature high low_th -> failed."""
    pytest.fail(load_mocked_failure("custom_low_th_failure.txt"))


def test_custom_weights():
    """TC7: Per-signature w_type=0.50 -> KeyError type matches, xfail."""
    raise KeyError("a_totally_different_key_error_message")


# --- Setup and Teardown Phases ---

def test_setup_failure_same_issue(setup_failure_fixture):
    """TC8a: Fixture fails in setup with matching signature -> xfail."""
    pass


def test_teardown_failure_same_issue(teardown_failure_fixture):
    """TC8b: Fixture fails in teardown with matching signature -> xfail."""
    pass


# --- Invalid Signature File ---

def test_missing_mandatory_field_static_xfail_with_note():
    """TC10: Signature file exists but missing mandatory field -> static xfail with note."""
    pytest.fail("this failure should be caught by static xfail with note")


# --- Multiple Issues ---

def test_multi_issue_clear_winner():
    """TC11: Two issues, one scores high -> xfail on winner."""
    pytest.fail(load_mocked_failure("multi_issue_interface_down.txt"))


def test_multi_issue_all_below_low():
    """TC12: Two issues, both score low -> failed."""
    raise KeyError("completely_unrelated_failure_xyz_12345")


# --- AI Agent (Mock Server) ---

def test_ai_returns_same_issue(mock_ai):
    """TC13: Middle range, AI says same_issue -> xfail."""
    mock_ai([{
        "status": 200,
        "body": {
            "is_same_issue": True,
            "reasoning": "Both failures are PFC watchdog timer accuracy issues",
            "processing_time_ms": 500,
        },
    }])
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


def test_ai_returns_different_issue(mock_ai):
    """TC14: Middle range, AI says different_issue -> failed."""
    mock_ai([{
        "status": 200,
        "body": {
            "is_same_issue": False,
            "reasoning": "Different root cause detected",
            "processing_time_ms": 300,
        },
    }])
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


def test_ai_timeout(mock_ai):
    """TC15: Middle range, AI times out -> xfail fallback."""
    mock_ai([{
        "delay": 60,
        "status": 200,
        "body": {"is_same_issue": True, "reasoning": "too late", "processing_time_ms": 0},
    }])
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


def test_ai_error_500(mock_ai):
    """TC16: Middle range, AI returns 500 -> xfail fallback."""
    mock_ai([{
        "status": 500,
        "body": {"error": "internal server error"},
    }])
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


def test_ai_malformed_response(mock_ai):
    """TC17: Middle range, AI returns invalid JSON -> xfail fallback."""
    mock_ai([{
        "status": 200,
        "body": {"garbage": True, "no_is_same_issue_field": 42},
    }])
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


def test_ai_disabled_fallback(monkeypatch):
    """TC18: Middle range, AI URL empty -> xfail fallback."""
    monkeypatch.setattr(failure_signature, "XFAIL_AI_AGENT_URL", "")
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


# --- Multi-Issue AI Disambiguation ---

def test_multi_issue_ai_one_match(mock_ai):
    """TC19: Two issues close scores, AI matches one -> xfail."""
    mock_ai([
        {"status": 200, "body": {
            "is_same_issue": True,
            "reasoning": "BGP route redistribution failure matches",
            "processing_time_ms": 600}},
        {"status": 200, "body": {
            "is_same_issue": False,
            "reasoning": "OSPF redistribution is a different issue",
            "processing_time_ms": 400}},
    ])
    pytest.fail(load_mocked_failure("multi_issue_close_scores.txt"))


def test_multi_issue_ai_none_match(mock_ai):
    """TC20: Two issues close scores, AI rejects both -> failed."""
    mock_ai([
        {"status": 200, "body": {
            "is_same_issue": False,
            "reasoning": "Not a BGP redistribution issue",
            "processing_time_ms": 500}},
        {"status": 200, "body": {
            "is_same_issue": False,
            "reasoning": "Not an OSPF redistribution issue",
            "processing_time_ms": 500}},
    ])
    pytest.fail(load_mocked_failure("multi_issue_close_scores.txt"))


def test_multi_issue_ai_all_error(mock_ai):
    """TC21: Two issues close scores, AI errors -> xfail fallback."""
    mock_ai([
        {"status": 500, "body": {"error": "server error"}},
        {"status": 500, "body": {"error": "server error"}},
    ])
    pytest.fail(load_mocked_failure("multi_issue_close_scores.txt"))


# --- Edge Case ---

def test_no_excinfo_fallback():
    """TC22: Test passes with no _dynamic_xfail_info -> PASSED."""
    pass
