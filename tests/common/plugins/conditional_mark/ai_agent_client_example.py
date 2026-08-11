"""HTTP client for the Failure-Validated xfail AI agent service.

Sends a current test failure and a reference failure signature to the AI agent
server's ``/compare-failures`` endpoint for semantic comparison.

The server returns a JSON verdict::

    {"is_same_issue": true, "reasoning": "...", "processing_time_ms": 1200}

The client parses the response and returns a result dict with ``decision``,
``reasoning``, and ``processing_time_ms``.

If anything goes wrong (timeout, connection error, malformed response), the
client returns ``None`` so the caller can apply fallback logic.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)


def consult_ai_agent(
    current_failure: dict,
    reference_signature: dict,
    failure_matching_rule: str,
    agent_url: str,
    timeout: int = 30,
    issue_url: str = "",
) -> Optional[dict]:
    """Ask the AI agent whether *current_failure* matches *reference_signature*.

    Args:
        current_failure: Dict with ``exception_type``, ``message``,
            ``stack_trace`` fields extracted from the live pytest failure.
        reference_signature: Dict with ``exception_type``, ``message``,
            ``stack_trace`` fields from the stored signature.
        failure_matching_rule: Engineer-provided rule for the LLM to use as a
            golden rule when comparing the failures.
        agent_url: Base URL of the AI agent server
            (e.g. ``http://10.228.227.92/api/v1``).
        timeout: Request timeout in seconds.
        issue_url: Known-issue URL for context (not queried by the server).

    Returns:
        Dict with ``decision`` (``"same_issue"`` or ``"different_issue"``),
        ``reasoning`` (str), and ``processing_time_ms`` (int).
        Returns ``None`` on error/timeout.
    """
    endpoint = f"{agent_url.rstrip('/')}/compare-failures"

    payload = {
        "reference_failure": {
            "exception_type": reference_signature.get("exception_type", ""),
            "exception_message": reference_signature.get("message", ""),
            "stack_trace": reference_signature.get("stack_trace", ""),
            "failure_matching_rule": failure_matching_rule or "",
        },
        "current_failure": {
            "exception_type": current_failure.get("exception_type", ""),
            "exception_message": current_failure.get("message", ""),
            "stack_trace": current_failure.get("stack_trace", ""),
        },
        "issue_url": issue_url,
        "stream": False,
    }

    try:
        logger.info(f"Consulting AI agent at {endpoint}")
        response = requests.post(
            endpoint,
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()

        verdict = response.json()

        if "is_same_issue" not in verdict:
            logger.warning(f"AI agent response missing 'is_same_issue'. Response: {verdict}")
            return None

        decision = "same_issue" if verdict["is_same_issue"] else "different_issue"
        reasoning = verdict.get("reasoning", "")
        processing_time = verdict.get("processing_time_ms", 0)

        result = {
            "decision": decision,
            "reasoning": reasoning,
            "processing_time_ms": processing_time,
        }
        logger.info(f"AI agent decision: {decision}, reasoning: {reasoning[:200]}, "
                    f"processing_time: {processing_time}ms")
        return result

    except requests.exceptions.Timeout:
        logger.warning(f"AI agent request timed out after {timeout}s")
        return None
    except requests.exceptions.ConnectionError:
        logger.warning(f"Cannot connect to AI agent at {endpoint}")
        return None
    except Exception as e:
        logger.warning(f"AI agent consultation failed: {e!r}")
        return None
