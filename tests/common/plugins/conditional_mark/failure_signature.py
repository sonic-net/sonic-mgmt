"""Failure-Validated xfail: signature loading, similarity scoring, and evaluation.

This module implements the core logic for the Failure-Validated xfail feature.
It loads reference failure signatures from YAML files, computes weighted Dice
similarity scores between a current test failure and stored references, and
orchestrates the three-tier decision logic (high -> xfail, low -> fail,
middle -> consult AI agent).

Signature files follow the naming convention::

    known_issue_signatures_{source}_{number}.yaml

where *source* is ``mgmt``, or ``buildimage``, and *number* is
the issue ID extracted from the URL.

See the HLD for the full YAML schema.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from .dice_similarity import dice_coefficient
from .ai_agent_client import consult_ai_agent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Weighted similarity scoring weights (must sum to 1.0)
# W_TYPE is 0.0 by default because the exception type is easy to get wrong
# (e.g. Failed vs AssertionError vs KeyError vs RunAnsibleModuleFail).
W_TYPE = 0.0
W_MESSAGE = 0.60
W_TRACE = 0.40

# Default thresholds -- can be overridden per-signature in the YAML
XFAIL_SIMILARITY_HIGH_DEFAULT = 0.90
XFAIL_SIMILARITY_LOW_DEFAULT = 0.60
XFAIL_AI_AGENT_TIMEOUT_DEFAULT = 30

# AI agent server URL
XFAIL_AI_AGENT_URL = "http://10.228.227.92/api/v1"

# Directory containing signature files
SIGNATURES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "known_issue_signatures")


# ---------------------------------------------------------------------------
# Issue URL -> Signature filename mapping
# ---------------------------------------------------------------------------

# URL patterns for supported issue trackers
_URL_PATTERNS = [
    # GitHub sonic-mgmt: https://github.com/sonic-net/sonic-mgmt/issues/1234
    (re.compile(r'https?://github\.com/sonic-net/sonic-mgmt/issues/(\d+)'), 'mgmt'),
    # GitHub sonic-buildimage: https://github.com/sonic-net/sonic-buildimage/issues/5678
    (re.compile(r'https?://github\.com/sonic-net/sonic-buildimage/issues/(\d+)'), 'buildimage'),
]

# Load custom URL patterns (e.g. internal issue trackers) if available
try:
    from .fv_custom_url_patterns import CUSTOM_URL_PATTERNS
    _URL_PATTERNS.extend(CUSTOM_URL_PATTERNS)
except ImportError:
    pass


def _issue_url_to_filename(url: str) -> Optional[str]:
    """Derive the signature filename from an issue URL.

    Args:
        url: Issue URL (GitHub sonic-mgmt, or GitHub sonic-buildimage).

    Returns:
        Filename string like ``known_issue_signatures_mgmt_24000.yaml``,
        or ``None`` if the URL does not match any known pattern.
    """
    for pattern, source in _URL_PATTERNS:
        m = pattern.match(url)
        if m:
            return f"known_issue_signatures_{source}_{m.group(1)}.yaml"
    return None


def _find_signature_file(url: str, signatures_dir: str) -> Optional[str]:
    """Find the signature file path for a given issue URL.

    Args:
        url: Issue URL.
        signatures_dir: Directory to search for signature files.

    Returns:
        Full path to the signature file, or ``None`` if not found.
    """
    filename = _issue_url_to_filename(url)
    if filename is None:
        return None
    filepath = os.path.join(signatures_dir, filename)
    if os.path.isfile(filepath):
        return filepath
    return None


# ---------------------------------------------------------------------------
# Signature loading
# ---------------------------------------------------------------------------

def _parse_signatures(filepath: str) -> List[dict]:
    """Parse a signature YAML file and return a list of signature dicts.

    Each signature dict must contain:
        - message (str)
        - stack_trace (str)
        - failure_matching_rule (str)

    And optionally:
        - exception_type (str)
        - name (str)
        - xfail_similarity_high_th (float)
        - xfail_similarity_low_th (float)
        - xfail_ai_agent_timeout (int)
        - w_type, w_message, w_trace (float)

    The YAML format is a flat list of signature dicts under ``signatures:``::

        signatures:
          - name: descriptive_name
            exception_type: ...
            message: ...
            stack_trace: ...
            failure_matching_rule: ...

    Args:
        filepath: Path to the YAML file.

    Returns:
        List of parsed signature dicts.
    """
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load signature file {filepath}: {e!r}")
        return []

    if not data or not isinstance(data, dict):
        logger.warning(f"Signature file {filepath} is empty or not a dict")
        return []

    raw_signatures = data.get("signatures", [])
    if not isinstance(raw_signatures, list):
        logger.warning(f"'signatures' in {filepath} is not a list")
        return []

    result = []
    for idx, entry in enumerate(raw_signatures):
        if not isinstance(entry, dict):
            continue

        # Each entry is a flat dict with the signature fields directly:
        #   {"exception_type": ..., "message": ..., "stack_trace": ..., ...}

        # Mandatory fields -- if any is missing or empty, skip this signature
        # so the caller falls back to the original static xfail flow.
        message = str(entry.get("message", "")).strip()
        stack_trace = str(entry.get("stack_trace", "")).strip()
        failure_matching_rule = str(entry.get("failure_matching_rule", "")).strip()

        name = str(entry.get("name", f"signature_{idx}")).strip()
        exception_type = str(entry.get("exception_type", "")).strip()

        if not all([message, stack_trace, failure_matching_rule]):
            mandatory = [("message", message),
                         ("stack_trace", stack_trace),
                         ("failure_matching_rule", failure_matching_rule)]
            missing = [field for field, val in mandatory if not val]
            logger.warning(f"Signature '{name}' in {filepath} is missing mandatory "
                           f"fields: {', '.join(missing)}. Skipping.")
            continue

        sig = {
            "name": name,
            "exception_type": exception_type,
            "message": message,
            "stack_trace": stack_trace,
            "failure_matching_rule": failure_matching_rule,
            "xfail_similarity_high_th": float(
                entry.get("xfail_similarity_high_th", XFAIL_SIMILARITY_HIGH_DEFAULT)),
            "xfail_similarity_low_th": float(
                entry.get("xfail_similarity_low_th", XFAIL_SIMILARITY_LOW_DEFAULT)),
            "xfail_ai_agent_timeout": int(
                entry.get("xfail_ai_agent_timeout", XFAIL_AI_AGENT_TIMEOUT_DEFAULT)),
            "w_type": float(entry.get("w_type", W_TYPE)),
            "w_message": float(entry.get("w_message", W_MESSAGE)),
            "w_trace": float(entry.get("w_trace", W_TRACE)),
        }
        result.append(sig)

    return result


def load_signatures_for_issues(
    issue_urls: List[str],
    signatures_dir: Optional[str] = None,
) -> Dict[str, List[dict]]:
    """Load failure signatures for the given issue URLs.

    Args:
        issue_urls: List of issue URLs to look up.
        signatures_dir: Directory containing the signature files.
            Defaults to the module-level SIGNATURES_DIR.

    Returns:
        Dict mapping each issue URL that has valid signatures to its list
        of parsed signature dicts.  URLs without a matching file or with
        only invalid signatures are omitted.
    """
    if signatures_dir is None:
        signatures_dir = SIGNATURES_DIR
    result = {}
    for url in issue_urls:
        filepath = _find_signature_file(url, signatures_dir)
        if not filepath:
            continue
        sigs = _parse_signatures(filepath)
        if sigs:
            result[url] = sigs
            logger.debug(f"Loaded {len(sigs)} signatures for {url} from {filepath}")
    return result


def has_any_stored_signatures(
    issue_urls: List[str],
    signatures_dir: Optional[str] = None,
) -> bool:
    """Check if any of the given issue URLs has a stored signature file.

    Args:
        issue_urls: List of issue URLs.
        signatures_dir: Directory to search.
            Defaults to the module-level SIGNATURES_DIR.

    Returns:
        True if at least one URL has a matching signature file.
    """
    if signatures_dir is None:
        signatures_dir = SIGNATURES_DIR
    return any(_find_signature_file(url, signatures_dir) for url in issue_urls)


# ---------------------------------------------------------------------------
# Similarity scoring
# ---------------------------------------------------------------------------

def compute_similarity(current: dict, reference: dict) -> float:
    """Compute the weighted Dice similarity between a current failure and a reference.

    The score is a weighted combination of three components:

    - **exception_type**: exact match (1.0 if equal, 0.0 otherwise)
    - **message**: Dice coefficient on message strings
    - **stack_trace**: Dice coefficient on stack trace strings

    Weights are read from the reference signature dict (``w_type``,
    ``w_message``, ``w_trace``), falling back to the module-level defaults.

    Args:
        current: Dict with ``exception_type``, ``message``, ``stack_trace``
            keys from the live test failure.
        reference: Dict with ``exception_type``, ``message``, ``stack_trace``
            keys from the stored signature. May also contain ``w_type``,
            ``w_message``, ``w_trace`` for per-signature weight overrides.

    Returns:
        Weighted similarity score in [0.0, 1.0].
    """
    w_type = reference.get("w_type", W_TYPE)
    w_message = reference.get("w_message", W_MESSAGE)
    w_trace = reference.get("w_trace", W_TRACE)

    # Exception type: exact match
    cur_type = (current.get("exception_type") or "").strip().lower()
    ref_type = (reference.get("exception_type") or "").strip().lower()
    type_score = 1.0 if cur_type == ref_type else 0.0

    # Message similarity
    cur_msg = current.get("message") or ""
    ref_msg = reference.get("message") or ""
    msg_score = dice_coefficient(cur_msg, ref_msg) if cur_msg and ref_msg else 0.0

    # Trace similarity
    cur_trace = current.get("stack_trace") or ""
    ref_trace = reference.get("stack_trace") or ""
    trace_score = dice_coefficient(cur_trace, ref_trace) if cur_trace and ref_trace else 0.0

    final_score = w_type * type_score + w_message * msg_score + w_trace * trace_score

    logger.debug(
        f"Similarity: type={type_score:.2f} (w={w_type:.2f}), "
        f"msg={msg_score:.4f} (w={w_message:.2f}), "
        f"trace={trace_score:.4f} (w={w_trace:.2f}) -> final={final_score:.4f}")
    return final_score


# ---------------------------------------------------------------------------
# Evaluation orchestration
# ---------------------------------------------------------------------------

# Minimum gap between the top two issue scores to consider the winner
# decisive without consulting the AI agent for both.
_SCORE_GAP_THRESHOLD = 0.10


def _best_score_for_issue(
    current_failure: dict,
    signatures: List[dict],
) -> Tuple[float, Optional[dict]]:
    """Return the (best_score, best_signature) for a single issue's signatures."""
    best_score = -1.0
    best_sig = None
    for sig in signatures:
        score = compute_similarity(current_failure, sig)
        if score > best_score:
            best_score = score
            best_sig = sig
    return best_score, best_sig


def _decide_single_issue(
    current_failure: dict,
    best_score: float,
    best_sig: dict,
    issue_url: str,
) -> Tuple[str, str]:
    """Apply the three-tier decision logic for a single issue's best signature.

    Returns (decision, detail).
    """
    high_th = best_sig.get("xfail_similarity_high_th", XFAIL_SIMILARITY_HIGH_DEFAULT)
    low_th = best_sig.get("xfail_similarity_low_th", XFAIL_SIMILARITY_LOW_DEFAULT)
    ai_timeout = best_sig.get("xfail_ai_agent_timeout", XFAIL_AI_AGENT_TIMEOUT_DEFAULT)
    matching_rule = best_sig.get("failure_matching_rule", "")
    sig_name = best_sig.get("name", "?")

    logger.info(f"Issue {issue_url}: best score {best_score:.4f} "
                f"(sig={sig_name}, high_th={high_th:.2f}, low_th={low_th:.2f})")

    # Tier 1: High similarity -> same issue
    if best_score >= high_th:
        detail = (f"Issue {issue_url}: similarity {best_score:.4f} >= high threshold "
                  f"{high_th:.2f}. Treating as same issue.")
        logger.info(detail)
        return "same_issue", detail

    # Tier 2: Low similarity -> different issue
    if best_score <= low_th:
        detail = (f"Issue {issue_url}: similarity {best_score:.4f} <= low threshold "
                  f"{low_th:.2f}. Treating as different issue.")
        logger.info(detail)
        return "different_issue", detail

    # Tier 3: Middle range -> consult AI agent (or fallback)
    has_matching_rule = bool(matching_rule.strip())
    logger.info(f"Issue {issue_url}: similarity {best_score:.4f} in middle range "
                f"({low_th:.2f}, {high_th:.2f}). Consulting AI agent "
                f"(matching_rule={'present' if has_matching_rule else 'absent'})...")

    if not XFAIL_AI_AGENT_URL:
        detail = (f"Issue {issue_url}: similarity {best_score:.4f} in middle range "
                  f"but AI agent URL not configured. Falling back to xfail.")
        logger.info(detail)
        return "same_issue", detail

    ai_result = consult_ai_agent(
        current_failure=current_failure,
        reference_signature=best_sig,
        failure_matching_rule=matching_rule,
        agent_url=XFAIL_AI_AGENT_URL,
        timeout=ai_timeout,
        issue_url=issue_url,
    )

    if ai_result is None:
        detail = f"Issue {issue_url}: AI agent unavailable or returned error. Falling back to xfail."
        logger.warning(detail)
        return "same_issue", detail

    decision = ai_result["decision"]
    reasoning = ai_result["reasoning"]
    processing_time = ai_result["processing_time_ms"]
    detail = (f"Issue {issue_url}: AI agent decision: {decision} "
              f"(similarity={best_score:.4f}, processing_time={processing_time}ms). "
              f"Reasoning: {reasoning}")
    logger.info(detail)
    return decision, detail


def evaluate_failure(
    current_failure: dict,
    issue_signatures: Dict[str, List[dict]],
) -> Tuple[str, str]:
    """Evaluate whether a test failure matches any stored known-issue signature.

    When multiple issues have stored signatures (e.g. from an 'or' condition),
    the logic is:

    1. Compute the best similarity score for each issue.
    2. If the top-scoring issue is clearly ahead of all others (gap >=
       ``_SCORE_GAP_THRESHOLD`` to every other candidate), apply the
       three-tier decision on the winner alone.
    3. If any candidates are within the gap of the top score, consult the
       AI agent for all close candidates.  If at least one returns
       ``same_issue``, use the highest-scoring one.  If none match, report
       as ``different_issue``.

    Args:
        current_failure: Dict with ``exception_type``, ``message``, ``stack_trace``.
        issue_signatures: Dict mapping issue URL -> list of signature dicts,
            as returned by :func:`load_signatures_for_issues`.

    Returns:
        Tuple of (decision, detail) where decision is ``"same_issue"`` or
        ``"different_issue"``, and detail is a human-readable explanation.
    """
    if not issue_signatures:
        return "different_issue", "No signatures found for comparison"

    # Score each issue's best signature and classify by threshold
    high_matches = []    # (score, sig, url) -- score >= high_th, definitive match
    mid_candidates = []  # (score, sig, url) -- in middle range, need AI

    for url, sigs in issue_signatures.items():
        score, sig = _best_score_for_issue(current_failure, sigs)
        if sig is None:
            continue
        high_th = sig.get("xfail_similarity_high_th", XFAIL_SIMILARITY_HIGH_DEFAULT)
        low_th = sig.get("xfail_similarity_low_th", XFAIL_SIMILARITY_LOW_DEFAULT)

        if score >= high_th:
            high_matches.append((score, sig, url))
        elif score > low_th:
            mid_candidates.append((score, sig, url))

    # If any issue exceeds its high threshold, use the highest-scoring one
    if high_matches:
        high_matches.sort(key=lambda x: x[0], reverse=True)
        score, sig, url = high_matches[0]
        high_th = sig.get("xfail_similarity_high_th", XFAIL_SIMILARITY_HIGH_DEFAULT)
        detail = (f"Issue {url}: similarity {score:.4f} >= high threshold "
                  f"{high_th:.2f}. Treating as same issue.")
        logger.info(detail)
        return "same_issue", detail

    # No high matches -- if no middle-range candidates either, all are below low
    if not mid_candidates:
        detail = "All candidates below their low thresholds. Treating as different issue."
        logger.info(detail)
        return "different_issue", detail

    # Middle-range candidates exist -- check if there is a clear winner among them
    mid_candidates.sort(key=lambda x: x[0], reverse=True)
    top_score, top_sig, top_url = mid_candidates[0]

    # Find candidates close to the top score
    close_candidates = [
        (score, sig, url) for score, sig, url in mid_candidates
        if (top_score - score) < _SCORE_GAP_THRESHOLD
    ]

    # Single middle-range candidate or clear winner -- decide on it alone
    if len(close_candidates) == 1:
        logger.info(f"Single middle-range candidate: {top_url} with score {top_score:.4f}")
        return _decide_single_issue(current_failure, top_score, top_sig, top_url)

    # Multiple close middle-range candidates -- consult AI for all
    logger.info(f"Multiple close middle-range candidates (gap < {_SCORE_GAP_THRESHOLD}): "
                f"{', '.join(f'{u}={s:.4f}' for s, _, u in close_candidates)}. "
                f"Consulting AI for all.")

    if not XFAIL_AI_AGENT_URL:
        logger.info("AI agent URL not configured. Falling back to top scorer.")
        return _decide_single_issue(current_failure, top_score, top_sig, top_url)

    results = []
    for score, sig, url in close_candidates:
        ai_timeout = sig.get("xfail_ai_agent_timeout", XFAIL_AI_AGENT_TIMEOUT_DEFAULT)
        matching_rule = sig.get("failure_matching_rule", "")
        ai_result = consult_ai_agent(
            current_failure=current_failure,
            reference_signature=sig,
            failure_matching_rule=matching_rule,
            agent_url=XFAIL_AI_AGENT_URL,
            timeout=ai_timeout,
            issue_url=url,
        )
        results.append((url, score, sig, ai_result))

    # Find candidates where AI says same_issue
    same_issue_results = [(url, score, sig, r) for url, score, sig, r in results
                          if r is not None and r["decision"] == "same_issue"]

    if same_issue_results:
        # Use the highest-scoring same_issue match
        url, score, sig, ai_result = same_issue_results[0]
        detail = (f"Issue {url}: AI agent decision: same_issue "
                  f"(similarity={score:.4f}, processing_time={ai_result['processing_time_ms']}ms). "
                  f"Reasoning: {ai_result['reasoning']}")
        logger.info(detail)
        return "same_issue", detail

    # Build details for reporting
    ai_details = []
    for url, score, sig, ai_result in results:
        if ai_result is None:
            ai_details.append(f"{url}: AI agent error (score={score:.4f})")
        else:
            ai_details.append(f"{url}: {ai_result['decision']} (score={score:.4f}, "
                              f"reasoning={ai_result['reasoning']})")

    if all(r is None for _, _, _, r in results):
        detail = f"AI agent unavailable for all candidates. Falling back to xfail. {'; '.join(ai_details)}"
        logger.warning(detail)
        return "same_issue", detail

    detail = f"No issue matched. {'; '.join(ai_details)}"
    logger.info(detail)
    return "different_issue", detail
