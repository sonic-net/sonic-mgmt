"""
Pure SAI fidelity tier engine (no pytest, no DUT).

Classifies SaiObjectChange records using a declarative tier.yml mapping and
computes a weighted fidelity score from observed SAI operations.

Score formula
-------------
    score = (w1*n1 + w2*n2 + w3*n3) / (n1 + n2 + n3)

Default weights (configurable in tier.yml)::

    w1 = 1.0   # Tier 1 — fully faithful
    w2 = 0.5   # Tier 2 — stored, not enforced
    w3 = 0.0   # Tier 3 — stubbed / missing

When n1+n2+n3 == 0 the score is None ("no SAI activity"). Absence of SAI
calls is not fidelity — do not report 1.0.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import yaml

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {1: 1.0, 2: 0.5, 3: 0.0}
DEFAULT_TIER = 3
SKIP_OPS = frozenset(("notify",))


@dataclass
class ObjectRule:
    tier: int
    rule: str
    object_type: Optional[str] = None
    object_type_prefix: Optional[str] = None
    attribute: Optional[str] = None
    attribute_prefix: Optional[str] = None
    specificity: int = 0


@dataclass
class OperationRule:
    tier: int
    rule: str
    operations: frozenset = field(default_factory=frozenset)


@dataclass
class TierTable:
    weights: Dict[int, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    default_tier: int = DEFAULT_TIER
    operation_rules: List[OperationRule] = field(default_factory=list)
    object_rules: List[ObjectRule] = field(default_factory=list)


def load_tiers(path: str) -> TierTable:
    """Load and validate a tier.yml file into a TierTable."""
    with open(path, "r") as fh:
        raw = yaml.safe_load(fh) or {}

    weights = dict(DEFAULT_WEIGHTS)
    for key, value in (raw.get("weights") or {}).items():
        weights[int(key)] = float(value)

    table = TierTable(
        weights=weights,
        default_tier=int(raw.get("default_tier", DEFAULT_TIER)),
    )

    for idx, entry in enumerate(raw.get("operations") or []):
        match = entry.get("match") or {}
        ops = match.get("operation") or []
        if isinstance(ops, str):
            ops = [ops]
        rule_name = entry.get("rule") or "op:{}".format(",".join(ops))
        table.operation_rules.append(
            OperationRule(
                tier=int(entry["tier"]),
                rule=rule_name,
                operations=frozenset(o.lower() for o in ops),
            )
        )

    for idx, entry in enumerate(raw.get("objects") or []):
        match = entry.get("match") or {}
        object_type = match.get("object_type")
        object_type_prefix = match.get("object_type_prefix")
        attribute = match.get("attribute")
        attribute_prefix = match.get("attribute_prefix")
        specificity = _rule_specificity(
            object_type, object_type_prefix, attribute, attribute_prefix
        )
        rule_name = entry.get("rule") or _auto_rule_name(
            object_type, object_type_prefix, attribute, attribute_prefix, idx
        )
        table.object_rules.append(
            ObjectRule(
                tier=int(entry["tier"]),
                rule=rule_name,
                object_type=object_type,
                object_type_prefix=object_type_prefix,
                attribute=attribute,
                attribute_prefix=attribute_prefix,
                specificity=specificity,
            )
        )

    # Higher specificity first so classify can walk in order; ties broken later
    # by worst-tier-wins across all matches.
    table.object_rules.sort(key=lambda r: r.specificity, reverse=True)
    return table


def _rule_specificity(
    object_type: Optional[str],
    object_type_prefix: Optional[str],
    attribute: Optional[str],
    attribute_prefix: Optional[str],
) -> int:
    score = 0
    if object_type:
        score += 4
    elif object_type_prefix:
        score += 2
    if attribute:
        score += 3
    elif attribute_prefix:
        score += 1
    return score


def _auto_rule_name(
    object_type: Optional[str],
    object_type_prefix: Optional[str],
    attribute: Optional[str],
    attribute_prefix: Optional[str],
    idx: int,
) -> str:
    parts = []
    if object_type:
        parts.append(object_type)
    elif object_type_prefix:
        parts.append(object_type_prefix + "*")
    if attribute:
        parts.append("attr=" + attribute)
    elif attribute_prefix:
        parts.append("attr_prefix=" + attribute_prefix)
    if not parts:
        parts.append("objects[{}]".format(idx))
    return "obj:" + "|".join(parts)


def classify(change: Any, table: TierTable) -> Tuple[int, str]:
    """
    Classify a SaiObjectChange (or duck-typed equivalent).

    Returns (tier, rule) where rule identifies which tier.yml entry matched.
    When multiple rules match, the worst (highest) tier wins; the rule string
    for that winning tier is returned. Unknown objects use default_tier with
    rule 'default:unknown' and are logged at WARNING.
    """
    operation = (getattr(change, "operation", "") or "").lower()
    if operation in SKIP_OPS:
        return (0, "skip:notify")

    candidates: List[Tuple[int, str]] = []

    for op_rule in table.operation_rules:
        if operation in op_rule.operations:
            candidates.append((op_rule.tier, op_rule.rule))

    object_type = getattr(change, "object_type", "") or ""
    attributes = getattr(change, "attributes", None) or {}
    attr_names = list(attributes.keys())

    matched_object = False
    for obj_rule in table.object_rules:
        if not _object_rule_matches(obj_rule, object_type, attr_names):
            continue
        matched_object = True
        candidates.append((obj_rule.tier, obj_rule.rule))

    if matched_object:
        # Object rule(s) matched (possibly plus op rules). Worst tier wins.
        return max(candidates, key=lambda c: c[0])

    if candidates:
        # Op-only match (e.g. get/stats on an unlisted object type).
        return max(candidates, key=lambda c: c[0])

    logger.warning(
        "SAI fidelity: unknown object type %s (op=%s) -> tier %s "
        "(rule default:unknown)",
        object_type,
        operation,
        table.default_tier,
    )
    return (table.default_tier, "default:unknown")


def _object_rule_matches(
    rule: ObjectRule,
    object_type: str,
    attr_names: Sequence[str],
) -> bool:
    if rule.object_type is not None and object_type != rule.object_type:
        return False
    if rule.object_type_prefix is not None and not object_type.startswith(
        rule.object_type_prefix
    ):
        return False

    needs_attr = rule.attribute is not None or rule.attribute_prefix is not None
    if not needs_attr:
        return True

    if rule.attribute is not None:
        return rule.attribute in attr_names

    # attribute_prefix: match if any attr name contains/starts with prefix
    prefix = rule.attribute_prefix or ""
    for name in attr_names:
        if name.startswith(prefix) or prefix in name:
            return True
    return False


def count_tiers(
    changes: Union[Iterable[Any], Any],
    table: TierTable,
) -> Dict[int, int]:
    """
    Count changes per tier. Accepts an iterable of SaiObjectChange or a
    SaiRedisChanges-like object with created/removed/edited/queried/stats lists.
    Skips notify (tier 0).
    """
    counts = {1: 0, 2: 0, 3: 0}
    for change in _iter_changes(changes):
        tier, rule = classify(change, table)
        if tier == 0:
            continue
        if tier not in counts:
            counts[tier] = 0
        counts[tier] += 1
        if rule == "default:unknown":
            # already logged in classify
            pass
    return counts


def calc_score(
    n1: int,
    n2: int,
    n3: int,
    weights: Optional[Dict[int, float]] = None,
) -> Optional[float]:
    """
    Weighted mean fidelity score.

    score = (w1*n1 + w2*n2 + w3*n3) / (n1+n2+n3)

    Returns None when there are zero SAI calls (not 1.0).
    """
    total = n1 + n2 + n3
    if total == 0:
        return None
    w = weights or DEFAULT_WEIGHTS
    numeric = (
        w.get(1, 1.0) * n1
        + w.get(2, 0.5) * n2
        + w.get(3, 0.0) * n3
    )
    return numeric / total


def format_summary(
    n1: int,
    n2: int,
    n3: int,
    score: Optional[float],
) -> str:
    """Human-readable one-liner for logs / terminal summary."""
    total = n1 + n2 + n3
    if score is None:
        if total == 0:
            return "0 SAI calls — no SAI activity"
        return (
            "{} SAI calls — {} tier 1, {} tier 2, {} tier 3 (score None)".format(
                total, n1, n2, n3
            )
        )
    return (
        "{} SAI calls — {} tier 1, {} tier 2, {} tier 3 (score {:.2f})".format(
            total, n1, n2, n3, score
        )
    )


def object_type_breakdown(
    changes: Union[Iterable[Any], Any],
    table: TierTable,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Top-N object_type breakdown by call count, including dominant tier.
    Useful for seeing what dragged a score down.
    """
    per_type: Dict[str, Counter] = {}
    for change in _iter_changes(changes):
        tier, _rule = classify(change, table)
        if tier == 0:
            continue
        obj = getattr(change, "object_type", "") or "UNKNOWN"
        per_type.setdefault(obj, Counter())[tier] += 1

    rows = []
    for obj, tier_counts in per_type.items():
        total = sum(tier_counts.values())
        dominant = max(tier_counts.keys(), key=lambda t: (tier_counts[t], t))
        rows.append(
            {
                "object_type": obj,
                "total": total,
                "tier1": tier_counts.get(1, 0),
                "tier2": tier_counts.get(2, 0),
                "tier3": tier_counts.get(3, 0),
                "dominant_tier": dominant,
            }
        )
    rows.sort(key=lambda r: (-r["total"], r["object_type"]))
    return rows[:top_n]


def default_tier_file() -> str:
    """Path to the packaged tier.yml next to this module."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "tier.yml")


def _iter_changes(changes: Union[Iterable[Any], Any]) -> List[Any]:
    if changes is None:
        return []
    if hasattr(changes, "created"):
        out = []
        for attr in ("created", "removed", "edited", "queried", "stats"):
            out.extend(getattr(changes, attr, None) or [])
        return out
    return list(changes)
