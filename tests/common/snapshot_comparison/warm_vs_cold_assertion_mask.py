"""Warm-vs-cold assertion mask.

Declarative mask of post-prune diffs that are currently expected on a given
platform for a given base->target upgrade path. Entries here represent
residual, known-acceptable diffs after prune_expected_from_diff() has run.

Semantics (applied in apply_diff_assertion_mask):
- Matching diff entries are masked out and do NOT count as regressions.
- Any remaining diffs after masking should be asserted as regressions by the caller.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Union

from tests.common.db_comparison import DBType


# -------- Expectation builders ---------------------------------------------
#
# The classes below describe how a mask entry should match a post-prune
# SnapshotDiff. The matcher in apply_diff_assertion_mask() walks each DB
# section's list of expectation instances and, for each one, decides which
# entries of the actual diff are "expected" so they can be subtracted before
# the final assertion.


class KeyMatchMode(Enum):
    """How a key/field pattern is compared against a candidate string."""

    # Pattern must equal the candidate string.
    EXACT = "exact"
    # Pattern must be a prefix of the candidate string (used for family
    # matches like "ROUTE_TABLE:" or "TRANSCEIVER_STATUS_FLAG|").
    PREFIX = "prefix"
    # Pattern is a regex fully matched against the candidate.
    REGEX = "regex"


class ValueSpecMode(Enum):
    """How an expected value on one side of a warm/cold pair is evaluated."""

    # Value must equal `value` exactly.
    LITERAL = "literal"
    # Field must be absent / None on this side of the diff.
    NULL = "null"
    # Any value (including absent) is accepted on this side.
    ANY = "any"
    # `value` is a regex fully matched against the actual stringified value.
    REGEX = "regex"
    # `value` is a tuple of accepted literals.
    ONE_OF = "one_of"


@dataclass(frozen=True)
class KeyMatch:
    """How to match a diff key (top-level table key or a field name)."""

    mode: KeyMatchMode
    pattern: str

    def __str__(self) -> str:
        return f"{self.mode.value}:{self.pattern!r}"


@dataclass(frozen=True)
class ValueSpec:
    """Expected value on one side of a warm/cold pair.

    Use the `literal`/`null`/`any_`/`regex`/`one_of` classmethod
    factories to build instances so mode/value stay consistent.
    """

    mode: ValueSpecMode
    value: Any = None

    @classmethod
    def literal(cls, v: Any) -> "ValueSpec":
        return cls(ValueSpecMode.LITERAL, v)

    @classmethod
    def null(cls) -> "ValueSpec":
        return cls(ValueSpecMode.NULL)

    @classmethod
    def any_(cls) -> "ValueSpec":
        return cls(ValueSpecMode.ANY)

    @classmethod
    def regex(cls, pattern: str) -> "ValueSpec":
        return cls(ValueSpecMode.REGEX, pattern)

    @classmethod
    def one_of(cls, values) -> "ValueSpec":
        # Frozen dataclass requires a hashable default, so store as a tuple.
        return cls(ValueSpecMode.ONE_OF, tuple(values))

    def __str__(self) -> str:
        if self.mode in (ValueSpecMode.LITERAL, ValueSpecMode.REGEX, ValueSpecMode.ONE_OF):
            return f"{self.mode.value}:{self.value!r}"
        return self.mode.value


@dataclass(frozen=True)
class FieldExpectation:
    """Describes an expected per-field diff inside a top-level key.

    Applies when a diff entry is nested under a "value" sub-dict (i.e. the
    top-level key is present in BOTH snapshots and individual fields differ).

    `field_match` picks which field name(s) this expectation covers.
    `after_warmboot` / `after_coldboot` describe what the diff's warm and
    cold sides should look like for the expectation to apply.
    """

    field_match: KeyMatch
    after_warmboot: ValueSpec
    after_coldboot: ValueSpec


@dataclass
class TopLevelKeyOneSideExpectation:
    """Top-level key is expected to appear on only one side of the diff.

    Example: "NEIGH_TABLE:eth0:*" appears only in the warm snapshot because
    management-interface neighbor state is repopulated fresh after cold boot.

    `after_warmboot_present` / `after_coldboot_present` encode which
    side(s) the key is expected to be observed on.

    Optional `present_side_value_specs` validates the field shape of the
    present side's `value` dict: keys are field names, values are
    :class:`ValueSpec` instances. When non-empty the present side must
    contain exactly these field names (no extras, no missing) and each
    field's value must satisfy its spec. Useful when the row's *presence*
    on one side is expected but its values still need a format check (e.g.
    PSU_INFO serial/model strings).
    """

    key_match: KeyMatch
    after_warmboot_present: bool
    after_coldboot_present: bool
    present_side_value_specs: Dict[str, ValueSpec] = field(default_factory=dict)

    def __str__(self) -> str:
        """Render a short identifier for warning messages, e.g.::

            TopLevelKeyOneSideExpectation(key=prefix:'NEIGH_TABLE:eth0:' present=warm)
            TopLevelKeyOneSideExpectation(key=exact:'DOCKER_STATS|gnmi' present=cold \
specs={NAME=literal:'gnmi', BLOCK_IN_BYTES=literal:'0'})
        """
        sides = []
        if self.after_warmboot_present:
            sides.append("warm")
        if self.after_coldboot_present:
            sides.append("cold")
        extra = f" present={'+'.join(sides) or 'neither'}"
        if self.present_side_value_specs:
            spec_strs = [f"{name}={vs}" for name, vs in self.present_side_value_specs.items()]
            extra += " specs={" + ", ".join(spec_strs) + "}"
        return f"{type(self).__name__}(key={self.key_match}{extra})"


@dataclass
class TopLevelKeyBothValueDiffExpectation:
    """Top-level key present in both snapshots, with expected field-level diffs.

    `fields` is the ordered list of per-field expectations. The matcher
    applies them to the "value" sub-dict of the diff entry; for an expectation
    to mask the entry, every field-level diff observed must be covered by one
    of the FieldExpectations here.
    """

    key_match: KeyMatch
    fields: List[FieldExpectation] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{type(self).__name__}(key={self.key_match})"


# Union alias used by the matcher to iterate a section's entries.
Expectation = Union[TopLevelKeyOneSideExpectation, TopLevelKeyBothValueDiffExpectation]


# -------- Arista mask -------------------------------------------------------

_ARISTA_ASSERTION_MASK = {
    DBType.APPL: [
        # IPv4/IPv6 ECMP routes warm-only 'weight' field.
        # Warm has a weight string ("1,1,1,1" for 4-member ECMP, "1" for single),
        # cold has no weight field.
        TopLevelKeyBothValueDiffExpectation(
            key_match=KeyMatch(mode=KeyMatchMode.PREFIX, pattern="ROUTE_TABLE:"),
            fields=[
                FieldExpectation(
                    field_match=KeyMatch(mode=KeyMatchMode.EXACT, pattern="weight"),
                    after_warmboot=ValueSpec.one_of(["1,1,1,1", "1"]),
                    after_coldboot=ValueSpec.null(),
                ),
            ],
        ),
        # PortChannel tpid appears only after cold boot.
        TopLevelKeyBothValueDiffExpectation(
            key_match=KeyMatch(mode=KeyMatchMode.PREFIX, pattern="LAG_TABLE:PortChannel"),
            fields=[
                FieldExpectation(
                    field_match=KeyMatch(mode=KeyMatchMode.EXACT, pattern="tpid"),
                    after_warmboot=ValueSpec.null(),
                    after_coldboot=ValueSpec.literal("0x8100"),
                ),
            ],
        ),
        # Management interface neighbor entries present only in warmboot.
        TopLevelKeyOneSideExpectation(
            key_match=KeyMatch(mode=KeyMatchMode.PREFIX, pattern="NEIGH_TABLE:eth0:"),
            after_warmboot_present=True,
            after_coldboot_present=False,
        ),
    ],
    DBType.STATE: [
        # PROCESS_STATS|<seq> entries are synthesized by
        # _diff_state_db_process_stats: every PID-paired CMD that exists on
        # only one side becomes its own one-sided top-level diff. CMD-string
        # value matching proved too flakey (sleep durations, container IDs,
        # neighbor counts, etc. change run-to-run), so we mask all of it out.
        # TODO: Investigate a more robust way to match
        TopLevelKeyOneSideExpectation(
            key_match=KeyMatch(mode=KeyMatchMode.REGEX, pattern=r"PROCESS_STATS\|\d+"),
            after_warmboot_present=True,
            after_coldboot_present=False,
        ),
        TopLevelKeyOneSideExpectation(
            key_match=KeyMatch(mode=KeyMatchMode.REGEX, pattern=r"PROCESS_STATS\|\d+"),
            after_warmboot_present=False,
            after_coldboot_present=True,
        ),
        # Fast restart enable flag set during warm boot sequence; the whole
        # FAST_RESTART_ENABLE_TABLE|system row is present only on the warm
        # side (hash {"enable": "false"}) and absent after cold boot.
        TopLevelKeyOneSideExpectation(
            key_match=KeyMatch(mode=KeyMatchMode.EXACT, pattern="FAST_RESTART_ENABLE_TABLE|system"),
            after_warmboot_present=True,
            after_coldboot_present=False,
        ),
    ],
    DBType.CONFIG: [
        # No residual config_db diffs known or expected
    ],
    DBType.ASIC: [
        # Intentionally empty: ASIC_DB comparison not implemented yet.
    ],
}

# -------- Top-level mask ----------------------------------------------------
#
# Platform masks keyed by a platform prefix. The resolver picks the first
# entry whose key is a prefix of duthost.facts["platform"].


PLATFORM_MASKS = {
    # Matched as prefix against duthost.facts["platform"].
    "x86_64-arista_7260": _ARISTA_ASSERTION_MASK,
    "x86_64-arista_7060": _ARISTA_ASSERTION_MASK,
    "x86_64-arista_7050cx3": _ARISTA_ASSERTION_MASK,
}


def resolve_warm_cold_diff_mask(platform: str):
    """Return the mask sections for the first platform prefix that matches.

    Returns None if no prefix matches; callers should warn in that case.
    The returned dict is the shared module-level structure and must not be
    mutated by callers.
    """
    if not platform:
        return None
    for platform_prefix, sections in PLATFORM_MASKS.items():
        if platform.startswith(platform_prefix):
            return sections
    return None
