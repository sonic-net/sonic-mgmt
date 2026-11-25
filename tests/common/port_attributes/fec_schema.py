"""Runtime schema validation for supplied FEC attribute shards."""

import re


FEC_CATEGORY_NAME = "fec"

FEC_CAPABILITY_ATTRIBUTES = frozenset({
    "basic_fec_stats_supported",
    "verify_fec_oper_mode_supported",
    "configure_fec_oper_mode_supported",
})

FEC_WAIT_ATTRIBUTE_MINIMUMS = {
    "fec_mode_restore_timeout_sec": 1,
    "clear_counters_wait_sec": 0,
    "fec_histogram_stale_error_wait_sec": 0,
}

FEC_ATTRIBUTE_NAMES = frozenset({
    "supported_speeds",
    "critical_histogram_bins",
}).union(FEC_CAPABILITY_ATTRIBUTES, FEC_WAIT_ATTRIBUTE_MINIMUMS)

_SPEED_PATTERN = re.compile(r"^[1-9][0-9]*G$")
_PN_RESERVED_SUBSLOTS = ("platform_hwsku_overrides",)


class FecAttributeValidationError(ValueError):
    """Raised when a supplied FEC shard violates the FEC schema."""


def _fail(path, scope, message):
    raise FecAttributeValidationError(f"{path} ({scope}): {message}")


def _require_mapping(value, path, scope):
    if not isinstance(value, dict):
        _fail(path, scope, f"expected a JSON object, got {type(value).__name__}")
    return value


def _validate_supported_speeds(value, path, scope):
    if not isinstance(value, list) or not value:
        _fail(path, scope, "'supported_speeds' must be a non-empty list")
    if any(not isinstance(speed, str) or not _SPEED_PATTERN.fullmatch(speed) for speed in value):
        _fail(
            path,
            scope,
            "'supported_speeds' entries must be canonical positive-Gbps strings such as '100G'",
        )
    if len(value) != len(set(value)):
        _fail(path, scope, "'supported_speeds' must not contain duplicates")


def _validate_histogram_bins(value, path, scope):
    if not isinstance(value, list) or not value:
        _fail(path, scope, "'critical_histogram_bins' must be a non-empty list")
    if any(type(bin_index) is not int or bin_index < 0 for bin_index in value):
        _fail(path, scope, "'critical_histogram_bins' entries must be non-negative integers")
    if len(value) != len(set(value)):
        _fail(path, scope, "'critical_histogram_bins' must not contain duplicates")


def _validate_attributes(attributes, path, scope):
    attributes = _require_mapping(attributes, path, scope)
    unknown = set(attributes) - FEC_ATTRIBUTE_NAMES
    if unknown:
        _fail(path, scope, f"unknown FEC attribute(s): {sorted(unknown)}")

    for name, value in attributes.items():
        if name == "supported_speeds":
            _validate_supported_speeds(value, path, scope)
        elif name == "critical_histogram_bins":
            _validate_histogram_bins(value, path, scope)
        elif name in FEC_CAPABILITY_ATTRIBUTES:
            if type(value) is not bool:
                _fail(path, scope, f"'{name}' must be a Boolean, got {value!r}")
        elif name in FEC_WAIT_ATTRIBUTE_MINIMUMS:
            minimum = FEC_WAIT_ATTRIBUTE_MINIMUMS[name]
            if type(value) is not int or value < minimum:
                _fail(
                    path,
                    scope,
                    f"'{name}' must be an integer greater than or equal to {minimum}, got {value!r}",
                )


def _validate_category_shard(path, body):
    body = _require_mapping(body, path, "category")

    if "mandatory" in body:
        mandatory = body["mandatory"]
        if not isinstance(mandatory, list):
            _fail(path, "category.mandatory", "'mandatory' must be a list")
        if any(not isinstance(name, str) or name not in FEC_ATTRIBUTE_NAMES for name in mandatory):
            _fail(path, "category.mandatory", "'mandatory' contains an unknown FEC attribute")
        if len(mandatory) != len(set(mandatory)):
            _fail(path, "category.mandatory", "'mandatory' must not contain duplicates")

    if "defaults" in body:
        _validate_attributes(body["defaults"], path, "category.defaults")

    if "dut" in body:
        dut_overrides = _require_mapping(body["dut"], path, "category.dut")
        for dut_name, attributes in dut_overrides.items():
            _validate_attributes(attributes, path, f"category.dut.{dut_name}")

    transceivers = body.get("transceivers", {})
    transceivers = _require_mapping(transceivers, path, "category.transceivers")
    deployment_configurations = transceivers.get("deployment_configurations", {})
    deployment_configurations = _require_mapping(
        deployment_configurations,
        path,
        "category.transceivers.deployment_configurations",
    )
    for deployment, attributes in deployment_configurations.items():
        _validate_attributes(
            attributes,
            path,
            f"category.transceivers.deployment_configurations.{deployment}",
        )


def _validate_pn_shard(path, body):
    body = _require_mapping(body, path, "part-number")
    direct_attributes = {
        key: value for key, value in body.items() if key not in _PN_RESERVED_SUBSLOTS
    }
    _validate_attributes(direct_attributes, path, "part-number")

    for slot in _PN_RESERVED_SUBSLOTS:
        if slot not in body:
            continue
        variants = _require_mapping(body[slot], path, f"part-number.{slot}")
        for variant, attributes in variants.items():
            _validate_attributes(attributes, path, f"part-number.{slot}.{variant}")


def validate_fec_shard(kind, path, meta, body):
    """Validate every value in one classified FEC shard.

    The generic parser remains responsible for path classification and merge
    precedence. This callback validates only the FEC attribute contract.
    """
    del meta
    if kind == "category":
        _validate_category_shard(path, body)
    elif kind == "pn":
        _validate_pn_shard(path, body)
    else:
        _validate_attributes(body, path, kind)
