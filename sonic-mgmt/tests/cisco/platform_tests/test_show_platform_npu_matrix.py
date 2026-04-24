"""
Matrix tests for `sudo show platform npu` CLIs: single-ASIC, all-ASICs on DUT, and RP→LC
variants on T2 (supervisor + linecard options).

Each JSON testcase with supported="yes" is a separate pytest item (parametrized by tcname in the report).
For every testcase, 1-2 command variants from the testcase choices JSON are sampled and
executed per matrix scope.

Uses duthosts fixtures: enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index,
enum_supervisor_dut_hostname (T2 RP→LC tests only).
"""
import logging
import random
import re

import pytest

import centralized_cli_test

CASES = centralized_cli_test.RP_LC_TESTCASE_CHOICES_CASES
_tcname_case_id = centralized_cli_test.rp_lc_testcase_choices_case_id


def _supported_show_clis(cases):
    out = []
    for c in cases:
        supported = str(c.get("supported", "")).strip().lower()
        if supported != "yes":
            continue
        cmd = (c.get("command") or "").strip()
        if not cmd or "TBD" in cmd:
            continue
        if not cmd.startswith("sudo show platform npu"):
            continue
        out.append(c)
    return out


SUPPORTED_SHOW_CLIS = _supported_show_clis(CASES)


def _param_case_id(case):
    if case is None:
        return "no_supported_commands"
    return _tcname_case_id(case)


_CLI_PARAMS = SUPPORTED_SHOW_CLIS if SUPPORTED_SHOW_CLIS else [pytest.param(None, id="no_supported_commands")]

_HAS_L_OPT = re.compile(r"(^|\s)-l(\s|$)")
_HAS_N_OPT = re.compile(r"(^|\s)-n(\s|$)")


def _valid_variant_command(cmd):
    """Return True when a command string is usable as a show-platform-npu variant.

    A valid variant must:
    - be a string,
    - be non-empty,
    - not contain "TBD",
    - start with "sudo show platform npu".

    Usage:
        if _valid_variant_command(variant_cmd):
            candidates.append(variant_cmd)
    """
    if not isinstance(cmd, str):
        return False
    cmd = cmd.strip()
    if not cmd or "TBD" in cmd:
        return False
    if not cmd.startswith("sudo show platform npu"):
        return False
    # Placeholders will be resolved at runtime; allow them here.
    return True


def _variant_candidates(tc_dict):
    """Build a normalized candidate list from testcase command fields.

    The function collects valid entries from ``command_variants`` first, then prepends the
    base ``command`` (when valid and not duplicated). Returned strings are stripped and
    ready for scope filtering/sampling.

    Usage:
        candidates = _variant_candidates(tc_dict)
    """
    variants = tc_dict.get("command_variants")
    candidates = []
    if isinstance(variants, list):
        for variant in variants:
            if _valid_variant_command(variant):
                candidates.append(variant.strip())

    base_cmd = (tc_dict.get("command") or "").strip()
    if _valid_variant_command(base_cmd) and base_cmd not in candidates:
        candidates.insert(0, base_cmd)
    return candidates


def _scope_allows_variant(variant, scope):
    """Check whether a command variant is compatible with a matrix scope.

    Matrix scopes in this test inject ``-l`` and/or ``-n`` themselves. For those scopes,
    variants that already contain either option are rejected to avoid conflicting CLI intent.

    Usage:
        allowed = _scope_allows_variant(cmd, "single_asic")
    """
    # Keep matrix controls (-l/-n) in this test, so skip variants that already pin these.
    if scope in {
        "single_asic",
        "all_asics",
        "sup_lc_one",
        "sup_lc_all",
        "sup_lc_one_n",
        "sup_lc_all_n",
    }:
        return not (_HAS_L_OPT.search(variant) or _HAS_N_OPT.search(variant))
    return True


def _pick_variant_commands(tc_dict, scope):
    """Randomly select 1-2 usable command variants for a testcase and scope.

    Candidate commands are first built from testcase data and filtered by scope constraints.
    If no commands remain, the testcase is skipped. Otherwise, up to two variants are sampled
    and returned.

    Usage:
        selected = _pick_variant_commands(tc_dict, "sup_lc_all_n")
        for cmd in selected:
            run_cmd(cmd)
    """
    candidates = [c for c in _variant_candidates(tc_dict) if _scope_allows_variant(c, scope)]
    if not candidates:
        pytest.skip(f"No usable command variants found for {tc_dict.get('tcname')} in {scope} scope")

    pick_count = min(len(candidates), random.randint(1, 2))
    selected = random.sample(candidates, pick_count)
    logging.info("[%s] picked %s variant(s) for %s: %s", scope, pick_count, tc_dict.get("tcname"), selected)
    return selected


def _resolve_command_placeholders(cmd, duthost):
    """Resolve supported placeholders in a command string using DUT facts.

    Currently supported placeholders:
    - ``{interface}``: first available interface from DUT facts.
    - ``{dummy_script}``: fixed dummy path ``/tmp/test_script.py``.

    Returns resolved command text, or ``None`` when a required placeholder (for example
    ``{interface}``) cannot be resolved from DUT data.

    Usage:
        resolved = _resolve_command_placeholders(base_cmd, duthost)
        if resolved:
            result = duthost.command(resolved, module_ignore_errors=True)
    """
    if not duthost or not hasattr(duthost, 'facts'):
        return cmd

    resolved = cmd

    # Resolve {interface} placeholder with a first available interface.
    if "{interface}" in resolved:
        interfaces = duthost.facts.get("ansible_interface_names", []) or []
        if not interfaces:
            # Fallback: try to find interface names from port_name_to_alias_map
            port_dict = duthost.facts.get("port_name_to_alias_map", {})
            interfaces = list(port_dict.keys()) if port_dict else []
        if interfaces:
            chosen_iface = interfaces[0]
            resolved = resolved.replace("{interface}", chosen_iface)
            logging.info("[placeholder] resolved {interface} to %s", chosen_iface)
        else:
            logging.warning("[placeholder] {interface} not resolved; no interfaces found on DUT")
            return None

    # Resolve {dummy_script} placeholder with a dummy path.
    if "{dummy_script}" in resolved:
        dummy_script = "/tmp/test_script.py"
        resolved = resolved.replace("{dummy_script}", dummy_script)
        logging.info("[placeholder] resolved {dummy_script} to %s", dummy_script)

    return resolved


def _cmd_with_matrix_options(base_cmd, lc=None, ns=None):
    """Append matrix options to a base command when options are not already present.

    - Adds ``-l <linecard>`` when ``lc`` is provided and command has no existing ``-l``.
    - Adds ``-n <namespace>`` when ``ns`` is provided and command has no existing ``-n``.

    Usage:
        cmd = _cmd_with_matrix_options("sudo show platform npu status", lc="all", ns="asic0")
    """
    cmd = base_cmd
    if lc and not _HAS_L_OPT.search(cmd):
        cmd = f"{cmd} -l {lc}"
    if ns and not _HAS_N_OPT.search(cmd):
        cmd = f"{cmd} -n {ns}"
    return cmd


def _require_tc_dict(tc_dict):
    if tc_dict is None:
        pytest.skip("No supported sudo show platform npu commands in testcase choices JSON")


def _supervisor_modular(duthosts, enum_supervisor_dut_hostname):
    """
    Resolve supervisor via conftest enum_supervisor_dut_hostname; same modular check as
    rp_lc_show_platform_npu_testcase. RP→LC matrix requires a multi-ASIC supervisor; skip on
    single-ASIC (e.g. some SIM / lab setups) where centralized -l / -n behavior does not apply.
    """
    sup = duthosts[enum_supervisor_dut_hostname]
    if not sup.facts["modular_chassis"]:
        pytest.skip("Test skipped applicable to modular chassis only")
    if not sup.is_supervisor_node():
        pytest.skip("Supervisor DUT required for centralized RP→LC CLI")
    if not sup.is_multi_asic:
        pytest.skip(
            "Multi-ASIC supervisor required for RP→LC show platform npu matrix tests "
            "(skipped when supervisor is single-ASIC, e.g. some SIM conditions)"
        )
    return sup


def _assert_show_npu(tc_dict, result):
    if centralized_cli_test.check_output_for_errors(result):
        snippet = (result.get("stdout") or "")[:800]
        pytest.fail(f"Error pattern in CLI output for {tc_dict.get('tcname')}: {snippet!r}")
    pat = tc_dict.get("output_match_str")
    if pat and pat not in ("NO_PATTERN", "TBD"):
        if not centralized_cli_test.does_result_contain(result, pat):
            pytest.fail(
                f"Expected pattern {pat!r} not found for {tc_dict.get('tcname')}"
            )


@pytest.mark.topology("any")
@pytest.mark.parametrize("tc_dict", _CLI_PARAMS, ids=_param_case_id)
def test_show_platform_npu_single_asic_scope(
    duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index, tc_dict
):
    """
    Random DUT per hwsku; on multi-ASIC DUTs use one random ASIC (-n asicN). On single-ASIC DUTs
    run without -n. One pytest item per JSON testcase (tcname).
    """
    _require_tc_dict(tc_dict)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    selected_variants = _pick_variant_commands(tc_dict, "single_asic")
    ns = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index) if duthost.is_multi_asic else None
    for base_cmd in selected_variants:
        resolved_cmd = _resolve_command_placeholders(base_cmd, duthost)
        if not resolved_cmd:
            logging.warning("[single-asic scope] skipping variant with unresolvable placeholders: %s", base_cmd)
            continue
        cmd = _cmd_with_matrix_options(resolved_cmd, ns=ns)
        logging.info("[single-asic scope] %s", cmd)
        result = duthost.command(cmd, module_ignore_errors=True)
        logging.info(result)
        _assert_show_npu(tc_dict, result)


@pytest.mark.topology("any")
@pytest.mark.parametrize("tc_dict", _CLI_PARAMS, ids=_param_case_id)
def test_show_platform_npu_all_asics_on_dut(duthosts, enum_rand_one_per_hwsku_hostname, tc_dict):
    """
    Multi-ASIC only: no -n (applies to all ASICs on that DUT). One pytest item per JSON testcase.
    """
    _require_tc_dict(tc_dict)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_multi_asic:
        pytest.skip("Multi-ASIC DUT required (no -n runs all ASICs on the host)")
    selected_variants = _pick_variant_commands(tc_dict, "all_asics")
    for base_cmd in selected_variants:
        resolved_cmd = _resolve_command_placeholders(base_cmd, duthost)
        if not resolved_cmd:
            logging.warning("[all ASICs on DUT] skipping variant with unresolvable placeholders: %s", base_cmd)
            continue
        logging.info("[all ASICs on DUT] %s", resolved_cmd)
        result = duthost.command(resolved_cmd, module_ignore_errors=True)
        logging.info(result)
        _assert_show_npu(tc_dict, result)


@pytest.mark.topology("t2")
@pytest.mark.parametrize("tc_dict", _CLI_PARAMS, ids=_param_case_id)
def test_show_platform_npu_sup_t2_linecard_one(duthosts, enum_supervisor_dut_hostname, tc_dict):
    """
    Supervisor on T2: one active LINE-CARD for -l, one pytest item per JSON testcase.
    """
    _require_tc_dict(tc_dict)
    sup = _supervisor_modular(duthosts, enum_supervisor_dut_hostname)
    active_lc = centralized_cli_test.find_active_lc_list(duthosts)
    if not active_lc:
        pytest.skip("No active linecards reported")
    lc = random.choice(active_lc)
    selected_variants = _pick_variant_commands(tc_dict, "sup_lc_one")
    for base_cmd in selected_variants:
        resolved_cmd = _resolve_command_placeholders(base_cmd, sup)
        if not resolved_cmd:
            logging.warning("[SUP -l LINE-CARD] skipping variant with unresolvable placeholders: %s", base_cmd)
            continue
        cmd = _cmd_with_matrix_options(resolved_cmd, lc=lc)
        logging.info("[SUP -l LINE-CARD] %s", cmd)
        result = sup.command(cmd, module_ignore_errors=True)
        logging.info(result)
        _assert_show_npu(tc_dict, result)


@pytest.mark.topology("t2")
@pytest.mark.parametrize("tc_dict", _CLI_PARAMS, ids=_param_case_id)
def test_show_platform_npu_sup_t2_linecard_all(duthosts, enum_supervisor_dut_hostname, tc_dict):
    """
    Supervisor on T2: -l all, one pytest item per JSON testcase.
    """
    _require_tc_dict(tc_dict)
    sup = _supervisor_modular(duthosts, enum_supervisor_dut_hostname)
    selected_variants = _pick_variant_commands(tc_dict, "sup_lc_all")
    for base_cmd in selected_variants:
        resolved_cmd = _resolve_command_placeholders(base_cmd, sup)
        if not resolved_cmd:
            logging.warning("[SUP -l all] skipping variant with unresolvable placeholders: %s", base_cmd)
            continue
        cmd = _cmd_with_matrix_options(resolved_cmd, lc="all")
        logging.info("[SUP -l all] %s", cmd)
        result = sup.command(cmd, module_ignore_errors=True)
        logging.info(result)
        _assert_show_npu(tc_dict, result)


@pytest.mark.topology("t2")
@pytest.mark.parametrize("tc_dict", _CLI_PARAMS, ids=_param_case_id)
def test_show_platform_npu_sup_t2_linecard_one_with_lc_asic(duthosts, enum_supervisor_dut_hostname, tc_dict):
    """
    Supervisor on T2: one LINE-CARD and -n from that linecard's ASIC namespaces (not RP ASICs).
    One pytest item per JSON testcase.
    """
    _require_tc_dict(tc_dict)
    sup = _supervisor_modular(duthosts, enum_supervisor_dut_hostname)
    active_lc = centralized_cli_test.find_active_lc_list(duthosts)
    if not active_lc:
        pytest.skip("No active linecards reported")
    lc = random.choice(active_lc)
    ns_list = centralized_cli_test.get_namespace_list_for_lc(sup, lc)
    if not ns_list:
        pytest.skip(f"No ASIC namespaces in CHASSIS_ASIC_TABLE for {lc}")
    asic_ns = random.choice(ns_list)
    selected_variants = _pick_variant_commands(tc_dict, "sup_lc_one_n")
    for base_cmd in selected_variants:
        resolved_cmd = _resolve_command_placeholders(base_cmd, sup)
        if not resolved_cmd:
            logging.warning("[SUP -l LINE-CARD -n LC-asic] skipping variant with unresolvable placeholders: %s", base_cmd)
            continue
        cmd = _cmd_with_matrix_options(resolved_cmd, lc=lc, ns=asic_ns)
        logging.info("[SUP -l LINE-CARD -n LC-asic] %s", cmd)
        result = sup.command(cmd, module_ignore_errors=True)
        logging.info(result)
        _assert_show_npu(tc_dict, result)


@pytest.mark.topology("t2")
@pytest.mark.parametrize("tc_dict", _CLI_PARAMS, ids=_param_case_id)
def test_show_platform_npu_sup_t2_linecard_all_with_lc_asic(duthosts, enum_supervisor_dut_hostname, tc_dict):
    """
    Supervisor on T2: -l all with -n from a linecard ASIC namespace (not supervisor).
    One pytest item per JSON testcase.
    """
    _require_tc_dict(tc_dict)
    sup = _supervisor_modular(duthosts, enum_supervisor_dut_hostname)
    active_lc = centralized_cli_test.find_active_lc_list(duthosts)
    if not active_lc:
        pytest.skip("No active linecards reported")
    lc = random.choice(active_lc)
    ns_list = centralized_cli_test.get_namespace_list_for_lc(sup, lc)
    if not ns_list:
        pytest.skip(f"No ASIC namespaces in CHASSIS_ASIC_TABLE for {lc}")
    asic_ns = random.choice(ns_list)
    selected_variants = _pick_variant_commands(tc_dict, "sup_lc_all_n")
    for base_cmd in selected_variants:
        resolved_cmd = _resolve_command_placeholders(base_cmd, sup)
        if not resolved_cmd:
            logging.warning("[SUP -l all -n LC-asic] skipping variant with unresolvable placeholders: %s", base_cmd)
            continue
        cmd = _cmd_with_matrix_options(resolved_cmd, lc="all", ns=asic_ns)
        logging.info("[SUP -l all -n LC-asic] %s", cmd)
        result = sup.command(cmd, module_ignore_errors=True)
        logging.info(result)
        _assert_show_npu(tc_dict, result)
