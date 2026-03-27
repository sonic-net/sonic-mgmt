"""
Matrix tests for `sudo show platform npu` CLIs: single-ASIC, all-ASICs on DUT, and RP→LC
variants on T2 (supervisor + linecard options).

Each supported JSON testcase is a separate pytest item (parametrized by tcname in the report).

Uses RP/LC testcase choices from centralized_cli_test (test_rp_lc_testcase_choices.json).
Uses duthosts fixtures: enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index,
enum_supervisor_dut_hostname (T2 RP→LC tests only).
"""
import logging
import random

import pytest

import centralized_cli_test

CASES = centralized_cli_test.RP_LC_TESTCASE_CHOICES_CASES
_tcname_case_id = centralized_cli_test.rp_lc_testcase_choices_case_id


def _supported_show_clis(cases):
    out = []
    for c in cases:
        if "yes" not in c.get("supported", []):
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
    if duthost.is_multi_asic:
        ns = duthost.get_namespace_from_asic_id(enum_rand_one_asic_index)
        cmd = f"{tc_dict['command']} -n {ns}"
    else:
        cmd = tc_dict["command"]
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
    cmd = tc_dict["command"]
    logging.info("[all ASICs on DUT] %s", cmd)
    result = duthost.command(cmd, module_ignore_errors=True)
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
    cmd = f"{tc_dict['command']} -l {lc}"
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
    cmd = f"{tc_dict['command']} -l all"
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
    cmd = f"{tc_dict['command']} -l {lc} -n {asic_ns}"
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
    cmd = f"{tc_dict['command']} -l all -n {asic_ns}"
    logging.info("[SUP -l all -n LC-asic] %s", cmd)
    result = sup.command(cmd, module_ignore_errors=True)
    logging.info(result)
    _assert_show_npu(tc_dict, result)
