"""
Verify online diag feature 
"""
import random
import re

import pytest

from spytest import st
from apis.common.sonic_hooks import SonicHooks

ONLINE_DIAG_SHOW = "show sai online-diag config"
ONLINE_DIAG_STATUS = "show sai online-diag status"
SIM_CORRUPT_EN = 'debug sai online-diag simulate corruption slice 2 enable'
SIM_CORRUPT_DIS = 'debug sai online-diag simulate corruption slice 2 disable'
SIM_DROP_EN = 'debug sai online-diag simulate drop slice 2 enable'
SIM_DROP_DIS = 'debug sai online-diag simulate drop slice 2 disable'
SIM_SLICE_ID = 2
WAIT_STATUS_SEC = 3
# Expected syslog line after online-diag corruption simulation (see show logging).
ONLINEDIAG_PAYLOAD_CORRUPTION_LOG_RE = re.compile(
    r"OnlineDiag:\s*Payload corruption detected\.",
    re.I,
)
CORRUPTION_SYSLOG_POLL_TIMEOUT_SEC = 30
CONFIG_RELOAD_POST_WAIT_SEC = 300
CONFIG_RELOAD_CORRUPTION_POLL_TIMEOUT_SEC = 120


@pytest.fixture(scope="module", autouse=True)
def _module_setup():
    global vars, sonichooks
    vars = st.get_testbed_vars()
    sonichooks = SonicHooks()
    yield


def _output_indicates_success(output):
    text = (output or "").strip()
    if not text:
        return True
    lower = text.lower()
    if re.search(r"\b(error|failed|cannot|not found|command not found)\b", lower):
        return False
    return True


def _cells_from_line(line):
    line = line.rstrip()
    if "|" not in line:
        return []
    return [c.strip() for c in line.split("|")[1:-1]]


def _packet_corruption_column_index(output):
    """Locate column index for packet-corruption-errors (excluding packet-loss)."""
    for line in output.splitlines():
        if "+-" in line and "---" in line:
            continue
        cells = _cells_from_line(line)
        if not cells:
            continue
        first = cells[0].lower().replace("\n", " ")
        if not first.startswith("slice"):
            continue
        for i, h in enumerate(cells):
            hlow = h.lower().replace("\n", " ")
            if "packet-corruption" in hlow and "loss" not in hlow:
                return i
    for line in output.splitlines():
        cells = _cells_from_line(line)
        for i, h in enumerate(cells):
            hlow = h.lower().replace("\n", " ")
            if "packet-corruption" in hlow and "loss" not in hlow:
                return i
    return 5


def _parse_online_diag_status_rows(output):
    """Return list of (slice_id, packet_corruption_errors)."""
    corruption_col = _packet_corruption_column_index(output)
    rows = []
    for line in output.splitlines():
        if "+-" in line:
            continue
        if "---" in line and line.strip().startswith("|"):
            continue
        cells = _cells_from_line(line)
        if len(cells) <= corruption_col:
            continue
        if not cells[0].isdigit():
            continue
        try:
            sid = int(cells[0])
            cor = int(str(cells[corruption_col]).replace(",", ""))
        except ValueError:
            continue
        rows.append((sid, cor))
    return rows


def _packet_loss_column_index(output):
    """Locate column index for packet-loss-errors."""
    for line in output.splitlines():
        if "+-" in line and "---" in line:
            continue
        cells = _cells_from_line(line)
        if not cells:
            continue
        first = cells[0].lower().replace("\n", " ")
        if not first.startswith("slice"):
            continue
        for i, h in enumerate(cells):
            hlow = h.lower().replace("\n", " ")
            if "packet-loss" in hlow:
                return i
    for line in output.splitlines():
        cells = _cells_from_line(line)
        for i, h in enumerate(cells):
            hlow = h.lower().replace("\n", " ")
            if "packet-loss" in hlow:
                return i
    return None


def _parse_online_diag_status_loss_rows(output):
    """Return list of (slice_id, packet_loss_errors)."""
    loss_col = _packet_loss_column_index(output)
    if loss_col is None:
        return []
    rows = []
    for line in output.splitlines():
        if "+-" in line:
            continue
        if "---" in line and line.strip().startswith("|"):
            continue
        cells = _cells_from_line(line)
        if len(cells) <= loss_col:
            continue
        if not cells[0].isdigit():
            continue
        try:
            sid = int(cells[0])
            loss = int(str(cells[loss_col]).replace(",", ""))
        except ValueError:
            continue
        rows.append((sid, loss))
    return rows


def _run_s1_cli_show(dut, cmd):
    out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    if not _output_indicates_success(out):
        st.report_fail("sudo s1-cli-sonic output suggests failure for cmd={!r}: {!r}".format(cmd, out))
    return out


def _s1_cmd(asic_num, inner_c):
    quoted = '"{}"'.format(inner_c)
    if asic_num is None:
        return "sudo s1-cli-sonic -c {}".format(quoted)
    return "sudo s1-cli-sonic --asic-num {} -c {}".format(asic_num, quoted)


def _parse_asic_ids_from_docker_ps(output):
    """
    Parse ASIC numbers from `docker ps` output: container names starting with syncd,
    extract syncd<N> -> N for s1-cli-sonic --asic-num.
    """
    ids = []
    for line in (output or "").splitlines():
        s = line.strip()
        if not s or s.upper().startswith("CONTAINER ID"):
            continue
        m = re.match(r"^syncd(\d+)\b", s, re.I)
        if m:
            ids.append(int(m.group(1)))
            continue
        for n in re.findall(r"(?<![A-Za-z0-9_./])syncd(\d+)\b", s):
            ids.append(int(n))
    return sorted(set(ids))


def _asic_ids_from_syncd_dockers(dut):
    """Run docker ps and return list of ASIC ids from syncd<N> container names."""
    for cmd in (
        "sudo docker ps --format '{{.Names}}'",
        "docker ps --format '{{.Names}}'",
    ):
        out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        ids = _parse_asic_ids_from_docker_ps(out)
        if ids:
            return ids
    out = st.show(dut, "sudo docker ps", skip_tmpl=True, skip_error_check=True)
    if not out:
        out = st.show(dut, "docker ps", skip_tmpl=True, skip_error_check=True)
    return _parse_asic_ids_from_docker_ps(out) if out else []


def _asic_ids_for_multi_asic_dut(dut):
    """
    Return list of ASIC instance ids from docker ps (containers named syncd<N> only).
    If none found, log error and fail the test (no ip netns / ASIC Count fallback).
    """
    asic_ids = _asic_ids_from_syncd_dockers(dut)
    if not asic_ids:
        st.error(
            "multi-ASIC: no running docker container with name matching syncd<N> "
            "(from docker ps --format / docker ps). Cannot determine ASIC ids.",
            dut=dut,
        )
        st.report_fail(
            "multi-ASIC online-diag tests require at least one syncd* container in docker ps output."
        )
    return asic_ids


def _sim_asic_num(dut):
    """None for single-ASIC; random --asic-num from syncd<N> docker names (see _asic_ids_for_multi_asic_dut)."""
    if not sonichooks.is_multi_asic(dut):
        return None
    asic_ids = _asic_ids_for_multi_asic_dut(dut)
    return random.choice(asic_ids)


def _foreach_asic_num(dut):
    """
    Single-ASIC: yield None once.
    Multi-ASIC: ASIC ids from docker ps syncd<N> names only, then yield one id at random.
    """
    if sonichooks.is_multi_asic(dut):
        asic_ids = _asic_ids_for_multi_asic_dut(dut)
        yield random.choice(asic_ids)
    else:
        yield None


def _foreach_all_asic_nums(dut):
    """Single-ASIC: yield None once. Multi-ASIC: yield every ASIC id from syncd* docker names."""
    if sonichooks.is_multi_asic(dut):
        for num in _asic_ids_for_multi_asic_dut(dut):
            yield num
    else:
        yield None


def _show_logging_has_payload_corruption_detected(dut):
    """True if current buffer from `show logging` contains the OnlineDiag payload-corruption line."""
    out = st.show(dut, "show logging | grep 'Payload corruption detected'", skip_tmpl=True, skip_error_check=True)
    if not out or not _output_indicates_success(out):
        return False
    return True

def _verify_packet_corruption_zero_all_asics(dut):
    """Return True if every slice's packet-corruption-errors is 0 on every ASIC (soft show for poll)."""
    for num in _foreach_all_asic_nums(dut):
        cmd = _s1_cmd(num, ONLINE_DIAG_STATUS)
        out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        if not _output_indicates_success(out):
            return False
        rows = _parse_online_diag_status_rows(out)
        if not rows:
            return False
        bad = [(s, c) for s, c in rows if c != 0]
        if bad:
            return False
    return True


def test_sai_online_diag_config_s1_cli_sonic():
    """
    Multi-ASIC: pick one random ASIC id from docker ps syncd<N> container names (required), run
      s1-cli-sonic --asic-num <num> -c "show sai online-diag config"
    Single-ASIC: run
      s1-cli-sonic -c "show sai online-diag config"
    """
    dut = vars.D1
    for num in _foreach_asic_num(dut):
        cmd = _s1_cmd(num, ONLINE_DIAG_SHOW)
        _run_s1_cli_show(dut, cmd)
    st.report_pass("test_case_passed")


def test_sai_online_diag_packet_corruption_zero_after_config_reload():
    """
    Save and config reload, wait, then verify show sai online-diag status reports zero
    packet-corruption-errors for every slice on each ASIC (poll until true or timeout).
    """
    dut = vars.D1
    st.config_db_reload(dut, save=True)
    st.wait(CONFIG_RELOAD_POST_WAIT_SEC)
    if not st.poll_wait(
        _verify_packet_corruption_zero_all_asics,
        CONFIG_RELOAD_CORRUPTION_POLL_TIMEOUT_SEC,
        dut,
    ):
        st.report_fail(
            "Packet-corruption-errors not all zero after config reload "
            "(within {}s poll)".format(CONFIG_RELOAD_CORRUPTION_POLL_TIMEOUT_SEC)
        )
    st.report_pass("test_case_passed")


def test_sai_online_diag_simulate_corruption_slice_asic():
    """
    On one randomly chosen ASIC (multi-ASIC): read baseline packet-corruption-errors for slice 2
    from status; enable corruption simulate; verify syslog shows 'OnlineDiag: Payload corruption detected.'
    (show logging); verify the count increases vs baseline; disable simulate and confirm the count
    does not increase across polls. Single-ASIC: same without --asic-num.
    """
    dut = vars.D1
    sim_asic = _sim_asic_num(dut)
    disable_cmd = _s1_cmd(sim_asic, SIM_CORRUPT_DIS)

    try:
        cmd_status = _s1_cmd(sim_asic, ONLINE_DIAG_STATUS)
        out0 = _run_s1_cli_show(dut, cmd_status)
        rows0 = _parse_online_diag_status_rows(out0)
        slices = dict(rows0)
        if SIM_SLICE_ID not in slices:
            st.report_fail(
                "Slice {} not present in online-diag status (asic={}): {!r}".format(
                    SIM_SLICE_ID, sim_asic, out0[:800]
                )
            )
        baseline_corruption = slices[SIM_SLICE_ID]

        cmd_en = _s1_cmd(sim_asic, SIM_CORRUPT_EN)
        _run_s1_cli_show(dut, cmd_en)
        st.wait(WAIT_STATUS_SEC)

        if not st.poll_wait(
            _show_logging_has_payload_corruption_detected,
            CORRUPTION_SYSLOG_POLL_TIMEOUT_SEC,
            dut,
        ):
            st.report_fail(
                "After corruption simulate enable, expected 'OnlineDiag: Payload corruption detected.' "
                "in output of 'show logging' (within {}s poll)".format(
                    CORRUPTION_SYSLOG_POLL_TIMEOUT_SEC
                )
            )

        out1 = _run_s1_cli_show(dut, cmd_status)
        slices1 = dict(_parse_online_diag_status_rows(out1))
        if SIM_SLICE_ID not in slices1:
            st.report_fail("Slice {} missing after enable simulate: {!r}".format(SIM_SLICE_ID, out1[:800]))
        if slices1[SIM_SLICE_ID] <= baseline_corruption:
            st.report_fail(
                "After corruption simulate enable, slice {} packet-corruption-errors expected to increase "
                "(baseline={}, after={})".format(
                    SIM_SLICE_ID, baseline_corruption, slices1[SIM_SLICE_ID]
                )
            )

        _run_s1_cli_show(dut, disable_cmd)
        st.wait(WAIT_STATUS_SEC)

        out2 = _run_s1_cli_show(dut, cmd_status)
        c_a = dict(_parse_online_diag_status_rows(out2)).get(SIM_SLICE_ID)
        if c_a is None:
            st.report_fail("Slice {} missing after disable simulate (first poll)".format(SIM_SLICE_ID))

        st.wait(WAIT_STATUS_SEC)

        out3 = _run_s1_cli_show(dut, cmd_status)
        c_b = dict(_parse_online_diag_status_rows(out3)).get(SIM_SLICE_ID)
        if c_b is None:
            st.report_fail("Slice {} missing after disable simulate (second poll)".format(SIM_SLICE_ID))

        if c_b != c_a:
            st.report_fail(
                "After simulate disable, slice {} packet-corruption-errors should not increment "
                "(stable across polls): first={} second={}".format(SIM_SLICE_ID, c_a, c_b)
            )
    finally:
        st.show(dut, disable_cmd, skip_tmpl=True, skip_error_check=True)

    st.report_pass("test_case_passed")


