#!/usr/bin/env python3
"""Unit tests for get_test_scripts.py dedup and data-plane detection."""

import os
import re
import subprocess
import sys
import copy
import json
import tempfile
import shutil
import builtins

# Ensure the module under test is importable
sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402
import yaml  # noqa: E402
from constant import (  # noqa: E402
    CONTROL_PLANE_DEDUP_RULES,
    MULTI_ASIC_T1_CHECKER,
    PR_CHECKER_JOBS,
    PR_TOPOLOGY_TYPE,
)
from get_test_scripts import (  # noqa: E402
    VPP_TOPOLOGY_CHECKERS,
    build_vpp_impacted_scripts,
    collect_scripts_by_topology_type,
    dedup_control_plane_tests,
    load_vpp_test_scripts_allowlist,
    main,
    _collect_conftest_files,
    _detect_data_plane_tests,
    _has_traffic_pattern,
    _read_file_safe,
    _resolve_local_imports,
)


@pytest.fixture
def test_dir():
    """Create a temp directory, cleaned up after test."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)
    _has_traffic_pattern.cache_clear()


def _write_file(directory, relpath, content=""):
    """Helper to create a file under directory."""
    full = os.path.join(directory, relpath)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    return full


def test_bgp_session_flap_keeps_classic_topology_selection():
    tests_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "tests")
    )

    result = collect_scripts_by_topology_type("bgp", tests_dir)

    script = "bgp/test_bgp_session_flap.py"
    assert script in result["t1_checker"]
    assert script in result["t2_checker"]


# ── VPP allowlist intersection ────────────────────────────

class TestVppImpactedArea:

    @pytest.mark.parametrize(
        "topology,checker", VPP_TOPOLOGY_CHECKERS.items()
    )
    def test_vpp_allowlist_intersection_includes_raw_script(
        self, test_dir, monkeypatch, topology, checker
    ):
        """Verify each VPP checker intersects impacted scripts with its allowlist."""
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_allowed.py", "import pytest\n")
        _write_file(tests_dir, "bgp/test_not_allowed.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda requested_topology: (
                ["bgp/test_allowed.py"]
                if requested_topology == topology else []
            ),
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert result[checker] == ["bgp/test_allowed.py"]
        assert "bgp/test_not_allowed.py" not in result[checker]

    @pytest.mark.parametrize(
        "topology,checker", VPP_TOPOLOGY_CHECKERS.items()
    )
    def test_vpp_checker_omitted_when_no_allowlisted_impacted_scripts(
        self, test_dir, monkeypatch, topology, checker
    ):
        """Verify a VPP checker is omitted when its allowlist has no impact."""
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_not_allowed.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda requested_topology: (
                ["route/test_default_route.py"]
                if requested_topology == topology else []
            ),
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert checker not in result

    @pytest.mark.parametrize(
        "topology,checker", VPP_TOPOLOGY_CHECKERS.items()
    )
    def test_vpp_output_order_follows_allowlist(
        self, test_dir, monkeypatch, topology, checker
    ):
        """Verify each VPP checker preserves its allowlist order."""
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_first.py", "import pytest\n")
        _write_file(tests_dir, "bgp/test_second.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda requested_topology: (
                ["bgp/test_second.py", "bgp/test_first.py"]
                if requested_topology == topology else []
            ),
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert result[checker] == [
            "bgp/test_second.py",
            "bgp/test_first.py",
        ]

    @pytest.mark.parametrize(
        "topology,checker", VPP_TOPOLOGY_CHECKERS.items()
    )
    def test_vpp_broad_impact_filters_by_allowlist(
        self, test_dir, monkeypatch, topology, checker
    ):
        """Verify broad impacts remain restricted to each VPP allowlist."""
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_allowed.py", "import pytest\n")
        _write_file(tests_dir, "bgp/test_not_allowed.py", "import pytest\n")
        _write_file(tests_dir, "route/test_allowed.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda requested_topology: (
                [
                    "route/test_allowed.py",
                    "bgp/test_allowed.py",
                    "missing/test_missing.py",
                ]
                if requested_topology == topology else []
            ),
        )

        result = collect_scripts_by_topology_type("", tests_dir)

        assert result[checker] == [
            "route/test_allowed.py",
            "bgp/test_allowed.py",
        ]

    @pytest.mark.parametrize(
        "topology,checker", VPP_TOPOLOGY_CHECKERS.items()
    )
    def test_vpp_includes_allowlisted_scripts_for_any_marker_shape(
        self, test_dir, monkeypatch, topology, checker
    ):
        """Verify VPP selection is based on allowlists, not topology markers."""
        tests_dir = os.path.join(test_dir, "tests")
        scripts = [
            "bgp/test_t0.py",
            "bgp/test_t2.py",
            "bgp/test_any.py",
            "bgp/test_missing_marker.py",
        ]
        _write_file(
            tests_dir,
            scripts[0],
            "pytestmark = [pytest.mark.topology('t0')]\n",
        )
        _write_file(
            tests_dir,
            scripts[1],
            "pytestmark = [pytest.mark.topology('t2')]\n",
        )
        _write_file(
            tests_dir,
            scripts[2],
            "pytestmark = [pytest.mark.topology('any')]\n",
        )
        _write_file(tests_dir, scripts[3], "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda requested_topology: (
                scripts if requested_topology == topology else []
            ),
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert result[checker] == scripts

    def test_vpp_topologies_use_independent_allowlists(
        self, test_dir, monkeypatch
    ):
        """Verify every VPP topology builds its own independent checker list."""
        tests_dir = os.path.join(test_dir, "tests")
        # One uniquely-named script per topology, so a checker picking up
        # another topology's script would be visible rather than masked.
        allowlists = {}
        for topology in VPP_TOPOLOGY_CHECKERS:
            script = "bgp/test_{}.py".format(topology.replace("-", "_"))
            _write_file(tests_dir, script, "import pytest\n")
            allowlists[topology] = [script]
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda topology: allowlists[topology],
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        for topology, checker in VPP_TOPOLOGY_CHECKERS.items():
            assert result[checker] == allowlists[topology]

    def test_build_vpp_impacted_scripts_preserves_allowlist_order(self):
        result = build_vpp_impacted_scripts(
            ["bgp/test_first.py", "bgp/test_second.py"],
            ["bgp/test_second.py", "bgp/test_first.py"],
        )

        assert result == ["bgp/test_second.py", "bgp/test_first.py"]

    @pytest.mark.parametrize("topology", VPP_TOPOLOGY_CHECKERS)
    def test_load_vpp_allowlist_requires_yaml_key(
        self, test_dir, monkeypatch, topology
    ):
        """Verify a missing VPP topology allowlist is rejected."""
        pipeline_dir = os.path.join(test_dir, ".azure-pipelines")
        _write_file(pipeline_dir, "pr_test_scripts.yaml", "t0: []\n")
        monkeypatch.setattr(
            "get_test_scripts.__file__",
            os.path.join(
                pipeline_dir,
                "impacted_area_testing",
                "get_test_scripts.py",
            ),
        )

        with pytest.raises(
            Exception,
            match="Missing {} allowlist".format(topology)
        ):
            load_vpp_test_scripts_allowlist(topology)

    @pytest.mark.parametrize("topology", VPP_TOPOLOGY_CHECKERS)
    def test_load_vpp_allowlist_requires_list(
        self, test_dir, monkeypatch, topology
    ):
        """Verify each VPP topology allowlist must be a list."""
        pipeline_dir = os.path.join(test_dir, ".azure-pipelines")
        _write_file(
            pipeline_dir,
            "pr_test_scripts.yaml",
            "{}: invalid\n".format(topology),
        )
        monkeypatch.setattr(
            "get_test_scripts.__file__",
            os.path.join(
                pipeline_dir,
                "impacted_area_testing",
                "get_test_scripts.py",
            ),
        )

        with pytest.raises(Exception, match="must be a list"):
            load_vpp_test_scripts_allowlist(topology)

    def test_load_vpp_allowlist_reports_load_error(
        self, test_dir, monkeypatch
    ):
        """Verify YAML loading failures identify the allowlist file."""
        pipeline_dir = os.path.join(test_dir, ".azure-pipelines")
        monkeypatch.setattr(
            "get_test_scripts.__file__",
            os.path.join(
                pipeline_dir,
                "impacted_area_testing",
                "get_test_scripts.py",
            ),
        )

        with pytest.raises(Exception, match="trying to load"):
            load_vpp_test_scripts_allowlist("t0-vpp")

    def test_load_vpp_allowlist_reports_missing_pyyaml(
        self, test_dir, monkeypatch
    ):
        """Verify a missing PyYAML dependency produces a clear error."""
        pipeline_dir = os.path.join(test_dir, ".azure-pipelines")
        _write_file(
            pipeline_dir,
            "pr_test_scripts.yaml",
            "t0-vpp: []\n",
        )
        monkeypatch.setattr(
            "get_test_scripts.__file__",
            os.path.join(
                pipeline_dir,
                "impacted_area_testing",
                "get_test_scripts.py",
            ),
        )
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named yaml")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        with pytest.raises(Exception, match="PyYAML is required"):
            load_vpp_test_scripts_allowlist("t0-vpp")


# ── dedup_control_plane_tests ──────────────────────────────

class TestDedupControlPlaneTests:

    def test_no_overlap_returns_unchanged(self, test_dir):
        scripts = {
            "t0_checker": ["a/test_a.py"],
            "t1_checker": ["b/test_b.py"],
        }
        _write_file(test_dir, "a/test_a.py", "# control plane")
        _write_file(test_dir, "b/test_b.py", "# control plane")
        result = dedup_control_plane_tests(scripts, test_dir)
        assert result["t0_checker"] == ["a/test_a.py"]
        assert result["t1_checker"] == ["b/test_b.py"]

    def test_control_plane_overlap_deduped(self, test_dir):
        _write_file(test_dir, "a/test_a.py", "# pure config")
        _write_file(test_dir, "b/test_b.py", "# t1 only")
        scripts = {
            "t0_checker": ["a/test_a.py"],
            "t1_checker": ["a/test_a.py", "b/test_b.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert "a/test_a.py" in result["t0_checker"]
        assert "a/test_a.py" not in result["t1_checker"]
        assert "b/test_b.py" in result["t1_checker"]

    def test_data_plane_overlap_kept(self, test_dir):
        _write_file(test_dir, "a/test_a.py", "import ptfadapter\n")
        scripts = {
            "t0_checker": ["a/test_a.py"],
            "t1_checker": ["a/test_a.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert "a/test_a.py" in result.get("t0_checker", [])
        assert "a/test_a.py" in result.get("t1_checker", [])

    def test_empty_checker_removed(self, test_dir):
        _write_file(test_dir, "a/test_a.py", "# config test")
        scripts = {
            "t0_checker": ["a/test_a.py"],
            "t1_checker": ["a/test_a.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert "t1_checker" not in result

    def test_missing_keep_checker_skips_rule(self, test_dir):
        _write_file(test_dir, "a/test_a.py", "# test")
        scripts = {"t1_checker": ["a/test_a.py"]}
        result = dedup_control_plane_tests(scripts, test_dir)
        assert result["t1_checker"] == ["a/test_a.py"]

    def test_rules_are_order_independent(
        self, test_dir, monkeypatch
    ):
        """Conflicting rule orders produce identical results."""
        _write_file(test_dir, "a/test_shared.py", "# config")
        _write_file(test_dir, "b/test_t1.py", "# config")
        _write_file(test_dir, "c/test_t2.py", "# config")

        # (A,B) then (B,C) vs (B,C) then (A,B)
        rules_fwd = [
            ("t0_checker", "t1_checker"),
            ("t1_checker", "t2_checker"),
        ]
        rules_rev = [
            ("t1_checker", "t2_checker"),
            ("t0_checker", "t1_checker"),
        ]

        def make_scripts():
            return {
                "t0_checker": ["a/test_shared.py"],
                "t1_checker": [
                    "a/test_shared.py", "b/test_t1.py"
                ],
                "t2_checker": ["b/test_t1.py", "c/test_t2.py"],
            }

        monkeypatch.setattr(
            "get_test_scripts.CONTROL_PLANE_DEDUP_RULES",
            rules_fwd,
        )
        r1 = dedup_control_plane_tests(make_scripts(), test_dir)

        monkeypatch.setattr(
            "get_test_scripts.CONTROL_PLANE_DEDUP_RULES",
            rules_rev,
        )
        r2 = dedup_control_plane_tests(make_scripts(), test_dir)

        assert r1 == r2


# ── Data-plane detection ───────────────────────────────────

class TestDataPlaneDetection:

    @pytest.mark.parametrize("pattern", [
        "import ptfadapter",
        "from ptf import testutils",
        "import ptf",
        "ptf_runner(",
        "ptf.testutils.send_packet",
        "send_packet(port, pkt)",
        "run_ptf_script('test.py')",
        "import snappi",
        "from tgen_utils import traffic",
        "craft_packet()",
        "pktgen.start()",
        "from scapy.all import IP",
        "import scapy.layers",
        "from ixnetwork_restpy import Session",
        "tcpreplay --intf1 eth0",
    ])
    def test_traffic_patterns_detected(self, test_dir, pattern):
        fp = _write_file(test_dir, "test_dp.py", pattern)
        assert _has_traffic_pattern(fp) is True

    def test_word_boundary_avoids_false_positive(self, test_dir):
        """'snappishly' should NOT trigger snappi pattern."""
        fp = _write_file(
            test_dir, "test_fp.py", "word = 'snappishly'\n"
        )
        assert _has_traffic_pattern(fp) is False

    def test_control_plane_not_detected(self, test_dir):
        fp = _write_file(
            test_dir, "test_cp.py",
            "import pytest\ndef test_config():\n    pass\n",
        )
        assert _has_traffic_pattern(fp) is False

    def test_indirect_traffic_via_import(self, test_dir):
        _write_file(test_dir, "helper.py", "import ptfadapter\n")
        fp = _write_file(
            test_dir, "test_ind.py",
            "from .helper import something\n",
        )
        assert _has_traffic_pattern(fp) is True

    def test_detect_data_plane_tests_returns_set(self, test_dir):
        _write_file(test_dir, "test_dp.py", "import ptfadapter\n")
        _write_file(test_dir, "test_cp.py", "import pytest\n")
        result = _detect_data_plane_tests(
            ["test_dp.py", "test_cp.py"], test_dir
        )
        assert result == {"test_dp.py"}


# ── §1: Conftest fixture scanning ─────────────────────────

class TestConftestScanning:

    def test_conftest_traffic_detected(self, test_dir):
        """Traffic pattern in conftest.py → test is data-plane."""
        _write_file(
            test_dir, "bgp/conftest.py",
            "import ptfadapter\n",
        )
        fp = _write_file(
            test_dir, "bgp/test_foo.py",
            "def test_x(dataplane_setup):\n    pass\n",
        )
        assert _has_traffic_pattern(fp, test_dir) is True

    def test_parent_conftest_traffic_detected(self, test_dir):
        """conftest.py in parent dir is also scanned."""
        _write_file(
            test_dir, "bgp/conftest.py", "import ptfadapter\n"
        )
        fp = _write_file(
            test_dir, "bgp/sub/test_foo.py",
            "def test_x(dp):\n    pass\n",
        )
        assert _has_traffic_pattern(fp, test_dir) is True

    def test_root_conftest_ignored(self, test_dir):
        """conftest.py at location applies to every test, so it is not scanned."""
        _write_file(
            test_dir, "conftest.py", "import ptfadapter\n"
        )
        fp = _write_file(
            test_dir, "bgp/test_foo.py",
            "def test_x():\n    pass\n",
        )
        assert _has_traffic_pattern(fp, test_dir) is False

    def test_no_conftest_stays_control_plane(self, test_dir):
        fp = _write_file(
            test_dir, "bgp/test_foo.py",
            "def test_x():\n    pass\n",
        )
        assert _has_traffic_pattern(fp, test_dir) is False

    def test_conftest_not_deduped_via_dedup(self, test_dir):
        """Overlap with conftest traffic stays in both checkers."""
        _write_file(
            test_dir, "bgp/conftest.py",
            "import ptfadapter\n",
        )
        _write_file(
            test_dir, "bgp/test_foo.py",
            "def test_x(dp):\n    pass\n",
        )
        scripts = {
            "t0_checker": ["bgp/test_foo.py"],
            "t1_checker": ["bgp/test_foo.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert "bgp/test_foo.py" in result.get("t0_checker", [])
        assert "bgp/test_foo.py" in result.get("t1_checker", [])

    def test_collect_conftest_files(self, test_dir):
        _write_file(test_dir, "conftest.py", "")
        _write_file(test_dir, "bgp/conftest.py", "")
        _write_file(test_dir, "bgp/sub/conftest.py", "")
        fp = _write_file(test_dir, "bgp/sub/test_x.py", "")
        conftests = _collect_conftest_files(fp, test_dir)
        assert conftests == [
            os.path.join(test_dir, "bgp", "sub", "conftest.py"),
            os.path.join(test_dir, "bgp", "conftest.py"),
        ]

    def test_collect_conftest_files_at_location(self, test_dir):
        _write_file(test_dir, "conftest.py", "")
        fp = _write_file(test_dir, "test_x.py", "")
        assert _collect_conftest_files(fp, test_dir) == []

    def test_dedup_removes_control_plane_tests_from_real_tree(self):
        """tests/conftest.py must not make every test look data-plane."""
        tests_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "tests")
        )
        scripts = collect_scripts_by_topology_type("", tests_dir)
        overlap = (
            set(scripts["t0_checker"]) & set(scripts["t1_checker"])
        )

        result = dedup_control_plane_tests(
            copy.deepcopy(scripts), tests_dir
        )

        removed = set(scripts["t1_checker"]) - set(result["t1_checker"])
        assert removed, "dedup removed nothing from t1_checker"
        assert removed < overlap, "data-plane overlap must stay in t1"
        assert result[MULTI_ASIC_T1_CHECKER] == scripts["t1_checker"]


# ── main(): dedup is opt-in ───────────────────────────────

class TestMainDedupFlag:

    @pytest.mark.parametrize("dedup, expected_t1, expected_multi_asic", [
        (False, ["feat/test_cp.py", "feat/test_dp.py"], None),
        (True, ["feat/test_dp.py"], ["feat/test_cp.py", "feat/test_dp.py"]),
    ])
    def test_dedup_only_when_requested(
        self, test_dir, capsys, dedup, expected_t1, expected_multi_asic
    ):
        marker = "pytestmark = [pytest.mark.topology('t0', 't1')]\n"
        _write_file(test_dir, "feat/test_cp.py", marker)
        _write_file(
            test_dir, "feat/test_dp.py", "import ptfadapter\n" + marker
        )

        main("feat", test_dir, dedup_control_plane=dedup)

        result = json.loads(capsys.readouterr().out)
        assert result["t0_checker"] == [
            "feat/test_cp.py", "feat/test_dp.py"
        ]
        assert result["t1_checker"] == expected_t1
        assert result.get(MULTI_ASIC_T1_CHECKER) == expected_multi_asic


# ── Dedup only applies when the kept copy will run ────────

class TestDedupIncludeJobs:

    @pytest.fixture
    def scripts(self, test_dir):
        _write_file(test_dir, "a/test_cp.py", "# config test")
        _write_file(test_dir, "b/test_t1.py", "# t1 only")
        return {
            "t0_checker": ["a/test_cp.py"],
            "t1_checker": ["a/test_cp.py", "b/test_t1.py"],
        }

    @pytest.mark.parametrize("include_jobs", [
        "t1_job",
        "t1_job,t1_multi_asic_job,t2_job",
        "t0_2vlans_job,t0_sonic_job,t0_vpp_job,t1_job",
        "",
    ])
    def test_t1_kept_when_t0_job_not_included(
        self, test_dir, scripts, include_jobs
    ):
        result = dedup_control_plane_tests(
            copy.deepcopy(scripts), test_dir, include_jobs
        )
        assert result == scripts

    @pytest.mark.parametrize("include_jobs", [
        "all",
        "ALL",
        "t0_job",
        "t0_job,t1_job,t1_multi_asic_job",
        "T1_JOB, T0_JOB",
    ])
    def test_t1_deduped_when_t0_job_included(
        self, test_dir, scripts, include_jobs
    ):
        result = dedup_control_plane_tests(
            copy.deepcopy(scripts), test_dir, include_jobs
        )
        assert result["t1_checker"] == ["b/test_t1.py"]

    def test_cli_keeps_t1_when_t0_job_not_included(self, test_dir):
        """Same arguments as get-impacted-area.yml passes in a PR build."""
        marker = "pytestmark = [pytest.mark.topology('t0', 't1')]\n"
        _write_file(test_dir, "feat/test_cp.py", marker)
        script = os.path.join(
            os.path.dirname(__file__), "get_test_scripts.py"
        )

        out = subprocess.run(
            [sys.executable, script, "--features", "feat",
             "--location", test_dir, "--dedup-control-plane",
             "--include-jobs", "t1_job,t1_multi_asic_job"],
            check=True, capture_output=True, text=True,
        ).stdout

        assert json.loads(out) == {
            "t0_checker": ["feat/test_cp.py"],
            "t1_checker": ["feat/test_cp.py"],
        }


# ── multi-asic-t1 keeps the original t1 list ──────────────

class TestDedupKeepsMultiAsicT1:

    def test_original_t1_list_kept(self, test_dir):
        _write_file(test_dir, "a/test_cp.py", "# config test")
        _write_file(test_dir, "b/test_t1.py", "# t1 only")
        scripts = {
            "t0_checker": ["a/test_cp.py"],
            "t1_checker": ["a/test_cp.py", "b/test_t1.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert result["t1_checker"] == ["b/test_t1.py"]
        assert result[MULTI_ASIC_T1_CHECKER] == [
            "a/test_cp.py", "b/test_t1.py"
        ]

    def test_kept_when_t1_lag_list_is_emptied(self, test_dir):
        _write_file(test_dir, "a/test_cp.py", "# config test")
        scripts = {
            "t0_checker": ["a/test_cp.py"],
            "t1_checker": ["a/test_cp.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert "t1_checker" not in result
        assert result[MULTI_ASIC_T1_CHECKER] == ["a/test_cp.py"]

    def test_not_added_when_t1_unchanged(self, test_dir):
        _write_file(test_dir, "a/test_dp.py", "import ptfadapter\n")
        scripts = {
            "t0_checker": ["a/test_dp.py"],
            "t1_checker": ["a/test_dp.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert MULTI_ASIC_T1_CHECKER not in result


# ── PR_CHECKER_JOBS matches pr_test_template.yml ──────────

class TestPrCheckerJobs:

    @pytest.fixture
    def template_jobs(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "pr_test_template.yml"
        )
        with open(path) as f:
            return yaml.safe_load(f)["jobs"]

    def test_matches_job_conditions(self, template_jobs):
        jobs_by_checker = {}
        for job in template_jobs:
            run_by = (job.get("variables") or {}).get(
                "RUN_BY_INCLUDE_JOBS", ""
            )
            names = re.findall(
                r"contains\(parameters\.INCLUDE_JOBS, '([^']+)'\)", run_by
            )
            checkers = re.findall(
                r"PR_CHECKERS'\], '([^']+)'\)", job.get("condition", "")
            )
            for checker in checkers:
                jobs_by_checker.setdefault(checker, []).extend(names)

        assert {k: sorted(v) for k, v in jobs_by_checker.items()} == {
            k: sorted(v) for k, v in PR_CHECKER_JOBS.items()
        }

    def test_multi_asic_t1_job_reads_its_own_list(self, template_jobs):
        job = next(
            j for j in template_jobs
            if "'t1_multi_asic_job'" in str(j.get("variables"))
        )
        step = next(
            s for s in job["steps"]
            if s.get("template", "").endswith(
                "calculate-instance-numbers.yml"
            )
        )
        assert step["parameters"]["CHECKER"] == MULTI_ASIC_T1_CHECKER

    def test_every_keep_in_checker_has_a_job(self):
        for keep_in, _ in CONTROL_PLANE_DEDUP_RULES:
            assert PR_CHECKER_JOBS.get(keep_in), keep_in

    def test_checker_names_are_not_substrings(self):
        """Job conditions match checkers with contains() on PR_CHECKERS."""
        names = set(PR_TOPOLOGY_TYPE) | set(PR_CHECKER_JOBS)
        for name in names:
            others = [n for n in names if n != name and name in n]
            assert not others, (name, others)


# ── Unreadable files (safe default) ───────────────────────

class TestUnreadableFiles:

    def test_read_file_safe_returns_none_on_missing(self):
        assert _read_file_safe("/nonexistent/test.py") is None

    def test_has_traffic_pattern_true_for_unreadable(self):
        assert _has_traffic_pattern("/nonexistent/test.py") is True

    def test_unreadable_file_not_deduped(self, test_dir):
        scripts = {
            "t0_checker": ["missing/test_gone.py"],
            "t1_checker": ["missing/test_gone.py"],
        }
        result = dedup_control_plane_tests(scripts, test_dir)
        assert "missing/test_gone.py" in result.get(
            "t0_checker", []
        )
        assert "missing/test_gone.py" in result.get(
            "t1_checker", []
        )


# ── Import resolution ─────────────────────────────────────

class TestResolveImports:

    def test_relative_import(self, test_dir):
        _write_file(test_dir, "pkg/helper.py", "")
        fp = _write_file(
            test_dir, "pkg/test_x.py",
            "from .helper import func\n",
        )
        resolved = _resolve_local_imports(
            fp, "from .helper import func\n"
        )
        assert any("helper.py" in r for r in resolved)

    def test_parent_relative_import(self, test_dir):
        _write_file(test_dir, "common/utils.py", "")
        fp = _write_file(
            test_dir, "common/sub/test_x.py",
            "from ..utils import func\n",
        )
        resolved = _resolve_local_imports(
            fp, "from ..utils import func\n"
        )
        assert any("utils.py" in r for r in resolved)

    def test_bare_relative_import(self, test_dir):
        """§3: from . import module should be resolved."""
        _write_file(test_dir, "pkg/helper.py", "")
        fp = _write_file(
            test_dir, "pkg/test_x.py",
            "from . import helper\n",
        )
        resolved = _resolve_local_imports(
            fp, "from . import helper\n"
        )
        assert any("helper.py" in r for r in resolved)

    def test_bare_parent_relative_import(self, test_dir):
        """§3: from .. import module should be resolved."""
        _write_file(test_dir, "common/utils.py", "")
        fp = _write_file(
            test_dir, "common/sub/test_x.py",
            "from .. import utils\n",
        )
        resolved = _resolve_local_imports(
            fp, "from .. import utils\n"
        )
        assert any("utils.py" in r for r in resolved)

    def test_absolute_tests_import_with_location(self, test_dir):
        """§2: tests.X.Y resolved relative to location."""
        loc = os.path.join(test_dir, "tests")
        os.makedirs(os.path.join(loc, "common"), exist_ok=True)
        _write_file(test_dir, "tests/common/helpers.py", "")
        fp = _write_file(
            test_dir, "tests/bgp/test_bgp.py",
            "import tests.common.helpers\n",
        )
        resolved = _resolve_local_imports(
            fp, "import tests.common.helpers\n", location=loc
        )
        assert any("helpers.py" in r for r in resolved)

    def test_from_tests_pkg_import_mod(self, test_dir):
        """from tests.common import helpers resolves helpers.py."""
        loc = os.path.join(test_dir, "tests")
        os.makedirs(os.path.join(loc, "common"), exist_ok=True)
        _write_file(test_dir, "tests/common/helpers.py", "")
        fp = _write_file(
            test_dir, "tests/bgp/test_bgp.py",
            "from tests.common import helpers\n",
        )
        resolved = _resolve_local_imports(
            fp,
            "from tests.common import helpers\n",
            location=loc,
        )
        assert any("helpers.py" in r for r in resolved)

    def test_package_init_resolved(self, test_dir):
        os.makedirs(
            os.path.join(test_dir, "pkg", "subpkg"),
            exist_ok=True,
        )
        _write_file(test_dir, "pkg/subpkg/__init__.py", "")
        fp = _write_file(
            test_dir, "pkg/test_x.py",
            "from .subpkg import thing\n",
        )
        resolved = _resolve_local_imports(
            fp, "from .subpkg import thing\n"
        )
        assert any("__init__.py" in r for r in resolved)
