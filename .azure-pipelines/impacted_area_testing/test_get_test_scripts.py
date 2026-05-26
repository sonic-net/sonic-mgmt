#!/usr/bin/env python3
"""Unit tests for get_test_scripts.py dedup and data-plane detection."""

import os
import sys
import tempfile
import shutil
import builtins

# Ensure the module under test is importable
sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402
from get_test_scripts import (  # noqa: E402
    VPP_CHECKER,
    VPP_TOPOLOGY,
    build_vpp_impacted_scripts,
    collect_scripts_by_topology_type,
    dedup_control_plane_tests,
    load_vpp_test_scripts_allowlist,
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


# ── t1-lag-vpp allowlist intersection ─────────────────────

class TestVppImpactedArea:

    def test_vpp_allowlist_intersection_includes_raw_script(
        self, test_dir, monkeypatch
    ):
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_allowed.py", "import pytest\n")
        _write_file(tests_dir, "bgp/test_not_allowed.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda: ["bgp/test_allowed.py"],
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert result[VPP_CHECKER] == ["bgp/test_allowed.py"]
        assert "bgp/test_not_allowed.py" not in result[VPP_CHECKER]

    def test_vpp_checker_omitted_when_no_allowlisted_impacted_scripts(
        self, test_dir, monkeypatch
    ):
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_not_allowed.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda: ["route/test_default_route.py"],
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert VPP_CHECKER not in result

    def test_vpp_output_order_follows_allowlist(
        self, test_dir, monkeypatch
    ):
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_first.py", "import pytest\n")
        _write_file(tests_dir, "bgp/test_second.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda: ["bgp/test_second.py", "bgp/test_first.py"],
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert result[VPP_CHECKER] == [
            "bgp/test_second.py",
            "bgp/test_first.py",
        ]

    def test_vpp_broad_impact_filters_by_allowlist(
        self, test_dir, monkeypatch
    ):
        tests_dir = os.path.join(test_dir, "tests")
        _write_file(tests_dir, "bgp/test_allowed.py", "import pytest\n")
        _write_file(tests_dir, "bgp/test_not_allowed.py", "import pytest\n")
        _write_file(tests_dir, "route/test_allowed.py", "import pytest\n")
        monkeypatch.setattr(
            "get_test_scripts.load_vpp_test_scripts_allowlist",
            lambda: [
                "route/test_allowed.py",
                "bgp/test_allowed.py",
                "missing/test_missing.py",
            ],
        )

        result = collect_scripts_by_topology_type("", tests_dir)

        assert result[VPP_CHECKER] == [
            "route/test_allowed.py",
            "bgp/test_allowed.py",
        ]

    def test_vpp_includes_allowlisted_scripts_for_any_marker_shape(
        self, test_dir, monkeypatch
    ):
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
            lambda: scripts,
        )

        result = collect_scripts_by_topology_type("bgp", tests_dir)

        assert result[VPP_CHECKER] == scripts

    def test_build_vpp_impacted_scripts_preserves_allowlist_order(self):
        result = build_vpp_impacted_scripts(
            ["bgp/test_first.py", "bgp/test_second.py"],
            ["bgp/test_second.py", "bgp/test_first.py"],
        )

        assert result == ["bgp/test_second.py", "bgp/test_first.py"]

    def test_load_vpp_allowlist_requires_yaml_key(
        self, test_dir, monkeypatch
    ):
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
            match="Missing {} allowlist".format(VPP_TOPOLOGY)
        ):
            load_vpp_test_scripts_allowlist()

    def test_load_vpp_allowlist_requires_list(
        self, test_dir, monkeypatch
    ):
        pipeline_dir = os.path.join(test_dir, ".azure-pipelines")
        _write_file(
            pipeline_dir,
            "pr_test_scripts.yaml",
            "{}: invalid\n".format(VPP_TOPOLOGY),
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
            load_vpp_test_scripts_allowlist()

    def test_load_vpp_allowlist_reports_load_error(
        self, test_dir, monkeypatch
    ):
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
            load_vpp_test_scripts_allowlist()

    def test_load_vpp_allowlist_reports_missing_pyyaml(
        self, test_dir, monkeypatch
    ):
        pipeline_dir = os.path.join(test_dir, ".azure-pipelines")
        _write_file(
            pipeline_dir,
            "pr_test_scripts.yaml",
            "{}: []\n".format(VPP_TOPOLOGY),
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
            load_vpp_test_scripts_allowlist()


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
            test_dir, "conftest.py", "import ptfadapter\n"
        )
        fp = _write_file(
            test_dir, "bgp/test_foo.py",
            "def test_x(dp):\n    pass\n",
        )
        assert _has_traffic_pattern(fp, test_dir) is True

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
        fp = _write_file(test_dir, "bgp/test_x.py", "")
        conftests = _collect_conftest_files(fp, test_dir)
        assert len(conftests) == 2
        assert any("bgp" in c for c in conftests)


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
