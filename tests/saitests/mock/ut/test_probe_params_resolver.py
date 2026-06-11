"""
Unit tests for ProbeParamsResolver hierarchy and registry.

Covers:
  1. ProbeParamsResolver (base): defaults, resolve_threshold for int and list
  2. CiscoProbeParamsResolver: packet_size, cell_size, threshold_divisor, list handling
  3. MellanoxProbeParamsResolver: packet_size, cell_size, cells_per_packet
  4. Registry lookup and get_probe_params integration
  5. List-type threshold handling (pkts_num_trig_pfc_shp is a list)

These tests replicate the resolver classes from tests/qos/test_qos_probe.py
since that module cannot be imported standalone (depends on Linux-only modules).

Keep in sync with: tests/qos/test_qos_probe.py :: ProbeParamsResolver hierarchy
"""
import math
import pytest


# ---------------------------------------------------------------------------
# Replicated resolver classes — must stay in sync with test_qos_probe.py
# ---------------------------------------------------------------------------

_DEFAULT_CELL_SIZE = 384


def _find_cell_size(param_dict):
    """Replicate TestQosProbe.find_cell_size() — search nested dicts for cell_size."""
    for key, val in param_dict.items():
        if isinstance(val, dict) and "cell_size" in val:
            return val["cell_size"]
    return None


class ProbeParamsResolver:
    """Default resolver: 64B packets, 1 cell per packet."""
    packet_length = 64
    cells_per_packet = 1

    def __init__(self, qosConfig_profile=None, dutQosConfig=None):
        pass

    def resolve_threshold(self, value):
        if isinstance(value, list):
            return [v // self.cells_per_packet for v in value]
        return value // self.cells_per_packet


class CiscoProbeParamsResolver(ProbeParamsResolver):
    """Cisco-8000: resolve probe params from QoS config."""
    def __init__(self, qosConfig_profile=None, dutQosConfig=None):
        super().__init__()
        qosConfig_profile = qosConfig_profile or {}
        dutQosConfig = dutQosConfig or {}
        self.packet_length = qosConfig_profile.get("packet_size", 64)

        cell_size = qosConfig_profile.get("cell_size")
        if cell_size is not None:
            self.threshold_divisor = (self.packet_length + cell_size - 1) // cell_size
        else:
            cell_size = (dutQosConfig.get("param", {}).get("cell_size")
                         or _find_cell_size(dutQosConfig.get("param", {}))
                         or _DEFAULT_CELL_SIZE)
            self.threshold_divisor = 1

        self.cells_per_packet = (self.packet_length + cell_size - 1) // cell_size

    def resolve_threshold(self, value):
        if isinstance(value, list):
            return [v // self.threshold_divisor for v in value]
        return value // self.threshold_divisor


class MellanoxProbeParamsResolver(ProbeParamsResolver):
    """Mellanox: resolve probe params from QoS config."""
    def __init__(self, qosConfig_profile=None, dutQosConfig=None):
        super().__init__()
        qosConfig_profile = qosConfig_profile or {}
        del dutQosConfig  # reserved for future platform-specific logic
        self.packet_length = qosConfig_profile.get("packet_size", 64)

        cell_size = qosConfig_profile.get("cell_size")
        if cell_size is not None:
            self.cells_per_packet = (self.packet_length + cell_size - 1) // cell_size
        else:
            self.cells_per_packet = 1


_PROBE_RESOLVER_REGISTRY = {
    "cisco-8000": CiscoProbeParamsResolver,
    "mellanox": MellanoxProbeParamsResolver,
}

_THRESHOLD_KEYS = (
    "pkts_num_trig_pfc", "pkts_num_trig_ingr_drp",
    "pkts_num_trig_egr_drp", "pkts_num_trig_pfc_shp",
)


def get_probe_params(platform_asic, qosConfig_profile, dutQosConfig):
    """Replicate TestQosProbe.get_probe_params()."""
    if not isinstance(qosConfig_profile, dict):
        qosConfig_profile = {}
    resolver_cls = _PROBE_RESOLVER_REGISTRY.get(platform_asic, ProbeParamsResolver)
    resolver = resolver_cls(qosConfig_profile, dutQosConfig)
    params = {
        "probe_packet_length": resolver.packet_length,
        "probe_cells_per_packet": resolver.cells_per_packet,
    }
    for key in _THRESHOLD_KEYS:
        if key in qosConfig_profile:
            params[key] = resolver.resolve_threshold(qosConfig_profile[key])
    return params


# ---------------------------------------------------------------------------
# Tests: ProbeParamsResolver (base class)
# ---------------------------------------------------------------------------

class TestProbeParamsResolverBase:
    """Base resolver: 64B packets, 1 cell/packet, identity threshold conversion."""

    @pytest.mark.order(9000)
    def test_defaults(self):
        r = ProbeParamsResolver()
        assert r.packet_length == 64
        assert r.cells_per_packet == 1

    @pytest.mark.order(9001)
    def test_defaults_with_none_args(self):
        r = ProbeParamsResolver(qosConfig_profile=None, dutQosConfig=None)
        assert r.packet_length == 64
        assert r.cells_per_packet == 1

    @pytest.mark.order(9002)
    def test_resolve_threshold_int(self):
        """Int threshold: cells_per_packet=1 → value unchanged."""
        r = ProbeParamsResolver()
        assert r.resolve_threshold(100) == 100
        assert r.resolve_threshold(0) == 0
        assert r.resolve_threshold(1) == 1

    @pytest.mark.order(9003)
    def test_resolve_threshold_list(self):
        """List threshold: each element divided by cells_per_packet."""
        r = ProbeParamsResolver()
        assert r.resolve_threshold([100, 200, 300]) == [100, 200, 300]

    @pytest.mark.order(9004)
    def test_resolve_threshold_empty_list(self):
        r = ProbeParamsResolver()
        assert r.resolve_threshold([]) == []


# ---------------------------------------------------------------------------
# Tests: MellanoxProbeParamsResolver
# ---------------------------------------------------------------------------

class TestMellanoxProbeParamsResolver:
    """Mellanox resolver: packet_size controls packet_length, cell_size controls cells_per_packet."""

    @pytest.mark.order(9100)
    def test_no_packet_size_no_cell_size(self):
        """Default profile (e.g. xoff_1): 64B, 1 cell/pkt."""
        r = MellanoxProbeParamsResolver(qosConfig_profile={})
        assert r.packet_length == 64
        assert r.cells_per_packet == 1

    @pytest.mark.order(9101)
    def test_packet_size_300_no_cell_size(self):
        """packet_size=300 but no cell_size → cells_per_packet stays 1."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 300}
        )
        assert r.packet_length == 300
        assert r.cells_per_packet == 1

    @pytest.mark.order(9102)
    def test_packet_size_300_cell_size_208(self):
        """SPC3: 300B / 208B cell = ceil(1.44) = 2 cells/pkt."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 300, "cell_size": 208}
        )
        assert r.packet_length == 300
        assert r.cells_per_packet == math.ceil(300 / 208)  # 2

    @pytest.mark.order(9103)
    def test_packet_size_300_cell_size_128(self):
        """Hypothetical: 300B / 128B cell = ceil(2.34) = 3 cells/pkt."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 300, "cell_size": 128}
        )
        assert r.packet_length == 300
        assert r.cells_per_packet == math.ceil(300 / 128)  # 3

    @pytest.mark.order(9104)
    def test_packet_size_64_cell_size_208(self):
        """SPC1: 64B / 208B cell = ceil(0.31) = 1 cell/pkt."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 64, "cell_size": 208}
        )
        assert r.packet_length == 64
        assert r.cells_per_packet == 1

    @pytest.mark.order(9105)
    def test_none_args(self):
        """Both args None → defaults."""
        r = MellanoxProbeParamsResolver(qosConfig_profile=None, dutQosConfig=None)
        assert r.packet_length == 64
        assert r.cells_per_packet == 1

    @pytest.mark.order(9106)
    def test_resolve_threshold_with_cells_per_packet_2(self):
        """Threshold conversion: 600 cells / 2 cells_per_pkt = 300 pkts."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 300, "cell_size": 208}
        )
        assert r.cells_per_packet == 2
        assert r.resolve_threshold(600) == 300
        assert r.resolve_threshold(1) == 0  # integer division

    @pytest.mark.order(9107)
    def test_resolve_threshold_list_with_cells_per_packet(self):
        """List threshold conversion with cells_per_packet > 1."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 300, "cell_size": 208}
        )
        assert r.cells_per_packet == 2
        assert r.resolve_threshold([600, 400, 200]) == [300, 200, 100]

    @pytest.mark.order(9108)
    def test_exact_cell_size_divisibility(self):
        """packet_size exactly divisible by cell_size."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 416, "cell_size": 208}
        )
        assert r.packet_length == 416
        assert r.cells_per_packet == 2  # 416 / 208 = exactly 2

    @pytest.mark.order(9109)
    def test_dutQosConfig_ignored(self):
        """Mellanox resolver does not use dutQosConfig (unlike Cisco)."""
        r = MellanoxProbeParamsResolver(
            qosConfig_profile={"packet_size": 300},
            dutQosConfig={"param": {"cell_size": 999}}
        )
        # cell_size not in qosConfig_profile → cells_per_packet stays 1
        # dutQosConfig cell_size is NOT used (unlike Cisco)
        assert r.cells_per_packet == 1


# ---------------------------------------------------------------------------
# Tests: CiscoProbeParamsResolver list handling (new)
# ---------------------------------------------------------------------------

class TestCiscoResolverListHandling:
    """Verify CiscoProbeParamsResolver.resolve_threshold handles list values."""

    @pytest.mark.order(9200)
    def test_resolve_threshold_int_with_divisor(self):
        """Profile WITH cell_size → threshold_divisor = cells_per_packet."""
        r = CiscoProbeParamsResolver(
            qosConfig_profile={"packet_size": 1350, "cell_size": 384}
        )
        # cells_per_packet = ceil(1350/384) = 4
        assert r.threshold_divisor == 4
        assert r.resolve_threshold(400) == 100

    @pytest.mark.order(9201)
    def test_resolve_threshold_list_with_divisor(self):
        """List threshold with cell_size present → each divided by threshold_divisor."""
        r = CiscoProbeParamsResolver(
            qosConfig_profile={"packet_size": 1350, "cell_size": 384}
        )
        assert r.threshold_divisor == 4
        assert r.resolve_threshold([400, 800, 1200]) == [100, 200, 300]

    @pytest.mark.order(9202)
    def test_resolve_threshold_list_no_cell_size(self):
        """Profile WITHOUT cell_size → threshold_divisor=1, list unchanged."""
        r = CiscoProbeParamsResolver(
            qosConfig_profile={"packet_size": 1350},
            dutQosConfig={"param": {"cell_size": 384}}
        )
        assert r.threshold_divisor == 1
        assert r.resolve_threshold([100, 200, 300]) == [100, 200, 300]

    @pytest.mark.order(9203)
    def test_resolve_threshold_empty_list(self):
        r = CiscoProbeParamsResolver(
            qosConfig_profile={"packet_size": 1350, "cell_size": 384}
        )
        assert r.resolve_threshold([]) == []


# ---------------------------------------------------------------------------
# Tests: Registry and get_probe_params integration
# ---------------------------------------------------------------------------

class TestResolverRegistry:
    """Registry lookup and get_probe_params integration."""

    @pytest.mark.order(9300)
    def test_registry_mellanox(self):
        assert _PROBE_RESOLVER_REGISTRY.get("mellanox") is MellanoxProbeParamsResolver

    @pytest.mark.order(9301)
    def test_registry_cisco(self):
        assert _PROBE_RESOLVER_REGISTRY.get("cisco-8000") is CiscoProbeParamsResolver

    @pytest.mark.order(9302)
    def test_registry_unknown_falls_back(self):
        assert _PROBE_RESOLVER_REGISTRY.get("broadcom", ProbeParamsResolver) is ProbeParamsResolver

    @pytest.mark.order(9310)
    def test_get_probe_params_mellanox_with_packet_size(self):
        """Mellanox profile with packet_size=300, cell_size=208."""
        profile = {
            "packet_size": 300,
            "cell_size": 208,
            "pkts_num_trig_egr_drp": 600,
        }
        params = get_probe_params("mellanox", profile, {})
        assert params["probe_packet_length"] == 300
        assert params["probe_cells_per_packet"] == 2
        assert params["pkts_num_trig_egr_drp"] == 300  # 600 // 2

    @pytest.mark.order(9311)
    def test_get_probe_params_mellanox_default_profile(self):
        """Mellanox profile without packet_size → 64B defaults."""
        profile = {
            "pkts_num_trig_pfc": 100,
        }
        params = get_probe_params("mellanox", profile, {})
        assert params["probe_packet_length"] == 64
        assert params["probe_cells_per_packet"] == 1
        assert params["pkts_num_trig_pfc"] == 100

    @pytest.mark.order(9312)
    def test_get_probe_params_mellanox_list_threshold(self):
        """Mellanox profile with list-type threshold (pkts_num_trig_pfc_shp)."""
        profile = {
            "packet_size": 300,
            "cell_size": 208,
            "pkts_num_trig_pfc_shp": [600, 400],
        }
        params = get_probe_params("mellanox", profile, {})
        assert params["pkts_num_trig_pfc_shp"] == [300, 200]

    @pytest.mark.order(9313)
    def test_get_probe_params_unknown_platform(self):
        """Unknown platform → default resolver → 64B, 1 cell/pkt."""
        profile = {"pkts_num_trig_pfc": 100}
        params = get_probe_params("broadcom", profile, {})
        assert params["probe_packet_length"] == 64
        assert params["probe_cells_per_packet"] == 1
        assert params["pkts_num_trig_pfc"] == 100

    @pytest.mark.order(9314)
    def test_get_probe_params_non_dict_profile(self):
        """Non-dict profile (e.g. hdrm_pool_size=int) → safe fallback."""
        params = get_probe_params("mellanox", 12345, {})
        assert params["probe_packet_length"] == 64
        assert params["probe_cells_per_packet"] == 1
        # No threshold keys in result since profile is not a dict
        assert "pkts_num_trig_pfc" not in params

    @pytest.mark.order(9315)
    def test_get_probe_params_threshold_keys_only_if_present(self):
        """Only threshold keys present in profile are included in params."""
        profile = {
            "pkts_num_trig_pfc": 100,
            "some_other_key": 999,
        }
        params = get_probe_params("mellanox", profile, {})
        assert "pkts_num_trig_pfc" in params
        assert "some_other_key" not in params
        assert "pkts_num_trig_ingr_drp" not in params


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
