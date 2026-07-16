"""Local unit test for generate_config_patch — single patch generation.

Run: pytest tests/generic_config_updater/test_generate_patch_local.py -v

Tests that generate_config_patch produces a single unified patch with proper
ordering (PORT -> INTERFACE -> BGP -> others -> ACL_TABLE) instead of two phases.
"""
import json
import os
import tempfile
import pytest

from tests.generic_config_updater.util.generate_patch import generate_config_patch, is_front_panel_port


def _make_full_config():
    """Synthetic single-ASIC dt2 config WITH a T1 neighbor."""
    return {
        "PORT": {
            "Ethernet0": {"lanes": "0,1,2,3", "speed": "100000", "admin_status": "up", "fec": "rs"},
            "Ethernet4": {"lanes": "4,5,6,7", "speed": "100000", "admin_status": "up", "fec": "rs"},
            "Ethernet8": {"lanes": "8,9,10,11", "speed": "400000", "admin_status": "up"},
        },
        "INTERFACE": {
            "Ethernet0": {},
            "Ethernet0|10.0.0.0/31": {},
            "Ethernet4": {},
            "Ethernet4|10.0.0.2/31": {},
        },
        "PORTCHANNEL": {
            "PortChannel101": {"admin_status": "up", "mtu": "9100", "min_links": "1"},
        },
        "PORTCHANNEL_MEMBER": {
            "PortChannel101|Ethernet0": {},
            "PortChannel101|Ethernet4": {},
        },
        "BGP_NEIGHBOR": {
            "10.0.0.1": {"admin_status": "true", "asn": "65001", "name": "ARISTA01T1"},
            "10.0.0.3": {"admin_status": "true", "asn": "65001", "name": "ARISTA01T1"},
        },
        "DEVICE_NEIGHBOR": {
            "ARISTA01T1": {"mgmt_addr": "192.168.1.10", "type": "LeafRouter"},
        },
        "DEVICE_NEIGHBOR_METADATA": {
            "ARISTA01T1": {"lo_addr": "10.1.0.10/32", "type": "LeafRouter"},
        },
        "CABLE_LENGTH": {
            "AZURE": {"Ethernet0": "5m", "Ethernet4": "5m", "Ethernet8": "10m"},
        },
        "PORT_QOS_MAP": {
            "Ethernet0": {"dscp_to_tc_map": "AZURE"},
            "Ethernet4": {"dscp_to_tc_map": "AZURE"},
        },
        "PFC_WD": {
            "Ethernet0": {"detection_time": "200", "restoration_time": "200", "action": "drop"},
            "Ethernet4": {"detection_time": "200", "restoration_time": "200", "action": "drop"},
        },
        "ACL_TABLE": {
            "DATAACL": {"type": "L3", "policy_desc": "Data ACL", "ports": ["Ethernet0", "Ethernet4", "Ethernet8"]},
            "EVERFLOW": {"type": "MIRROR", "policy_desc": "Everflow", "ports": ["Ethernet0", "Ethernet4", "Ethernet8"]},
        },
    }


def _make_no_leaf_config():
    """Synthetic single-ASIC dt2 config WITHOUT the T1 neighbor (Ethernet0, Ethernet4 removed)."""
    return {
        "PORT": {
            # Ports still exist (platform.json) but with defaults / admin_status=down
            "Ethernet0": {"lanes": "0,1,2,3", "speed": "400000", "admin_status": "down"},
            "Ethernet4": {"lanes": "4,5,6,7", "speed": "400000", "admin_status": "down"},
            "Ethernet8": {"lanes": "8,9,10,11", "speed": "400000", "admin_status": "up"},
        },
        # No INTERFACE entries for Ethernet0/4
        "INTERFACE": {},
        # No PortChannel
        "PORTCHANNEL": {},
        "PORTCHANNEL_MEMBER": {},
        # No BGP neighbors for the removed T1
        "BGP_NEIGHBOR": {},
        "DEVICE_NEIGHBOR": {},
        "DEVICE_NEIGHBOR_METADATA": {},
        "CABLE_LENGTH": {
            "AZURE": {"Ethernet8": "10m"},
        },
        "PORT_QOS_MAP": {},
        "PFC_WD": {},
        "ACL_TABLE": {
            "DATAACL": {"type": "L3", "policy_desc": "Data ACL", "ports": ["Ethernet8"]},
            "EVERFLOW": {"type": "MIRROR", "policy_desc": "Everflow", "ports": ["Ethernet8"]},
        },
    }


def _write_config(tmpdir, name, config):
    path = os.path.join(tmpdir, name)
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    return path


class TestGeneratePatchSinglePhase:
    """Verify generate_config_patch returns a single patch file with correct ordering."""

    def test_returns_single_file(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", _make_full_config())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", _make_no_leaf_config())

        result = generate_config_patch(full_path, no_leaf_path)

        # Should return a single string path, not a tuple
        assert isinstance(result, str), f"Expected str, got {type(result)}: {result}"
        assert os.path.exists(result)

    def test_patch_is_valid_json(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", _make_full_config())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", _make_no_leaf_config())

        patch_file = generate_config_patch(full_path, no_leaf_path)
        with open(patch_file) as f:
            patch = json.load(f)

        assert isinstance(patch, list)
        assert len(patch) > 0
        # Every entry should have op and path
        for entry in patch:
            assert 'op' in entry
            assert 'path' in entry

    def test_ordering_port_before_interface(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", _make_full_config())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", _make_no_leaf_config())

        patch_file = generate_config_patch(full_path, no_leaf_path)
        with open(patch_file) as f:
            patch = json.load(f)

        # Find first PORT and first INTERFACE entry indices
        first_port_idx = None
        first_interface_idx = None
        for i, entry in enumerate(patch):
            path = entry['path']
            parts = path.strip('/').split('/')
            table = parts[0] if parts[0] else parts[1]
            if table == 'PORT' and first_port_idx is None:
                first_port_idx = i
            if table == 'INTERFACE' and first_interface_idx is None:
                first_interface_idx = i

        if first_port_idx is not None and first_interface_idx is not None:
            assert first_port_idx < first_interface_idx, \
                f"PORT (idx {first_port_idx}) should come before INTERFACE (idx {first_interface_idx})"

    def test_ordering_acl_last(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", _make_full_config())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", _make_no_leaf_config())

        patch_file = generate_config_patch(full_path, no_leaf_path)
        with open(patch_file) as f:
            patch = json.load(f)

        # Find last non-ACL entry and first ACL entry
        last_non_acl_idx = None
        first_acl_idx = None
        for i, entry in enumerate(patch):
            path = entry['path']
            parts = path.strip('/').split('/')
            table = parts[0] if parts[0] else parts[1]
            if table == 'ACL_TABLE':
                if first_acl_idx is None:
                    first_acl_idx = i
            else:
                last_non_acl_idx = i

        if first_acl_idx is not None and last_non_acl_idx is not None:
            assert first_acl_idx > last_non_acl_idx, \
                f"ACL_TABLE (first at {first_acl_idx}) should come after all non-ACL entries (last at {last_non_acl_idx})"

    def test_acl_entries_include_new_ports(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", _make_full_config())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", _make_no_leaf_config())

        patch_file = generate_config_patch(full_path, no_leaf_path)
        with open(patch_file) as f:
            patch = json.load(f)

        # Find ACL_TABLE entries and verify they contain the new ports
        acl_entries = [e for e in patch if 'ACL_TABLE' in e['path']]
        assert len(acl_entries) > 0, "Expected ACL_TABLE entries in patch"

        # At least one ACL entry should reference Ethernet0 or Ethernet4
        acl_ports = set()
        for entry in acl_entries:
            value = entry.get('value', {})
            if isinstance(value, dict):
                ports = value.get('ports', [])
                acl_ports.update(ports)

        assert 'Ethernet0' in acl_ports or 'Ethernet4' in acl_ports, \
            f"ACL entries should reference new ports. Found ports: {acl_ports}"

    def test_metadata_file_generated(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", _make_full_config())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", _make_no_leaf_config())

        generate_config_patch(full_path, no_leaf_path)

        metadata_path = os.path.join(str(tmp_path), 'generated_patch_metadata.json')
        assert os.path.exists(metadata_path)
        with open(metadata_path) as f:
            metadata = json.load(f)
        assert 'total_patches' in metadata
        assert metadata['total_patches'] > 0


class TestGeneratePatchMultiAsic:
    """Verify generate_config_patch handles multi-ASIC (namespaced) configs."""

    def _make_multi_asic_full(self):
        return {
            "localhost": {
                "DEVICE_NEIGHBOR_METADATA": {
                    "ARISTA01T1": {"lo_addr": "10.1.0.10/32", "type": "LeafRouter"},
                },
            },
            "asic0": {
                "PORT": {
                    "Ethernet0": {"lanes": "0,1,2,3", "speed": "100000", "admin_status": "up", "fec": "rs"},
                },
                "INTERFACE": {
                    "Ethernet0": {},
                    "Ethernet0|10.0.0.0/31": {},
                },
                "BGP_NEIGHBOR": {
                    "10.0.0.1": {"admin_status": "true", "asn": "65001", "name": "ARISTA01T1"},
                },
                "ACL_TABLE": {
                    "EVERFLOW": {"type": "MIRROR", "policy_desc": "Everflow", "ports": ["Ethernet0"]},
                },
            },
        }

    def _make_multi_asic_no_leaf(self):
        return {
            "localhost": {
                "DEVICE_NEIGHBOR_METADATA": {},
            },
            "asic0": {
                "PORT": {
                    "Ethernet0": {"lanes": "0,1,2,3", "speed": "400000", "admin_status": "down"},
                },
                "INTERFACE": {},
                "BGP_NEIGHBOR": {},
                "ACL_TABLE": {
                    "EVERFLOW": {"type": "MIRROR", "policy_desc": "Everflow", "ports": []},
                },
            },
        }

    def test_multi_asic_returns_single_file(self, tmp_path):
        full_path = _write_config(str(tmp_path), "full.json", self._make_multi_asic_full())
        no_leaf_path = _write_config(str(tmp_path), "no_leaf.json", self._make_multi_asic_no_leaf())

        result = generate_config_patch(full_path, no_leaf_path)
        assert isinstance(result, str)
        assert os.path.exists(result)

        with open(result) as f:
            patch = json.load(f)
        assert isinstance(patch, list)
        assert len(patch) > 0
