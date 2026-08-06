#!/usr/bin/env python3
"""
Transceiver Attribute Infrastructure Test Suite

This test suite validates the transceiver attribute infrastructure components:
- DutInfoLoader: Loads and validates base port attributes from dut_info.json
- AttributeManager: Merges category-specific attributes (e.g., EEPROM) with base attributes

Test Categories:
1. Basic functionality tests (config parsing, port expansion)
2. Integration tests (DutInfoLoader + AttributeManager merge)
3. Error scenario tests (missing files, invalid data, validation failures)
4. Edge case tests (malformed JSON, empty sections, invalid formats)

How to Run:
-----------
# From repository root:
python tests/transceiver/attribute_parser/transceiver_attribute_infra_test.py

# From tests directory:
cd tests
python transceiver/attribute_parser/transceiver_attribute_infra_test.py

Expected Output:
----------------
- Each test prints its name and status (✓ passed / ✗ failed)
- Summary shows total passed/failed count
- Exit code 0 if all tests pass, 1 if any fail

Test Isolation:
---------------
- Each test uses temporary directories created via test_temp_environment()
- All temporary files are automatically cleaned up after each test
- Tests can run in any order and do not interfere with each other
"""

from pathlib import Path
import sys

# Early insertion of repository root to allow 'tests.*' imports when running file directly.
_CURRENT_FILE = Path(__file__).resolve()
# parents: [attribute_parser, transceiver, tests, repo_root]; repo_root is parents[3]
_REPO_ROOT = _CURRENT_FILE.parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import json  # noqa: E402
import tempfile  # noqa: E402
import shutil  # noqa: E402
from contextlib import contextmanager  # noqa: E402

from tests.transceiver.attribute_parser.dut_info_loader import DutInfoLoader  # noqa: E402
from tests.transceiver.attribute_parser.attribute_manager import AttributeManager  # noqa: E402
from tests.transceiver.attribute_parser.exceptions import (  # noqa: E402
    DutInfoError,
    AttributeMergeError,
    TemplateValidationError,
)  # noqa: E402
from tests.transceiver.attribute_parser.template_validator import TemplateValidator  # noqa: E402
from tests.transceiver.attribute_parser.paths import (  # noqa: E402
    REL_NORMALIZATION_MAPPINGS_FILE,
    REL_DUT_INFO_DIR,
    REL_ATTR_DIR,
    REL_DEPLOYMENT_TEMPLATES_FILE,
)  # noqa: E402
from tests.transceiver.attribute_parser.utils import format_kv_block  # noqa: E402

ATTR_PARSER_DIR = Path(__file__).parent
TRANSCEIVER_DIR = ATTR_PARSER_DIR.parent
TESTS_DIR = TRANSCEIVER_DIR.parent
REPO_ROOT = TESTS_DIR.parent

TEST_DUT_NAME = 'lab-dut-1'
TEST_PLATFORM = 'x86_64-nvidia_sn5600-r0'
TEST_HWSKU = 'Mellanox-SN5600-C256S1'
TEST_PLATFORM_HWSKU_KEY = f"{TEST_PLATFORM}+{TEST_HWSKU}"

SEPARATOR_LINE = "=" * 70

EMBEDDED_NORMALIZATION_MAPPINGS = {
    "vendor_names": {"ACME CORP.": "ACME_CORP"},
    "part_numbers": {"PN-ABC-123DE": "PN-ABC-123DE"}
}

EMBEDDED_DUT_DATA = {
    "Ethernet0:8": {
        "vendor_name": "ACME CORP.",
        "vendor_pn": "PN-ABC-123DE",
        "vendor_sn": "IDOBIS130378",
        "vendor_date": "2024-09-02",
        "vendor_oui": "34-36-07",
        "vendor_rev": "1A",
        "hardware_rev": "1.10"
    },
    "Ethernet0": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x1-0x1"},
    "Ethernet1": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x2-0x2"},
    "Ethernet2": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x4-0x4"},
    "Ethernet3": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x8-0x8"},
    "Ethernet4": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x10-0x10"},
    "Ethernet5": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x20-0x20"},
    "Ethernet6": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x40-0x40"},
    "Ethernet7": {"transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x80-0x80"}
}

EMBEDDED_EEPROM_JSON = {
    "mandatory": ["sff8024_identifier"],
    "defaults": {"vdm_supported": False, "cmis_active_optical": False, "eeprom_dump_timeout_sec": 5},
    "transceivers": {
        "deployment_configurations": {"8x100G_DR8": {"vdm_supported": True}},
        "vendors": {
            "ACME_CORP": {
                "part_numbers": {
                    "PN-ABC-123DE": {
                        "cmis_active_optical": True,
                        "sff8024_identifier": 25,
                        "platform_hwsku_overrides": {
                            TEST_PLATFORM_HWSKU_KEY: {"eeprom_dump_timeout_sec": 2}
                        }
                    }
                }
            }
        }
    }
}


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def _shard_category(category_dir, category_name, data):
    """Split a combined category dict into the sharded layout on disk.

    Each non-category shard is *scope-rooted*: the JSON body contains only the
    body for its scope; the scope itself is encoded in the directory path.

    Layout written:
        <category_dir>/<cat>.json
            mandatory / defaults / dut / transceivers.deployment_configurations
        <category_dir>/transceivers/vendors/<V>/<cat>.json
            <vendor defaults body>
        <category_dir>/transceivers/vendors/<V>/part_numbers/<PN>/<cat>.json
            <PN body, including any platform_hwsku_overrides / firmware_overrides>
        <category_dir>/platforms/<P>/<cat>.json
            <platform body>
        <category_dir>/platforms/<P>/hwskus/<H>.json
            <hwsku body>
    """
    category_root = {}
    for k in ('mandatory', 'defaults', 'dut'):
        if k in data:
            category_root[k] = data[k]
    transceivers = data.get('transceivers', {})
    if 'deployment_configurations' in transceivers:
        category_root.setdefault('transceivers', {})['deployment_configurations'] = (
            transceivers['deployment_configurations']
        )
    _write_json(category_dir / f"{category_name}.json", category_root)

    for vendor, vendor_body in transceivers.get('vendors', {}).items():
        vendor_dir = category_dir / 'transceivers' / 'vendors' / vendor
        if 'defaults' in vendor_body:
            _write_json(vendor_dir / f"{category_name}.json", vendor_body['defaults'])
        for pn, pn_body in vendor_body.get('part_numbers', {}).items():
            pn_dir = vendor_dir / 'part_numbers' / pn
            _write_json(pn_dir / f"{category_name}.json", pn_body)

    for platform, platform_body in data.get('platforms', {}).items():
        platform_dir = category_dir / 'platforms' / platform
        _write_json(platform_dir / f"{category_name}.json", platform_body)
    # HWSKUs live in their own top-level slot but on disk under a chosen platform.
    # For test simplicity, attach every hwsku under every provided platform dir.
    hwskus = data.get('hwskus', {})
    platforms = list(data.get('platforms', {}).keys())
    for hwsku, hwsku_body in hwskus.items():
        if not platforms:
            raise ValueError(
                "_shard_category: cannot place hwskus without at least one platform in data"
            )
        for platform in platforms:
            hwsku_file = category_dir / 'platforms' / platform / 'hwskus' / f"{hwsku}.json"
            _write_json(hwsku_file, hwsku_body)


@contextmanager
def test_temp_environment(prefix='sonic_test_', create_dut_info=False, create_eeprom=False, eeprom_data=None):
    """
    Context manager that creates a temporary inventory tree on disk.

    Args:
        prefix: Prefix for temporary directory name.
        create_dut_info: If True, creates normalization_mappings.json and per-DUT file.
        create_eeprom: If True, splays an EEPROM category dict into the sharded layout
            under attributes/eeprom/.
        eeprom_data: Custom EEPROM dict (uses EMBEDDED_EEPROM_JSON if None).

    Cleanup: removes the temp directory on exit.
    """
    temp_root = tempfile.mkdtemp(prefix=prefix)
    try:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        attr_dir.mkdir(parents=True, exist_ok=True)
        if create_dut_info:
            _write_json(Path(temp_root) / REL_NORMALIZATION_MAPPINGS_FILE,
                        EMBEDDED_NORMALIZATION_MAPPINGS)
            _write_json(Path(temp_root) / REL_DUT_INFO_DIR / f"{TEST_DUT_NAME}.json",
                        EMBEDDED_DUT_DATA)
        if create_eeprom:
            data = eeprom_data if eeprom_data is not None else EMBEDDED_EEPROM_JSON
            _shard_category(attr_dir / 'eeprom', 'eeprom', data)
        yield temp_root
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def run_test(test_func):
    test_name = test_func.__name__
    try:
        test_func()
        print(f"✓ {test_name} passed")
        return True
    except Exception as e:
        print(f"✗ {test_name} failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_parser():
    """Test parsing of transceiver configuration string format."""
    print("Testing config parser...")
    config = "AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF"
    parts = config.split('-')
    assert len(parts) == 6
    type_name, speed, form_factor, deployment, media_mask, host_mask = parts
    media_val = int(media_mask, 16)
    host_val = int(host_mask, 16)
    result = {
        'cable_type': type_name,
        'speed_gbps': int(speed),
        'form_factor': form_factor,
        'deployment': deployment,
        'media_lane_mask': media_mask,
        'host_lane_mask': host_mask,
        'media_lane_count': bin(media_val).count('1'),
        'host_lane_count': bin(host_val).count('1'),
    }
    assert result['cable_type'] == 'AOC'
    assert result['speed_gbps'] == 200
    assert result['media_lane_count'] == 8
    print("Config parser works")


def test_port_expansion():
    """Test expansion using PortSpecExpander (range, step, single, list, mixed, edge, invalid)."""
    print("Testing port expansion via PortSpecExpander...")
    from tests.transceiver.attribute_parser.port_spec import PortSpecExpander
    from tests.transceiver.attribute_parser.exceptions import PortSpecError

    test_cases = [
        # (spec, expected_ports)
        ("Ethernet0", ["Ethernet0"]),
        ("Ethernet4:7", ["Ethernet4", "Ethernet5", "Ethernet6"]),  # stop exclusive
        ("Ethernet0:9:4", ["Ethernet0", "Ethernet4", "Ethernet8"]),
        ("Ethernet0,Ethernet2,Ethernet5", ["Ethernet0", "Ethernet2", "Ethernet5"]),
        ("Ethernet8:11,Ethernet15", ["Ethernet8", "Ethernet9", "Ethernet10", "Ethernet15"]),
        ("Ethernet3:3", []),  # empty range start==stop
        ("Ethernet3:3:2", []),  # empty with step
        ("Ethernet10:11:5", ["Ethernet10"]),  # single element range with large step
    ]
    for spec, expected in test_cases:
        expanded = PortSpecExpander.expand(spec)
        assert expanded == expected, f"Spec '{spec}' expected {expected} got {expanded}"

    # Invalid specs
    invalid_specs = [
        "",  # empty
        "  ",  # whitespace only
        "EthernetA",  # bad suffix
        "Eth0",  # wrong prefix
        "Ethernet0::8",  # malformed
        "Ethernet0:8:0",  # zero step
        "Ethernet8:4",  # start>=stop -> empty list; expand treats ':' case as range; considered valid producing []
        "Ethernet0:9:-2",  # negative step
    ]
    for bad in invalid_specs:
        try:
            result = PortSpecExpander.expand(bad)
            # Special case: start>=stop is allowed to produce empty list, so do not fail for that
            if bad in ["Ethernet8:4"]:
                assert result == [], f"Spec '{bad}' should produce empty list, got {result}"
                continue
            raise AssertionError(f"Expected PortSpecError for spec '{bad}', got {result}")
        except PortSpecError:
            pass
    print("PortSpecExpander expansion tests passed")

# =============================================================================
# Integration Tests
# =============================================================================


def test_dut_info_loader_and_eeprom_merge():
    """
    Integration test: Validate complete flow from DutInfoLoader to AttributeManager.

    Tests:
    - DutInfoLoader builds BASE_ATTRIBUTES from dut_info.json
    - AttributeManager merges EEPROM_ATTRIBUTES from eeprom.json
    - Merge follows correct precedence: defaults < deployment < vendor/PN < platform override
    - All mandatory fields are present after merge
    """
    print("Testing DUT info loader and EEPROM attribute merge...")
    with test_temp_environment(create_dut_info=True, create_eeprom=True) as temp_root:
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        assert base, f"No ports loaded for {TEST_DUT_NAME}"
        eeprom_data = EMBEDDED_EEPROM_JSON
        defaults = eeprom_data.get('defaults', {})
        transceivers = eeprom_data.get('transceivers', {})
        deployment_configs = transceivers.get('deployment_configurations', {})
        vendors = transceivers.get('vendors', {})

        def build_expected_eeprom_attrs(port_data):
            base_attrs = port_data.get('BASE_ATTRIBUTES', {})
            deployment = base_attrs.get('deployment')
            vendor_name = base_attrs.get('normalized_vendor_name')
            part_number = base_attrs.get('normalized_vendor_pn')
            merged = {}
            # defaults layer
            for k, v in defaults.items():
                merged[k] = v
            # deployment layer
            if deployment and deployment in deployment_configs:
                for k, v in deployment_configs[deployment].items():
                    merged[k] = v
            # vendor part number layer
            part_number_attrs = {}
            if vendor_name and vendor_name in vendors:
                part_number_attrs = (
                    vendors[vendor_name].get('part_numbers', {}).get(part_number, {}) or {}
                )
            platform_override = {}
            if 'platform_hwsku_overrides' in part_number_attrs:
                if TEST_PLATFORM_HWSKU_KEY in part_number_attrs['platform_hwsku_overrides']:
                    platform_override = part_number_attrs['platform_hwsku_overrides'][TEST_PLATFORM_HWSKU_KEY]
                part_number_attrs = {
                    k: v
                    for k, v in part_number_attrs.items()
                    if k != 'platform_hwsku_overrides'
                }
            for k, v in part_number_attrs.items():
                merged[k] = v
            for k, v in platform_override.items():
                merged[k] = v
            return merged

        expected = {port: build_expected_eeprom_attrs(port_data) for port, port_data in base.items()}
        mgr = AttributeManager(temp_root, base)
        actual = mgr.build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        actual_eeprom = {port: port_data.get('EEPROM_ATTRIBUTES', {}) for port, port_data in actual.items()}
        mismatches = []
        for port in sorted(expected.keys()):
            if expected[port] != actual_eeprom.get(port):
                mismatches.append(port)
                print(f"Mismatch for {port}")
                print(format_kv_block('Expected', expected[port]))
                print(format_kv_block('Actual  ', actual_eeprom.get(port, {})))
        assert not mismatches, (
            f"EEPROM attribute merge mismatches on ports: {mismatches}"
        )
        mandatory = eeprom_data.get('mandatory', [])
        for port, attrs in actual_eeprom.items():
            for mandatory_field in mandatory:
                assert mandatory_field in attrs, f"Port {port} missing mandatory field {mandatory_field}"
        print(f"  Validated {len(actual_eeprom)} ports. All mandatory fields present.")
        sample_port = sorted(actual_eeprom.keys())[0]
        print("Base attributes for sample port:")
        print(format_kv_block(f'  Sample {sample_port} BASE_ATTRIBUTES', base[sample_port]['BASE_ATTRIBUTES']))
        print("EEPROM attributes for sample port:")
        print(format_kv_block(f'  Sample {sample_port} EEPROM_ATTRIBUTES', actual_eeprom[sample_port]))


def test_missing_dut_info_file():
    """Test that DutInfoLoader raises DutInfoError when dut_info.json doesn't exist."""
    print("Testing missing dut_info.json file...")
    with test_temp_environment(prefix='sonic_test_missing_dut_') as temp_root:
        try:
            loader = DutInfoLoader(temp_root)
            loader.build_base_port_attributes(TEST_DUT_NAME)
            raise AssertionError("Expected DutInfoError but got successful load")
        except DutInfoError as e:
            print(f"  Correctly caught: {e}")


def test_dut_not_in_dut_info():
    """Test that DutInfoLoader raises error when DUT file not found."""
    print("Testing DUT name not in dut_info (missing DUT file)...")
    with test_temp_environment(prefix='sonic_test_no_dut_', create_dut_info=True) as temp_root:
        try:
            loader = DutInfoLoader(temp_root)
            loader.build_base_port_attributes('nonexistent-dut')
            raise AssertionError("Expected DutInfoError for nonexistent DUT file")
        except DutInfoError as e:
            assert 'not found' in str(e) or 'Available DUTs' in str(e), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_attribute_manager_mandatory_field_missing():
    """
    Test AttributeManager validation: Mandatory fields must be present after merging.

    Tests category attribute validation layer (EEPROM mandatory fields).
    """
    print("Testing AttributeManager mandatory field validation...")
    eeprom_missing_mandatory = {
        "mandatory": ["sff8024_identifier"],
        "defaults": {"vdm_supported": False, "cmis_active_optical": False},
        "transceivers": {
            "deployment_configurations": {"8x100G_DR8": {"vdm_supported": True}},
            "vendors": {
                "ACME_CORP": {
                    "part_numbers": {
                        "PN-ABC-123DE": {"cmis_active_optical": True}
                    }
                }
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_mandatory_',
                               create_dut_info=True,
                               create_eeprom=True,
                               eeprom_data=eeprom_missing_mandatory) as temp_root:
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        mgr = AttributeManager(temp_root, base)
        try:
            mgr.build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError(
                "Expected AttributeMergeError for missing mandatory fields"
            )
        except AttributeMergeError as e:
            print(f"  Correctly caught: {e}")


def test_missing_category_file():
    """Test graceful handling when category file (eeprom.json) doesn't exist."""
    print("Testing missing category file...")
    with test_temp_environment(prefix='sonic_test_no_category_', create_dut_info=True) as temp_root:
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        mgr = AttributeManager(temp_root, base)
        actual = mgr.build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        for port, port_data in actual.items():
            assert 'EEPROM_ATTRIBUTES' not in port_data, f"Port {port} should not have EEPROM_ATTRIBUTES"
            assert 'BASE_ATTRIBUTES' in port_data, f"Port {port} missing BASE_ATTRIBUTES"
        print(f"  Correctly returned {len(actual)} ports with only BASE_ATTRIBUTES")


def test_default_and_mandatory_overlap():
    """Test that AttributeManager rejects category files with overlapping mandatory and default fields."""
    print("Testing default and mandatory overlap validation...")
    eeprom_overlap = {
        "mandatory": ["sff8024_identifier", "vdm_supported"],
        "defaults": {"vdm_supported": False, "cmis_active_optical": False, "eeprom_dump_timeout_sec": 5},
        "transceivers": {
            "deployment_configurations": {"8x100G_DR8": {}},
            "vendors": {
                "ACME_CORP": {
                    "part_numbers": {
                        "PN-ABC-123DE": {
                            "cmis_active_optical": True,
                            "sff8024_identifier": 25
                        }
                    }
                }
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_overlap_',
                               create_dut_info=True,
                               create_eeprom=True,
                               eeprom_data=eeprom_overlap) as temp_root:
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        mgr = AttributeManager(temp_root, base)
        try:
            mgr.build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError(
                "Expected AttributeMergeError for overlapping mandatory and defaults"
            )
        except AttributeMergeError as e:
            assert 'mandatory' in str(e) and 'defaults' in str(e), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_malformed_json():
    """Test that DutInfoLoader handles malformed JSON syntax gracefully."""
    print("Testing malformed JSON in per-DUT file...")
    with test_temp_environment(prefix='sonic_test_malformed_') as temp_root:
        # Create valid normalization_mappings.json first
        mappings_path = Path(temp_root) / REL_NORMALIZATION_MAPPINGS_FILE
        mappings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(mappings_path, 'w', encoding='utf-8') as f:
            json.dump(EMBEDDED_NORMALIZATION_MAPPINGS, f, indent=2)

        # Create malformed per-DUT file
        dut_info_dir = Path(temp_root) / REL_DUT_INFO_DIR
        dut_info_dir.mkdir(parents=True, exist_ok=True)
        dut_file_path = dut_info_dir / f"{TEST_DUT_NAME}.json"
        with open(dut_file_path, 'w', encoding='utf-8') as f:
            f.write('{"invalid": "json", missing_quote: true}')
        try:
            loader = DutInfoLoader(temp_root)
            loader.build_base_port_attributes(TEST_DUT_NAME)
            raise AssertionError("Expected DutInfoError for malformed JSON")
        except DutInfoError as e:
            assert 'JSON' in str(e) or 'json' in str(e), f"Expected JSON error, got: {e}"
            print(f"  Correctly caught: {e}")


def test_dut_info_loader_mandatory_field_missing():
    print("Testing DutInfoLoader mandatory field validation...")
    normalization_mappings = {
        "vendor_names": {"ACME CORP.": "ACME_CORP"},
        "part_numbers": {"PN-ABC-123DE": "PN-ABC-123DE"}
    }
    dut_data_missing_field = {
        "Ethernet0": {
            "vendor_name": "ACME CORP.",
            "vendor_pn": "PN-ABC-123DE"
        }
    }
    with test_temp_environment(prefix='sonic_test_missing_field_') as temp_root:
        # Create normalization_mappings.json
        mappings_path = Path(temp_root) / REL_NORMALIZATION_MAPPINGS_FILE
        mappings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(mappings_path, 'w', encoding='utf-8') as f:
            json.dump(normalization_mappings, f, indent=2)

        # Create per-DUT file with missing field
        dut_info_dir = Path(temp_root) / REL_DUT_INFO_DIR
        dut_info_dir.mkdir(parents=True, exist_ok=True)
        dut_file_path = dut_info_dir / f"{TEST_DUT_NAME}.json"
        with open(dut_file_path, 'w', encoding='utf-8') as f:
            json.dump(dut_data_missing_field, f, indent=2)
        try:
            loader = DutInfoLoader(temp_root)
            loader.build_base_port_attributes(TEST_DUT_NAME)
            raise AssertionError(
                "Expected DutInfoError for missing transceiver_configuration"
            )
        except DutInfoError as e:
            assert 'mandatory' in str(e).lower() or 'transceiver_configuration' in str(e), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_invalid_port_spec():
    """Test that DutInfoLoader rejects invalid port name formats (must be Ethernet<N>)."""
    print("Testing invalid port specification format...")
    normalization_mappings = {"vendor_names": {}, "part_numbers": {}}
    dut_data_invalid_spec = {
        "InvalidPort123": {
            "vendor_name": "ACME CORP.",
            "vendor_pn": "PN-ABC-123DE",
            "transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x1-0x1"
        }
    }
    with test_temp_environment(prefix='sonic_test_invalid_spec_') as temp_root:
        # Create normalization_mappings.json
        mappings_path = Path(temp_root) / REL_NORMALIZATION_MAPPINGS_FILE
        mappings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(mappings_path, 'w', encoding='utf-8') as f:
            json.dump(normalization_mappings, f, indent=2)

        # Create per-DUT file with invalid port spec
        dut_info_dir = Path(temp_root) / REL_DUT_INFO_DIR
        dut_info_dir.mkdir(parents=True, exist_ok=True)
        dut_file_path = dut_info_dir / f"{TEST_DUT_NAME}.json"
        with open(dut_file_path, 'w', encoding='utf-8') as f:
            json.dump(dut_data_invalid_spec, f, indent=2)
        try:
            loader = DutInfoLoader(temp_root)
            loader.build_base_port_attributes(TEST_DUT_NAME)
            raise AssertionError(
                "Expected DutInfoError for invalid port spec format"
            )
        except DutInfoError as e:
            assert 'port' in str(e).lower() or 'invalid' in str(e).lower(), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_invalid_transceiver_config():
    """Test that DutInfoLoader validates transceiver_configuration format (6 hyphen-separated components)."""
    print("Testing invalid transceiver configuration format...")
    normalization_mappings = {"vendor_names": {}, "part_numbers": {}}
    dut_data_bad_config = {
        "Ethernet0": {
            "vendor_name": "ACME CORP.",
            "vendor_pn": "PN-ABC-123DE",
            "transceiver_configuration": "INVALID-CONFIG"
        }
    }
    with test_temp_environment(prefix='sonic_test_bad_config_') as temp_root:
        # Create normalization_mappings.json
        mappings_path = Path(temp_root) / REL_NORMALIZATION_MAPPINGS_FILE
        mappings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(mappings_path, 'w', encoding='utf-8') as f:
            json.dump(normalization_mappings, f, indent=2)

        # Create per-DUT file with invalid config
        dut_info_dir = Path(temp_root) / REL_DUT_INFO_DIR
        dut_info_dir.mkdir(parents=True, exist_ok=True)
        dut_file_path = dut_info_dir / f"{TEST_DUT_NAME}.json"
        with open(dut_file_path, 'w', encoding='utf-8') as f:
            json.dump(dut_data_bad_config, f, indent=2)
        try:
            loader = DutInfoLoader(temp_root)
            loader.build_base_port_attributes(TEST_DUT_NAME)
            raise AssertionError(
                "Expected DutInfoError for invalid transceiver_configuration format"
            )
        except DutInfoError as e:
            assert 'component' in str(e).lower() or 'format' in str(e).lower(), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_empty_dut_section():
    """Test that DutInfoLoader handles DUT with no port definitions (empty dict)."""
    print("Testing empty DUT section...")
    normalization_mappings = {"vendor_names": {}, "part_numbers": {}}
    dut_data_empty = {}
    with test_temp_environment(prefix='sonic_test_empty_dut_') as temp_root:
        # Create normalization_mappings.json
        mappings_path = Path(temp_root) / REL_NORMALIZATION_MAPPINGS_FILE
        mappings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(mappings_path, 'w', encoding='utf-8') as f:
            json.dump(normalization_mappings, f, indent=2)

        # Create empty per-DUT file
        dut_info_dir = Path(temp_root) / REL_DUT_INFO_DIR
        dut_info_dir.mkdir(parents=True, exist_ok=True)
        dut_file_path = dut_info_dir / f"{TEST_DUT_NAME}.json"
        with open(dut_file_path, 'w', encoding='utf-8') as f:
            json.dump(dut_data_empty, f, indent=2)
        loader = DutInfoLoader(temp_root)
        base = loader.build_base_port_attributes(TEST_DUT_NAME)
        assert base == {}, f"Expected empty dict for empty DUT section, got {base}"
        print("  Correctly returned empty dict for DUT with no ports")

# =============================================================================
# TemplateValidator Tests
# =============================================================================


def _write_templates(repo_root, template_data):
    """Helper to write deployment_templates.json under the proper relative path."""
    templates_path = Path(repo_root) / REL_DEPLOYMENT_TEMPLATES_FILE
    templates_path.parent.mkdir(parents=True, exist_ok=True)
    with open(templates_path, 'w', encoding='utf-8') as f:
        json.dump(template_data, f, indent=2)


def test_template_validator_no_file():
    """If template file does not exist, validator returns empty results and 100% compliance."""
    print("Testing TemplateValidator with no template file present...")
    with test_temp_environment(prefix='sonic_test_tpl_none_', create_dut_info=True) as temp_root:
        # Build a minimal port attributes dict similar to post-merge structure but only BASE_ATTRIBUTES
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        v = TemplateValidator(temp_root)
        result = v.validate(base)
        assert result['results'] == []
        assert result['total_ports'] == len(base)
        assert result['compliance_percent'] == (100 if base else 0)
        print("  Correctly handled missing template file")


def test_template_validator_full_compliance():
    """All required and optional attributes present -> FULLY_COMPLIANT."""
    print("Testing TemplateValidator full compliance scenario...")
    template_data = {
        'deployment_templates': {
            '8x100G_DR8': {
                'required_attributes': {'EEPROM_ATTRIBUTES': ['sff8024_identifier']},
                'optional_attributes': {'EEPROM_ATTRIBUTES': ['vdm_supported']}
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_tpl_full_', create_dut_info=True, create_eeprom=True) as temp_root:
        _write_templates(temp_root, template_data)
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        mgr = AttributeManager(temp_root, base)
        merged = mgr.build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        v = TemplateValidator(temp_root)
        result = v.validate(merged)
        statuses = {r['status'] for r in result['results']}
        assert statuses == {'FULLY_COMPLIANT'}
        print(f"  {len(result['results'])} ports fully compliant")


def test_template_validator_partial_optional():
    """Missing optional attribute -> PARTIAL status, no exception."""
    print("Testing TemplateValidator partial compliance (missing optional)...")
    template_data = {
        'deployment_templates': {
            '8x100G_DR8': {
                'required_attributes': {'EEPROM_ATTRIBUTES': ['sff8024_identifier']},
                'optional_attributes': {'EEPROM_ATTRIBUTES': ['nonexistent_optional_flag']}
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_tpl_partial_', create_dut_info=True, create_eeprom=True) as temp_root:
        _write_templates(temp_root, template_data)
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        mgr = AttributeManager(temp_root, base)
        merged = mgr.build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        v = TemplateValidator(temp_root)
        result = v.validate(merged)
        assert any(r['status'] == 'PARTIAL' for r in result['results'])
        assert all(
            'EEPROM_ATTRIBUTES.nonexistent_optional_flag' in r['missing_optional']
            or r['status'] != 'PARTIAL'
            for r in result['results']
        )
    print("  Partial compliance: missing optional attr detected")


def test_template_validator_missing_required():
    """Missing required attribute -> raises TemplateValidationError (single canonical test)."""
    print("Testing TemplateValidator missing required attribute (raises)...")
    template_data = {
        'deployment_templates': {
            '8x100G_DR8': {
                'required_attributes': {
                    'EEPROM_ATTRIBUTES': [
                        'sff8024_identifier',
                        'MISSING_REQ_ATTR',
                    ]
                },
                'optional_attributes': {}
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_tpl_fail_',
                               create_dut_info=True,
                               create_eeprom=True) as temp_root:
        _write_templates(temp_root, template_data)
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        merged = AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        v = TemplateValidator(temp_root)
        try:
            v.validate(merged)
            raise AssertionError(
                "Expected TemplateValidationError for missing required attribute"
            )
        except TemplateValidationError as e:
            assert 'MISSING_REQ_ATTR' in str(e)
            print(f"  Correctly raised TemplateValidationError: {e}")


# Removed duplicate test_template_validator_missing_required_always_raises (redundant after flag removal)

# =============================================================================
# Loader Validation Tests (sharded schema)
# =============================================================================


def test_loader_slot_whitelist_violation():
    """Category-level shard cannot carry a top-level `platforms` block."""
    print("Testing category top-key whitelist violation...")
    bad = {
        'mandatory': ['sff8024_identifier'],
        'defaults': {'vdm_supported': False},
        'platforms': {TEST_PLATFORM: {'sff8024_identifier': 25}},
        'transceivers': {
            'vendors': {
                'ACME_CORP': {
                    'part_numbers': {'PN-ABC-123DE': {'sff8024_identifier': 25}}
                }
            }
        },
    }
    with test_temp_environment(prefix='sonic_test_slot_', create_dut_info=True) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        _write_json(attr_dir / 'eeprom' / 'eeprom.json', bad)
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        try:
            AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError("Expected AttributeMergeError for slot-whitelist violation")
        except AttributeMergeError as e:
            assert 'platforms' in str(e) and 'not allowed' in str(e), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_loader_normalization_check_unknown_vendor_dir():
    """Vendor directory not in normalization_mappings is rejected."""
    print("Testing normalization check on shard-owning vendor...")
    with test_temp_environment(prefix='sonic_test_norm_', create_dut_info=True, create_eeprom=True) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        rogue_pn_file = (attr_dir / 'eeprom' / 'transceivers' / 'vendors' / 'UNKNOWN_VENDOR'
                         / 'part_numbers' / 'PN-ABC-123DE' / 'eeprom.json')
        _write_json(rogue_pn_file, {'sff8024_identifier': 99})
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        try:
            AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError("Expected AttributeMergeError for unregistered vendor dir")
        except AttributeMergeError as e:
            assert 'UNKNOWN_VENDOR' in str(e) and 'normalization_mappings' in str(e), f"Unexpected error: {e}"
            print(f"  Correctly caught: {e}")


def test_loader_mandatory_resolution():
    """Mandatory field that does not resolve via the hierarchy raises."""
    print("Testing mandatory-field resolution per port...")
    # This is already covered by test_attribute_manager_mandatory_field_missing,
    # but we add a positive variant that asserts a mandatory field can be satisfied
    # purely by a platform-level shard.
    eeprom = {
        'mandatory': ['sff8024_identifier'],
        'defaults': {'vdm_supported': False, 'cmis_active_optical': False},
        'platforms': {TEST_PLATFORM: {'sff8024_identifier': 42}},
        'transceivers': {
            'deployment_configurations': {'8x100G_DR8': {}},
            'vendors': {
                'ACME_CORP': {
                    'part_numbers': {'PN-ABC-123DE': {}}
                }
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_mand_ok_',
                               create_dut_info=True,
                               create_eeprom=True,
                               eeprom_data=eeprom) as temp_root:
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        result = AttributeManager(temp_root, base).build_port_attributes(
            TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        for port, data in result.items():
            assert data['EEPROM_ATTRIBUTES']['sff8024_identifier'] == 42, port
        print(f"  Mandatory field resolved via platform-level shard for {len(result)} ports")


def test_loader_normalization_check_unknown_pn_dir():
    """PN directory not in normalization_mappings is rejected."""
    print("Testing normalization check on shard-owning PN...")
    with test_temp_environment(prefix='sonic_test_norm_pn_', create_dut_info=True, create_eeprom=True) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        rogue_pn_file = (attr_dir / 'eeprom' / 'transceivers' / 'vendors' / 'ACME_CORP'
                         / 'part_numbers' / 'UNKNOWN_PN' / 'eeprom.json')
        _write_json(rogue_pn_file, {'sff8024_identifier': 7})
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        try:
            AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError("Expected AttributeMergeError for unregistered PN dir")
        except AttributeMergeError as e:
            assert 'UNKNOWN_PN' in str(e) and 'normalization_mappings' in str(e), f"Unexpected: {e}"
            print(f"  Correctly caught: {e}")


def test_loader_pn_reserved_subslot_shape():
    """Per-PN shard: `platform_hwsku_overrides` variant body must be an object."""
    print("Testing per-PN reserved sub-slot shape check...")
    with test_temp_environment(prefix='sonic_test_pn_subslot_', create_dut_info=True, create_eeprom=True) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        pn_file = (attr_dir / 'eeprom' / 'transceivers' / 'vendors' / 'ACME_CORP'
                   / 'part_numbers' / 'PN-ABC-123DE' / 'eeprom.json')
        _write_json(pn_file, {
            'sff8024_identifier': 25,
            'platform_hwsku_overrides': {TEST_PLATFORM_HWSKU_KEY: "not-an-object"},
        })
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        try:
            AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError("Expected AttributeMergeError for non-dict override variant body")
        except AttributeMergeError as e:
            assert 'platform_hwsku_overrides' in str(e) and 'must be an object' in str(e), f"Unexpected: {e}"
            print(f"  Correctly caught: {e}")


def test_loader_unrecognized_subdir():
    """A directory under a category that doesn't match the contract is rejected."""
    print("Testing rejection of unrecognized subdirectory under category...")
    with test_temp_environment(prefix='sonic_test_unknown_dir_', create_dut_info=True, create_eeprom=True) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        stray = attr_dir / 'eeprom' / 'random_unknown_folder' / 'eeprom.json'
        _write_json(stray, {'defaults': {'vdm_supported': True}})
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        try:
            AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError("Expected AttributeMergeError for unknown subdirectory")
        except AttributeMergeError as e:
            assert 'not in a recognized location' in str(e), f"Unexpected: {e}"
            print(f"  Correctly caught: {e}")


def test_loader_category_disallows_vendors_block():
    """Category-level shard may not carry `transceivers.vendors` (PN/vendor live in their own shards)."""
    print("Testing category-level shard rejecting transceivers.vendors block...")
    bad = {
        'mandatory': ['sff8024_identifier'],
        'defaults': {'vdm_supported': False},
        'transceivers': {
            'deployment_configurations': {'8x100G_DR8': {}},
            'vendors': {
                'ACME_CORP': {
                    'part_numbers': {'PN-ABC-123DE': {'sff8024_identifier': 25}}
                }
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_cat_vendors_', create_dut_info=True) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        _write_json(attr_dir / 'eeprom' / 'eeprom.json', bad)
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        try:
            AttributeManager(temp_root, base).build_port_attributes(TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
            raise AssertionError("Expected AttributeMergeError for vendors in category-level shard")
        except AttributeMergeError as e:
            assert "'transceivers.deployment_configurations'" in str(e), f"Unexpected: {e}"
            print(f"  Correctly caught: {e}")


def test_hwsku_same_name_under_different_platforms():
    """Two ``platforms/<P>/hwskus/<H>.json`` shards with the same ``<H>`` filename
    but under different platform directories must each be retained in the merged
    tree and resolved by the current DUT's (platform, hwsku) pair - not silently
    overwritten by walk order.
    """
    print("Testing HWSKU same-name-different-platform isolation...")
    other_platform = 'x86_64-other_vendor_other_model-r0'
    eeprom = {
        'mandatory': ['sff8024_identifier'],
        'defaults': {'vdm_supported': False, 'cmis_active_optical': False},
        'transceivers': {
            'vendors': {
                'ACME_CORP': {
                    'part_numbers': {
                        'PN-ABC-123DE': {'sff8024_identifier': 25}
                    }
                }
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_hwsku_platform_scope_',
                               create_dut_info=True,
                               create_eeprom=True,
                               eeprom_data=eeprom) as temp_root:
        attr_dir = Path(temp_root) / REL_ATTR_DIR
        # Same HWSKU filename under two different platform directories with
        # different bodies. Walk order is alphabetical by directory name, so
        # ``other_platform`` is processed before ``TEST_PLATFORM`` - if the
        # loader keyed solely by HWSKU name, the TEST_PLATFORM body would win
        # in this layout. We verify both coexist and the resolver picks the
        # one matching the DUT's platform.
        _write_json(
            attr_dir / 'eeprom' / 'platforms' / TEST_PLATFORM / 'hwskus' / f"{TEST_HWSKU}.json",
            {'eeprom_dump_timeout_sec': 7},
        )
        _write_json(
            attr_dir / 'eeprom' / 'platforms' / other_platform / 'hwskus' / f"{TEST_HWSKU}.json",
            {'eeprom_dump_timeout_sec': 99},
        )
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        merged = AttributeManager(temp_root, base).build_port_attributes(
            TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        for port, data in merged.items():
            attrs = data['EEPROM_ATTRIBUTES']
            assert attrs['eeprom_dump_timeout_sec'] == 7, (
                f"{port}: expected current platform's HWSKU body (7); got {attrs['eeprom_dump_timeout_sec']} "
                "- the other platform's HWSKU shard with the same filename leaked in."
            )
        print(f"  HWSKU correctly scoped by platform for {len(merged)} ports")


def test_priority_dut_layer_overrides_all():
    """`dut.<DUT>` (priority 1) must override every lower-priority layer."""
    print("Testing dut-layer priority override...")
    eeprom = {
        'mandatory': ['sff8024_identifier'],
        'defaults': {'vdm_supported': False, 'cmis_active_optical': False, 'eeprom_dump_timeout_sec': 5},
        'dut': {TEST_DUT_NAME: {'eeprom_dump_timeout_sec': 99, 'sff8024_identifier': 100}},
        'transceivers': {
            'deployment_configurations': {'8x100G_DR8': {'vdm_supported': True}},
            'vendors': {
                'ACME_CORP': {
                    'part_numbers': {
                        'PN-ABC-123DE': {
                            'sff8024_identifier': 25,
                            'platform_hwsku_overrides': {
                                TEST_PLATFORM_HWSKU_KEY: {'eeprom_dump_timeout_sec': 2}
                            }
                        }
                    }
                }
            }
        }
    }
    with test_temp_environment(prefix='sonic_test_dut_prio_',
                               create_dut_info=True,
                               create_eeprom=True,
                               eeprom_data=eeprom) as temp_root:
        base = DutInfoLoader(temp_root).build_base_port_attributes(TEST_DUT_NAME)
        result = AttributeManager(temp_root, base).build_port_attributes(
            TEST_DUT_NAME, TEST_PLATFORM, TEST_HWSKU)
        for port, data in result.items():
            attrs = data['EEPROM_ATTRIBUTES']
            assert attrs['eeprom_dump_timeout_sec'] == 99, (
                f"{port}: dut layer should beat platform_hwsku_overrides (got {attrs['eeprom_dump_timeout_sec']})"
            )
            assert attrs['sff8024_identifier'] == 100, (
                f"{port}: dut layer should beat PN layer (got {attrs['sff8024_identifier']})"
            )
        print(f"  dut layer correctly overrode lower layers for {len(result)} ports")


# =============================================================================
# Test Runner
# =============================================================================

if __name__ == "__main__":
    print(SEPARATOR_LINE)
    print("Running Transceiver Infrastructure Test Suite")
    print(SEPARATOR_LINE)
    tests = [
        test_config_parser,
        test_port_expansion,
        test_dut_info_loader_and_eeprom_merge,
        test_missing_dut_info_file,
        test_dut_not_in_dut_info,
        test_attribute_manager_mandatory_field_missing,
        test_missing_category_file,
        test_default_and_mandatory_overlap,
        test_malformed_json,
        test_dut_info_loader_mandatory_field_missing,
        test_invalid_port_spec,
        test_invalid_transceiver_config,
        test_empty_dut_section,
        test_template_validator_no_file,
        test_template_validator_full_compliance,
        test_template_validator_partial_optional,
        test_template_validator_missing_required,
        test_loader_slot_whitelist_violation,
        test_loader_normalization_check_unknown_vendor_dir,
        test_loader_mandatory_resolution,
        test_loader_normalization_check_unknown_pn_dir,
        test_loader_pn_reserved_subslot_shape,
        test_loader_unrecognized_subdir,
        test_loader_category_disallows_vendors_block,
        test_hwsku_same_name_under_different_platforms,
        test_priority_dut_layer_overrides_all,
    ]
    results = [run_test(test) for test in tests]

    # Print summary
    passed = sum(results)
    failed = len(results) - passed
    print(SEPARATOR_LINE)
    print(f"Test Summary: {passed} passed, {failed} failed out of {len(results)} tests")
    print(SEPARATOR_LINE)
    if failed > 0:
        raise SystemExit(1)
    print("All tests passed!")
