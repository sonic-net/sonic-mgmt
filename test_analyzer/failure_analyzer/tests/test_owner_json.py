"""
Unit tests for validating owner JSON files:
- test_analyzer/owner/platform_owner.json
- test_analyzer/owner/feature_owner.json

These tests ensure the JSON files are well-formed and contain
all required fields, preventing issues with downstream tools
like the ADO creation tool.
"""

import json
import os
import re
import pytest

OWNER_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'owner')
PLATFORM_OWNER_PATH = os.path.join(OWNER_DIR, 'platform_owner.json')
FEATURE_OWNER_PATH = os.path.join(OWNER_DIR, 'feature_owner.json')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')


def load_json(path):
    """Load and parse a JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


class TestPlatformOwnerJson:
    """Validate platform_owner.json format and content."""

    @pytest.fixture(scope="class")
    def platform_data(self):
        return load_json(PLATFORM_OWNER_PATH)

    def test_valid_json(self, platform_data):
        """Verify platform_owner.json is valid JSON and is a list."""
        assert isinstance(platform_data, list), "platform_owner.json should be a JSON array"
        assert len(platform_data) > 0, "platform_owner.json should not be empty"

    def test_required_fields(self, platform_data):
        """Verify each entry has all required fields."""
        required_fields = ['hwsku', 'topo', 'owner', 'email']
        for i, entry in enumerate(platform_data):
            for field in required_fields:
                assert field in entry, \
                    f"Entry {i} missing required field '{field}': {json.dumps(entry)}"

    def test_fields_not_empty(self, platform_data):
        """Verify hwsku, topo, owner, email are non-empty strings."""
        for i, entry in enumerate(platform_data):
            for field in ['hwsku', 'topo', 'owner', 'email']:
                assert isinstance(entry.get(field), str) and entry[field].strip(), \
                    f"Entry {i} field '{field}' is empty or not a string: {json.dumps(entry)}"

    def test_valid_email(self, platform_data):
        """Verify email fields have valid format."""
        for i, entry in enumerate(platform_data):
            email = entry.get('email', '')
            assert EMAIL_PATTERN.match(email), \
                f"Entry {i} has invalid email '{email}': {json.dumps(entry)}"

    def test_no_duplicate_entries(self, platform_data):
        """Verify no duplicate (hwsku, topo) combinations."""
        seen = set()
        for i, entry in enumerate(platform_data):
            key = (entry.get('hwsku', ''), entry.get('topo', ''))
            assert key not in seen, \
                f"Duplicate entry at index {i}: hwsku='{key[0]}', topo='{key[1]}'"
            seen.add(key)

    def test_optional_fields_are_strings(self, platform_data):
        """Verify optional fields (new_platform, tag) are strings if present."""
        for i, entry in enumerate(platform_data):
            for field in ['new_platform', 'tag']:
                if field in entry:
                    assert isinstance(entry[field], str), \
                        f"Entry {i} field '{field}' should be a string: {json.dumps(entry)}"


class TestFeatureOwnerJson:
    """Validate feature_owner.json format and content."""

    @pytest.fixture(scope="class")
    def feature_data(self):
        return load_json(FEATURE_OWNER_PATH)

    def test_valid_json(self, feature_data):
        """Verify feature_owner.json is valid JSON and is a list."""
        assert isinstance(feature_data, list), "feature_owner.json should be a JSON array"
        assert len(feature_data) > 0, "feature_owner.json should not be empty"

    def test_required_fields(self, feature_data):
        """Verify each entry has all required fields."""
        required_fields = ['feature', 'owner', 'email', 'scripts']
        for i, entry in enumerate(feature_data):
            for field in required_fields:
                assert field in entry, \
                    f"Entry {i} missing required field '{field}': {json.dumps(entry)}"

    def test_feature_not_empty(self, feature_data):
        """Verify feature, owner, email are non-empty strings."""
        for i, entry in enumerate(feature_data):
            for field in ['feature', 'owner', 'email']:
                assert isinstance(entry.get(field), str) and entry[field].strip(), \
                    f"Entry {i} field '{field}' is empty or not a string: {json.dumps(entry)}"

    def test_valid_email(self, feature_data):
        """Verify email fields have valid format."""
        for i, entry in enumerate(feature_data):
            email = entry.get('email', '')
            assert EMAIL_PATTERN.match(email), \
                f"Entry {i} has invalid email '{email}': {json.dumps(entry)}"

    def test_no_duplicate_features(self, feature_data):
        """Verify no duplicate feature names."""
        seen = set()
        for i, entry in enumerate(feature_data):
            feature = entry.get('feature', '')
            assert feature not in seen, \
                f"Duplicate feature at index {i}: '{feature}'"
            seen.add(feature)

    def test_scripts_structure(self, feature_data):
        """Verify scripts field is a list with proper structure."""
        for i, entry in enumerate(feature_data):
            scripts = entry.get('scripts', [])
            assert isinstance(scripts, list), \
                f"Entry {i} ('{entry.get('feature')}') scripts should be a list"
            for j, script_group in enumerate(scripts):
                assert isinstance(script_group, dict), \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}] should be a dict"
                assert 'scripts' in script_group, \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}] missing 'scripts' field"
                assert 'owner' in script_group, \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}] missing 'owner' field"
                assert 'email' in script_group, \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}] missing 'email' field"
                assert isinstance(script_group['scripts'], list), \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}]['scripts'] should be a list"
                assert len(script_group['scripts']) > 0, \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}]['scripts'] should not be empty"

    def test_scripts_email_valid(self, feature_data):
        """Verify all email fields in script groups are valid."""
        for i, entry in enumerate(feature_data):
            for j, script_group in enumerate(entry.get('scripts', [])):
                email = script_group.get('email', '')
                assert EMAIL_PATTERN.match(email), \
                    f"Entry {i} ('{entry.get('feature')}') scripts[{j}] has invalid email '{email}'"

    def test_scripts_entries_are_strings(self, feature_data):
        """Verify all script names are non-empty strings."""
        for i, entry in enumerate(feature_data):
            for j, script_group in enumerate(entry.get('scripts', [])):
                for k, script in enumerate(script_group.get('scripts', [])):
                    assert isinstance(script, str) and script.strip(), \
                        f"Entry {i} ('{entry.get('feature')}') scripts[{j}]['scripts'][{k}] " \
                        f"should be a non-empty string, got: {repr(script)}"
