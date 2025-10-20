"""AttributeManager for merging category attributes per port.

Priority (highest to lowest):
1. dut.<DUT_NAME>
2. vendors.<VENDOR>.part_numbers.<PN>.platform_hwsku_overrides.<PLATFORM>+<HWSKU>
3. vendors.<VENDOR>.part_numbers.<PN>
4. vendors.<VENDOR>.defaults
5. deployment_configurations.<DEPLOYMENT>
6. hwsku.<HWSKU>
7. platform.<PLATFORM>
8. defaults

Validation: All fields named in 'mandatory' must resolve in final merged dict (cannot be in
defaults list as per design rule).
"""

import json
import os
import logging

from .exceptions import AttributeMergeError
from .paths import REL_ATTR_DIR

logger = logging.getLogger(__name__)

# Centralized attributes directory from paths.py
ATTRIBUTES_REL_DIR = REL_ATTR_DIR
CATEGORY_SUFFIX = '_ATTRIBUTES'


class AttributeManager:
    def __init__(self, repo_root, base_port_dict):
        self.repo_root = repo_root
        # Mapping: port -> {BASE_ATTRIBUTES: {...}}
        self.base_port_dict = base_port_dict  # output of DutInfoLoader

    def _list_category_files(self):
        attributes_dir = os.path.join(self.repo_root, ATTRIBUTES_REL_DIR)
        if not os.path.isdir(attributes_dir):
            logging.info("Attributes directory %s not present; no category attributes loaded", attributes_dir)
            return []
        json_files = [f for f in os.listdir(attributes_dir) if f.endswith('.json')]
        return [os.path.join(attributes_dir, f) for f in json_files]

    def _load_json(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise AttributeMergeError(f"Failed to load attribute file {file_path}: {e}") from e

    @staticmethod
    def _category_key_from_filename(filename):
        # eeprom.json -> EEPROM_ATTRIBUTES
        base_name = os.path.basename(filename)
        stem = os.path.splitext(base_name)[0]
        return f"{stem.upper()}{CATEGORY_SUFFIX}"

    @staticmethod
    def _apply_layer(target, layer):
        for k, v in layer.items():
            target[k] = v

    def _resolve_priority(self, category_data, base_attrs, dut_name, platform, hwsku):
        """Resolve layered overrides into a final dict following defined priority.

        Layer application order (low -> high): defaults, platform, hwsku, deployment, vendor_defaults,
        part_number, pn_platform_hwsku, dut.
        """
        merged = {}
        deployment = base_attrs.get('deployment')
        vendor_name = base_attrs.get('normalized_vendor_name')
        part_number = base_attrs.get('normalized_vendor_pn')

        # Extract sections
        defaults_layer = category_data.get('defaults', {})
        platform_layer = category_data.get('platform', {}).get(platform, {})
        hwsku_layer = category_data.get('hwsku', {}).get(hwsku, {})
        dut_layer = category_data.get('dut', {}).get(dut_name, {})
        transceivers_section = category_data.get('transceivers', {})
        deployment_layer = (
            transceivers_section.get('deployment_configurations', {}).get(deployment, {})
            if deployment
            else {}
        )
        vendors_section = transceivers_section.get('vendors', {})
        vendor_section = vendors_section.get(vendor_name, {}) if vendor_name else {}
        vendor_defaults_layer = vendor_section.get('defaults', {})
        part_number_layer = vendor_section.get('part_numbers', {}).get(part_number, {}) if part_number else {}
        part_number_platform_override_layer = {}
        if 'platform_hwsku_overrides' in part_number_layer:
            key = f"{platform}+{hwsku}"
            part_number_platform_override_layer = part_number_layer['platform_hwsku_overrides'].get(key, {})
            part_number_layer = {k: v for k, v in part_number_layer.items() if k != 'platform_hwsku_overrides'}

        for layer in [
            defaults_layer,
            platform_layer,
            hwsku_layer,
            deployment_layer,
            vendor_defaults_layer,
            part_number_layer,
            part_number_platform_override_layer,
            dut_layer,
        ]:
            self._apply_layer(merged, layer)
        return merged

    @staticmethod
    def _validate_mandatory(category_data, merged, category_file):
        mandatory = category_data.get('mandatory', [])
        defaults_list = category_data.get('defaults', {}).keys()
        overlap = set(mandatory).intersection(defaults_list)
        if overlap:
            raise AttributeMergeError(
                f"Category file {category_file} invalid: fields {overlap} appear in both 'mandatory' and 'defaults'"
            )
        missing = [m for m in mandatory if m not in merged]
        if missing:
            raise AttributeMergeError(
                f"Category file {category_file} missing mandatory fields after merging: {missing}"
            )

    def build_port_attributes(self, dut_name, platform, hwsku):
        category_files = self._list_category_files()
        if not category_files:
            return self.base_port_dict

        for category_path in category_files:
            category_data = self._load_json(category_path)
            category_key = self._category_key_from_filename(category_path)
            logging.info(
                "Processing attribute category %s (%s)",
                category_key,
                category_path,
            )
            for port_name, port_data in self.base_port_dict.items():
                base_attrs = port_data.get('BASE_ATTRIBUTES', {})
                merged_attrs = self._resolve_priority(category_data, base_attrs, dut_name, platform, hwsku)
                try:
                    self._validate_mandatory(category_data, merged_attrs, category_path)
                except AttributeMergeError as e:
                    raise AttributeMergeError(f"Failed to merge attributes for {port_name}: {e}") from e
                port_data[category_key] = merged_attrs
        return self.base_port_dict
