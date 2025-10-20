"""
Load and process dut_info.json to build BASE_ATTRIBUTES per port.

Responsibilities:
- Load JSON
- Extract normalization mappings
- For a given dut_name, expand all port specs to individual ports
- Apply normalization (default to raw if not mapped)
- Parse transceiver_configuration components
- Build structure: { 'EthernetX': { 'BASE_ATTRIBUTES': {...}} }
"""

import json
import os
import logging

from .port_spec import PortSpecExpander
from .config_parser import parse_transceiver_configuration
from .exceptions import DutInfoError
from .paths import REL_DUT_INFO_FILE

logger = logging.getLogger(__name__)

# Centralized path imported from paths.py
MANDATORY_FIELDS = ['vendor_name', 'vendor_pn', 'transceiver_configuration']


class DutInfoLoader:
    def __init__(self, repo_root):
        self.repo_root = repo_root
        self._dut_info_json = None
        self._mappings = None

    def _load_file(self):
        """Load and validate dut_info.json with comprehensive error handling."""
        if self._dut_info_json is not None:
            return self._dut_info_json
        file_path = os.path.join(self.repo_root, REL_DUT_INFO_FILE)
        if not os.path.isfile(file_path):
            raise DutInfoError(f"dut_info.json not found at {file_path}")

        logger.debug("Loading dut_info.json from %s", file_path)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise DutInfoError(f"Invalid JSON syntax in dut_info.json: {e}") from e
        except Exception as e:
            raise DutInfoError(f"Failed to load dut_info.json: {e}") from e

        self._dut_info_json = data
        logger.info("Successfully loaded dut_info.json")
        return self._dut_info_json

    def _get_mappings(self):
        """Extract normalization mappings with validation and safe defaults."""
        if self._mappings is not None:
            return self._mappings

        data = self._load_file()
        mappings = data.get('normalization_mappings', {})

        vendor_names = mappings.get('vendor_names', {})
        part_numbers = mappings.get('part_numbers', {})

        self._mappings = {
            'vendor_names': vendor_names,
            'part_numbers': part_numbers,
        }

        logger.debug(
            "Loaded %d vendor name mappings, %d part number mappings",
            len(vendor_names),
            len(part_numbers),
        )
        return self._mappings

    def _collect_port_attributes(self, dut_section):
        """First pass: collect and merge all attributes per port from overlapping specs."""
        port_attributes = {}

        for port_spec, attributes in dut_section.items():
            try:
                expanded_ports = PortSpecExpander.expand(port_spec)
            except Exception as e:
                raise DutInfoError(f"Failed expanding port spec '{port_spec}': {e}") from e

            logger.debug(
                "Port spec '%s' expands to %d ports: %s",
                port_spec,
                len(expanded_ports),
                expanded_ports,
            )

            for port in expanded_ports:
                if port not in port_attributes:
                    port_attributes[port] = {}
                # Merge attributes (later specs override earlier ones)
                port_attributes[port].update(attributes)

        logger.info("Collected attributes for %d ports after expansion", len(port_attributes))
        return port_attributes

    def _validate_and_process_port(self, port, merged_attrs, mappings, dut_name):
        """Validate mandatory fields and process a single port's attributes."""
        # Check for mandatory fields after all merging is complete
        missing_fields = [field for field in MANDATORY_FIELDS if field not in merged_attrs]
        if missing_fields:
            raise DutInfoError(
                f"Mandatory fields {missing_fields} missing for port '{port}' in DUT '{dut_name}' "
                f"after merging all applicable port specs"
            )

        # Copy all fields to avoid modifying source
        base_attrs = dict(merged_attrs)

        # Apply normalization with validation
        try:
            raw_vendor_name = base_attrs['vendor_name']
            raw_part_number = base_attrs['vendor_pn']

            # Normalize with safe lookup
            vendor_name_map = mappings['vendor_names']
            part_number_map = mappings['part_numbers']

            normalized_vendor = vendor_name_map.get(raw_vendor_name, raw_vendor_name)
            normalized_part_number = part_number_map.get(raw_part_number, raw_part_number)

            base_attrs['normalized_vendor_name'] = normalized_vendor
            base_attrs['normalized_vendor_pn'] = normalized_part_number
        except KeyError as e:
            raise DutInfoError(f"Missing required field {e} for port {port}") from e

        # Parse transceiver configuration with enhanced error context
        try:
            config_str = base_attrs['transceiver_configuration']
            parsed_config = parse_transceiver_configuration(config_str)
            base_attrs.update(parsed_config)
            logger.debug(
                "Port %s: parsed config '%s' -> %d components",
                port,
                config_str,
                len(parsed_config),
            )
        except Exception as e:
            raise DutInfoError(
                f"Invalid transceiver_configuration '{base_attrs.get('transceiver_configuration', 'N/A')}' "
                f"for port {port}: {e}"
            ) from e

        return base_attrs

    def build_base_port_attributes(self, dut_name):
        """Build comprehensive port attributes dictionary for the specified DUT.

        Args:
            dut_name: Name of the DUT to process

        Returns:
            Dict mapping port names to their BASE_ATTRIBUTES

        Raises:
            DutInfoError: If DUT not found, validation fails, or processing errors occur
        """
        logger.info("Building base port attributes for DUT '%s'", dut_name)

        data = self._load_file()
        mappings = self._get_mappings()

        if dut_name not in data:
            available_duts = [k for k in data.keys() if k != 'normalization_mappings']
            logger.warning(
                "DUT '%s' not present in dut_info.json. Available DUTs: %s",
                dut_name,
                available_duts,
            )
            return {}

        dut_section = data[dut_name]

        # First pass: collect and merge attributes per port
        port_attributes = self._collect_port_attributes(dut_section)
        if not port_attributes:
            logger.warning("No ports found for DUT '%s' after expansion", dut_name)
            return {}

        # Second pass: validate and process each port
        port_base_attributes_dict = {}
        processed_count = 0

        for port_name, merged_attrs in port_attributes.items():
            try:
                base_attrs = self._validate_and_process_port(port_name, merged_attrs, mappings, dut_name)
                port_base_attributes_dict[port_name] = {'BASE_ATTRIBUTES': base_attrs}
                processed_count += 1
            except Exception as e:
                logger.error("Failed to process port %s: %s", port_name, e)
                raise DutInfoError(f"Failed to process port {port_name}: {e}") from e

        logger.info("Successfully processed %d ports for DUT '%s'", processed_count, dut_name)
        return port_base_attributes_dict
