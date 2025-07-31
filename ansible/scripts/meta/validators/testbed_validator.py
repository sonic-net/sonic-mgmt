"""
TestbedValidator - Validates testbed configuration, name uniqueness, and topology file existence.
"""

import os
from .base_validator import GlobalValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("testbed")
class TestbedValidator(GlobalValidator):
    """Validates testbed configuration, name uniqueness, and topology file existence"""

    def __init__(self, config=None):
        super().__init__(
            name="testbed",
            description="Validates testbed configuration, name uniqueness, and topology file existence",
            category="configuration",
            config=config
        )

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate testbed names are unique and topology files exist

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """
        testbed_info = context.get_testbeds()

        # Collect and validate testbed names in one pass
        seen_names, duplicate_names, total_testbeds = self._validate_name_uniqueness(testbed_info)

        # Validate topology files for each testbed
        topology_stats = self._validate_topology_files(testbed_info)

        # Add metadata using the returned values for better performance
        self.result.metadata.update({
            "total_testbeds": total_testbeds,
            "unique_names": len(seen_names),
            "duplicate_count": len(duplicate_names),
            "duplicate_names": list(duplicate_names),
            "topology_files_checked": topology_stats["checked"],
            "topology_files_missing": topology_stats["missing"],
            "topology_files_found": topology_stats["found"]
        })

        if self.result.success:
            self.logger.info(
                f"Testbed validation summary: {total_testbeds} testbeds validated, {len(seen_names)} unique names, "
                f"{topology_stats['found']} of {topology_stats['checked']} topology files found"
            )

    def _validate_name_uniqueness(self, testbed_info):
        """
        Collect testbed names and validate uniqueness in a single pass

        Args:
            testbed_info: List of testbed configurations

        Returns:
            tuple: (seen_names, duplicate_names, total_testbeds)
                - seen_names: Set of unique testbed names
                - duplicate_names: Set of duplicate testbed names
                - total_testbeds: Total count of valid testbeds processed
        """
        seen_names = set()
        duplicate_names = set()
        total_testbeds = 0

        for i, testbed in enumerate(testbed_info):
            if not isinstance(testbed, dict):
                # bad_config_data_in_graph: Bad testbed configuration data in connection graph
                self.result.add_issue(
                    'E1001',
                    {"index": i, "type": str(type(testbed))}
                )
                continue

            conf_name = testbed.get('conf-name')
            if not conf_name:
                # missing_conf_name: Testbed configuration missing conf-name field
                self.result.add_issue(
                    'E1002',
                    {"index": i}
                )
                continue

            total_testbeds += 1

            # Check for duplicates and track names in one pass
            if conf_name in seen_names:
                duplicate_names.add(conf_name)
                # duplicate_name: Duplicate testbed name found
                self.result.add_issue(
                    'E1003',
                    {"name": conf_name}
                )
            else:
                seen_names.add(conf_name)

        return seen_names, duplicate_names, total_testbeds

    def _validate_topology_files(self, testbed_info):
        """
        Validate that topology files exist for each testbed

        Args:
            testbed_info: List of testbed configurations

        Returns:
            dict: Statistics about topology file validation
        """
        checked = 0
        found = 0
        missing = 0

        for i, testbed in enumerate(testbed_info):
            if not isinstance(testbed, dict):
                continue

            # Get topology name from testbed configuration
            topo = testbed.get('topo')
            if not topo:
                continue

            checked += 1

            # Look for topology file in ansible/vars directory
            topology_file_path = self._find_topology_file(topo)

            if topology_file_path and os.path.exists(topology_file_path):
                found += 1
            else:
                missing += 1
                conf_name = testbed.get('conf-name', f'testbed-{i}')
                # missing_topology_file: Topology file not found for testbed
                self.result.add_issue(
                    'E1004',
                    {
                        "testbed": conf_name,
                        "topology": topo,
                        "expected_path": topology_file_path or f"ansible/vars/topo_{topo}.yml"
                    }
                )

        return {
            "checked": checked,
            "found": found,
            "missing": missing
        }

    def _find_topology_file(self, topo_name):
        """
        Find the topology file for a given topology name

        Args:
            topo_name: Name of the topology

        Returns:
            str: Path to topology file if found, None otherwise
        """
        # Standard topology file locations with topo_ prefix
        possible_paths = [
            f"ansible/vars/topo_{topo_name}.yml",
            f"ansible/vars/topo_{topo_name}.yaml"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        return None
