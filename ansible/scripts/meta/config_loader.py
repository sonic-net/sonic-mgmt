"""
Configuration-driven validator loading system
"""

import yaml
import json
import logging
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

from validators.base_validator import BaseValidator
from validators.validator_factory import ValidatorRegistry, ConfigurableValidatorFactory
from validators.validation_result import get_issue_registry


class ValidationConfig:
    """Configuration container for validation settings"""

    def __init__(self, config_dict: Dict[str, Any]):
        self.config_dict = config_dict
        self.logger = logging.getLogger("meta.config")

    def get_validator_configs(self) -> List[Dict[str, Any]]:
        """Get validator configurations"""
        return self.config_dict.get('validators', [])

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.config_dict.get('logging', {})

    def get_issue_severities(self) -> Dict[str, str]:
        """Get issue severity configuration"""
        return self.config_dict.get('issue_severities', {})

    def is_validator_enabled(self, validator_name: str) -> bool:
        """Check if a specific validator is enabled"""
        for validator_config in self.get_validator_configs():
            if validator_config.get('name') == validator_name:
                return validator_config.get('enabled', True)
        return False


class ConfigLoader:
    """Loads validation configuration from various sources"""

    def __init__(self):
        self.logger = logging.getLogger("meta.config_loader")

    def load_from_file(self, config_path: Union[str, Path]) -> ValidationConfig:
        """
        Load configuration from file (YAML or JSON)

        Args:
            config_path: Path to configuration file

        Returns:
            ValidationConfig object
        """
        config_path = Path(config_path)

        if not config_path.exists():
            self.logger.warning(f"Config file not found: {config_path}")
            return ValidationConfig({})

        try:
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() in ['.yaml', '.yml']:
                    config_dict = yaml.safe_load(f)
                elif config_path.suffix.lower() == '.json':
                    config_dict = json.load(f)
                else:
                    self.logger.error(f"Unsupported config file format: {config_path.suffix}")
                    return ValidationConfig({})

            self.logger.info(f"Loaded configuration from: {config_path}")
            return ValidationConfig(config_dict or {})

        except Exception as e:
            self.logger.error(f"Failed to load config from {config_path}: {str(e)}")
            return ValidationConfig({})

    def load_from_dict(self, config_dict: Dict[str, Any]) -> ValidationConfig:
        """Load configuration from dictionary"""
        return ValidationConfig(config_dict)

    def get_default_config(self) -> ValidationConfig:
        """Get default validation configuration"""
        default_config = {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'validators': [
                {
                    'name': 'testbed',
                    'enabled': True,
                    'config': {}
                },
                {
                    'name': 'device_info',
                    'enabled': True,
                    'config': {
                        'invalid_chars': [],
                        'max_length': 255
                    }
                },
                {
                    'name': 'ip_address',
                    'enabled': True,
                    'config': {}
                },
                {
                    'name': 'vlan',
                    'enabled': True,
                    'config': {}
                },
                {
                    'name': 'console',
                    'enabled': True,
                    'config': {}
                },
                {
                    'name': 'pdu',
                    'enabled': True,
                    'config': {}
                },
                {
                    'name': 'topology',
                    'enabled': True,
                    'config': {}
                }
            ]
        }
        return ValidationConfig(default_config)


class ValidatorConfigManager:
    """Manages validator configuration and creation"""

    def __init__(
            self,
            registry: ValidatorRegistry,
            config_loader: Optional[ConfigLoader] = None
    ):
        self.registry = registry
        self.config_loader = config_loader or ConfigLoader()
        self.logger = logging.getLogger("meta.config_manager")

    def create_validators_from_config(
            self,
            config: ValidationConfig
    ) -> List[BaseValidator]:
        """
        Create validators from configuration

        Args:
            config: ValidationConfig containing validator specifications

        Returns:
            List of configured validator instances
        """
        # Apply issue severities
        severities = config.get_issue_severities()
        if severities:
            issue_registry = get_issue_registry()
            issue_registry.configure_severities(severities)
            self.logger.info(f"Applied {len(severities)} issue severities")

        factory = ConfigurableValidatorFactory(
            self.registry,
            {}
        )

        validator_configs = config.get_validator_configs()
        validators = []

        for validator_config in validator_configs:
            validator = factory.create_validator_from_config(validator_config)
            if validator:
                validators.append(validator)

        self.logger.info(f"Created {len(validators)} validators from configuration")
        return validators

    def create_validators_from_file(
            self,
            config_path: Union[str, Path]
    ) -> List[BaseValidator]:
        """Create validators from configuration file"""
        config = self.config_loader.load_from_file(config_path)
        return self.create_validators_from_config(config)

    def create_default_validators(self) -> List[BaseValidator]:
        """Create validators using default configuration"""
        config = self.config_loader.get_default_config()
        return self.create_validators_from_config(config)

    def validate_config(self, config: ValidationConfig) -> List[str]:
        """
        Validate configuration for correctness

        Args:
            config: ValidationConfig to validate

        Returns:
            List of validation error messages
        """
        errors = []

        # Check validator configs
        validator_configs = config.get_validator_configs()
        validator_names = set()

        for i, validator_config in enumerate(validator_configs):
            if not isinstance(validator_config, dict):
                errors.append(f"Validator config {i} must be a dictionary")
                continue

            name = validator_config.get('name')
            if not name:
                errors.append(f"Validator config {i} missing required 'name' field")
                continue

            if name in validator_names:
                errors.append(f"Duplicate validator name: {name}")
            validator_names.add(name)

            # Check if validator is registered
            if not self.registry.get_validator_class(name):
                errors.append(f"Unknown validator: {name}")

            # Validate enabled field
            enabled = validator_config.get('enabled', True)
            if not isinstance(enabled, bool):
                errors.append(f"Validator {name}: 'enabled' must be boolean")

        return errors


def create_sample_config_file(output_path: Union[str, Path]):
    """Create a sample configuration file"""
    sample_config = {
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'issue_severities': {
            # Examples: Override specific issue severities
            # 'E2002': 'ignore',    # Ignore reserved IP warnings
            # 'E3008': 'info',      # Downgrade console server type warnings to info logs
            # 'E3001': 'warning',   # Downgrade console conflicts to warnings
            # 'E4004': 'error'      # Upgrade PDU redundancy warnings to errors
        },
        'validators': [
            {
                'name': 'testbed',
                'enabled': True,
                'config': {}
            },
            {
                'name': 'device_info',
                'enabled': True,
                'config': {
                    'invalid_chars': [],
                    'max_length': 255
                }
            },
            {
                'name': 'ip_address',
                'enabled': True,
                'config': {}
            },
            {
                'name': 'vlan',
                'enabled': True,
                'config': {
                    'min_vlan_id': 1,
                    'max_vlan_id': 4096
                }
            },
            {
                'name': 'console',
                'enabled': True,
                'config': {}
            },
            {
                'name': 'pdu',
                'enabled': True,
                'config': {}
            }
        ]
    }

    output_path = Path(output_path)

    with open(output_path, 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False, indent=2)

    print(f"Sample configuration created at: {output_path}")
