"""
Validator factory for creating and managing validators
"""

import logging
from typing import Dict, List, Type, Optional, Any
from abc import ABC, abstractmethod

from .base_validator import BaseValidator


class ValidatorRegistry:
    """Registry for managing available validators"""

    def __init__(self):
        self._validators: Dict[str, Type[BaseValidator]] = {}
        self.logger = logging.getLogger("meta.validator_registry")

    def register(self, name: str, validator_class: Type[BaseValidator]):
        """Register a validator class"""
        if not issubclass(validator_class, BaseValidator):
            raise ValueError(f"Validator {name} must inherit from BaseValidator")

        self._validators[name] = validator_class
        self.logger.debug(f"Registered validator: {name}")

    def unregister(self, name: str):
        """Unregister a validator"""
        if name in self._validators:
            del self._validators[name]
            self.logger.debug(f"Unregistered validator: {name}")

    def get_validator_class(self, name: str) -> Optional[Type[BaseValidator]]:
        """Get validator class by name"""
        return self._validators.get(name)

    def list_validators(self) -> List[str]:
        """List all registered validator names"""
        return list(self._validators.keys())

    def get_validator_info(self, name: str) -> Optional[Dict[str, str]]:
        """Get validator information"""
        validator_class = self._validators.get(name)
        if validator_class:
            # Create temporary instance to get info
            try:
                temp_instance = validator_class()
                return temp_instance.get_info()
            except Exception:
                return {"name": name, "description": "Error getting info", "category": "unknown"}
        return None


class ValidatorFactory(ABC):
    """Abstract factory for creating validators"""

    @abstractmethod
    def create_validator(self, name: str, config: Optional[Dict[str, Any]] = None) -> Optional[BaseValidator]:
        """Create a validator instance"""
        pass

    @abstractmethod
    def create_validators(self, validator_configs: List[Dict[str, Any]]) -> List[BaseValidator]:
        """Create multiple validators from configurations"""
        pass


class DefaultValidatorFactory(ValidatorFactory):
    """Default implementation of validator factory"""

    def __init__(self, registry: ValidatorRegistry):
        self.registry = registry
        self.logger = logging.getLogger("meta.validator_factory")

    def create_validator(self, name: str, config: Optional[Dict[str, Any]] = None) -> Optional[BaseValidator]:
        """
        Create a validator instance by name

        Args:
            name: Validator name
            config: Optional configuration for the validator

        Returns:
            BaseValidator instance or None if not found
        """
        validator_class = self.registry.get_validator_class(name)
        if not validator_class:
            self.logger.error(f"Validator not found: {name}")
            return None

        try:
            # Create validator instance with or without config
            if config:
                # Try to pass config to constructor if supported
                try:
                    validator = validator_class(config=config)
                except TypeError:
                    # Fallback to default constructor
                    validator = validator_class()
                    # Set config as attribute if validator supports it
                    if hasattr(validator, 'config'):
                        validator.config = config
            else:
                validator = validator_class()

            self.logger.debug(f"Created validator: {name}")
            return validator

        except Exception as e:
            self.logger.error(f"Failed to create validator {name}: {str(e)}")
            return None

    def create_validators(self, validator_configs: List[Dict[str, Any]]) -> List[BaseValidator]:
        """
        Create multiple validators from configurations

        Args:
            validator_configs: List of validator configurations
                Each config should have at least 'name' field
                Optional fields: 'enabled', 'config'

        Returns:
            List of validator instances
        """
        validators = []

        for config in validator_configs:
            if not isinstance(config, dict):
                self.logger.warning(f"Invalid validator config format: {config}")
                continue

            name = config.get('name')
            if not name:
                self.logger.warning(f"Validator config missing name: {config}")
                continue

            enabled = config.get('enabled', True)
            if not enabled:
                self.logger.debug(f"Skipping disabled validator: {name}")
                continue

            validator_config = config.get('config', {})
            validator = self.create_validator(name, validator_config)

            if validator:
                validators.append(validator)
            else:
                self.logger.warning(f"Failed to create validator: {name}")

        self.logger.info(f"Created {len(validators)} validators")
        return validators


class ConfigurableValidatorFactory(DefaultValidatorFactory):
    """Factory that supports configuration-driven validator creation"""

    def __init__(self, registry: ValidatorRegistry, default_config: Optional[Dict[str, Any]] = None):
        super().__init__(registry)
        self.default_config = default_config or {}

    def create_validator_from_config(self, validator_config: Dict[str, Any]) -> Optional[BaseValidator]:
        """
        Create validator from comprehensive configuration

        Args:
            validator_config: Configuration dict with:
                - name: validator name (required)
                - enabled: whether to create (default: True)
                - params: constructor parameters
                - config: runtime configuration

        Returns:
            BaseValidator instance or None
        """
        name = validator_config.get('name')
        if not name:
            self.logger.error("Validator config missing required 'name' field")
            return None

        enabled = validator_config.get('enabled', True)
        if not enabled:
            self.logger.debug(f"Skipping disabled validator: {name}")
            return None

        validator_class = self.registry.get_validator_class(name)
        if not validator_class:
            self.logger.error(f"Validator class not found: {name}")
            return None

        try:
            # Set runtime configuration
            runtime_config = validator_config.get('config', {})
            merged_config = {**self.default_config.get('default_config', {}), **runtime_config}

            # Create validator with parameters
            validator = validator_class(merged_config)

            self.logger.debug(f"Created configured validator: {name}")
            return validator

        except Exception as e:
            self.logger.error(f"Failed to create configured validator {name}: {str(e)}")
            return None


def register_validator(name: str):
    """Decorator for automatically registering validators"""
    def decorator(validator_class: Type[BaseValidator]):
        if not hasattr(register_validator, '_registry'):
            register_validator._registry = ValidatorRegistry()

        register_validator._registry.register(name, validator_class)
        return validator_class

    return decorator


def get_default_registry() -> ValidatorRegistry:
    """Get the default validator registry"""
    if not hasattr(register_validator, '_registry'):
        register_validator._registry = ValidatorRegistry()
    return register_validator._registry


def get_default_factory() -> ValidatorFactory:
    """Get the default validator factory"""
    registry = get_default_registry()
    return DefaultValidatorFactory(registry)
