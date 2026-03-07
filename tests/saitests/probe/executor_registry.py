#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ExecutorRegistry - Executor Factory with Decorator-based Self-Registration

Purpose:
- Register executor implementations using @register_executor decorator
- Lazy import to avoid importing unused dependencies
- Support physical/sim environments

Usage in Probe classes:
    # In create_executor():
    return ExecutorRegistry.create('pfc_xoff', self.PROBING_ENV,
        ptftest=self, observer=observer, verbose=True, name=name
    )

Registration (in each executor module):
    @ExecutorRegistry.register('pfc_xoff', 'physical')
    class PfcXoffProbingExecutor:
        ...

    @ExecutorRegistry.register('pfc_xoff', 'sim')
    class SimPfcXoffProbingExecutor:
        ...
"""

from typing import Dict, Tuple, Any, Type, Callable


class ExecutorRegistry:
    """
    Singleton registry for executor implementations.

    Design Goals:
    1. Decouple Probe classes from specific executor imports
    2. Decorator-based self-registration - executors register themselves
    3. Lazy import - only load modules when needed
    4. Easy to add new environments (UT, sim) without changing Probe code
    5. Support scenario parameter for different sim scenarios

    Registry Key Format:
    - Physical: (executor_type, 'physical')
    - Sim: (executor_type, 'sim', scenario)
      where scenario can be None (normal), 'noisy', 'wrong_config', etc.

    Public API:
    - register(): Decorator for executor self-registration
    - create(): Create executor instance with lazy import
    """

    # Registry: {key: executor_class}
    # Key formats:
    #   Physical: (probe_type, 'physical')
    #   Sim: (probe_type, 'sim', scenario)
    # probe_type: 'pfc_xoff', 'ingress_drop'
    # executor_env: 'physical', 'sim'
    # scenario: None (normal), 'noisy', 'wrong_config', 'intermittent'
    _registry: Dict[Tuple, Type] = {}

    # Track which modules have been loaded
    _loaded_modules: set = set()

    @classmethod
    def clear_registry(cls):
        """
        Clear all registered executors and loaded modules.

        Used for test isolation to ensure tests don't share state.
        Should be called before each test in conftest.py fixture.
        """
        cls._registry.clear()
        cls._loaded_modules.clear()

    @classmethod
    def register(cls, probe_type: str, executor_env: str, scenario: str = None) -> Callable[[Type], Type]:
        """
        Decorator for executor self-registration.

        Usage:
            @ExecutorRegistry.register('pfc_xoff', 'physical')
            class PfcXoffProbingExecutor:
                ...

            @ExecutorRegistry.register('ingress_drop', 'sim')
            class SimIngressDropProbingExecutor:
                ...

            @ExecutorRegistry.register('ingress_drop', 'sim', 'noisy')
            class SimIngressDropProbingExecutorNoisy:
                ...

        Args:
            probe_type: 'pfc_xoff' or 'ingress_drop'
            executor_env: 'physical' or 'sim'
            scenario: Sim test scenario (only for executor_env='sim')
                      None - normal sim
                      'noisy' - hardware noise simulation
                      'wrong_config' - wrong threshold configuration
                      'intermittent' - intermittent failure

        Returns:
            Decorator function
        """
        def decorator(executor_class: Type) -> Type:
            # Build registry key
            if executor_env == 'physical':
                key = (probe_type, 'physical')
            else:  # sim
                key = (probe_type, 'sim', scenario)

            cls._registry[key] = executor_class
            return executor_class
        return decorator

    @classmethod
    def _ensure_loaded(cls, probe_type: str, executor_env: str):
        """
        Ensure the executor module is loaded (lazy import).

        Module naming convention:
        - Physical: {probe_type}_probing_executor
        - Sim: sim_{probe_type}_probing_executor

        When a module with @register() decorator is imported,
        the decorator automatically registers the class.
        """
        # Convention-based module path
        if executor_env == 'physical':
            module_path = f"{probe_type}_probing_executor"
        elif executor_env == 'sim':
            module_path = f"sim_{probe_type}_probing_executor"
        else:
            raise ValueError(f"Unknown executor_env: {executor_env}")

        # Check if module already loaded
        if module_path not in cls._loaded_modules:
            import importlib
            try:
                importlib.import_module(module_path)
                cls._loaded_modules.add(module_path)
            except ImportError as e:
                raise ImportError(
                    f"Failed to import executor module {module_path}: {e}"
                )

    @classmethod
    def create(cls, probe_type: str, executor_env: str, scenario: str = None, **kwargs) -> Any:
        """
        Create executor instance with lazy import.

        This is the main API for Probe classes.

        Args:
            probe_type: 'pfc_xoff' or 'ingress_drop'
            env: 'physical' or 'sim'
            scenario: Sim test scenario (only for env='sim')
                      None - normal sim
                      'noisy' - hardware noise simulation
                      'wrong_config' - wrong threshold configuration
                      'intermittent' - intermittent failure
            **kwargs: Arguments passed to executor constructor

        Returns:
            Executor instance

        Example:
            # Physical
            exec = ExecutorRegistry.create('ingress_drop', 'physical', ptftest=self, ...)

            # Sim - normal
            exec = ExecutorRegistry.create('ingress_drop', 'sim', ptftest=self, ...)

            # Sim - noisy
            exec = ExecutorRegistry.create('ingress_drop', 'sim', scenario='noisy',
                                          noise_level=10, ptftest=self, ...)

        Raises:
            KeyError: If executor not registered for given type/env/scenario
            ValueError: If executor_env is invalid
            ImportError: If module cannot be imported
        """
        # Ensure module is loaded (triggers @register() decorator)
        cls._ensure_loaded(probe_type, executor_env)

        # Build lookup key
        if executor_env == 'physical':
            key = (probe_type, 'physical')
        else:  # sim
            key = (probe_type, 'sim', scenario)

        if key not in cls._registry:
            available = [k for k in cls._registry.keys() if k[0] == probe_type]
            raise KeyError(
                f"Executor '{probe_type}' not registered for executor_env '{executor_env}' "
                f"with scenario='{scenario}'. Available: {available}"
            )

        executor_class = cls._registry[key]
        return executor_class(**kwargs)


# =============================================================================
# Module Naming Convention
# =============================================================================
#
# Convention over Configuration:
# - Physical: {probe_type}_probing_executor
#   Example: pfc_xoff -> pfc_xoff_probing_executor.py
# - Sim: sim_{probe_type}_probing_executor
#   Example: pfc_xoff -> sim_pfc_xoff_probing_executor.py
#
# To add a new executor:
# 1. Create module following the naming convention
# 2. Use @ExecutorRegistry.register() decorator in the module
# 3. Done!
# =============================================================================
