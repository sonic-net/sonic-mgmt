#!/usr/bin/env python3
"""
Unit Tests for ExecutorRegistry

IMPORTANT: These tests use @pytest.mark.order(900+) to run LAST in execution order.
This test file clears registry entries during cleanup, which could affect other
tests that depend on mock executors being registered. Running it last ensures
all other tests complete before registry cleanup occurs.

Requires: pytest-order plugin (pip install pytest-order)

Tests all public APIs:
- register() decorator
- create()
- _ensure_loaded()
- Convention over configuration
- Error handling
"""

import sys
import os
import pytest

# Add probe directory to path
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)


@pytest.mark.order(900)
def test_register_decorator_physical():
    """
    UT: Test @register decorator for physical environment.

    Verifies:
    - Decorator correctly registers class
    - Physical key format: (type, 'physical')
    - Returned class is unchanged
    """
    from executor_registry import ExecutorRegistry

    print("\n=== UT: register() decorator - physical ===")

    # Create a test class with decorator
    @ExecutorRegistry.register(probe_type='test_physical', executor_env='physical')
    class TestPhysicalExecutor:
        def __init__(self, name):
            self.name = name

    # Verify registration
    key = ('test_physical', 'physical')
    assert key in ExecutorRegistry._registry, f"Key {key} should be in registry"
    assert ExecutorRegistry._registry[key] == TestPhysicalExecutor

    # Verify decorator doesn't modify class
    assert TestPhysicalExecutor.__name__ == 'TestPhysicalExecutor'

    # Verify we can instantiate
    instance = TestPhysicalExecutor(name='test')
    assert instance.name == 'test'

    print("[OK] Physical executor registered correctly")

    # Cleanup
    del ExecutorRegistry._registry[key]


@pytest.mark.order(901)
def test_register_decorator_mock_variants():
    """
    UT: Test @register decorator for mock with different targets.

    Verifies:
    - Mock normal: (type, 'sim', None)
    - Mock variants: (type, 'sim', 'noisy'), etc.
    - Multiple registrations don't interfere
    """
    from executor_registry import ExecutorRegistry

    print("\n=== UT: register() decorator - mock variants ===")

    # Register normal mock
    @ExecutorRegistry.register(probe_type='test_sim', executor_env='sim')
    class TestSimExecutor:
        pass

    # Register noisy mock
    @ExecutorRegistry.register(probe_type='test_sim', executor_env='sim', scenario='noisy')
    class TestSimExecutorNoisy:
        pass

    # Register wrong_config mock
    @ExecutorRegistry.register(probe_type='test_sim', executor_env='sim', scenario='wrong_config')
    class TestSimExecutorWrongConfig:
        pass

    # Verify all three are registered
    keys = [
        ('test_sim', 'sim', None),
        ('test_sim', 'sim', 'noisy'),
        ('test_sim', 'sim', 'wrong_config'),
    ]

    for key in keys:
        assert key in ExecutorRegistry._registry, f"Key {key} should be in registry"

    assert ExecutorRegistry._registry[keys[0]] == TestSimExecutor
    assert ExecutorRegistry._registry[keys[1]] == TestSimExecutorNoisy
    assert ExecutorRegistry._registry[keys[2]] == TestSimExecutorWrongConfig

    print("[OK] All mock variants registered correctly")

    # Cleanup
    for key in keys:
        del ExecutorRegistry._registry[key]


@pytest.mark.order(902)
def test_create_invalid_env():
    """
    UT: Test create() with invalid env parameter.

    Verifies:
    - Raises ValueError for unknown env
    - Error message is clear
    """
    from executor_registry import ExecutorRegistry

    print("\n=== UT: create() - invalid env ===")

    with pytest.raises(ValueError, match="Unknown executor_env"):
        ExecutorRegistry.create(probe_type='test_type', executor_env='invalid_env', observer=None, name='test')

    print("[OK] Invalid env raises ValueError")


@pytest.mark.order(903)
def test_create_error_unregistered_executor():
    """
    UT: Test create() error handling for unregistered scenario.

    Verifies:
    - Raises KeyError with helpful message
    - Lists available executors
    """
    from executor_registry import ExecutorRegistry

    print("\n=== UT: create() - unregistered executor ===")

    # Clear pfc module if loaded
    if 'sim_pfc_xoff_probing_executor' in sys.modules:
        keys_to_remove = [k for k in ExecutorRegistry._registry.keys()
                          if k[0] == 'pfc_xoff']
        for k in keys_to_remove:
            del ExecutorRegistry._registry[k]
        ExecutorRegistry._loaded_modules.discard('sim_pfc_xoff_probing_executor')

    # Force load the module first
    import importlib
    importlib.import_module('sim_pfc_xoff_probing_executor')
    ExecutorRegistry._loaded_modules.add('sim_pfc_xoff_probing_executor')

    # Now try to create with non-existent scenario
    # This should raise KeyError because the variant doesn't exist
    with pytest.raises(KeyError, match="not registered"):
        ExecutorRegistry.create('pfc_xoff', 'sim',
                                scenario='nonexistent_variant',
                                observer=None, name='test')

    print("[OK] Unregistered scenario raises KeyError")


@pytest.mark.order(904)
def test_create_physical_env():
    """
    UT: Test create() with physical environment.

    Verifies:
    - Physical env uses key format: (type, 'physical')
    - Successfully creates physical executor
    - Covers line 214 in executor_registry.py
    """
    from executor_registry import ExecutorRegistry

    print("\n=== UT: create() - physical environment ===")

    # Register a physical executor without actual module
    # (We'll register the module path to avoid import attempt)
    @ExecutorRegistry.register(probe_type='test_physical_exec', executor_env='physical')
    class TestPhysicalExecutor:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    # Register module path to mark it as "loaded" (skip import)
    ExecutorRegistry._loaded_modules.add('test_physical_exec_probing_executor')

    # Create physical executor (should use key = (type, 'physical'))
    executor = ExecutorRegistry.create(
        probe_type='test_physical_exec',
        executor_env='physical',
        name='test',
        value=123
    )

    assert executor is not None
    assert isinstance(executor, TestPhysicalExecutor)
    assert executor.kwargs['name'] == 'test'
    assert executor.kwargs['value'] == 123

    print("[OK] Physical environment create() works correctly")
    print("[OK] Line 214 covered: key = (executor_type, 'physical')")

    # Cleanup
    key = ('test_physical_exec', 'physical')
    if key in ExecutorRegistry._registry:
        del ExecutorRegistry._registry[key]
    ExecutorRegistry._loaded_modules.discard('test_physical_exec_probing_executor')


@pytest.mark.order(905)
def test_create_import_error():
    """
    UT: Test create() with invalid module path (ImportError).

    Verifies:
    - ImportError raised when module cannot be imported
    - Error message includes module path and original error
    """
    from executor_registry import ExecutorRegistry

    print("\n=== UT: create() - ImportError on invalid module ===")

    # Try to create an executor whose module doesn't exist
    # Convention will try to import: sim_nonexistent_type_executor
    # This module doesn't exist, so we expect ImportError
    with pytest.raises(ImportError, match="Failed to import executor module"):
        ExecutorRegistry.create(
            probe_type='nonexistent_type',
            executor_env='sim',
            observer=None,
            name='test'
        )

    print("[OK] ImportError raised with proper message")


@pytest.mark.order(906)
def test_create_with_real_mock_executor():
    """
    UT: Test create() with actual mock executor.

    Verifies:
    - Successfully creates executor instance
    - Passes kwargs correctly
    - Returns correct type
    """
    from executor_registry import ExecutorRegistry
    import importlib

    print("\n=== UT: create() - with real executor ===")

    # Ensure module is loaded and decorators are registered
    if 'sim_pfc_xoff_probing_executor' in sys.modules:
        # Module was already imported, reload to ensure decorators execute
        importlib.reload(sys.modules['sim_pfc_xoff_probing_executor'])
    else:
        importlib.import_module('sim_pfc_xoff_probing_executor')

    # Mock observer
    class MockObserver:
        def trace(self, msg): pass
        def console(self, msg): pass

    # Create normal executor
    executor = ExecutorRegistry.create(
        probe_type='pfc_xoff',
        executor_env='sim',
        observer=MockObserver(),
        name='unittest',
        actual_threshold=123
    )

    assert executor is not None
    assert type(executor).__name__ == 'SimPfcXoffProbingExecutor'
    assert executor.name == 'unittest'
    assert executor._actual_threshold == 123

    # Create noisy executor
    executor_noisy = ExecutorRegistry.create(
        probe_type='pfc_xoff',
        executor_env='sim',
        scenario='noisy',
        observer=MockObserver(),
        name='unittest_noisy',
        actual_threshold=456,
        noise_level=20
    )

    assert type(executor_noisy).__name__ == 'SimPfcXoffProbingExecutorNoisy'
    assert executor_noisy.noise_level == 20

    print("[OK] create() works with real executors")


@pytest.mark.order(907)
def test_module_caching():
    """
    UT: Test module loading is cached (loaded only once).

    Verifies:
    - First create() loads module
    - Subsequent creates use cache
    - _loaded_modules tracks loaded modules
    """
    from executor_registry import ExecutorRegistry
    import importlib

    print("\n=== UT: Module caching ===")

    # Ensure ingress_drop module is available
    if 'sim_ingress_drop_probing_executor' in sys.modules:
        # Module already imported by previous tests, reload to restore registry
        importlib.reload(sys.modules['sim_ingress_drop_probing_executor'])
        # Clear loaded modules tracking to test caching from fresh state
        ExecutorRegistry._loaded_modules.discard('sim_ingress_drop_probing_executor')

    class MockObserver:
        def trace(self, msg): pass
        def console(self, msg): pass

    # First create - should load module
    assert 'sim_ingress_drop_probing_executor' not in ExecutorRegistry._loaded_modules

    executor1 = ExecutorRegistry.create(
        probe_type='ingress_drop',
        executor_env='sim',
        observer=MockObserver(),
        name='test1',
        actual_threshold=100
    )

    assert 'sim_ingress_drop_probing_executor' in ExecutorRegistry._loaded_modules

    # Second create - should use cache (count loaded modules)
    loaded_count_before = len(ExecutorRegistry._loaded_modules)

    executor2 = ExecutorRegistry.create(
        'ingress_drop', 'sim', scenario='noisy',
        observer=MockObserver(),
        name='test2',
        actual_threshold=200
    )

    loaded_count_after = len(ExecutorRegistry._loaded_modules)

    # Module count shouldn't increase (already cached)
    assert loaded_count_after == loaded_count_before

    # But both executors should work (check() returns (success, detected))
    assert executor1.check(None, None, 150)[1] is True
    assert executor2.check(None, None, 150)[1] is False  # noise might affect

    print("[OK] Module caching works correctly")


@pytest.mark.order(908)
def test_lazy_import_execution_order():
    """
    UT: Verify lazy import execution order and decorator timing.

    Verifies that ExecutorRegistry performs lazy import correctly:
    - Modules are NOT imported until create() is called
    - Decorators execute DURING import
    - Registry is populated BY decorators
    """
    from executor_registry import ExecutorRegistry

    # Clear module to ensure fresh import
    if 'sim_pfc_xoff_probing_executor' in sys.modules:
        del sys.modules['sim_pfc_xoff_probing_executor']
        # Clear registry entries for this module
        keys_to_remove = [k for k in ExecutorRegistry._registry.keys()
                          if k[0] == 'pfc_xoff']
        for k in keys_to_remove:
            del ExecutorRegistry._registry[k]
        ExecutorRegistry._loaded_modules.discard('sim_pfc_xoff_probing_executor')

    # Mock observer
    class MockObserver:
        def trace(self, msg): pass
        def console(self, msg): pass

    print("\n=== UT: Lazy Import Execution Order ===")

    # Step 1: Verify registry empty for pfc_xoff
    print("1. Initial state (before create):")
    pfc_entries = [k for k in ExecutorRegistry._registry.keys()
                   if k[0] == 'pfc_xoff']
    print(f"   PFC executors in registry: {len(pfc_entries)}")
    print(f"   sim_pfc_xoff_probing_executor loaded: "
          f"{'sim_pfc_xoff_probing_executor' in ExecutorRegistry._loaded_modules}")

    assert len(pfc_entries) == 0, "No PFC executors should be registered initially"
    assert 'sim_pfc_xoff_probing_executor' not in ExecutorRegistry._loaded_modules

    # Step 2: Call create()
    print("2. Calling create('pfc_xoff', 'sim')...")

    executor = ExecutorRegistry.create('pfc_xoff', 'sim',
                                       observer=MockObserver(),
                                       name='test',
                                       actual_threshold=500)

    # Step 3: Verify state after create
    print("3. After create():")
    pfc_entries_after = [k for k in ExecutorRegistry._registry.keys()
                         if k[0] == 'pfc_xoff']
    print(f"   PFC executors in registry: {len(pfc_entries_after)}")
    print(f"   sim_pfc_xoff_probing_executor loaded: "
          f"{'sim_pfc_xoff_probing_executor' in ExecutorRegistry._loaded_modules}")
    print(f"   Executor type: {type(executor).__name__}")

    # Step 4: Verify all expected variants registered
    print("4. Registered variants:")
    for key in sorted(pfc_entries_after, key=str):
        print(f"   {key}")

    # Assertions
    assert len(pfc_entries_after) == 4, \
        f"Should have 4 PFC executors registered, got {len(pfc_entries_after)}"

    assert 'sim_pfc_xoff_probing_executor' in ExecutorRegistry._loaded_modules, \
        "Module should be loaded after create()"

    assert type(executor).__name__ == 'SimPfcXoffProbingExecutor', \
        f"Should get normal executor, got {type(executor).__name__}"

    # Verify all expected keys exist
    expected_keys = [
        ('pfc_xoff', 'sim', None),
        ('pfc_xoff', 'sim', 'noisy'),
        ('pfc_xoff', 'sim', 'wrong_config'),
        ('pfc_xoff', 'sim', 'intermittent'),
    ]
    for key in expected_keys:
        assert key in ExecutorRegistry._registry, f"Missing key: {key}"

    print("[OK] All assertions passed!")
    print("[OK] Lazy import verified: module loaded only when create() called")
    print("[OK] Decorator timing verified: 4 executors registered after import")
    print("[OK] Execution order verified: create -> import -> decorators -> instantiate")


if __name__ == '__main__':
    # Run all tests
    test_register_decorator_physical()
    test_register_decorator_mock_variants()
    test_create_invalid_env()
    test_create_error_unregistered_executor()
    test_create_physical_env()
    test_create_import_error()
    test_create_with_real_mock_executor()
    test_module_caching()
    test_lazy_import_execution_order()

    print("\n" + "="*70)
    print("[PASS] All ExecutorRegistry unit tests passed!")
    print("="*70)
