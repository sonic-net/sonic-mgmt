"""
SONiC Buffer Threshold Probing Module

This module contains probing test cases for MMU threshold detection,
using the Template Method Pattern for clean architecture.

Architecture:
- ProbingBase: Base class with template method runTest()
  - setUp(): PTF init + common parse_param
  - runTest(): Template - calls setup_traffic() + probe()
  - tearDown(): PTF cleanup

Probing Test Cases (1 src -> N dst pattern):
- PfcXoffProbing: PFC Xoff threshold probing
- IngressDropProbing: Ingress Drop threshold probing

Probing Test Cases (N src -> 1 dst pattern):
- HeadroomPoolProbing: Headroom Pool Size probing (multi-PG iteration)

Supporting Components:
- Algorithm: UpperBound, LowerBound, ThresholdRange, ThresholdPoint
- Executor: Lazy loaded via ExecutorRegistry
- Observer: ProbingObserver with ObserverConfig
- BufferOccupancyController: TX state and buffer management
- ExecutorRegistry: Factory for environment-specific executors (physical/mock)

Usage in test_qos_sai.py:
    # PFC Xoff probing
    self.runPtfTest(ptfhost, testCase="pfc_xoff_probing.PfcXoffProbing",
                    testParams=testParams, test_subdir='probe')

    # Ingress Drop probing
    self.runPtfTest(ptfhost, testCase="ingress_drop_probing.IngressDropProbing",
                    testParams=testParams, test_subdir='probe')

    # Headroom Pool probing
    self.runPtfTest(ptfhost, testCase="headroom_pool_probing.HeadroomPoolProbing",
                    testParams=testParams, test_subdir='probe')

Extensibility:
    # For UT/mock, register mock executors:
    from executor_registry import ExecutorRegistry
    ExecutorRegistry.register('pfc_xoff', 'mock', 'MockPfcXoffExecutor', 'mock.MockPfcXoffExecutor')
"""

__version__ = "0.1.0"

# No module-level imports - PTF loads test classes directly
