# Unit Tests for tests/common2

This directory contains unit tests for modules in the `tests/common2` directory.

## Running Unit Tests

### Run all unit tests
```bash
# From the repository root
python3 -m pytest tests/common2/unit_tests/ -m unit_test -v

# Or from tests/common2 directory
cd tests/common2
python3 -m pytest unit_tests/ -m unit_test -v
```

### Run specific test file
```bash
python3 -m pytest tests/common2/unit_tests/test_bgp_route_helper.py -m unit_test -v
```

### Run specific test class
```bash
python3 -m pytest tests/common2/unit_tests/test_bgp_route_helper.py::TestBGPRouteController -m unit_test -v
```

### Run specific test method
```bash
python3 -m pytest tests/common2/unit_tests/test_bgp_route_helper.py::TestBGPRouteController::test_announce_route_basic -m unit_test -v
```

### Run unit tests with coverage
```bash
python3 -m pytest tests/common2/unit_tests/ -m unit_test --cov=bgp_route_control --cov-report=html
```

## Custom Markers

- `unit_test`: Marks tests as unit tests. Use `-m unit_test` to run only unit tests or `-m "not unit_test"` to exclude them.

## Test Structure

### TestBGPRouteController
Tests for the main `BGPRouteController` class:
- Basic route announcement and withdrawal
- Route operations with communities and local preferences
- Bulk route operations
- Error handling (HTTP errors, connection errors, timeouts)
- Input validation

### TestConvenienceFunctions
Tests for backward compatibility convenience functions:
- `announce_route()` and `withdraw_route()`
- `announce_route_with_community()` and `withdraw_route_with_community()`
- `install_route_from_exabgp()`
- `update_routes()`

### TestLogging
Tests for logging functionality:
- Verification that operations are properly logged
- Different log levels (info, debug, warning)

### TestEdgeCases
Tests for edge cases and boundary conditions:
- IPv6 addresses
- Large route lists
- Special characters in communities
- Boundary values for local preferences
- High port numbers

## Dependencies

The unit tests require:
- `pytest`
- `unittest.mock` (built-in)
- `requests` (for exception testing)

## Mocking Strategy

The tests use `unittest.mock` to:
- Mock `requests.post` to avoid actual HTTP calls
- Mock the logger to verify logging behavior
- Test error conditions by mocking exceptions

All tests are isolated and do not make real network calls.
