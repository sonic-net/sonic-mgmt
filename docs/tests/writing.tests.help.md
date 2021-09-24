# Writing for SONiC-mgmt Pytest

- [About Pytest](#about-pytest)
- [Writing a Test](#writing-a-test)
- [Failing/Passing a Test](#failingpassing-a-test)
- [Setup and Teardown](#setup-and-teardown)

## About Pytest

Tests are written for the sonic-mgmt repository using the [pytest](https://docs.pytest.org/en/6.2.x/) library. Most of the process is self explanatory, but reading through the documentation may help for anything that isn't clear. It may be useful read about pytest [fixtures](https://docs.pytest.org/en/latest/how-to/fixtures.html) prior to contributing as they can be useful in creating more readible and consice tests.


## Writing a Test

```
def test_http_copy(duthosts, rand_one_dut_hostname, ptfhost, localhost):
    ...
```
If a class is being used, the class name must begin with `Test` and any test function it contains should start with `test` as above. Pytest will only run the methods that start with that keyword unless otherwise specified by a pytest fixture.

```
class TestHttpCopy(object):
    def __init__:
        ...
    
    def test_http_copy(duthosts, rand_one_dut_hostname, ptfhost, localhost):
        ...
```

## Failing/Passing a Test 
A test will pass so long as an exception is no thrown and a fail statement is not reached. The prefered way to fail a test is using the `pytest_assert`. If the `condition` parameter is `False`, the test will fail and the error message will be displayed.

```
pytest_assert(condition, error_message)
```

If for whatever reason, a test needs to be failed without checking for a condition, `pytest.fail` can be used.

```
pytest.fail(error_message)
```

## Setup and Teardown
A setup/teardown method using a pytest fixture can be useful to separate the setup process and the cleanup process from the test itself. This method will run the setup process before your test starts and will run the cleanup after your test finishes. Crucially, pytest will run the cleanup even if the test fails. In order for this process to run, the name of the setup/teardown method must be included as an argument in you test.

The setup portion is separated from the teardown portion by a `yield`. This `yield` can also provide information as seen below.

```
@pytest.fixture
def setup_teardown():
    # Do setup stuff here

    yield data1, data2, data3

    # Do teardown stuff here

def test_some_feature(setup_teardown):
    data1, data2, data3 = setup_teardown
```