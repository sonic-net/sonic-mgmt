
# Sanity Check for pytest scripts

## Motivation

If we run a test based on ansible playbook, a sanity check is always performed by sonic-mgmt/ansible/roles/test/tasks/base_sanity.yml. This plugin is to be aligned with the base sanity check of ansible playbook tests.

## Fixture `sanity_check` in plugin `sanity_check`.

Sanity check for pytest is implemented as an 'autouse' fixture in the `sanity_check` plugin. The plugin is required in sonic-mgmt/tests/conftest.py. This means that if we run pytest scripts under the sonic-mgmt/tests folder, sanity check will be automatically performed.

sonic-mgmt/tests/conftest.py:
```
pytest_plugins = [
    'common.plugins.sanity_check',
    ...
]
```

sonic-mgmt/tests/common/plugins/sanity_check:
```
@pytest.fixture(scope="module", autouse=True)
def sanity_check(localhost, duthosts, request, fanouthosts, tbinfo):
    ...
```

## Override default sanity check behaviors

The default sanity check behaviors can be overridden in test scripts using pytest marks. The basic syntax example is like below:

sonic-mgmt/tests/test_something.py:
```
import pytest
...

pytestmark = [pytest.mark.sanity_check(kw_arg=kw_value)]
...
```

We can specify multiple keyword arguments to override the default sanity check behavior. Currently supported keyword arguments:

* skip_sanity: Boolean, specify whether the whole sanity check should be skipped. Default: False.
* allow_recover: Boolean, specify whether recovery should be performed in case of pre-test sanity check failed. Default: False.
* recover_method: String, specify the method to be used for recovery. Default: "config_reload". Supported values: refer to sonic-mgmt/tests/common/plugins/sanity_check/constants.py::RECOVER_METHODS.
* post_check: Boolean, specify whether post-test sanity check should be performed. Default: False.
* check_items: Please refer to below section for details.
* post_check_items: Please refer to below section for details.

### Fine tune `check_items`

We can use keyword argument `check_items` to fine tune the items to be checked in sanity check. All the function starts with 'check_' in `tests/common/plugins/sanity_check/checks.py` is a check item. Item name is the function name without the `check_` prefix. Currently supported check items:
* services: Check the status of all critical services.
* interfaces: Check the status of network interfaces.
* bgp: Check BGP status.
* dbmemory: Check database memory.
* monit: Check monit status.
* processes: Check status of critical processes.
* mux_simulator: Check status of mux simulator.
*
Please refer to `sonic-mgmt/tests/common/plugins/sanity_check/checks.py` for the latest supported check items.

Value for `check_items` should be a tuple or list of strings. Each item in the tuple or list must be a string. The string can be name of the supported check items with optional prefix `+` or `-` or `_`. Unsupported check items will be ignored.

If a supported check item is prefixed with `-` or `_`, then this item will not be checked in sanity. For items with prefix `+` or without prefixes, the item should be included in the list of items to be checked in sanity.

With this design, we can extend the sanity check items in the future. By default, only a very basic set of sanity check is performed. For some test scripts that do not need some default sanity check items or need some extra sanity check items, we can use this syntax to fine tune the check items that fit best for the current test script.

User can change check item list by passing parameter from command line --check_items="add remove string". Example: --check_items="_services,+bgp" means do not check services, but add bgp to the check list. This parameter is not an absolute list, it is addition or subtraction from the existing list. On command line "-" has special meaning. So, we need to prefix "_" to skip a check item.

### Fine tune `post_check_items`

By default, the list of post check items is the same as pre test. Sometimes, we may need different post test checks. In this case, we can use the `post_check_items` marker argument or `--post_check_items` command line option to fine tune post check items just the same way as pre test.

Please be noted that the post check items list is always based on the final pre test check items (updated by test marker args and command line options).

## Log collecting
If sanity check is to be performed, the script will also run some commands on the DUT to collect some basic information for debugging. Please refer to sonic-mgmt/tests/common/plugins/sanity_check/constants::PRINT_LOGS for the list of logs that will be collected.

## Pytest cmd option `--skip_sanity`

Besides specifying keywoard argument `skip_sanity=True` for `pytest.mark.sanity_check`, we can skip sanity check for test scripts. However, modifying test script is still required. With the pytest command line option `--skip_sanity`, we can skip sanity check on the fly for test scripts. For example:
```
$ pytest -i inventory --host-pattern switch1-t0 --module-path ../ansible/library/ --testbed switch1-t0 --testbed-file testbed.csv --log-cli-level info test_something.py --skip_sanity
```

## Pytest cmd option `--allow_recover`

The sanity check plugin also supports pytest command line option `--allow_recover`. When this command option presents, sanity check will always try to recover the test bed in case sanity check failed in the first round. The command option has higher priority than the keyword argument value of `allow_recover` for `pytest.mark.sanity_check`. For example:
```
$ pytest -i inventory --host-pattern switch1-t0 --module-path ../ansible/library/ --testbed switch1-t0 --testbed-file testbed.csv --log-cli-level info test_something.py --allow_recover
```

## Check item
The check items are defined in the `checks.py` module. In the original design, check item is defined as an ordinary function. All the dependent fixtures must be specified in the argument list of `sanity_check`. Then objects of the fixtures are passed to the check functions as arguments. However, this design has a limitation. Not all the sanity check dependent fixtures are supported on all topologies. On some topologies, sanity check may fail with getting those fixtures.
To resolve that issue, we have changed the design. Now the check items must be defined as fixtures. Then the check fixtures can be dynamically attached to test cases during run time. In the sanity check plugin, we can check the current testbed type or other conditions to decide whether or not to load certain check fixtures.

### Check item implementation details
Each check fixture must use the factory design pattern to return a check function. Then we can delay execution of the various sanity checks after the sanity check items have been dynamically adjusted.

Check fixture must be named with pattern `check_<item name>`. When a new check fixture is defined, its name must be added to the `__all__` list of the `checks.py` module.

## Why check networking uptime?

The sanity check may be performed right after the DUT is rebooted or config reload is performed. In this case, services and interfaces may not be ready yet and sanity check will fail unnecessarily.

If we reboot the DUT or perform a config reload on it, the networking service is always restarted. Before checking services or interfaces status, we can check the networking service restart time. If it was restarted not long ago, we use a retry logic to check services and interfaces status. Otherwise, we just check and move on to save time.

## Example

file: test_feature1.py
```
import pytest
pytestmark = [pytest.mark.sanity_check(
    allow_recover=True,
    recover_method="reboot",
    post_check=True,
    check_items=("-interfaces",))]
```
In the above example, both pre-test and post-test sanity check will be performed. Status of the interfaces will not be checked. In case of failure in the first round of sanity check, the sanity check plugin will try to recover the DUT by rebooting it.


file: test_feature2.py
```
import pytest
pytestmark = [pytest.mark.sanity_check(
    allow_recover=False,
    recover_method="adaptive",
    post_check=True,
    check_items=["-interfaces",],
    post_check_items=["-services",])]
```
In the above example, both pre-test and post-test sanity check will be performed. Status of the interfaces will not be checked in pre and post test. Status of services will not be checked in post test. In case of failure in the first round of sanity check, the sanity check plugin will try to recover the DUT using method 'adaptive'.

The check options can be overridden by command line options:
* --skip_sanity
* --allow_recover
* --check_items
* --post_check_items

References:
* [Working with custom markers](https://docs.pytest.org/en/latest/example/markers.html)
* [Pytest request](https://docs.pytest.org/en/latest/reference.html#request)
* [Pytest node](https://docs.pytest.org/en/latest/reference.html#node)
* [Pytest mark](https://docs.pytest.org/en/latest/reference.html#mark)
* [pytestmark](https://docs.pytest.org/en/latest/reference.html#pytestmark)
