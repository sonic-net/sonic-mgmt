
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
def sanity_check(testbed_devices, request):
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
* check_items: Please refer to below section for more detailed explanation.

### Fine tune `check_items`

We can use keyword argument `check_items` to fine tune the items to be checked in sanity check. At the time of writing, we implemented 2 check items.
* services: Check the status of all critical services.
* interfaces: Check the status of network interfaces.
Please refer to sonic-mgmt/tests/common/plugins/sanity_check/constants::SUPPORTED_CHECK_ITEMS for the latest supported check items.

Value for `check_items` should be a tuple or list of strings. Each item in the tuple or list should be a string. The string can be name of the supported check items with optional prefix `+` or `-`. Unsupported check items will be ignored.

If a supported check item is prefixed with `-`, then this item will not be checked in sanity. For items with prefix `+` or without prefixes, the item should be included in the list of items to be checked in sanity.

With this design, we can extend the sanity check items in the future. By default, only a very basic set of sanity check is performed. For some test scripts that do not need some default sanity check items or need some extra sanity check items, we can use this syntax to tailor the check items that fit best for the current test script.

## Log collecting
If sanity check is to be performed, the script will also run some commands on the DUT to collect some basic information for debugging. Please refer to sonic-mgmt/tests/common/plugins/sanity_check/constants::PRINT_LOGS for the list of logs that will be collected.

## Pytest cmd option `--allow_recover`

The sanity check plugin also supports pytest command line option `--allow_recover`. When this command option presents, sanity check will always try to recover the test bed in case sanity check failed in the first round. The command option has higher priority than the keyword argument value of `allow_recover` for `pytest.mark.sanity_check`. For example:
```
$ pytest -i inventory --host-pattern switch1-t0 --module-path ../ansible/library/ --testbed switch1-t0 --testbed-file testbed.csv --log-cli-level info test_something.py --allow_recover
```

## Why check networking uptime?

The sanity check may be performed right after the DUT is rebooted or config reload is performed. In this case, services and interfaces may not be ready yet and sanity check will fail unnecessarily.

If we reboot the DUT or perform a config reload on it, the networking service is always restarted. Before checking services or interfaces status, we can check the networking service restart time. If it was restarted not long ago, we use a retry logic to check services and interfaces status. Otherwise, we just check and move on to save time.

## Example

```
import pytest
pytestmark = [pytest.mark.sanity_check(allow_recover=True, recover_method="reboot", post_check=True, check_items=("-interfaces",))]
```

In the above example, both pre-test and post-test sanity check will be performed. Status of the interfaces will not be checked. In case of failure in the first round of sanity check, the sanity check plugin will try to recover the DUT by rebooting it.

References:
* [Working with custom markers](https://docs.pytest.org/en/latest/example/markers.html)
* [Pytest request](https://docs.pytest.org/en/latest/reference.html#request)
* [Pytest node](https://docs.pytest.org/en/latest/reference.html#node)
* [Pytest mark](https://docs.pytest.org/en/latest/reference.html#mark)
* [pytestmark](https://docs.pytest.org/en/latest/reference.html#pytestmark)
