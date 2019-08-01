#### Loganalyzer API usage example

Below is described possibility of loganalyzer fixture/module usage.

##### Loganalyzer fixture
In the root conftest there is implemented "loganalyzer" pytest fixture, which starts automatically for all test cases.
Fixture main flow:
- loganalyzer will add start marker before test case start
- loganalyzer will add stop marker after test case finish
- if loganalyzer analysis is not disabled for current test case it will analyze DUT syslog and display results.
If loganalyzer find specified messages which corresponds to defined regular expressions, it will display found messages and pytest will generate 'error'.

##### To skip loganalyzer analysis for:
- all test cases - use pytest command line option ```--disable_loganalyzer```
- specific test case: mark test case with ```@disable_loganalyzer``` decorator. Example is shown below.

```python
import pytest
import time
import os
import sys
import logging

from ansible_host import ansible_host
sys.path.append(os.path.join(os.path.split(__file__)[0], "loganalyzer"))
from loganalyzer.loganalyzer import LogAnalyzer
from loganalyzer.loganalyzer import COMMON_MATCH
from lib.helpers import disable_loganalyzer


def adder(x, y=10, z=0):
    """
    Syslog on the DUT will be verified during this callback execution. Expected that this callback will do some stuff on the DUT side.
    """
    return x + y

def test_loganalyzer_functionality(localhost, ansible_adhoc, testbed):
    """
    @summary: Example of loganalyzer usage
    """
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)

    log = LogAnalyzer(ansible_host=ans_host, marker_prefix="test_loganalyzer")
    # Read existed common regular expressions located with legacy loganalyzer module
    log.load_common_config()
    # Add start marker to the DUT syslog
    marker = log.init()
    # Emulate that new error messages appears in the syslog
    time.sleep(1)
    ans_host.command("echo '---------- ERR: text 1 error --------------' >> /var/log/syslog")
    ans_host.command("echo '---------- THRESHOLD_CLEAR test1 xyz test2 --------------' >> /var/log/syslog")
    time.sleep(2)
    ans_host.command("echo '---------- kernel: says Oops --------------' >> /var/log/syslog")

    # Perform syslog analysis based on added messages
    result = log.analyze(marker)
    if not result:
        pytest.fail("Log analyzer failed.")
    assert result["total"]["match"] == 2, "Found errors: {}".format(result)
    # Download extracted syslog file from DUT to the local host
    log.save_extracted_log(dest="/tmp/log/syslog")

    # Example: update previously configured marker
    # Now start marker will have new prefix
    log.update_marker_prefix("test_bgp")

    # Execute function and analyze logs during function execution
    # Return tuple of (FUNCTION_RESULT, LOGANALYZER_RESULT)
    run_cmd_result = log.run_cmd(adder, 5, y=5, z=11)

    # Clear current regexp match list
    log.match_regex = []
    # Load regular expressions from the specified file
    reg_exp = log.parse_regexp_file(src=COMMON_MATCH)
    # Extend existed match regular expresiions with previously read
    log.match_regex.extend(reg_exp)

    # Verify that new regular expressions are found by log analyzer. Again add new error message to the syslog.
    marker = log.init()
    ans_host.command("echo '---------- kernel: says Oops --------------' >> /var/log/syslog")
    result = log.analyze(marker)
    if not result:
        pytest.fail("Log analyzer failed.")
    assert result["total"]["match"] == 1, "Found errors: {}".format(result)

@disable_loganalyzer
def test_skipped_test(localhost, ansible_adhoc, testbed):
    pass
```
