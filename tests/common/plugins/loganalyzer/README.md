#### Loganalyzer API usage example

Below is described possibility of loganalyzer fixture/module usage.

##### Loganalyzer fixture
In the root conftest there is implemented "loganalyzer" pytest fixture, which starts automatically for all test cases.
Fixture main flow:
- loganalyzer will add start marker before test case start
- loganalyzer will add stop marker after test case finish
- if loganalyzer analysis is not disabled for current test case it will analyze DUT syslog and display results.
If loganalyzer find specified messages which corresponds to defined regular expressions, it will display found messages and pytest will generate 'error'.

#### To skip loganalyzer analysis for:
- all test cases - use pytest command line option ```--disable_loganalyzer```
- specific test case: mark test case with ```@pytest.mark.disable_loganalyzer``` decorator. Example is shown below.


#### Notes:
loganalyzer.init() - can be called several times without calling "loganalyzer.analyze(marker)" between calls. Each call return its unique marker, which is used for "analyze" phase - loganalyzer.analyze(marker).


### Loganalyzer usage example

#### Example calling loganalyzer init/analyze methods automatically by using with statement
```python
    # Read existed common regular expressions located with legacy loganalyzer module
    loganalyzer.load_common_config()
    # Analyze syslog for code executed inside with statement
    with loganalyzer as analyzer:
        logging.debug("============== Test steps ===================")
        # Add test code here ...
        time.sleep(1)

    # Separately analyze syslog for code executed inside each with statement
    with loganalyzer as analyzer:
        # Clear current regexp match list if there is a need to have clear configuration
        loganalyzer.match_regex = []
        # Load regular expressions from the specified file
        reg_exp = loganalyzer.parse_regexp_file(src=COMMON_MATCH)
        # Extend currently configured match criteria (regular expressions) with data read from "COMMON_MATCH" file
        loganalyzer.match_regex.extend(reg_exp)
        # Add test code here ...
        # Here will be executed syslog analysis on context manager __exit__
        time.sleep(1)
        with loganalyzer as analyzer:
            # Clear current regexp match list if there is a need to have clear configuration
            loganalyzer.match_regex = []
            # Set match criteria (regular expression) to custom regexp - "test:.*Error"
            loganalyzer.match_regex.extend(["test:.*Error"])
            # Add test code here ...
            # Here will be executed syslog analysis on context manager __exit__
            time.sleep(1)
            with loganalyzer as analyzer:
                # Add test code here ...
                # Here will be executed syslog analysis on context manager __exit__
                time.sleep(1)
```

#### Example calling loganalyzer init/analyze methods directly in test case
```python
    # Example 1
    # Read existed common regular expressions located with legacy loganalyzer module
    loganalyzer.load_common_config()
    # Add start marker to the DUT syslog
    marker = loganalyzer.init()
    # PERFORM TEST CASE STEPS ...
    # Verify that error messages were not found in DUT syslog. Exception will be raised if in DUT syslog will be found messages which fits regexp defined in COMMON_MATCH
    loganalyzer.analyze(marker)

    # Example 2
    # Read existed common regular expressions located with legacy loganalyzer module
    loganalyzer.load_common_config()
    # Add start marker to the DUT syslog
    marker = loganalyzer.init()
    # PERFORM TEST CASE STEPS ...
    # Get summary of analyzed DUT syslog
    result = loganalyzer.analyze(marker, fail=False)
    # Verify that specific amount of error messages found in syslog # Negative test case
    assert result["total"]["match"] == 2, "Not found expected errors: {}".format(result)

    # Example 3
    # Download extracted syslog file from DUT to the local host
    loganalyzer.save_extracted_log(dest="/tmp/log/syslog")

    # Example 4
    # Update previously configured marker
    # Now start marker will have new prefix - test_bgp
    marker = loganalyzer.update_marker_prefix("test_bgp")

    def get_platform_info(dut):
        """
        Example callback which gets DUT platform information and returns obtained string
        """
        return dut.command("show platform summary")

    # Example 5
    # Execute specific function and analyze logs during function execution
    run_cmd_result = loganalyzer.run_cmd(get_platform_info, ans_host)
    # Process result of "get_platform_info" callback
    assert all(item in run_cmd_result["stdout"] for item in ["Platform", "HwSKU", "ASIC"]) is True, "Unexpected output returned after command execution: {}".format(run_cmd_result)

    # Example 6
    # Clear current regexp match list
    loganalyzer.match_regex = []
    # Load regular expressions from the specified file defined in COMMON_MATCH variable
    reg_exp = loganalyzer.parse_regexp_file(src=COMMON_MATCH)
    # Extend currently configured match criteria (regular expressions) with data read from "COMMON_MATCH" file
    loganalyzer.match_regex.extend(reg_exp)
    marker = loganalyzer.init()
    # PERFORM TEST CASE STEPS ...
    # Verify that error messages were not found in DUT syslog. Exception will be raised if in DUT syslog will be found messages which fits regexp defined in COMMON_MATCH
    loganalyzer.analyze(marker)

    # Example 7
    loganalyzer.expect_regex = []
    # Add specific EXPECTED regular expression
    # Means that in the DUT syslog loganalyzer will search for message which matches with "kernel:.*Oops" regular expression
    # If such message will not be present in DUT syslog, it will raise exception
    loganalyzer.expect_regex.append("kernel:.*Oops")
    # Add start marker to the DUT syslog
    marker = loganalyzer.init()
    # PERFORM TEST CASE STEPS ...
    # Verify that expected error messages WERE FOUND in DUT syslog. Exception will be raised if in DUT syslog will NOT be found messages which fits to "kernel:.*Oops" regular expression
    loganalyzer.analyze(marker)

    # Example 8
    loganalyzer.expect_regex = []
    # Add specific EXPECTED regular expression
    # Means that in the DUT syslog loganalyzer will search for message which matches with "kernel:.*Oops" regular expression
    # If such message will not be present in DUT syslog, it will raise exception
    loganalyzer.expect_regex.append("kernel:.*Oops")
    # PERFORM TEST CASE STEPS ...
    # Verify that expected error messages WERE FOUND in DUT syslog. Exception will be raised if in DUT syslog will NOT be found messages which fits to "kernel:.*Oops" regular expression
    loganalyzer.run_cmd(ans_host.command, "echo '---------- kernel: says Oops --------------' >> /var/log/syslog")
```
