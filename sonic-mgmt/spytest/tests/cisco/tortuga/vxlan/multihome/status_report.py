from spytest import st


def log(msg):
    """
    Log a message to the console.
    Args:
        msg (str): Message to log.
    """
    st.log(msg)


def start_banner(msg=""):
    """
    Display a start banner message for the test case.
    Args:
        msg (str): Message to display in the banner.
    """
    st.banner(msg)


def report_fail(dut, msg=""):
    """
    Report failure message to the console and log file.
    Args:
        dut (str): Device under test.
        msg (str): Failure message to report.
    """
    st.banner(msg)
    st.report_fail("test_case_failed", dut)


def report_pass(dut, msg=""):
    """
    Report success message to the console and log file.
    Args:
        dut (str): Device under test.
        msg (str): Success message to report.
    """
    st.banner(msg)
    st.report_pass("test_case_passed", dut)
