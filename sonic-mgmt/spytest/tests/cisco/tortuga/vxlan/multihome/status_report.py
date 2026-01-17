from spytest import st
import utilities.common as utils


def log(msg):
    """
    Log a message to the console.
    Args:
        msg (str): Message to log.
    """
    line = utils.get_line_number(1)
    st.log(msg + " @{}".format(line))


def banner(msg=""):
    """
    Display a start banner message for the test case.
    Args:
        msg (str): Message to display in the banner.
    """
    line = utils.get_line_number(1)
    st.banner(msg + " @{}".format(line))


def report_fail(dut, msg=""):
    """
    Report failure message to the console and log file.
    Args:
        dut (str): Device under test.
        msg (str): Failure message to report.
    """
    line = utils.get_line_number(1)
    st.banner(msg + " @{}".format(line), delimiter="@")
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
