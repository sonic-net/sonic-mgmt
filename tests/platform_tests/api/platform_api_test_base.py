from tests.common.helpers.assertions import pytest_assert


class PlatformApiTestBase(object):
    """Platform API test base class"""

    failed_expectations = []

    def expect(self, expr, err_msg):
        """
        A pytest method can call this method multiple times. It will accumulate
        error messages for each expression which would have failed an
        assertion in failed_expectations. When the test method is ready to
        check if any of the previous expressions passed to this function would
        have failed an assertion, it should call assert_expectations()
        """
        if not expr:
            self.failed_expectations.append(err_msg)
        return expr

    def assert_expectations(self):
        """
        Checks if there are any error messages waiting in failed_expectations.
        If so, it will fail an assert and pass a concatenation of all pending
        error messages. It will also clear failed_expectations to prepare it
        for the next use.
        """
        if len(self.failed_expectations) > 0:
            err_msg = ", ".join(self.failed_expectations)
            # TODO: When we move to Python 3.3+, we can use self.failed_expectations.clear() instead
            del self.failed_expectations[:]
            pytest_assert(False, err_msg)
