from abc import ABC, abstractmethod


class BugHandler(ABC):
    @abstractmethod
    def bug_handler_wrapper(self, analyzers, duthosts, la_results):
        pass


class ConsolidatedBugHandler(BugHandler):
    def bug_handler_wrapper(self, analyzers, duthosts, la_results):
        """
        Consolidated bug handler.
        This handler will consolidate the loganalyzer results from all the DUTs
        """
        pass


class NoOpBugHandler(BugHandler):
    """No operation bug handler"""
    def bug_handler_wrapper(self, analyzers, duthosts, la_results):
        pass


def get_bughandler_instance(kwargs: dict) -> BugHandler:
    if isinstance(kwargs, dict) and kwargs.get("type", "noop") == "consolidated":
        return ConsolidatedBugHandler()
    return NoOpBugHandler()
