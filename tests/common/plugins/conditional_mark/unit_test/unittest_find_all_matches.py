import logging
import unittest
from unittest.mock import MagicMock, patch
from tests.common.plugins import conditional_mark
from tests.common.plugins.conditional_mark import find_all_matches, load_conditions

logger = logging.getLogger(__name__)

DYNAMIC_UPDATE_SKIP_REASON = False
CUSTOM_BASIC_FACTS = {"asic_type": "vs", "topo_type": "t0"}


def load_test_conditions():
    session_mock = MagicMock()
    session_mock.config.option.mark_conditions_files = \
        ["tests/common/plugins/conditional_mark/unit_test/tests_conditions.yaml"]
    return load_conditions(session_mock), session_mock


def collect_marks(nodeid):
    """Return the marks that find_all_matches resolves for the given node id.

    Args:
        nodeid (str): Full test case name.

    Returns:
        dict: Mapping of mark name to mark details.
    """
    conditions, session_mock = load_test_conditions()
    matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

    marks = {}
    for match in matches:
        for mark_name, mark_details in list(list(match.values())[0].items()):
            marks[mark_name] = mark_details
    return marks


class TestFindAllMatches(unittest.TestCase):
    """Test cases for find_all_matches function."""

    # Test case 1: The condition in the longest matching entry is True
    # Use the conditions in the longest matching entry.
    def test_true_conditions_in_longest_entry(self):
        conditions, session_mock = load_test_conditions()

        marks_found = []
        nodeid = "test_conditional_mark.py::test_mark"

        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 2: The condition in the longest matching entry is partly false
    # Use the conditions in second longest matching entry.
    def test_partly_false_conditions_in_longest_entry(self):
        conditions, session_mock = load_test_conditions()

        marks_found = []
        nodeid = "test_conditional_mark.py::test_mark_1"

        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "xfail":
                    self.assertEqual(mark_details.get("reason"), "Xfail test_conditional_mark.py::test_mark_1")
                elif mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark")

        self.assertEqual(len(marks_found), 2)
        self.assertIn('skip', marks_found)
        self.assertIn('xfail', marks_found)

    # Test case 3: All conditions in the matching path are false
    def test_all_false_conditions_in_matching_path_1(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py"

        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        self.assertFalse(matches)

    def test_all_false_conditions_in_matching_path_2(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_false_mark_1"

        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        self.assertFalse(matches)

    def test_all_false_conditions_in_matching_path_3(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_false_mark_2"

        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        self.assertFalse(matches)

    # Test case 4: The condition in the longest matching entry is empty
    def test_empty_conditions(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_mark_2"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark_2")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 5: Test logic operation `or`
    def test_logic_operation_or(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_mark_3"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark_3")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 6: Test default logic operation
    def test_defalut_logic_operation(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_mark_4"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 7: Test logic operation `and`
    def test_logic_operation_and(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_mark_4"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 8: Test duplicated conditions
    def test_duplicated_conditions(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_mark_6"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark_6")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 9: Test contradicting conditions
    def test_contradicting_conditions(self):
        conditions, session_mock = load_test_conditions()

        nodeid = "test_conditional_mark.py::test_mark_7"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    # Test case 10: Test no matches
    def test_no_matches(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark_no_matches.py"
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)
        self.assertFalse(matches)

    # Test case 11: Test only use the longest match
    def test_only_use_the_longest_1(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark.py::test_mark_8"
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)
        self.assertFalse(matches)

    def test_only_use_the_longest_2(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark.py::test_mark_8_1"
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)
        self.assertFalse(matches)

    def test_only_use_the_longest_3(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark.py::test_mark_8_2"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark_8_2")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    def test_only_use_the_longest_4(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark.py::test_mark_9"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark_9")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    def test_only_use_the_longest_5(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark.py::test_mark_9_1"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "skip":
                    self.assertEqual(mark_details.get("reason"), "Skip test_conditional_mark.py::test_mark_9_1")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('skip', marks_found)

    def test_only_use_the_longest_6(self):
        conditions, session_mock = load_test_conditions()
        nodeid = "test_conditional_mark.py::test_mark_9_2"

        marks_found = []
        matches = find_all_matches(nodeid, conditions, session_mock, DYNAMIC_UPDATE_SKIP_REASON, CUSTOM_BASIC_FACTS)

        for match in matches:
            for mark_name, mark_details in list(list(match.values())[0].items()):
                marks_found.append(mark_name)

                if mark_name == "xfail":
                    self.assertEqual(mark_details.get("reason"), "Xfail test_conditional_mark.py::test_mark_9_2")

        self.assertEqual(len(marks_found), 1)
        self.assertIn('xfail', marks_found)

    # Regression coverage for https://github.com/sonic-net/sonic-mgmt/issues/26793:
    # pytest 9.1 changed the order in which independently parametrized fixtures are joined
    # into the generated node ID, so "ipv6-erspan_ipv4" under pytest <= 9.0 becomes
    # "erspan_ipv4-ipv6" under pytest >= 9.1. A plain nodeid.startswith() key written
    # against one ordering silently stops matching under the other. The cases below
    # exercise regex keys mirroring the production everflow entries, which must match both
    # orderings without over-matching.
    def test_reorder_regex_matches_legacy_param_order(self):
        """Node IDs generated by pytest <= 9.0 list ip_ver before erspan_ip_ver."""
        for nodeid in (
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark[ipv6-erspan_ipv4-default]",
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark[ipv6-erspan_ipv6-default]",
        ):
            marks = collect_marks(nodeid)

            self.assertEqual(list(marks.keys()), ['skip'], "unexpected marks for {}".format(nodeid))
            self.assertEqual(marks['skip'].get("reason"),
                             "Skip test_everflow_reorder_mark.py::test_everflow_reorder_mark")

    def test_reorder_regex_matches_pytest_9_1_param_order(self):
        """Node IDs generated by pytest >= 9.1 list erspan_ip_ver before ip_ver."""
        for nodeid in (
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark[erspan_ipv4-ipv6-default]",
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark[erspan_ipv6-ipv6-default]",
        ):
            marks = collect_marks(nodeid)

            self.assertEqual(list(marks.keys()), ['skip'], "unexpected marks for {}".format(nodeid))
            self.assertEqual(marks['skip'].get("reason"),
                             "Skip test_everflow_reorder_mark.py::test_everflow_reorder_mark")

    def test_reorder_regex_does_not_match_ipv4(self):
        """The IPv6 only skip must not leak onto IPv4 cases in either ordering.

        The IPv4 cases are gated by a separate order-independent xfail key, so they pick up
        that mark and nothing else.
        """
        for nodeid in (
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark[ipv4-erspan_ipv4-default]",
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark[erspan_ipv4-ipv4-default]",
        ):
            marks = collect_marks(nodeid)

            self.assertEqual(list(marks.keys()), ['xfail'], "unexpected marks for {}".format(nodeid))
            self.assertEqual(marks['xfail'].get("reason"),
                             "Xfail test_everflow_reorder_mark.py::test_everflow_reorder_mark")

    def test_reorder_regex_does_not_match_similar_test_function(self):
        """The regex keys are anchored on the test function name, not on the parameters alone."""
        for nodeid in (
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark_extra[ipv6-erspan_ipv4-default]",
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark_extra[erspan_ipv4-ipv6-default]",
            "test_everflow_reorder_mark.py::test_everflow_reorder_mark_extra[ipv4-erspan_ipv4-default]",
        ):
            self.assertFalse(collect_marks(nodeid), "unexpected match for {}".format(nodeid))


class TestTestbedInfoCache(unittest.TestCase):
    """Collection lookups share the tbinfo fixture's cache without eager loading."""

    def setUp(self):
        self.session = MagicMock()
        self.session.config.option.testbed = 'sample-testbed'
        self.session.config.option.testbed_file = 'sample-testbed.yaml'
        self.session.config.option.ansible_host_pattern = 'all'
        self.session.config.option.ignore_conditional_mark = False
        self.session.config.option.dynamic_update_skip_reason = False
        self.session.config.option.customize_inventory_file = False
        self.session.config.rootpath = 'tests'
        self.session.config.getoption.side_effect = (
            lambda name, default: 'other' if name == '--dut_vendor' else default)
        pytest_cache = {
            'TESTS_MARK_CONDITIONS': [{'test_case.py': {}}],
            'BASIC_FACTS_dut-a': {'topo_type': 't0'},
        }
        self.session.config.cache.get.side_effect = pytest_cache.get
        self.session.config.cache.set.side_effect = pytest_cache.__setitem__
        self.testbed_info = MagicMock()
        self.testbed_info.testbed_topo = {
            'sample-testbed': {'duts': ['dut-a'], 'topo': {'name': 't0', 'type': 't0'}},
        }
        self.entries = {}
        self.cache = MagicMock()
        self.cache.NOTEXIST = object()
        self.cache.read.side_effect = lambda zone, key: self.entries.get((zone, key), self.cache.NOTEXIST)
        self.cache.write.side_effect = lambda zone, key, value: self.entries.__setitem__((zone, key), value)
        factory_patch = patch.object(conditional_mark, 'FactsCache', return_value=self.cache)
        constructor_patch = patch.object(conditional_mark, 'TestbedInfo', return_value=self.testbed_info)
        self.cache_factory = factory_patch.start()
        self.constructor = constructor_patch.start()
        self.addCleanup(factory_patch.stop)
        self.addCleanup(constructor_patch.stop)

    def test_collection_reuses_testbed_info(self):
        """DUT resolution during collection constructs and caches testbed info once."""
        item = MagicMock()
        item.nodeid = 'test_case.py::test_case'
        item.get_closest_marker.return_value = None
        with patch.object(conditional_mark, 'load_conditions', return_value=[{'test_case.py': {}}]), \
                patch.object(conditional_mark, 'find_all_matches', return_value=[]):
            conditional_mark.pytest_collection(self.session)
            conditional_mark.pytest_collection_modifyitems(self.session, self.session.config, [item])
        self.constructor.assert_called_once_with('sample-testbed.yaml')
        self.cache.write.assert_called_once_with('sample-testbed', 'tbinfo', self.testbed_info)

    def test_basic_facts_reuse_existing_testbed_cache(self):
        """An existing fixture cache serves both DUT-name and basic-fact lookups."""
        self.entries[('sample-testbed', 'tbinfo')] = self.testbed_info
        with patch.object(conditional_mark, 'get_http_proxies', return_value={}):
            self.assertEqual(conditional_mark.get_dut_name(self.session), 'dut-a')
            facts = conditional_mark.load_basic_facts('dut-a', self.session)
        self.assertEqual(facts['testbed'], 'sample-testbed')
        self.assertEqual(facts['topo_type'], 't0')
        self.constructor.assert_not_called()
        self.cache.write.assert_not_called()

    def test_all_skipped_items_do_not_load_testbed_info(self):
        """Preserve lazy loading when earlier hooks have skipped every item."""
        item = MagicMock()
        item.get_closest_marker.return_value = object()
        conditional_mark.pytest_collection_modifyitems(self.session, self.session.config, [item])
        self.constructor.assert_not_called()
        self.cache_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
