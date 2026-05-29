import logging
import unittest
from unittest.mock import MagicMock
from tests.common.plugins.conditional_mark import find_all_matches, load_conditions

logger = logging.getLogger(__name__)

DYNAMIC_UPDATE_SKIP_REASON = False
CUSTOM_BASIC_FACTS = {"asic_type": "vs", "topo_type": "t0"}


def load_test_conditions():
    session_mock = MagicMock()
    session_mock.config.option.mark_conditions_files = \
        ["tests/common/plugins/conditional_mark/unit_test/tests_conditions.yaml"]
    return load_conditions(session_mock), session_mock


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


if __name__ == "__main__":
    unittest.main()
