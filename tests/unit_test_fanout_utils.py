import unittest

from tests._fanout_utils import get_fanout_host_vars


class TestFanoutUtils(unittest.TestCase):
    def test_get_fanout_host_vars_uses_provided_inventory_sources(self):
        expected_inv_files = ["/tmp/inventory-a", "/tmp/inventory-b"]
        getter_calls = []

        def fake_host_visible_vars_getter(inv_files, host_name):
            getter_calls.append((inv_files, host_name))
            return {"os": "sonic", "ansible_host": "10.0.0.10"}

        host_vars = get_fanout_host_vars(expected_inv_files, "fanout01", fake_host_visible_vars_getter)

        self.assertEqual({"os": "sonic", "ansible_host": "10.0.0.10"}, host_vars)
        self.assertEqual([(expected_inv_files, "fanout01")], getter_calls)

    def test_get_fanout_host_vars_returns_empty_dict_when_host_is_missing(self):
        def fake_host_visible_vars_getter(inv_files, host_name):
            self.assertEqual(["/tmp/inventory"], inv_files)
            self.assertEqual("missing-fanout", host_name)
            return None

        host_vars = get_fanout_host_vars(["/tmp/inventory"], "missing-fanout", fake_host_visible_vars_getter)

        self.assertEqual({}, host_vars)


if __name__ == "__main__":
    unittest.main()
