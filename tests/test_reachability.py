import unittest

from analyzer.call_graph import CallGraph
from analyzer.models import EntryPoint, EntryPointType
from analyzer.reachability import ReachabilityEngine


class TestReachabilityEngine(unittest.TestCase):

    def setUp(self):
        self.graph = CallGraph()
        # Route 1: login -> process_user -> parse_input -> unsafe_deserialize
        self.graph.add_edge("app.login", "app.process_user")
        self.graph.add_edge("app.process_user", "app.parse_input")
        self.graph.add_edge("app.parse_input", "dummy_vuln_lib.unsafe_deserialize")

        # Route 2: safe_route -> safe_helper
        self.graph.add_edge("app.safe_route", "app.safe_helper")

        # Dead code: uncalled_func -> unsafe_deserialize
        self.graph.add_edge("app.uncalled_func", "dummy_vuln_lib.unsafe_deserialize")

        # Cycle: cyclic_route -> func_a -> func_b -> func_a, func_b -> vuln_target
        self.graph.add_edge("app.cyclic_route", "app.func_a")
        self.graph.add_edge("app.func_a", "app.func_b")
        self.graph.add_edge("app.func_b", "app.func_a")  # Cycle
        self.graph.add_edge("app.func_b", "dummy_vuln_lib.unsafe_deserialize")

        self.entry_points = [
            EntryPoint("app.login", EntryPointType.FLASK_ROUTE, "app.py", 10),
            EntryPoint("app.safe_route", EntryPointType.FLASK_ROUTE, "app.py", 20),
            EntryPoint("app.cyclic_route", EntryPointType.FLASK_ROUTE, "app.py", 30),
        ]
        self.engine = ReachabilityEngine(self.graph, self.entry_points)

    def test_dfs_reachable_path(self):
        result = self.engine.check_reachability("dummy_vuln_lib.unsafe_deserialize", strategy="dfs")
        self.assertTrue(result.is_reachable)
        self.assertGreater(len(result.paths), 0)

        # First path should be login -> process_user -> parse_input -> unsafe_deserialize
        direct_path = result.paths[0]
        self.assertEqual(direct_path, [
            "app.login",
            "app.process_user",
            "app.parse_input",
            "dummy_vuln_lib.unsafe_deserialize"
        ])

    def test_bfs_shortest_path(self):
        result = self.engine.check_reachability("dummy_vuln_lib.unsafe_deserialize", strategy="bfs")
        self.assertTrue(result.is_reachable)
        self.assertGreater(len(result.paths), 0)

    def test_fuzzy_symbol_matching(self):
        # Target passed without package prefix
        result = self.engine.check_reachability("unsafe_deserialize", strategy="dfs")
        self.assertTrue(result.is_reachable)

    def test_unreachable_function(self):
        result = self.engine.check_reachability("non_existent_function", strategy="dfs")
        self.assertFalse(result.is_reachable)
        self.assertEqual(len(result.paths), 0)

    def test_dead_code_not_reachable(self):
        # Only route 2 as entry point
        safe_only_engine = ReachabilityEngine(
            self.graph,
            [EntryPoint("app.safe_route", EntryPointType.FLASK_ROUTE, "app.py", 20)]
        )
        result = safe_only_engine.check_reachability("dummy_vuln_lib.unsafe_deserialize")
        self.assertFalse(result.is_reachable)
        self.assertEqual(len(result.paths), 0)

    def test_cycle_does_not_loop_infinitely(self):
        cyclic_only_engine = ReachabilityEngine(
            self.graph,
            [EntryPoint("app.cyclic_route", EntryPointType.FLASK_ROUTE, "app.py", 30)]
        )
        result = cyclic_only_engine.check_reachability("dummy_vuln_lib.unsafe_deserialize")
        self.assertTrue(result.is_reachable)
        # Verify the path traverses the cycle safely without infinite recursion
        self.assertEqual(result.paths[0], [
            "app.cyclic_route",
            "app.func_a",
            "app.func_b",
            "dummy_vuln_lib.unsafe_deserialize"
        ])

    def test_streamlit_reachability(self):
        st_graph = CallGraph()
        # Streamlit module top-level calls calculate_metrics -> parse_data -> unsafe_deserialize
        st_graph.add_edge("dashboard.__module__", "dashboard.calculate_metrics")
        st_graph.add_edge("dashboard.calculate_metrics", "dashboard.parse_data")
        st_graph.add_edge("dashboard.parse_data", "dummy_vuln_lib.unsafe_deserialize")

        st_ep = [EntryPoint("dashboard.__module__", EntryPointType.STREAMLIT_SCRIPT, "dashboard.py", 1)]
        st_engine = ReachabilityEngine(st_graph, st_ep)
        result = st_engine.check_reachability("dummy_vuln_lib.unsafe_deserialize")

        self.assertTrue(result.is_reachable)
        self.assertEqual(result.paths[0], [
            "dashboard.__module__",
            "dashboard.calculate_metrics",
            "dashboard.parse_data",
            "dummy_vuln_lib.unsafe_deserialize"
        ])


if __name__ == "__main__":
    unittest.main()
