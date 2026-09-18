import tempfile
import unittest
from pathlib import Path

from analyzer.ast_parser import ProjectParser
from analyzer.call_graph import CallGraph


class TestCallGraph(unittest.TestCase):

    def test_basic_graph_operations(self):
        graph = CallGraph()
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")

        self.assertIn("b", graph.get_callees("a"))
        self.assertIn("c", graph.get_callees("b"))
        self.assertIn("a", graph.get_callers("b"))
        self.assertEqual(graph.total_nodes, 3)
        self.assertEqual(graph.total_edges, 2)

    def test_find_matching_nodes(self):
        graph = CallGraph()
        graph.add_edge("app.login", "dummy_vuln_lib.unsafe_deserialize")
        graph.add_edge("app.safe", "utils.sanitize")

        matches_full = graph.find_matching_nodes("dummy_vuln_lib.unsafe_deserialize")
        self.assertEqual(matches_full, ["dummy_vuln_lib.unsafe_deserialize"])

        matches_suffix = graph.find_matching_nodes("unsafe_deserialize")
        self.assertEqual(matches_suffix, ["dummy_vuln_lib.unsafe_deserialize"])

        matches_none = graph.find_matching_nodes("non_existent")
        self.assertEqual(matches_none, [])

    def test_graph_construction_from_parser(self):
        code = """
def alpha():
    beta()

def beta():
    gamma()

def gamma():
    pass
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            parser = ProjectParser(temp_path)
            parser.parse()
            graph = CallGraph.build_from_parser(parser)

            # Local calls should be resolved to module scope
            module_name = parser.file_visitors[temp_path].module_name
            alpha = f"{module_name}.alpha"
            beta = f"{module_name}.beta"
            gamma = f"{module_name}.gamma"

            self.assertIn(beta, graph.get_callees(alpha))
            self.assertIn(gamma, graph.get_callees(beta))
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
