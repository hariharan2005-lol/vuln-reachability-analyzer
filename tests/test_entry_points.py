import tempfile
import unittest
from pathlib import Path

from analyzer.ast_parser import ProjectParser
from analyzer.call_graph import CallGraph
from analyzer.entry_points import EntryPointDetector
from analyzer.models import EntryPointType


class TestEntryPointDetector(unittest.TestCase):

    def test_flask_and_main_entry_points(self):
        code = """
from flask import Flask

app = Flask(__name__)

@app.route("/api/test", methods=["POST"])
def api_test():
    return "ok"

def helper():
    pass

if __name__ == "__main__":
    helper()
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            parser = ProjectParser(temp_path)
            parser.parse()
            detector = EntryPointDetector(parser)
            entry_points = detector.detect()

            types = {ep.entry_type for ep in entry_points}
            self.assertIn(EntryPointType.FLASK_ROUTE, types)
            self.assertIn(EntryPointType.MAIN_BLOCK, types)

            flask_ep = [ep for ep in entry_points if ep.entry_type == EntryPointType.FLASK_ROUTE][0]
            self.assertTrue(flask_ep.symbol.endswith(".api_test"))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_fastapi_entry_points(self):
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {"id": item_id}
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            parser = ProjectParser(temp_path)
            parser.parse()
            detector = EntryPointDetector(parser)
            entry_points = detector.detect()

            self.assertEqual(len(entry_points), 1)
            self.assertEqual(entry_points[0].entry_type, EntryPointType.FASTAPI_ROUTE)
            self.assertEqual(entry_points[0].metadata.get("method"), "GET")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_streamlit_entry_points(self):
        code = """
import streamlit as st

def calculate_metrics():
    return 42

def render_dashboard(data):
    st.write(f"Metrics: {data}")

# Module-level calls (typical of Streamlit apps)
result = calculate_metrics()
render_dashboard(result)
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            parser = ProjectParser(temp_path)
            parser.parse()
            detector = EntryPointDetector(parser)
            entry_points = detector.detect()

            self.assertEqual(len(entry_points), 1)
            ep = entry_points[0]
            self.assertEqual(ep.entry_type, EntryPointType.STREAMLIT_SCRIPT)
            self.assertTrue(ep.symbol.endswith(".__module__"))

            # Confirm detector and call graph pick up module-level calls as reachable from the entry point
            graph = CallGraph.build_from_parser(parser)
            callees = graph.get_callees(ep.symbol)
            callee_basenames = {c.rsplit(".", 1)[-1] for c in callees}
            self.assertIn("calculate_metrics", callee_basenames)
            self.assertIn("render_dashboard", callee_basenames)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_general_top_level_script_entry_points(self):
        code = """
def run_job():
    save_result()

def save_result():
    pass

# Direct script execution without if __name__ == '__main__':
run_job()
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            parser = ProjectParser(temp_path)
            parser.parse()
            detector = EntryPointDetector(parser)
            entry_points = detector.detect()

            self.assertEqual(len(entry_points), 1)
            ep = entry_points[0]
            self.assertEqual(ep.entry_type, EntryPointType.TOP_LEVEL_SCRIPT)
            self.assertTrue(ep.symbol.endswith(".__module__"))

            # Confirm call graph connects module entry point to run_job
            graph = CallGraph.build_from_parser(parser)
            callees = graph.get_callees(ep.symbol)
            callee_basenames = {c.rsplit(".", 1)[-1] for c in callees}
            self.assertIn("run_job", callee_basenames)
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
