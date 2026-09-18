import ast
import tempfile
import unittest
from pathlib import Path

from analyzer.ast_parser import ProjectASTVisitor, ProjectParser, get_module_name_from_path


class TestASTParser(unittest.TestCase):

    def test_get_module_name_from_path(self):
        self.assertEqual(get_module_name_from_path("app.py", "."), "app")
        self.assertEqual(get_module_name_from_path("pkg/__init__.py", "."), "pkg")
        self.assertEqual(get_module_name_from_path("pkg/sub/module.py", "."), "pkg.sub.module")

    def test_visitor_extracts_functions_and_calls(self):
        code = """
from helper_lib import sanitize
import external_pkg as ext

class Service:
    def execute(self, payload):
        clean = sanitize(payload)
        return self.save(clean)

    def save(self, data):
        ext.write_data(data)

def handler():
    svc = Service()
    svc.execute("data")

if __name__ == "__main__":
    handler()
"""
        tree = ast.parse(code)
        visitor = ProjectASTVisitor(file_path="service.py", module_name="service")
        visitor.visit(tree)

        # Check imports
        self.assertEqual(visitor.imports.get("sanitize"), "helper_lib.sanitize")
        self.assertEqual(visitor.imports.get("ext"), "external_pkg")

        # Check function extraction
        self.assertIn("service.Service.execute", visitor.functions)
        self.assertIn("service.Service.save", visitor.functions)
        self.assertIn("service.handler", visitor.functions)

        # Check call resolution
        callees = [c.callee_name for c in visitor.call_sites]
        self.assertIn("helper_lib.sanitize", callees)
        self.assertIn("external_pkg.write_data", callees)

        # Check main block calls
        self.assertEqual(len(visitor.main_block_calls), 1)
        self.assertEqual(visitor.main_block_calls[0].callee_name, "handler")
        self.assertEqual(visitor.main_block_calls[0].caller_symbol, "service.__main__")

    def test_project_parser_on_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write("def foo(): return bar()\ndef bar(): pass\n")
            temp_path = f.name

        try:
            parser = ProjectParser(temp_path)
            parser.parse()
            self.assertEqual(len(parser.functions), 2)
            self.assertEqual(len(parser.call_sites), 1)
            self.assertEqual(parser.call_sites[0].callee_name, "bar")
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
