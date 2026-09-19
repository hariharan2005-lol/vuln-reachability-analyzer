import ast
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from analyzer.models import CallSite, FunctionNode


def get_module_name_from_path(file_path: str, base_dir: str) -> str:
    """Converts a file path to a python dotted module name relative to base_dir."""
    rel_path = os.path.relpath(file_path, base_dir)
    without_ext = os.path.splitext(rel_path)[0]
    parts = Path(without_ext).parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else "__main__"


class ProjectASTVisitor(ast.NodeVisitor):
    """AST Visitor that traverses a single Python file extracting functions, imports, and calls."""

    def __init__(self, file_path: str, module_name: str):
        self.file_path = file_path
        self.module_name = module_name

        # Imports table: alias -> fully qualified symbol/module
        # e.g. "unsafe_deserialize" -> "dummy_vuln_lib.unsafe_deserialize"
        # e.g. "dvl" -> "dummy_vuln_lib"
        self.imports: Dict[str, str] = {}
        # Import origins table: alias -> originating module
        # e.g. "io" -> "io", "BytesIO" -> "io", "dvl" -> "dummy_vuln_lib", "unsafe_deserialize" -> "dummy_vuln_lib"
        self.import_origins: Dict[str, str] = {}

        self.functions: Dict[str, FunctionNode] = {}
        self.call_sites: List[CallSite] = []
        self.main_block_calls: List[CallSite] = []
        # Module-level calls outside any function/class and outside __main__
        self.top_level_calls: List[CallSite] = []

        self.has_streamlit_import: bool = False
        self.streamlit_import_lineno: Optional[int] = None

        # Current scope stack (e.g. ['MyClass'])
        self._scope_stack: List[str] = []
        self._current_function_symbol: Optional[str] = None
        self._inside_main_block: bool = False

    def _get_current_symbol_prefix(self) -> str:
        if self._scope_stack:
            return f"{self.module_name}.{'.'.join(self._scope_stack)}"
        return self.module_name

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            imported_name = alias.name
            as_name = alias.asname if alias.asname else alias.name
            self.imports[as_name] = imported_name
            self.import_origins[as_name] = imported_name
            if imported_name == "streamlit" or imported_name.startswith("streamlit."):
                self.has_streamlit_import = True
                if self.streamlit_import_lineno is None:
                    self.streamlit_import_lineno = node.lineno
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        if mod == "streamlit" or mod.startswith("streamlit."):
            self.has_streamlit_import = True
            if self.streamlit_import_lineno is None:
                self.streamlit_import_lineno = node.lineno
        # Handle relative imports if mod is empty or relative
        if node.level and node.level > 0:
            prefix = "." * node.level
            mod_prefix = f"{prefix}{mod}" if mod else prefix
        else:
            mod_prefix = mod

        for alias in node.names:
            as_name = alias.asname if alias.asname else alias.name
            if mod_prefix:
                full_name = f"{mod_prefix}.{alias.name}"
                origin_mod = mod_prefix
            else:
                full_name = alias.name
                origin_mod = alias.name
            self.imports[as_name] = full_name
            self.import_origins[as_name] = origin_mod
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def _extract_decorator_str(self, decorator: ast.expr) -> str:
        """Helper to get string representation of decorator."""
        try:
            return ast.unparse(decorator)
        except Exception:
            if isinstance(decorator, ast.Name):
                return decorator.id
            elif isinstance(decorator, ast.Attribute):
                return f"{self._extract_attribute_name(decorator)}"
            elif isinstance(decorator, ast.Call):
                return self._extract_decorator_str(decorator.func)
            return "unknown_decorator"

    def _process_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool = False) -> None:
        prefix = self._get_current_symbol_prefix()
        symbol = f"{prefix}.{node.name}"
        is_method = len(self._scope_stack) > 0

        decorators = [self._extract_decorator_str(d) for d in node.decorator_list]

        fn_node = FunctionNode(
            symbol=symbol,
            file_path=self.file_path,
            line_number=node.lineno,
            name=node.name,
            is_method=is_method,
            decorators=decorators,
        )
        self.functions[symbol] = fn_node

        prev_fn_symbol = self._current_function_symbol
        self._current_function_symbol = symbol
        self._scope_stack.append(node.name)

        self.generic_visit(node)

        self._scope_stack.pop()
        self._current_function_symbol = prev_fn_symbol

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._process_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._process_function(node, is_async=True)

    def _extract_attribute_name(self, node: ast.Attribute) -> str:
        """Recursively formats attribute access like foo.bar.baz."""
        parts = []
        curr = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        elif isinstance(curr, ast.Call):
            parts.append("<call>")
        parts.reverse()
        return ".".join(parts)

    def _resolve_callee_and_origin(self, callee_raw: str) -> Tuple[str, Optional[str]]:
        """
        Resolves a callee name against imports or local module scope and returns (callee, origin).
        e.g.:
        - 'io.BytesIO' -> ('io.BytesIO', 'io')
        - 'BytesIO' (when from io import BytesIO) -> ('io.BytesIO', 'io')
        - 'dvl.unsafe_deserialize' -> ('dummy_vuln_lib.unsafe_deserialize', 'dummy_vuln_lib')
        - 'unsafe_deserialize' -> ('dummy_vuln_lib.unsafe_deserialize', 'dummy_vuln_lib')
        - 'process_user' (local function) -> ('app.process_user', 'app')
        - 'self.method' -> ('app.Class.method', 'app')
        """
        parts = callee_raw.split(".")
        root = parts[0]

        if root in self.imports:
            imported_base = self.imports[root]
            origin = self.import_origins.get(root)
            if len(parts) > 1:
                return f"{imported_base}.{'.'.join(parts[1:])}", origin
            return imported_base, origin

        # Check if caller used self.method() or cls.method() inside a class
        if (root in ("self", "cls")) and self._scope_stack:
            class_name = self._scope_stack[0]
            rest = ".".join(parts[1:])
            return f"{self.module_name}.{class_name}.{rest}", self.module_name

        # If it's a local call without dots, origin is current module
        if len(parts) == 1:
            return callee_raw, self.module_name

        return callee_raw, root

    def _resolve_callee(self, callee_raw: str) -> str:
        """
        Resolves a callee name against imports or local module scope.
        e.g.:
        - If 'unsafe_deserialize' was imported as 'from dummy_vuln_lib import unsafe_deserialize'
          -> 'dummy_vuln_lib.unsafe_deserialize'
        - If 'dvl.unsafe_deserialize' was called and 'dvl' is 'import dummy_vuln_lib as dvl'
          -> 'dummy_vuln_lib.unsafe_deserialize'
        - If 'process_user' is defined in current module -> '{module_name}.process_user'
        """
        resolved, _ = self._resolve_callee_and_origin(callee_raw)
        return resolved

    def visit_Call(self, node: ast.Call) -> None:
        callee_raw = None
        if isinstance(node.func, ast.Name):
            callee_raw = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee_raw = self._extract_attribute_name(node.func)

        if callee_raw:
            resolved_callee, callee_origin = self._resolve_callee_and_origin(callee_raw)

            if self._current_function_symbol:
                caller = self._current_function_symbol
                site = CallSite(
                    caller_symbol=caller,
                    callee_name=resolved_callee,
                    line_number=node.lineno,
                    file_path=self.file_path,
                    callee_origin=callee_origin,
                )
                self.call_sites.append(site)
            elif self._inside_main_block:
                main_symbol = f"{self.module_name}.__main__"
                site = CallSite(
                    caller_symbol=main_symbol,
                    callee_name=resolved_callee,
                    line_number=node.lineno,
                    file_path=self.file_path,
                    callee_origin=callee_origin,
                )
                self.main_block_calls.append(site)
            elif not self._scope_stack:
                module_symbol = f"{self.module_name}.__module__"
                site = CallSite(
                    caller_symbol=module_symbol,
                    callee_name=resolved_callee,
                    line_number=node.lineno,
                    file_path=self.file_path,
                    callee_origin=callee_origin,
                )
                self.top_level_calls.append(site)

        self.generic_visit(node)

    def _is_main_check(self, test_node: ast.expr) -> bool:
        """Checks for `if __name__ == '__main__':` or `if '__main__' == __name__:`."""
        if isinstance(test_node, ast.Compare):
            left = test_node.left
            for op, comparator in zip(test_node.ops, test_node.comparators):
                if isinstance(op, ast.Eq):
                    if (isinstance(left, ast.Name) and left.id == "__name__" and
                            isinstance(comparator, ast.Constant) and comparator.value == "__main__"):
                        return True
                    if (isinstance(comparator, ast.Name) and comparator.id == "__name__" and
                            isinstance(left, ast.Constant) and left.value == "__main__"):
                        return True
        return False

    def visit_If(self, node: ast.If) -> None:
        if self._is_main_check(node.test):
            prev_inside = self._inside_main_block
            self._inside_main_block = True
            for stmt in node.body:
                self.visit(stmt)
            self._inside_main_block = prev_inside

            for stmt in node.orelse:
                self.visit(stmt)
        else:
            self.generic_visit(node)


class ProjectParser:
    """Parses Python source code in a project directory into ASTs and extracts nodes & calls."""

    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)
        self.functions: Dict[str, FunctionNode] = {}
        self.call_sites: List[CallSite] = []
        self.main_block_calls: List[CallSite] = []
        self.top_level_calls: List[CallSite] = []
        self.file_visitors: Dict[str, ProjectASTVisitor] = {}

    def parse(self) -> "ProjectParser":
        """Discovers and parses all .py files in the target path."""
        if os.path.isfile(self.project_path):
            py_files = [self.project_path]
            base_dir = os.path.dirname(self.project_path)
        else:
            py_files = []
            for root, _, files in os.walk(self.project_path):
                # Skip virtual environments and hidden dirs
                if any(ignored in root for ignored in (".venv", "venv", ".git", "__pycache__", ".pytest_cache")):
                    continue
                for file in files:
                    if file.endswith(".py"):
                        py_files.append(os.path.join(root, file))
            base_dir = self.project_path

        for file_path in py_files:
            self._parse_file(file_path, base_dir)

        return self

    def _parse_file(self, file_path: str, base_dir: str) -> None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=file_path)
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return

        module_name = get_module_name_from_path(file_path, base_dir)
        visitor = ProjectASTVisitor(file_path=file_path, module_name=module_name)
        visitor.visit(tree)

        self.file_visitors[file_path] = visitor
        self.functions.update(visitor.functions)
        self.call_sites.extend(visitor.call_sites)
        self.main_block_calls.extend(visitor.main_block_calls)
        self.top_level_calls.extend(visitor.top_level_calls)
