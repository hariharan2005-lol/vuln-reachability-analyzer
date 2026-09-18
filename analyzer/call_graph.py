import sys
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from analyzer.ast_parser import ProjectParser
from analyzer.models import CallSite, FunctionNode

STDLIB_MODULES = getattr(sys, "stdlib_module_names", frozenset({
    "io", "os", "sys", "json", "re", "collections", "math", "time", "datetime",
    "urllib", "http", "socket", "subprocess", "shutil", "tempfile", "pathlib",
    "logging", "typing", "ast", "types", "copy", "itertools", "functools",
    "hashlib", "hmac", "random", "secrets", "sqlite3", "pickle", "csv",
    "tarfile", "zipfile", "gzip", "bz2", "lzma", "zlib", "threading",
    "multiprocessing", "queue", "asyncio", "unittest", "inspect", "importlib",
    "contextlib", "string", "traceback", "warnings", "weakref", "gc", "platform"
}))


def normalize_pkg_name(name: str) -> str:
    """Normalizes package names (e.g. 'dummy-vuln-lib' -> 'dummy_vuln_lib')."""
    return name.replace("-", "_").lower().strip()


def is_origin_compatible(origin: Optional[str], target_package: Optional[str]) -> bool:
    """
    Checks if a node's origin module is compatible with target_package.
    - If target_package is not specified, returns True.
    - If origin is a stdlib module and target_package is not that stdlib module, returns False.
    - If target_package is specified, origin must match target_package (exact, submodule, or parent).
    """
    if not target_package:
        return True

    pkg_norm = normalize_pkg_name(target_package)
    if not origin:
        return True

    orig_norm = normalize_pkg_name(origin)
    orig_root = orig_norm.split(".")[0]

    # Stdlib check: if origin is stdlib and target_package is not that stdlib module
    if orig_root in STDLIB_MODULES and pkg_norm != orig_root:
        return False

    # Check if origin matches target package
    if orig_norm == pkg_norm or orig_root == pkg_norm:
        return True
    if orig_norm.startswith(f"{pkg_norm}."):
        return True
    if pkg_norm.startswith(f"{orig_norm}."):
        return True

    return False


class CallGraph:
    """Directed graph representing caller -> callee relationships across the application."""

    def __init__(self):
        self.nodes: Dict[str, Optional[FunctionNode]] = {}
        self.node_origins: Dict[str, Optional[str]] = {}
        self.edges: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_edges: Dict[str, Set[str]] = defaultdict(set)

    def add_node(
        self,
        symbol: str,
        node_info: Optional[FunctionNode] = None,
        origin: Optional[str] = None,
    ) -> None:
        if symbol not in self.nodes or (self.nodes[symbol] is None and node_info is not None):
            self.nodes[symbol] = node_info
        if origin is not None:
            self.node_origins[symbol] = origin
        elif symbol not in self.node_origins:
            if "." in symbol:
                self.node_origins[symbol] = symbol.split(".")[0]
            else:
                self.node_origins[symbol] = None

    def add_edge(self, caller: str, callee: str, callee_origin: Optional[str] = None) -> None:
        self.add_node(caller)
        self.add_node(callee, origin=callee_origin)
        self.edges[caller].add(callee)
        self.reverse_edges[callee].add(caller)

    def get_node_origin(self, symbol: str) -> Optional[str]:
        return self.node_origins.get(symbol)

    def get_callees(self, symbol: str) -> Set[str]:
        return self.edges.get(symbol, set())

    def get_callers(self, symbol: str) -> Set[str]:
        return self.reverse_edges.get(symbol, set())

    def has_node(self, symbol: str) -> bool:
        return symbol in self.nodes

    def find_matching_nodes(self, target: str, package_name: Optional[str] = None) -> List[str]:
        """
        Finds all nodes matching the target string.
        Matches exact symbol ('dummy_vuln_lib.unsafe_deserialize')
        or suffix/name ('unsafe_deserialize').
        Filters out nodes whose origin is incompatible with target package.
        """
        matches = []
        target_lower = target.lower()

        inferred_pkg = package_name
        if not inferred_pkg and "." in target:
            inferred_pkg = target.split(".")[0]

        for node in self.nodes:
            node_lower = node.lower()
            is_name_match = (node_lower == target_lower) or node_lower.endswith(f".{target_lower}")
            if not is_name_match and "." in target:
                bare_target = target.split(".")[-1].lower()
                if (node_lower == bare_target) or node_lower.endswith(f".{bare_target}"):
                    is_name_match = True

            if is_name_match:
                origin = self.get_node_origin(node)
                if is_origin_compatible(origin, inferred_pkg):
                    matches.append(node)
        return matches

    def find_origin_mismatches(self, target: str, package_name: Optional[str] = None) -> List[Tuple[str, str]]:
        """
        Finds candidate nodes that matched the bare symbol name but were excluded due to origin mismatch.
        Returns list of (node_symbol, origin_module).
        """
        mismatches = []
        inferred_pkg = package_name
        if not inferred_pkg and "." in target:
            inferred_pkg = target.split(".")[0]

        if not inferred_pkg:
            return []

        target_lower = target.lower()
        bare_target = target.split(".")[-1].lower()

        for node in self.nodes:
            node_lower = node.lower()
            is_name_match = (
                (node_lower == target_lower)
                or node_lower.endswith(f".{target_lower}")
                or (node_lower == bare_target)
                or node_lower.endswith(f".{bare_target}")
            )
            if is_name_match:
                origin = self.get_node_origin(node)
                if not is_origin_compatible(origin, inferred_pkg):
                    mismatches.append((node, origin or "unknown"))
        return mismatches

    @classmethod
    def build_from_parser(cls, parser: ProjectParser) -> "CallGraph":
        """Builds a CallGraph from a parsed ProjectParser instance."""
        graph = cls()

        # 1. Register all declared functions/methods
        for symbol, func_node in parser.functions.items():
            origin = symbol.rsplit(".", 1)[0] if "." in symbol else symbol
            graph.add_node(symbol, func_node, origin=origin)

        # Set of all defined symbols for fast resolution
        defined_symbols = set(parser.functions.keys())

        # 2. Process regular call sites
        for call in parser.call_sites:
            caller = call.caller_symbol
            callee_raw = call.callee_name
            resolved_callee = cls._resolve_call_target(caller, callee_raw, defined_symbols)
            graph.add_edge(caller, resolved_callee, callee_origin=call.callee_origin)

        # 3. Process calls inside if __name__ == '__main__':
        for call in parser.main_block_calls:
            caller = call.caller_symbol
            callee_raw = call.callee_name
            resolved_callee = cls._resolve_call_target(caller, callee_raw, defined_symbols)
            graph.add_edge(caller, resolved_callee, callee_origin=call.callee_origin)

        # 4. Process module-level / top-level calls (e.g. Streamlit scripts or data scripts)
        for call in parser.top_level_calls:
            caller = call.caller_symbol
            callee_raw = call.callee_name
            resolved_callee = cls._resolve_call_target(caller, callee_raw, defined_symbols)
            graph.add_edge(caller, resolved_callee, callee_origin=call.callee_origin)

        return graph

    @staticmethod
    def _resolve_call_target(caller_symbol: str, callee_raw: str, defined_symbols: Set[str]) -> str:
        """
        Resolves callee relative to caller's module if it's an unqualified local call.
        e.g. caller = 'app.login', callee = 'process_user' -> 'app.process_user' (if defined)
        """
        # If it's already an exact match to a defined symbol
        if callee_raw in defined_symbols:
            return callee_raw

        # Extract caller's module
        module_prefix = caller_symbol.rsplit(".", 1)[0]
        # In case caller is a method (e.g. 'app.MyClass.method'), check root module too
        root_module = caller_symbol.split(".")[0]

        candidate_module_callee = f"{module_prefix}.{callee_raw}"
        if candidate_module_callee in defined_symbols:
            return candidate_module_callee

        candidate_root_callee = f"{root_module}.{callee_raw}"
        if candidate_root_callee in defined_symbols:
            return candidate_root_callee

        # Otherwise, assume callee_raw (e.g. external import or third-party call)
        return callee_raw

    @property
    def total_nodes(self) -> int:
        return len(self.nodes)

    @property
    def total_edges(self) -> int:
        return sum(len(callees) for callees in self.edges.values())
