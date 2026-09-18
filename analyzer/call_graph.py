from collections import defaultdict
from typing import Dict, List, Optional, Set

from analyzer.ast_parser import ProjectParser
from analyzer.models import CallSite, FunctionNode


class CallGraph:
    """Directed graph representing caller -> callee relationships across the application."""

    def __init__(self):
        self.nodes: Dict[str, Optional[FunctionNode]] = {}
        self.edges: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_edges: Dict[str, Set[str]] = defaultdict(set)

    def add_node(self, symbol: str, node_info: Optional[FunctionNode] = None) -> None:
        if symbol not in self.nodes or (self.nodes[symbol] is None and node_info is not None):
            self.nodes[symbol] = node_info

    def add_edge(self, caller: str, callee: str) -> None:
        self.add_node(caller)
        self.add_node(callee)
        self.edges[caller].add(callee)
        self.reverse_edges[callee].add(caller)

    def get_callees(self, symbol: str) -> Set[str]:
        return self.edges.get(symbol, set())

    def get_callers(self, symbol: str) -> Set[str]:
        return self.reverse_edges.get(symbol, set())

    def has_node(self, symbol: str) -> bool:
        return symbol in self.nodes

    def find_matching_nodes(self, target: str) -> List[str]:
        """
        Finds all nodes matching the target string.
        Matches exact symbol ('dummy_vuln_lib.unsafe_deserialize')
        or suffix/name ('unsafe_deserialize').
        """
        matches = []
        target_lower = target.lower()
        for node in self.nodes:
            node_lower = node.lower()
            if node_lower == target_lower:
                matches.append(node)
            elif node_lower.endswith(f".{target_lower}"):
                matches.append(node)
        return matches

    @classmethod
    def build_from_parser(cls, parser: ProjectParser) -> "CallGraph":
        """Builds a CallGraph from a parsed ProjectParser instance."""
        graph = cls()

        # 1. Register all declared functions/methods
        for symbol, func_node in parser.functions.items():
            graph.add_node(symbol, func_node)

        # Set of all defined symbols for fast resolution
        defined_symbols = set(parser.functions.keys())

        # 2. Process regular call sites
        for call in parser.call_sites:
            caller = call.caller_symbol
            callee_raw = call.callee_name
            resolved_callee = cls._resolve_call_target(caller, callee_raw, defined_symbols)
            graph.add_edge(caller, resolved_callee)

        # 3. Process calls inside if __name__ == '__main__':
        for call in parser.main_block_calls:
            caller = call.caller_symbol
            callee_raw = call.callee_name
            resolved_callee = cls._resolve_call_target(caller, callee_raw, defined_symbols)
            graph.add_edge(caller, resolved_callee)

        # 4. Process module-level / top-level calls (e.g. Streamlit scripts or data scripts)
        for call in parser.top_level_calls:
            caller = call.caller_symbol
            callee_raw = call.callee_name
            resolved_callee = cls._resolve_call_target(caller, callee_raw, defined_symbols)
            graph.add_edge(caller, resolved_callee)

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
