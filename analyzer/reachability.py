from collections import deque
from typing import List, Set, Tuple

from analyzer.call_graph import CallGraph
from analyzer.models import EntryPoint, ReachabilityResult


class ReachabilityEngine:
    """Analyzes reachability from application entry points to target functions."""

    def __init__(self, graph: CallGraph, entry_points: List[EntryPoint]):
        self.graph = graph
        self.entry_points = entry_points

    def check_reachability(
        self,
        target_symbol: str,
        strategy: str = "dfs",
        find_all_paths: bool = True,
        max_depth: int = 50,
    ) -> ReachabilityResult:
        """
        Determines whether target_symbol is reachable from any known entry point.
        """
        matching_targets = set(self.graph.find_matching_nodes(target_symbol))
        # If no exact match was found, still test against target_symbol directly
        if not matching_targets:
            matching_targets.add(target_symbol)

        all_paths: List[List[str]] = []
        reached_entry_points: List[EntryPoint] = []

        for ep in self.entry_points:
            ep_symbol = ep.symbol
            if strategy.lower() == "bfs":
                paths = self._bfs(ep_symbol, matching_targets)
            else:
                paths = self._dfs(ep_symbol, matching_targets, max_depth, find_all_paths)

            if paths:
                all_paths.extend(paths)
                reached_entry_points.append(ep)

        # Remove duplicate paths while preserving order
        unique_paths: List[List[str]] = []
        seen_paths = set()
        for p in all_paths:
            p_tuple = tuple(p)
            if p_tuple not in seen_paths:
                seen_paths.add(p_tuple)
                unique_paths.append(p)

        is_reachable = len(unique_paths) > 0

        return ReachabilityResult(
            target_symbol=target_symbol,
            is_reachable=is_reachable,
            paths=unique_paths,
            entry_points_reached=reached_entry_points,
        )

    def _dfs(
        self,
        start_node: str,
        target_symbols: Set[str],
        max_depth: int,
        find_all_paths: bool,
    ) -> List[List[str]]:
        """Cycle-safe Depth-First Search finding paths to targets."""
        found_paths: List[List[str]] = []

        def dfs_visit(current_node: str, current_path: List[str], visited_set: Set[str]):
            if len(current_path) > max_depth:
                return
            if not find_all_paths and len(found_paths) > 0:
                return

            callees = self.graph.get_callees(current_node)
            for callee in callees:
                # Check if callee matches any of our target symbols
                if callee in target_symbols:
                    found_paths.append(current_path + [callee])
                    if not find_all_paths:
                        return

                # Avoid cycles in the current path
                if callee not in visited_set:
                    visited_set.add(callee)
                    dfs_visit(callee, current_path + [callee], visited_set)
                    visited_set.remove(callee)

        # Check if the entry point itself is the target
        if start_node in target_symbols:
            return [[start_node]]

        dfs_visit(start_node, [start_node], {start_node})
        return found_paths

    def _bfs(self, start_node: str, target_symbols: Set[str]) -> List[List[str]]:
        """Breadth-First Search finding shortest path to targets."""
        if start_node in target_symbols:
            return [[start_node]]

        queue = deque([[start_node]])
        visited = {start_node}
        found_paths: List[List[str]] = []

        while queue:
            path = queue.popleft()
            node = path[-1]

            for callee in self.graph.get_callees(node):
                if callee in target_symbols:
                    found_paths.append(path + [callee])
                    return found_paths  # Return first shortest path

                if callee not in visited:
                    visited.add(callee)
                    queue.append(path + [callee])

        return found_paths
