import re
from typing import List, Set

from analyzer.ast_parser import ProjectParser
from analyzer.models import EntryPoint, EntryPointType, FunctionNode


class EntryPointDetector:
    """Detects application entry points (web routes, CLI commands, __main__ blocks)."""

    FLASK_ROUTE_PATTERN = re.compile(r"^@?(\w+)\.route\s*\((.*)\)", re.DOTALL)
    FASTAPI_ROUTE_PATTERN = re.compile(r"^@?(\w+)\.(get|post|put|delete|patch|options|head|api_route)\s*\((.*)\)", re.DOTALL)
    CLICK_COMMAND_PATTERN = re.compile(r"^@?(click|[\w_]+)\.(command|group)\s*\(?", re.DOTALL)

    def __init__(self, parser: ProjectParser):
        self.parser = parser

    def detect(self) -> List[EntryPoint]:
        entry_points: List[EntryPoint] = []
        seen_symbols: Set[str] = set()
        files_with_route_or_cli: Set[str] = set()

        # 1. Detect entry points from function decorators
        for symbol, node in self.parser.functions.items():
            ep = self._check_function_decorators(symbol, node)
            if ep and ep.symbol not in seen_symbols:
                entry_points.append(ep)
                seen_symbols.add(ep.symbol)
                files_with_route_or_cli.add(node.file_path)

        # 2. Detect `if __name__ == '__main__':` blocks
        main_callers = {call.caller_symbol: call for call in self.parser.main_block_calls}
        main_file_paths = {call.file_path for call in self.parser.main_block_calls}
        for main_symbol, call in main_callers.items():
            if main_symbol not in seen_symbols:
                ep = EntryPoint(
                    symbol=main_symbol,
                    entry_type=EntryPointType.MAIN_BLOCK,
                    file_path=call.file_path,
                    line_number=call.line_number,
                    metadata={"description": "Execution in if __name__ == '__main__' block"}
                )
                entry_points.append(ep)
                seen_symbols.add(main_symbol)

        # 3. Streamlit detection: if a file imports streamlit, treat entire module top-level code as entry point
        for file_path, visitor in self.parser.file_visitors.items():
            if visitor.has_streamlit_import:
                module_symbol = f"{visitor.module_name}.__module__"
                if module_symbol not in seen_symbols:
                    ep = EntryPoint(
                        symbol=module_symbol,
                        entry_type=EntryPointType.STREAMLIT_SCRIPT,
                        file_path=file_path,
                        line_number=visitor.streamlit_import_lineno or 1,
                        metadata={"description": "Streamlit script top-level execution"}
                    )
                    entry_points.append(ep)
                    seen_symbols.add(module_symbol)

        # 4. General top-level script fallback: files with top-level function calls outside any def/class body
        # and outside an if __name__ == '__main__': block (for scripts that aren't Flask/FastAPI/CLI apps)
        for file_path, visitor in self.parser.file_visitors.items():
            if visitor.has_streamlit_import:
                continue
            if file_path in files_with_route_or_cli or file_path in main_file_paths:
                continue
            if visitor.top_level_calls:
                module_symbol = f"{visitor.module_name}.__module__"
                if module_symbol not in seen_symbols:
                    first_call = visitor.top_level_calls[0]
                    ep = EntryPoint(
                        symbol=module_symbol,
                        entry_type=EntryPointType.TOP_LEVEL_SCRIPT,
                        file_path=file_path,
                        line_number=first_call.line_number,
                        metadata={"description": "Top-level script execution"}
                    )
                    entry_points.append(ep)
                    seen_symbols.add(module_symbol)

        # 5. Fallback: if no entry points were found, look for standard `main()` functions
        if not entry_points:
            for symbol, node in self.parser.functions.items():
                if node.name in ("main", "run", "cli", "app_start") and symbol not in seen_symbols:
                    ep = EntryPoint(
                        symbol=symbol,
                        entry_type=EntryPointType.CUSTOM,
                        file_path=node.file_path,
                        line_number=node.line_number,
                        metadata={"description": f"Common entrypoint naming convention: {node.name}"}
                    )
                    entry_points.append(ep)
                    seen_symbols.add(symbol)

        return entry_points

    def _check_function_decorators(self, symbol: str, node: FunctionNode) -> EntryPoint | None:
        for dec in node.decorators:
            dec_clean = dec.strip()

            # Flask route check
            flask_match = self.FLASK_ROUTE_PATTERN.search(dec_clean)
            if flask_match:
                route_args = flask_match.group(2)
                return EntryPoint(
                    symbol=symbol,
                    entry_type=EntryPointType.FLASK_ROUTE,
                    file_path=node.file_path,
                    line_number=node.line_number,
                    metadata={"decorator": dec_clean, "route_args": route_args}
                )

            # FastAPI route check
            fastapi_match = self.FASTAPI_ROUTE_PATTERN.search(dec_clean)
            if fastapi_match:
                http_method = fastapi_match.group(2).upper()
                route_args = fastapi_match.group(3)
                return EntryPoint(
                    symbol=symbol,
                    entry_type=EntryPointType.FASTAPI_ROUTE,
                    file_path=node.file_path,
                    line_number=node.line_number,
                    metadata={"decorator": dec_clean, "method": http_method, "route_args": route_args}
                )

            # Click CLI check
            click_match = self.CLICK_COMMAND_PATTERN.search(dec_clean)
            if click_match:
                return EntryPoint(
                    symbol=symbol,
                    entry_type=EntryPointType.CLI_COMMAND,
                    file_path=node.file_path,
                    line_number=node.line_number,
                    metadata={"decorator": dec_clean}
                )

        return None
