import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from analyzer.ast_parser import ProjectParser
from analyzer.call_graph import CallGraph
from analyzer.entry_points import EntryPointDetector
from analyzer.models import EntryPoint, ReachabilityResult, VulnerabilityInfo
from analyzer.osv_client import OSVClient
from analyzer.reachability import ReachabilityEngine


def format_path_string(path: List[str]) -> str:
    """Formats a list of symbol names as a readable arrow-delimited call chain."""
    formatted = []
    for sym in path:
        if "(" not in sym:
            formatted.append(f"{sym}()")
        else:
            formatted.append(sym)
    return " -> ".join(formatted)


def run_analysis(
    project_path: str,
    target_func: Optional[str] = None,
    requirements_file: Optional[str] = None,
    strategy: str = "dfs",
    all_paths: bool = False,
) -> tuple[ProjectParser, CallGraph, List[EntryPoint], List[ReachabilityResult]]:
    """Executes the analysis pipeline on the specified project."""
    project_path = os.path.abspath(project_path)
    if not os.path.exists(project_path):
        raise FileNotFoundError(f"Project directory not found: {project_path}")

    parser = ProjectParser(project_path)
    parser.parse()

    graph = CallGraph.build_from_parser(parser)

    detector = EntryPointDetector(parser)
    entry_points = detector.detect()

    targets_to_check: List[tuple[str, Optional[str], Optional[str]]] = []  # (symbol, pkg_name, advisory_id)

    if target_func:
        targets_to_check.append((target_func, None, None))

    req_path = None
    if requirements_file:
        if not os.path.exists(requirements_file) or not os.path.isfile(requirements_file):
            print(f"Warning: Requirements file '{requirements_file}' not found or unreadable.", file=sys.stderr)
        else:
            try:
                with open(requirements_file, "r", encoding="utf-8-sig") as _:
                    pass
                req_path = requirements_file
            except Exception as e:
                print(f"Warning: Requirements file '{requirements_file}' not found or unreadable: {e}", file=sys.stderr)
    elif not target_func:
        auto_req = os.path.join(project_path, "requirements.txt")
        if os.path.exists(auto_req) and os.path.isfile(auto_req):
            req_path = auto_req

    if req_path:
        osv_client = OSVClient()
        packages = osv_client.parse_requirements_file(req_path)
        if not packages and requirements_file:
            print(f"Warning: Requirements file '{req_path}' parsed but contained no recognizable packages.", file=sys.stderr)
        for pkg_name, version in packages:
            vulns = osv_client.query_package(pkg_name, version)
            for v in vulns:
                for sym in v.affected_symbols:
                    targets_to_check.append((sym, v.package_name, v.advisory_id))

    engine = ReachabilityEngine(graph, entry_points)
    results: List[ReachabilityResult] = []

    for symbol, pkg, adv_id in targets_to_check:
        res = engine.check_reachability(
            target_symbol=symbol,
            strategy=strategy,
            find_all_paths=all_paths,
            package_name=pkg,
        )
        res.package_name = pkg
        res.advisory_id = adv_id
        results.append(res)

    return parser, graph, entry_points, results


def output_rich(
    project_path: str,
    parser: ProjectParser,
    graph: CallGraph,
    entry_points: List[EntryPoint],
    results: List[ReachabilityResult],
) -> None:
    console = Console(highlight=False)

    console.print()
    header_content = (
        f"[bold cyan]Target Project:[/bold cyan] {project_path}\n"
        f"[bold cyan]Source Files Analyzed:[/bold cyan] {len(parser.file_visitors)}\n"
        f"[bold cyan]Functions Discovered:[/bold cyan] {len(parser.functions)}\n"
        f"[bold cyan]Call Graph:[/bold cyan] {graph.total_nodes} nodes, {graph.total_edges} directed edges\n"
        f"[bold cyan]Entry Points Detected:[/bold cyan] {len(entry_points)}"
    )
    console.print(Panel(header_content, title="[bold white]Vulnerability Reachability Analysis[/bold white]", border_style="cyan"))

    if entry_points:
        ep_table = Table(title="Detected Entry Points", show_header=True, header_style="bold magenta")
        ep_table.add_column("Symbol", style="cyan")
        ep_table.add_column("Type", style="yellow")
        ep_table.add_column("Location", style="white")
        ep_table.add_column("Details", style="dim")

        for ep in entry_points:
            rel_file = os.path.relpath(ep.file_path, project_path)
            meta_desc = ep.metadata.get("decorator") or ep.metadata.get("description") or ""
            ep_table.add_row(
                ep.symbol,
                ep.entry_type.value,
                f"{rel_file}:{ep.line_number}",
                str(meta_desc)
            )
        console.print(ep_table)
        console.print()

    vuln_table = Table(title="Vulnerability Reachability Summary", show_header=True, header_style="bold blue")
    vuln_table.add_column("Target Vulnerable Function", style="white", no_wrap=True)
    vuln_table.add_column("Package / Advisory", style="yellow")
    vuln_table.add_column("Status", justify="center")
    vuln_table.add_column("Reachable Paths Found", justify="right")

    for res in results:
        pkg_desc = f"{res.package_name or 'N/A'} ({res.advisory_id or 'Manual'})"
        if res.is_reachable:
            status_text = "[bold white on red] REACHABLE [/bold white on red]"
            path_count = f"[red]{len(res.paths)}[/red]"
        elif res.notes:
            status_text = "[bold yellow] NOT REACHABLE [/bold yellow]\n[dim](origin mismatch)[/dim]"
            path_count = "[yellow]0[/yellow]"
        else:
            status_text = "[bold white on green] NOT REACHABLE [/bold white on green]"
            path_count = "[green]0[/green]"
        vuln_table.add_row(res.target_symbol, pkg_desc, status_text, path_count)

    console.print(vuln_table)
    console.print()

    mismatched_results = [r for r in results if not r.is_reachable and r.notes]
    if mismatched_results:
        console.print("[dim yellow]Note on filtered name collisions / origin mismatches:[/dim yellow]")
        for res in mismatched_results:
            console.print(f"  [dim]- {res.target_symbol}: {res.notes}[/dim]")
        console.print()

    reachable_results = [r for r in results if r.is_reachable]
    if reachable_results:
        console.print("[bold red](!) REACHABLE CALL PATHS DETECTED:[/bold red]")
        for res in reachable_results:
            adv_str = f" [{res.advisory_id}]" if res.advisory_id else ""
            console.print(f"\n  [bold underline]Vulnerable Symbol:[/bold underline] [yellow]{res.target_symbol}[/yellow]{adv_str}")
            for idx, path in enumerate(res.paths, 1):
                chain_str = format_path_string(path)
                console.print(f"    [bold cyan]Path #{idx}:[/bold cyan] {chain_str}")
        console.print()
    else:
        console.print("[bold green](+) No reachable vulnerable functions found from any registered entry point.[/bold green]\n")


def output_plain(
    project_path: str,
    parser: ProjectParser,
    graph: CallGraph,
    entry_points: List[EntryPoint],
    results: List[ReachabilityResult],
) -> None:
    print("=" * 70)
    print("FUNCTION-LEVEL VULNERABILITY REACHABILITY ANALYZER")
    print("=" * 70)
    print(f"Project Path:          {project_path}")
    print(f"Files Analyzed:        {len(parser.file_visitors)}")
    print(f"Functions Discovered:  {len(parser.functions)}")
    print(f"Call Graph:            {graph.total_nodes} nodes, {graph.total_edges} edges")
    print(f"Entry Points Detected: {len(entry_points)}")
    print("-" * 70)

    print("ENTRY POINTS:")
    for ep in entry_points:
        rel_file = os.path.relpath(ep.file_path, project_path)
        meta = ep.metadata.get("decorator") or ep.metadata.get("description") or ""
        print(f"  * {ep.symbol} [{ep.entry_type.value}] at {rel_file}:{ep.line_number} {meta}")
    print("-" * 70)

    print("REACHABILITY RESULTS:")
    for res in results:
        status = "REACHABLE" if res.is_reachable else "NOT REACHABLE"
        print(f"\n[ {status} ] Target: {res.target_symbol}")
        if res.package_name:
            print(f"  Package:  {res.package_name} ({res.advisory_id})")
        if not res.is_reachable and res.notes:
            print(f"  Note:     {res.notes}")
        if res.is_reachable:
            print(f"  Found {len(res.paths)} path(s):")
            for idx, path in enumerate(res.paths, 1):
                print(f"    Path #{idx}: {format_path_string(path)}")
    print("=" * 70)


def output_json(results: List[ReachabilityResult], entry_points: List[EntryPoint]) -> None:
    output_data = {
        "entry_points": [
            {
                "symbol": ep.symbol,
                "type": ep.entry_type.value,
                "file_path": ep.file_path,
                "line_number": ep.line_number,
                "metadata": ep.metadata,
            }
            for ep in entry_points
        ],
        "results": [
            {
                "target_symbol": res.target_symbol,
                "is_reachable": res.is_reachable,
                "package_name": res.package_name,
                "advisory_id": res.advisory_id,
                "notes": res.notes,
                "paths": res.paths,
            }
            for res in results
        ],
    }
    print(json.dumps(output_data, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Function-Level Vulnerability Reachability Analyzer (vuln-reachability-analyzer)"
    )
    parser.add_argument(
        "--path",
        "-p",
        default=".",
        help="Path to target project directory to analyze (default: current directory)",
    )
    parser.add_argument(
        "--target-func",
        "-t",
        default=None,
        help="Target vulnerable function name/symbol (e.g. 'dummy_vuln_lib.unsafe_deserialize' or 'unsafe_deserialize')",
    )
    parser.add_argument(
        "--requirements",
        "-r",
        default=None,
        help="Path to requirements.txt for automatic vulnerability lookup via OSV.dev",
    )
    parser.add_argument(
        "--strategy",
        "-s",
        choices=["dfs", "bfs"],
        default="dfs",
        help="Graph search algorithm (default: dfs)",
    )
    parser.add_argument(
        "--all-paths",
        action="store_true",
        help="Find all reachable paths instead of terminating after the first match",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    args = parser.parse_args()

    try:
        ast_parser, graph, entry_points, results = run_analysis(
            project_path=args.path,
            target_func=args.target_func,
            requirements_file=args.requirements,
            strategy=args.strategy,
            all_paths=args.all_paths,
        )
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(2)

    # If no target function was specified and no requirements-based targets were found, exit cleanly
    if not results and not args.target_func:
        auto_req_path = os.path.join(os.path.abspath(args.path), "requirements.txt")
        has_auto_req = os.path.isfile(auto_req_path)
        if not args.requirements and not has_auto_req:
            print("No target function specified and no requirements.txt found in target project directory — nothing to check.", file=sys.stderr)
        else:
            print("No target function specified and no vulnerabilities found via requirements file — nothing to check.", file=sys.stderr)
        sys.exit(2)

    if args.format == "json":
        output_json(results, entry_points)
    else:
        if HAS_RICH:
            output_rich(os.path.abspath(args.path), ast_parser, graph, entry_points, results)
        else:
            output_plain(os.path.abspath(args.path), ast_parser, graph, entry_points, results)

    # Return exit code 1 if any target is reachable, else 0
    any_reachable = any(res.is_reachable for res in results)
    sys.exit(1 if any_reachable else 0)


if __name__ == "__main__":
    main()
