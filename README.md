# Function-Level Vulnerability Reachability Analyzer (`vuln-reachability-analyzer`)

A static analysis tool that determines not just which dependencies have known vulnerabilities, but whether the vulnerable functions inside those dependencies are actually reachable from your application's entry points.

## Features

- **AST-Based Call Graph Construction**: Uses Python's native `ast` module to extract functions, classes, methods, import aliases, and function invocations without running target code.
- **Entry Point Detection**: Automatically discovers Flask routes (`@app.route`), FastAPI endpoints (`@app.get`, `@app.post`), Click CLI commands, and `if __name__ == '__main__':` blocks.
- **OSV.dev Integration**: Connects to the OSV.dev vulnerability database to fetch advisories for dependencies declared in `requirements.txt` and identify vulnerable function symbols.
- **Cycle-Safe Reachability Analysis**: Implements Depth-First Search (DFS) and Breadth-First Search (BFS) graph traversal algorithms to trace call paths from entry points to vulnerable functions.
- **Rich Terminal & JSON Output**: Formatted tables, call chains with step-by-step arrows (`login() → process_user() → parse_input() → unsafe_deserialize()`), and JSON output for CI/CD pipelines.

## Project Structure

```
vuln-reachability-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── ast_parser.py       # AST parsing & symbol/call extraction
│   ├── call_graph.py       # Directed call graph (nodes/edges)
│   ├── entry_points.py     # Entry point detection (Flask, FastAPI, __main__)
│   ├── models.py           # Typed dataclasses
│   ├── osv_client.py       # OSV.dev API client & requirements parser
│   └── reachability.py     # DFS/BFS traversal engine
├── samples/
│   └── sample_flask_app/   # Sample Flask application
│       ├── app.py
│       └── requirements.txt
├── tests/                  # Unit tests for all modules
│   ├── test_ast_parser.py
│   ├── test_call_graph.py
│   ├── test_entry_points.py
│   ├── test_osv_client.py
│   └── test_reachability.py
├── cli.py                  # Command-line interface
└── requirements.txt        # Tool dependencies
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Tests
```bash
python -m unittest discover tests
```

### 3. Run Analysis on the Sample Flask App
Check reachability for a target vulnerable function:
```bash
python cli.py --path ./samples/sample_flask_app --target-func dummy_vuln_lib.unsafe_deserialize
```

Check with OSV.dev automated requirements lookup:
```bash
python cli.py --path ./samples/sample_flask_app --requirements ./samples/sample_flask_app/requirements.txt
```

Run using Breadth-First Search (BFS):
```bash
python cli.py --path ./samples/sample_flask_app --target-func dummy_vuln_lib.unsafe_deserialize --strategy bfs
```

Output as JSON (useful for CI/CD integrations):
```bash
python cli.py --path ./samples/sample_flask_app --target-func dummy_vuln_lib.unsafe_deserialize --format json
```
