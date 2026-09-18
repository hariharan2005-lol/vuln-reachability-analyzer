# Function-Level Vulnerability Reachability Analyzer (`vuln-reachability-analyzer`)

A static analysis tool that determines not just which dependencies have known vulnerabilities, but whether the vulnerable functions inside those dependencies are actually reachable from your application's entry points.

## Features

- **AST-Based Call Graph Construction**: Uses Python's native `ast` module to extract functions, classes, methods, import aliases, and function invocations without running target code.
- **Entry Point Detection**: Automatically discovers Flask routes (`@app.route`), FastAPI endpoints (`@app.get`, `@app.post`), Click CLI commands, Streamlit scripts, general top-level script execution, and `if __name__ == '__main__':` blocks.
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
│   ├── entry_points.py     # Entry point detection (Flask, FastAPI, Streamlit, __main__)
│   ├── models.py           # Typed dataclasses
│   ├── osv_client.py       # OSV.dev API client & requirements parser
│   └── reachability.py     # DFS/BFS traversal engine
├── samples/
│   ├── sample_flask_app/   # Sample Flask application
│   │   ├── app.py
│   │   └── requirements.txt
│   └── sample_streamlit_app/  # Sample Streamlit application
│       └── app.py
├── tests/                  # Unit tests for all modules
│   ├── test_ast_parser.py
│   ├── test_call_graph.py
│   ├── test_cli.py
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

## Known Limitations

This tool was validated against real-world projects (a 400-node FastAPI codebase and a Streamlit/LangChain app), and testing surfaced a few honest limitations worth knowing about:

**1. Symbol matching can produce false positives on common names.**
The reachability engine matches vulnerable function names from OSV advisories against the call graph by name, without always distinguishing *which module* a symbol comes from. For example, testing against a real FastAPI project flagged `io.BytesIO()` — a completely standard, safe Python stdlib call — as "REACHABLE" for a `pypdf`-specific vulnerability advisory that also happened to mention `BytesIO`. The call itself was safe; the match was a same-name coincidence, not a real vulnerable code path. Results should be treated as a strong signal to investigate, not a guaranteed finding — always check the reported call path before treating a REACHABLE result as confirmed.

**2. Heuristic symbol extraction from unstructured OSV advisories is noisy.**
When an OSV advisory doesn't provide structured `affected.ecosystem_specific.imports` data, the tool falls back to regex-extracting backtick-wrapped terms from the advisory's free-text summary. This can pull in generic words that aren't real function names (e.g. `True`, `i`, `write`, `name` were extracted from a `python-multipart` advisory in testing). These almost always resolve to NOT REACHABLE harmlessly, but they add noise to the output table.

**3. Entry point detection covers common frameworks, not all of them.**
Currently supports Flask, FastAPI, CLI (`argparse`/`click`), Streamlit, and general top-level script execution. Frameworks with less conventional startup patterns (e.g. Django's URL routing, Celery task queues, background job schedulers) aren't yet detected and may require passing `--target-func` directly instead of relying on automatic entry point discovery.

**4. Dynamic dispatch isn't traced.**
Calls made via `getattr()`, `**kwargs` unpacking, or other runtime-resolved dispatch patterns aren't captured by the static call graph, since they can't be determined without executing the code. This is a known limitation of static analysis generally, not specific to this tool.


## Real-World Validation

To move beyond documenting limitations in the abstract, the tool was run against a real 400-node call graph (29 files, FastAPI backend with `pypdf`, `python-multipart`, and `pillow` dependencies — see [Document Intelligence Pipeline] for the target project). 

- **18 real entry points** were automatically detected (6 FastAPI routes, 12 top-level module entries) with no manual configuration needed.
- Of the vulnerable symbols pulled from live OSV.dev advisories across 3 packages, **2 were flagged REACHABLE**. Manual review confirmed **1 of the 2 was a false positive** (`io.BytesIO`, a stdlib name collision with an unrelated `pypdf` advisory), and 1 was a plausible true positive.
- After adding stoplist filtering for common Python keywords/builtins to the OSV heuristic extractor (see commit `b42caaf`), obvious noise symbols (`True`, `i`, `write`, `name`) were eliminated from the output entirely, reducing the total flagged-symbol count without affecting the REACHABLE/NOT REACHABLE findings.

This is a small sample, not a rigorous benchmark — but it's a real number from a real codebase rather than a hypothetical.