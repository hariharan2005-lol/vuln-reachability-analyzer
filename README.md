```markdown
# Function-Level Vulnerability Reachability Analyzer

A static analysis tool that determines not just which dependencies have known vulnerabilities, but whether the vulnerable functions inside those dependencies are actually reachable from your application's entry points.

---

## Features

- **AST-Based Call Graph Construction**: Uses Python's native `ast` module to extract functions, classes, methods, import aliases, and function invocations without running target code.
- **Import Origin Resolution & Stdlib Protection**: Traces every call site to its resolved import origin using AST alias mapping and `sys.stdlib_module_names`. Calls to Python standard library modules (such as `io.BytesIO()`, `os`, `sys`, `json`) are rejected when an advisory targets a third-party package, preventing false-positive matches.
- **Entry Point Detection**: Automatically discovers Flask routes (`@app.route`), FastAPI endpoints (`@app.get`, `@app.post`), Click CLI commands, Streamlit scripts, general top-level script execution, and `if __name__ == '__main__':` blocks.
- **OSV.dev Integration**: Connects to the OSV.dev vulnerability database to fetch advisories for dependencies declared in `requirements.txt` and identify vulnerable function symbols.
- **Pure Local RAG Advisory Symbol Extraction**: Leverages a local embedding model (`all-MiniLM-L6-v2`) and persistent vector store (`chromadb`) to semantically extract vulnerable symbols and filter out remediation suggestions (e.g., distinguishing `load` from `safe_load`) completely offline with no paid API keys. Regex fallback heuristics have been entirely eliminated in favor of deterministic confidence thresholds.
- **Cycle-Safe Reachability Analysis**: Implements Depth-First Search (DFS) and Breadth-First Search (BFS) graph traversal algorithms to trace call paths from entry points to vulnerable functions.
- **Rich Terminal & JSON Output**: Formatted tables, call chains with step-by-step arrows (`login() -> process_user() -> parse_input() -> unsafe_deserialize()`), and JSON output for CI/CD pipelines.

---

## Project Structure

```text
vuln-reachability-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── ast_parser.py          # AST parsing & symbol/origin extraction
│   ├── call_graph.py          # Directed call graph & origin compatibility checks
│   ├── data/
│   │   ├── advisory_examples.json  # Curated advisory training pairs
│   │   └── chroma_db/              # Local ChromaDB persistent vector store
│   ├── entry_points.py        # Entry point detection (Flask, FastAPI, Streamlit, main)
│   ├── models.py              # Typed dataclasses (CallSite, ReachabilityResult, etc.)
│   ├── osv_client.py          # OSV.dev API client & requirements parser
│   ├── rag_extractor.py       # Pure local RAG symbol extractor (SentenceTransformers + ChromaDB)
│   └── reachability.py        # DFS/BFS traversal engine with origin verification
├── samples/
│   ├── sample_flask_app/      # Sample Flask application
│   │   ├── app.py
│   │   └── requirements.txt
│   └── sample_streamlit_app/  # Sample Streamlit application
│       └── app.py
├── tests/                     # Unit & regression test suite
│   ├── test_ast_parser.py
│   ├── test_call_graph.py
│   ├── test_cli.py
│   ├── test_entry_points.py
│   ├── test_osv_client.py
│   ├── test_rag_extractor.py
│   └── test_reachability.py
├── cli.py                     # Command-line interface
└── requirements.txt           # Tool dependencies

```

---

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

---

## Known Limitations

> [!NOTE]
> **1. Module Import Origin Resolution & Third-Party Namespaces**
> The analyzer traces call sites back to their source modules to prevent bare-name collisions with standard library functions (`io`, `os`, `sys`, `json`, etc.). When a call resolves to the standard library while an advisory targets a separate package (e.g., `io.BytesIO` vs. `pypdf.BytesIO`), the engine marks it as `NOT REACHABLE (origin mismatch)` with diagnostic notes and exits with code 0. For dynamic imports, star imports (`from pkg import *`), or deep unaliased namespace packages, specify qualified target function names.

> [!NOTE]
> **2. Advisory Symbol Extraction via Pure Local RAG**
> Unstructured OSV advisories are processed exclusively via a local vector store (`chromadb`) and embedding model (`all-MiniLM-L6-v2`). All legacy regex fallbacks and heuristic pattern matching have been removed. If advisory descriptions fall below the cosine similarity threshold (< 0.5) or fail token validation, the extractor safely returns an empty list (`[]`) rather than generating noisy heuristic guesses.

> [!NOTE]
> **3. Framework & Dynamic Dispatch Coverage**
> Entry point detection covers Flask, FastAPI, Click CLI, Streamlit, and standard `__main__` blocks. Frameworks with indirect routing (such as Django URL patterns or Celery task workers) and runtime dynamic dispatches (`getattr()`, `**kwargs` dispatching, `importlib`) cannot be traced via static AST inspection and require passing `--target-func` explicitly.

---

## Real-World Validation

> [!NOTE]
> **Test Benchmark: 400-Node Production FastAPI Pipeline**
> The analyzer was evaluated against a real-world repository containing 29 source files, a 400-node call graph, and third-party dependencies including `pypdf`, `python-multipart`, and `pillow`:
> * **Automatic Entry Point Discovery**: Successfully mapped 18 entry points (6 FastAPI route endpoints and 12 top-level module initializations) without manual configuration.
> * **Resolved Stdlib Collision**: In previous versions, `io.BytesIO()` was falsely flagged as `REACHABLE` for a `pypdf` advisory due to bare symbol matching. With AST import origin tracking and `sys.stdlib_module_names` validation, this is now correctly identified as `NOT REACHABLE (origin mismatch)` with exit code 0.
> * **Pure RAG Precision**: Eliminating regex extraction and routing OSV text directly through ChromaDB successfully extracted true vulnerable call targets while rejecting remediation tokens (such as `safe_load`) and Python language keywords.
> 
> 

```

```