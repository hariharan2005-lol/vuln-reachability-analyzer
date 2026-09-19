```text
# Function-Level Vulnerability Reachability Analyzer

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-unittest%20passing-brightgreen.svg)](tests/)
[![Security Gate](https://img.shields.io/badge/CI%2FCD-exit%20code%20enforced-orange.svg)](#cicd-integration)

A deterministic static analysis tool that cuts false alarms by checking whether vulnerable open-source functions (CVE/OSV) are **actually reachable** from application entry points via inter-procedural AST call graphs and local RAG advisory parsing.

---

## The Problem

Traditional Software Composition Analysis (SCA) tools scan `requirements.txt` or lockfiles and flag every package with a known CVE. In practice, applications frequently use only safe utility functions from that library without touching the vulnerable submodules. 

This creates alert fatigue and breaks builds unnecessarily. **Vulnerability Reachability Analyzer** verifies execution reachability before flagging a security hazard:

```text
┌─────────────────────────┐      ┌─────────────────────────┐
│  Dependency in Manifest │ ───► │ Is Function Reachable?  │ ───► Exit 1 (Block CI)
│  (e.g., Pillow 8.4.0)   │      │ (via AST Call Graph)    │  └─► Exit 0 (Pass CI)
└─────────────────────────┘      └─────────────────────────┘

```

---

## How It Works

```text
 PHASE 1: ADVISORY INGESTION (RAG)           PHASE 2: CODE ANALYSIS (AST)
 ───────────────────────────────────         ────────────────────────────
 requirements.txt ──► OSV.dev API            Target Python Project (*.py)
          │                                               │
          ▼                                               ▼
 Raw CVE Advisory Text                       ast.parse() & NodeVisitor
          │                                               │
          ▼ (384-dim Vectors)                             ▼
 ChromaDB + all-MiniLM-L6-v2                 Entry Points & Call Graph
          │                                               │
          ▼                                               │
 Clean Target: "PIL.ImageMath.eval"                       │
          │                                               │
          └───────────────────────┬───────────────────────┘
                                  │
                                  ▼
                     [ DFS / BFS Call Graph Search ]
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
         🔴 REACHABLE                       🟢 UNREACHABLE
        (Call Path Found)                 (Safe / Unused API)
          exit code 1                         exit code 0

```

---

## Features

* **AST-Based Call Graph Construction**: Uses Python's native `ast` module to extract functions, classes, methods, import aliases, and invocations without executing untrusted code.
* **Import Origin Resolution & Stdlib Protection**: Traces every call site to its resolved import origin using AST alias mapping and `sys.stdlib_module_names`. Calls to Python standard library modules (`io.BytesIO()`, `os`, `sys`, `json`) are rejected when an advisory targets a third-party package, eliminating false positives.
* **Automatic Entry Point Discovery**: Identifies Flask routes (`@app.route`), FastAPI endpoints (`@app.get`, `@app.post`), Click CLI commands, Streamlit scripts, and `if __name__ == '__main__':` startup routines.
* **Live OSV.dev Integration**: Queries the Open Source Vulnerability (OSV) database to retrieve current CVE advisories for packages pinned in `requirements.txt`.
* **Pure Local RAG Advisory Extraction**: Leverages a local embedding model (`all-MiniLM-L6-v2`) and an in-memory vector store (`chromadb`) to semantically extract vulnerable function symbols while discarding remediation noise (e.g., distinguishing `load` from `safe_load`). Requires zero cloud LLM keys.
* **Cycle-Safe Traversal Engine**: Implements Depth-First Search (DFS) and Breadth-First Search (BFS) graph traversals with visited state tracking to handle circular imports and recursive calls safely.
* **Deterministic CI/CD Outputs**: Generates human-readable terminal tables with step-by-step call chains (`route() -> helper() -> vuln_func()`) or structured JSON with exit code `1` (reachable) and `0` (unreachable).

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
│   ├── rag_extractor.py       # Local RAG symbol extractor (SentenceTransformers + ChromaDB)
│   └── reachability.py        # DFS/BFS traversal engine with origin verification
├── samples/
│   ├── sample_flask_app/      # Sample vulnerable Flask application
│   └── sample_streamlit_app/  # Sample Streamlit application
├── tests/                     # Unit & integration test suite
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

### 1. Installation

```bash
git clone [https://github.com/hariharan2005-lol/vuln-reachability-analyzer.git](https://github.com/hariharan2005-lol/vuln-reachability-analyzer.git)
cd vuln-reachability-analyzer
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

```

### 2. Run the Test Suite

```bash
python -m unittest discover tests

```

### 3. Usage Examples

**Scan a project against an automated OSV requirements check:**

```bash
python cli.py --path ./samples/sample_flask_app --requirements ./samples/sample_flask_app/requirements.txt

```

**Target a specific vulnerable function explicitly:**

```bash
python cli.py --path ./samples/sample_flask_app --target-func dummy_vuln_lib.unsafe_deserialize

```

**Traverse using Breadth-First Search (BFS):**

```bash
python cli.py --path ./samples/sample_flask_app --target-func dummy_vuln_lib.unsafe_deserialize --strategy bfs

```

**Output machine-readable JSON for CI/CD:**

```bash
python cli.py --path ./samples/sample_flask_app --target-func dummy_vuln_lib.unsafe_deserialize --format json

```

---

## CI/CD Integration

Use the analyzer as an automated security quality gate in GitHub Actions:

```yaml
# .github/workflows/reachability-gate.yml
name: Reachability Security Gate

on: [push, pull_request]

jobs:
  reachability-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Analyzer Dependencies
        run: pip install -r requirements.txt

      - name: Run Reachability Check
        run: |
          python cli.py --path ./src --requirements ./requirements.txt --format json

```

---

## Known Limitations

> [!NOTE]
> **1. Module Import Origin Resolution & Third-Party Namespaces**
> The analyzer traces call sites back to their source modules to prevent bare-name collisions with standard library functions (`io`, `os`, `sys`, `json`, etc.). When a call resolves to the standard library while an advisory targets a separate package (e.g., `io.BytesIO` vs. `pypdf.BytesIO`), the engine marks it as `NOT REACHABLE (origin mismatch)` with diagnostic notes and exits with code 0. For dynamic imports, star imports (`from pkg import *`), or deep unaliased namespace packages, specify qualified target function names.

> [!NOTE]
> **2. Advisory Symbol Extraction via Pure Local RAG**
> Unstructured OSV advisories are processed exclusively via an offline vector store (`chromadb`) and embedding model (`all-MiniLM-L6-v2`). Legacy regex heuristics have been removed. If advisory descriptions fall below the cosine similarity threshold (< 0.5) or fail token validation, the extractor safely returns an empty list (`[]`) rather than generating noisy heuristic guesses.

> [!NOTE]
> **3. Dynamic Dispatch & Indirect Routing**
> Entry point detection supports Flask, FastAPI, Click CLI, Streamlit, and standard `__main__` blocks. Frameworks relying heavily on dynamic runtime routing (such as Django URL patterns or Celery task brokers) and dynamic dispatch patterns (`getattr()`, `**kwargs` dispatching, `importlib`) cannot be fully resolved via static AST inspection and require passing `--target-func` explicitly.

---

## Real-World Validation

> [!NOTE]
> **Benchmark: 400-Node Production FastAPI Pipeline**
> Evaluated against a real-world repository containing 29 source files, a 400-node call graph, and third-party dependencies including `pypdf`, `python-multipart`, and `pillow`:
> * **Automatic Entry Point Discovery**: Successfully mapped 18 entry points (6 FastAPI route endpoints and 12 top-level module initializations) without manual configuration.
> * **Resolved Stdlib Collisions**: `io.BytesIO()` was prevented from matching a `pypdf` vulnerability advisory through AST import origin tracking and `sys.stdlib_module_names` validation, correctly reporting `NOT REACHABLE (origin mismatch)` with exit code 0.
> * **Pure RAG Precision**: Extracted true vulnerable call targets while rejecting remediation tokens (`safe_load`) and standard language keywords.
> 
> 

```

```
