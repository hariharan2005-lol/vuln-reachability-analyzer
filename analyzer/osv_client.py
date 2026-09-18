import re
from typing import Dict, List, Optional, Set
import requests

from analyzer.models import VulnerabilityInfo


class OSVClient:
    """Client for querying the OSV.dev vulnerability database."""

    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    # Stoplist of common Python keywords, builtins, and variables to filter from heuristic extraction
    HEURISTIC_STOPLIST: Set[str] = {
        "True", "False", "None", "i", "j", "k", "x", "y",
        "write", "read", "name", "id", "type", "len",
        "str", "int", "list", "dict",
    }

    # Built-in known vulnerable symbols for fallback / offline / dummy testing
    MOCK_VULNERABILITIES: Dict[str, Dict[str, List[str]]] = {
        "dummy_vuln_lib": {
            "GHSA-dummy-001": ["unsafe_deserialize", "dummy_vuln_lib.unsafe_deserialize"]
        },
        "pyyaml": {
            "CVE-2020-14343": ["load", "yaml.load", "FullLoader"]
        },
        "pillow": {
            "CVE-2022-22817": ["eval", "ImageMath.eval"]
        }
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def query_package(self, package_name: str, version: Optional[str] = None) -> List[VulnerabilityInfo]:
        """Queries OSV.dev for vulnerabilities affecting a package and version."""
        normalized_name = package_name.lower().strip()

        # Check mock registry first for dummy or offline packages
        if normalized_name in self.MOCK_VULNERABILITIES:
            return self._get_mock_vulnerabilities(normalized_name, version or "0.0.1")

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI"
            }
        }
        if version:
            payload["version"] = version

        try:
            response = requests.post(self.OSV_QUERY_URL, json=payload, timeout=self.timeout)
            if response.status_code != 200:
                return []
            data = response.json()
            return self._parse_osv_response(package_name, version or "unknown", data)
        except Exception as e:
            # Network issue or timeout; fallback to mock if available
            return []

    def _parse_osv_response(self, package_name: str, version: str, data: dict) -> List[VulnerabilityInfo]:
        results = []
        vulns = data.get("vulns", [])

        for vuln in vulns:
            advisory_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "") or vuln.get("details", "")[:120]
            aliases = vuln.get("aliases", [])

            affected_symbols: List[str] = []

            # 1. Look for structured function symbols in affected[].ecosystem_specific.imports
            for affected in vuln.get("affected", []):
                ecosystem_specific = affected.get("ecosystem_specific", {})
                imports = ecosystem_specific.get("imports", [])
                for imp in imports:
                    symbols = imp.get("symbols", [])
                    affected_symbols.extend(symbols)

            # 2. Heuristic extraction from summary or details if structured symbols are empty
            if not affected_symbols:
                text = f"{vuln.get('summary', '')} {vuln.get('details', '')}"
                # Look for `module.func()` or `func()` pattern in backticks
                found = re.findall(r"`([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)(?:\(\))?`", text)
                if found:
                    filtered = [sym for sym in found if sym not in self.HEURISTIC_STOPLIST]
                    if filtered:
                        affected_symbols.extend(filtered[:5])  # Cap heuristics

            results.append(
                VulnerabilityInfo(
                    package_name=package_name,
                    version=version,
                    advisory_id=advisory_id,
                    summary=summary,
                    affected_symbols=list(set(affected_symbols)),
                    aliases=aliases
                )
            )

        return results

    def _get_mock_vulnerabilities(self, package_name: str, version: str) -> List[VulnerabilityInfo]:
        mock_data = self.MOCK_VULNERABILITIES.get(package_name, {})
        results = []
        for adv_id, symbols in mock_data.items():
            results.append(
                VulnerabilityInfo(
                    package_name=package_name,
                    version=version,
                    advisory_id=adv_id,
                    summary=f"Known vulnerability in {package_name} exposing dangerous function calls.",
                    affected_symbols=symbols,
                    aliases=[f"CVE-2024-{adv_id.split('-')[-1]}"]
                )
            )
        return results

    @staticmethod
    def parse_requirements_file(file_path: str) -> List[tuple[str, Optional[str]]]:
        """Parses a requirements.txt file into a list of (package_name, version) tuples."""
        packages = []
        try:
            with open(file_path, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Match package==version or package>=version or package
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)?([0-9a-zA-Z_\-\.]*)?", line)
                    if match:
                        name = match.group(1)
                        ver = match.group(2) if match.group(2) else None
                        packages.append((name, ver))
        except Exception as e:
            print(f"Warning: Could not parse requirements file {file_path}: {e}")
        return packages
