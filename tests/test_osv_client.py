import tempfile
import unittest
from pathlib import Path

from analyzer.osv_client import OSVClient


class TestOSVClient(unittest.TestCase):

    def setUp(self):
        self.client = OSVClient()

    def test_parse_requirements_file(self):
        req_content = """
# Production dependencies
flask==2.3.2
dummy_vuln_lib==1.0.0
pyyaml>=5.4
requests
"""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write(req_content)
            temp_path = f.name

        try:
            packages = self.client.parse_requirements_file(temp_path)
            pkg_dict = dict(packages)
            self.assertIn("flask", pkg_dict)
            self.assertEqual(pkg_dict["flask"], "2.3.2")
            self.assertIn("dummy_vuln_lib", pkg_dict)
            self.assertEqual(pkg_dict["dummy_vuln_lib"], "1.0.0")
            self.assertIn("pyyaml", pkg_dict)
            self.assertEqual(pkg_dict["pyyaml"], "5.4")
            self.assertIn("requests", pkg_dict)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_parse_requirements_file_with_bom(self):
        # UTF-8 BOM is \xef\xbb\xbf
        content_with_bom = b"\xef\xbb\xbfdummy_vuln_lib==1.0.0\nflask==2.3.2\n"
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="wb", delete=False) as f:
            f.write(content_with_bom)
            temp_path = f.name

        try:
            packages = self.client.parse_requirements_file(temp_path)
            self.assertEqual(len(packages), 2)
            # Ensure the first package didn't retain the BOM character in its name
            self.assertEqual(packages[0], ("dummy_vuln_lib", "1.0.0"))
            self.assertEqual(packages[1], ("flask", "2.3.2"))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_mock_vulnerability_retrieval(self):
        vulns = self.client.query_package("dummy_vuln_lib", "1.0.0")
        self.assertGreater(len(vulns), 0)
        self.assertIn("unsafe_deserialize", vulns[0].affected_symbols)

    def test_parse_osv_response_structured_symbols(self):
        mock_api_data = {
            "vulns": [
                {
                    "id": "GHSA-1234-5678",
                    "summary": "Arbitrary code execution in parser",
                    "aliases": ["CVE-2023-9999"],
                    "affected": [
                        {
                            "package": {"name": "sample_lib", "ecosystem": "PyPI"},
                            "ecosystem_specific": {
                                "imports": [
                                    {
                                        "path": "sample_lib.parser",
                                        "symbols": ["parse_payload", "load_custom_config"]
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        vulns = self.client._parse_osv_response("sample_lib", "1.0.0", mock_api_data)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].advisory_id, "GHSA-1234-5678")
        self.assertIn("parse_payload", vulns[0].affected_symbols)
        self.assertIn("load_custom_config", vulns[0].affected_symbols)

    def test_parse_osv_response_delegates_to_rag(self):
        """Verify that unstructured advisory text is delegated to RAGExtractor."""
        from unittest.mock import MagicMock

        mock_rag = MagicMock()
        mock_rag.extract_symbols.return_value = ["extracted_func"]

        client = OSVClient(rag_extractor=mock_rag)
        mock_api_data = {
            "vulns": [
                {
                    "id": "GHSA-rag-delegate",
                    "summary": "Vulnerability affecting extracted_func in certain situations.",
                    "details": "More details here.",
                    "aliases": ["CVE-2024-1111"],
                    "affected": [
                        {
                            "package": {"name": "sample_lib", "ecosystem": "PyPI"},
                        }
                    ]
                }
            ]
        }

        vulns = client._parse_osv_response("sample_lib", "1.0.0", mock_api_data)
        self.assertEqual(len(vulns), 1)
        mock_rag.extract_symbols.assert_called_once()
        self.assertIn("extracted_func", vulns[0].affected_symbols)

    def test_parse_osv_response_no_regex_fallback_when_rag_empty(self):
        """Verify that when RAG returns no symbols, no regex fallback occurs."""
        from unittest.mock import MagicMock

        mock_rag = MagicMock()
        mock_rag.extract_symbols.return_value = []

        client = OSVClient(rag_extractor=mock_rag)
        # Even with backtick-wrapped function names, empty RAG result means no symbols extracted
        mock_api_data = {
            "vulns": [
                {
                    "id": "GHSA-no-fallback",
                    "summary": "Flaw in `backtick_func()` but RAG has low confidence.",
                    "aliases": ["CVE-2024-2222"],
                    "affected": [
                        {
                            "package": {"name": "sample_lib", "ecosystem": "PyPI"},
                        }
                    ]
                }
            ]
        }

        vulns = client._parse_osv_response("sample_lib", "1.0.0", mock_api_data)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].affected_symbols, [])

    def test_parse_osv_response_use_rag_false_returns_empty(self):
        """Verify that disabling RAG returns empty list for unstructured advisories."""
        client = OSVClient(use_rag=False)
        mock_api_data = {
            "vulns": [
                {
                    "id": "GHSA-no-rag",
                    "summary": "Flaw in `backtick_func()`.",
                    "aliases": ["CVE-2024-3333"],
                    "affected": [
                        {
                            "package": {"name": "sample_lib", "ecosystem": "PyPI"},
                        }
                    ]
                }
            ]
        }

        vulns = client._parse_osv_response("sample_lib", "1.0.0", mock_api_data)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].affected_symbols, [])

    def test_parse_osv_response_rag_remediation_filtering(self):
        """Verify RAG extractor correctly extracts load and not safe_load in remediation context."""
        mock_api_data = {
            "vulns": [
                {
                    "id": "GHSA-remediation-test",
                    "summary": "The library is vulnerable via `load()`. Use `safe_load()` instead to avoid the issue.",
                    "aliases": ["CVE-2024-4444"],
                    "affected": [
                        {
                            "package": {"name": "yaml_parser", "ecosystem": "PyPI"},
                        }
                    ]
                }
            ]
        }
        vulns = self.client._parse_osv_response("yaml_parser", "1.0.0", mock_api_data)
        self.assertEqual(len(vulns), 1)
        symbols = vulns[0].affected_symbols
        self.assertIn("load", symbols)
        self.assertNotIn("safe_load", symbols)


if __name__ == "__main__":
    unittest.main()
