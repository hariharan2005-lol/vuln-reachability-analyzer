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


if __name__ == "__main__":
    unittest.main()
