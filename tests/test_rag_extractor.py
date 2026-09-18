import os
import shutil
import tempfile
import unittest

from analyzer.osv_client import OSVClient
from analyzer.rag_extractor import SymbolRAGExtractor


class TestSymbolRAGExtractor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a dedicated temp directory for the test Chroma collection
        cls.temp_db_dir = tempfile.mkdtemp(prefix="test_chroma_")
        cls.extractor = SymbolRAGExtractor(db_dir=cls.temp_db_dir)

    @classmethod
    def tearDownClass(cls):
        # Cleanup temporary chroma db
        shutil.rmtree(cls.temp_db_dir, ignore_errors=True)

    def test_chroma_collection_builds_from_examples(self):
        """Verify the ChromaDB collection builds successfully from the example file."""
        self.assertGreater(self.extractor.collection.count(), 0)
        initial_count = self.extractor.collection.count()

        # Re-initializing with the same persistent directory should not duplicate examples
        reloaded_extractor = SymbolRAGExtractor(db_dir=self.temp_db_dir)
        self.assertEqual(reloaded_extractor.collection.count(), initial_count)

    def test_remediation_context_extracts_load_not_safeload(self):
        """Verify the extractor retrieves 'load' (not 'safe_load') for remediation context."""
        advisory_text = (
            "The library is vulnerable to arbitrary code execution via load(). "
            "Use safe_load() instead to avoid the issue."
        )
        symbol = self.extractor.extract_symbol(advisory_text)
        self.assertEqual(symbol, "load")
        self.assertNotEqual(symbol, "safe_load")

    def test_direct_mention_extraction(self):
        """Verify direct vulnerable function mentions are accurately extracted."""
        advisory_text = "Remote code execution flaw in unsafe_deserialize allows arbitrary payload execution."
        symbol = self.extractor.extract_symbol(advisory_text)
        self.assertEqual(symbol, "unsafe_deserialize")

    def test_low_confidence_unrelated_text_returns_none(self):
        """Verify that low-confidence / unrelated text returns None."""
        unrelated_text = "The forecast for tomorrow predicts mild temperatures and occasional afternoon showers."
        symbol = self.extractor.extract_symbol(unrelated_text)
        self.assertIsNone(symbol)

    def test_no_symbol_mentioned_returns_none(self):
        """Verify that an advisory with no vulnerable symbol mentioned (e.g., DoS) returns None."""
        dos_advisory = "Denial of service vulnerability due to excessive memory consumption on large input files."
        symbol = self.extractor.extract_symbol(dos_advisory)
        self.assertIsNone(symbol)

    def test_osv_client_falls_back_when_rag_returns_none(self):
        """Verify OSVClient falls back to regex when RAG extraction returns None."""
        client = OSVClient(timeout=10, rag_extractor=self.extractor)

        # Advisory with low similarity to training examples, but valid backticks
        mock_data = {
            "vulns": [
                {
                    "id": "GHSA-fallback-test",
                    "summary": "Random completely obscure bug in `custom_unseen_helper()` function.",
                    "details": "Rainy weather observations.",
                    "aliases": ["CVE-2024-9999"],
                    "affected": [
                        {
                            "package": {"name": "sample_lib", "ecosystem": "PyPI"}
                        }
                    ]
                }
            ]
        }

        vulns = client._parse_osv_response("sample_lib", "1.0.0", mock_data)
        self.assertEqual(len(vulns), 1)
        # Even if RAG returns None on unseen/unrelated text, regex fallback extracts the symbol
        self.assertIn("custom_unseen_helper", vulns[0].affected_symbols)


if __name__ == "__main__":
    unittest.main()
