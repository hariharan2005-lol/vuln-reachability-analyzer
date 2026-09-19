import json
import os
import re
from collections import defaultdict
from typing import List, Optional

import chromadb
from sentence_transformers import SentenceTransformer


class SymbolRAGExtractor:
    """Retrieval-Augmented symbol extractor using SentenceTransformers and ChromaDB."""

    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    DEFAULT_CONFIDENCE_THRESHOLD = 0.5

    def __init__(
        self,
        db_dir: Optional[str] = None,
        examples_path: Optional[str] = None,
        model_name: str = DEFAULT_MODEL,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_dir = db_dir or os.path.join(base_dir, "data", "chroma_db")
        self.examples_path = examples_path or os.path.join(base_dir, "data", "advisory_examples.json")
        self.confidence_threshold = confidence_threshold

        os.makedirs(self.db_dir, exist_ok=True)

        self.model = SentenceTransformer(model_name)
        self.client = chromadb.PersistentClient(path=self.db_dir)
        self.collection = self.client.get_or_create_collection(
            name="advisory_symbols",
            metadata={"hnsw:space": "cosine"}
        )

        self._ensure_knowledge_base()

    def _ensure_knowledge_base(self) -> None:
        """Loads labeled examples from JSON and embeds them if not already present."""
        if self.collection.count() > 0:
            return

        if not os.path.exists(self.examples_path):
            return

        with open(self.examples_path, "r", encoding="utf-8") as f:
            examples: List[dict] = json.load(f)

        if not examples:
            return

        texts = [ex["text"] for ex in examples]
        ids = [ex.get("id", f"ex-{idx}") for idx, ex in enumerate(examples)]
        metadatas = [
            {
                "symbol": ex.get("vulnerable_symbol") or "",
                "remediation": ex.get("remediation") or "",
            }
            for ex in examples
        ]

        embeddings = self.model.encode(texts, convert_to_numpy=True).tolist()

        self.collection.add(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=metadatas,
        )

    def extract_symbol(self, advisory_text: str) -> Optional[str]:
        """
        Embeds the input advisory text, retrieves the top-3 most similar examples from ChromaDB,
        and uses a similarity-weighted nearest-neighbor vote to decide the extracted symbol.
        Returns None if top match similarity is below confidence_threshold or no valid symbol won.
        """
        if not advisory_text or not advisory_text.strip():
            return None

        if self.collection.count() == 0:
            return None

        query_embedding = self.model.encode(advisory_text.strip(), convert_to_numpy=True).tolist()

        n_results = min(3, self.collection.count())
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
        )

        distances = results.get("distances", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]

        if not distances or not metadatas:
            return None

        # Cosine similarity calculation: cosine distance d in [0, 2] -> similarity = 1 - d
        top_distance = distances[0]
        top_similarity = max(0.0, min(1.0, 1.0 - top_distance))

        if top_similarity < self.confidence_threshold:
            return None

        # Weighted majority voting among retrieved nearest neighbors
        symbol_weights = defaultdict(float)
        for d, meta in zip(distances, metadatas):
            similarity = max(0.0, min(1.0, 1.0 - d))
            sym = (meta.get("symbol") or "").strip()
            symbol_weights[sym] += similarity

        if not symbol_weights:
            return None

        winning_symbol, total_weight = max(symbol_weights.items(), key=lambda item: item[1])

        # If winning symbol is empty (e.g. no-symbol / DoS pattern), return None
        if not winning_symbol:
            return None

        # Verify that winning_symbol actually appears in the advisory text as a word/token
        if not re.search(rf"\b{re.escape(winning_symbol)}\b", advisory_text, re.IGNORECASE):
            return None

        return winning_symbol

    def extract_symbols(self, advisory_text: str) -> List[str]:
        """
        Extracts vulnerable symbols from advisory text.
        Returns a list of symbols (empty list if no high-confidence symbol found).
        """
        sym = self.extract_symbol(advisory_text)
        return [sym] if sym else []


# Alias for direct import / injection
RAGExtractor = SymbolRAGExtractor

