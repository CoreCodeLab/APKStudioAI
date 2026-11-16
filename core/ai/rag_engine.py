"""
RAG Engine for APKStudioAI 2.1
Retrieval-Augmented Generation with ChromaDB vector database.
"""
import json
import hashlib
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("rag_engine")


@dataclass
class Document:
    """Document in the knowledge base."""
    id: str
    content: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None


@dataclass
class SearchResult:
    """Search result with score."""
    document: Document
    score: float
    rank: int


class RAGEngine:
    """Retrieval-Augmented Generation engine with ChromaDB."""

    def __init__(self, config: Dict = None, persist_dir: str = "./chroma_db"):
        self.config = config or get_config().get_all()
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self.client = None
        self.collection = None
        self.embedding_model = None
        self._init_chromadb()
        self._init_embeddings()

    def _init_chromadb(self):
        """Initialize ChromaDB client."""
        try:
            import chromadb
            from chromadb.config import Settings

            self.client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True,
                )
            )

            # Get or create collection
            self.collection = self.client.get_or_create_collection(
                name="apkstudio_knowledge",
                metadata={"hnsw:space": "cosine"}
            )

            logger.info("chromadb_initialized", path=str(self.persist_dir), count=self.collection.count())

        except ImportError:
            logger.warning("chromadb_not_installed")
            self.client = None
        except Exception as e:
            logger.error("chromadb_init_failed", error=str(e))
            self.client = None

    def _init_embeddings(self):
        """Initialize embedding model."""
        try:
            from sentence_transformers import SentenceTransformer

            # Use a lightweight but effective model
            model_name = self.config.get("rag", {}).get("embedding_model", "all-MiniLM-L6-v2")
            self.embedding_model = SentenceTransformer(model_name)
            logger.info("embedding_model_loaded", model=model_name)

        except ImportError:
            logger.warning("sentence_transformers_not_installed")
        except Exception as e:
            logger.error("embedding_model_failed", error=str(e))

    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text."""
        if self.embedding_model:
            return self.embedding_model.encode(text).tolist()

        # Fallback: simple hash-based pseudo-embedding
        import hashlib
        hash_obj = hashlib.sha256(text.encode())
        hash_bytes = hash_obj.digest()
        # Convert to 384-dim vector (matching MiniLM)
        embedding = []
        for i in range(384):
            idx = i % len(hash_bytes)
            embedding.append((hash_bytes[idx] - 128) / 128.0)
        return embedding

    def add_document(self, content: str, metadata: Dict[str, Any] = None, doc_id: str = None) -> str:
        """Add a document to the knowledge base."""
        if not self.client or not self.collection:
            return ""

        if doc_id is None:
            doc_id = str(uuid.uuid4())

        if metadata is None:
            metadata = {}

        # Add standard metadata
        metadata.update({
            "added_at": datetime.now().isoformat(),
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            "content_length": len(content),
        })

        # Generate embedding
        embedding = self._generate_embedding(content)

        try:
            self.collection.add(
                ids=[doc_id],
                documents=[content],
                metadatas=[metadata],
                embeddings=[embedding]
            )
            logger.debug("document_added", id=doc_id, length=len(content))
            return doc_id
        except Exception as e:
            logger.error("document_add_failed", id=doc_id, error=str(e))
            return ""

    def add_documents_batch(self, documents: List[Tuple[str, Dict[str, Any]]]) -> int:
        """Add multiple documents efficiently."""
        if not self.client or not self.collection or not documents:
            return 0

        ids = []
        contents = []
        metadatas = []
        embeddings = []

        for content, metadata in documents:
            doc_id = str(uuid.uuid4())
            meta = metadata.copy() if metadata else {}
            meta.update({
                "added_at": datetime.now().isoformat(),
                "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                "content_length": len(content),
            })

            ids.append(doc_id)
            contents.append(content)
            metadatas.append(meta)
            embeddings.append(self._generate_embedding(content))

        try:
            self.collection.add(
                ids=ids,
                documents=contents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info("batch_documents_added", count=len(documents))
            return len(documents)
        except Exception as e:
            logger.error("batch_add_failed", error=str(e))
            return 0

    def search(self, query: str, n_results: int = 10,
               filter_metadata: Dict = None) -> List[SearchResult]:
        """Search for relevant documents."""
        if not self.client or not self.collection:
            return []

        query_embedding = self._generate_embedding(query)

        try:
            where = filter_metadata if filter_metadata else None

            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                where=where,
                include=["documents", "metadatas", "distances"]
            )

            search_results = []
            if results["ids"] and results["ids"][0]:
                for i, (doc_id, content, metadata, distance) in enumerate(zip(
                    results["ids"][0],
                    results["documents"][0],
                    results["metadatas"][0],
                    results["distances"][0]
                )):
                    doc = Document(
                        id=doc_id,
                        content=content,
                        metadata=metadata,
                    )
                    # Convert distance to similarity score (cosine)
                    score = 1.0 - distance
                    search_results.append(SearchResult(
                        document=doc,
                        score=score,
                        rank=i + 1
                    ))

            return search_results

        except Exception as e:
            logger.error("search_failed", error=str(e))
            return []

    def search_by_metadata(self, filter_metadata: Dict, n_results: int = 100) -> List[Document]:
        """Search documents by metadata only (no vector search)."""
        if not self.client or not self.collection:
            return []

        try:
            results = self.collection.get(
                where=filter_metadata,
                limit=n_results,
                include=["documents", "metadatas"]
            )

            docs = []
            if results["ids"]:
                for doc_id, content, metadata in zip(
                    results["ids"],
                    results["documents"],
                    results["metadatas"]
                ):
                    docs.append(Document(
                        id=doc_id,
                        content=content,
                        metadata=metadata,
                    ))
            return docs

        except Exception as e:
            logger.error("metadata_search_failed", error=str(e))
            return []

    def delete_document(self, doc_id: str) -> bool:
        """Delete a document by ID."""
        if not self.client or not self.collection:
            return False

        try:
            self.collection.delete(ids=[doc_id])
            return True
        except Exception as e:
            logger.error("delete_failed", id=doc_id, error=str(e))
            return False

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        if not self.client or not self.collection:
            return {"available": False}

        try:
            count = self.collection.count()
            return {
                "available": True,
                "document_count": count,
                "persist_dir": str(self.persist_dir),
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def reset_collection(self) -> bool:
        """Reset the entire collection."""
        if not self.client:
            return False

        try:
            self.client.delete_collection("apkstudio_knowledge")
            self.collection = self.client.create_collection(
                name="apkstudio_knowledge",
                metadata={"hnsw:space": "cosine"}
            )
            logger.info("collection_reset")
            return True
        except Exception as e:
            logger.error("reset_failed", error=str(e))
            return False


# ============================================================
# KNOWLEDGE BASE BUILDERS
# ============================================================

class KnowledgeBaseBuilder:
    """Builds the malware research knowledge base from various sources."""

    def __init__(self, rag_engine: RAGEngine):
        self.rag = rag_engine

    def index_android_apis(self, api_docs_path: Path = None) -> int:
        """Index Android API documentation."""
        if not api_docs_path or not api_docs_path.exists():
            # Create basic Android API reference
            return self._create_default_android_apis()

        count = 0
        for file_path in api_docs_path.rglob("*.md"):
            try:
                content = file_path.read_text()
                # Split into chunks
                chunks = self._split_text(content, chunk_size=1000, overlap=200)
                docs = [(chunk, {
                    "source": "android_api",
                    "file": str(file_path.relative_to(api_docs_path)),
                    "chunk_index": i,
                    "type": "api_reference"
                }) for i, chunk in enumerate(chunks)]
                count += self.rag.add_documents_batch(docs)
            except Exception as e:
                logger.warning("api_index_failed", file=str(file_path), error=str(e))
        return count

    def index_mitre_attack(self, mitre_path: Path = None) -> int:
        """Index MITRE ATT&CK Mobile techniques."""
        # Create default MITRE Mobile techniques
        techniques = [
            {
                "id": "T1432",
                "name": "Exploit via Bluetooth",
                "tactics": ["Initial Access"],
                "description": "Adversaries may exploit Bluetooth vulnerabilities to gain initial access."
            },
            {
                "id": "T1433",
                "name": "Exploit via NFC",
                "tactics": ["Initial Access"],
                "description": "Adversaries may exploit NFC vulnerabilities."
            },
            {
                "id": "T1472",
                "name": "Data from Local System",
                "tactics": ["Collection"],
                "description": "Adversaries may search local system sources for files of interest."
            },
            {
                "id": "T1473",
                "name": "Data from Network Shared Drive",
                "tactics": ["Collection"],
                "description": "Adversaries may search network shares."
            },
            {
                "id": "T1505",
                "name": "Server Software Component",
                "tactics": ["Persistence"],
                "description": "Adversaries may install malicious components."
            },
            {
                "id": "T1659",
                "name": "Content Injection",
                "tactics": ["Initial Access"],
                "description": "Adversaries may inject malicious content."
            },
        ]

        docs = []
        for tech in techniques:
            content = f"MITRE ATT&CK Mobile Technique {tech['id']}: {tech['name']}\nTactics: {', '.join(tech['tactics'])}\nDescription: {tech['description']}"
            docs.append((content, {
                "source": "mitre_attack_mobile",
                "technique_id": tech["id"],
                "name": tech["name"],
                "tactics": tech["tactics"],
                "type": "threat_intelligence"
            }))

        return self.rag.add_documents_batch(docs)

    def index_yara_rules(self, rules_dir: Path = None) -> int:
        """Index YARA rules as searchable documents."""
        if not rules_dir or not rules_dir.exists():
            return 0

        docs = []
        for rule_file in rules_dir.rglob("*.yar"):
            try:
                content = rule_file.read_text()
                docs.append((content, {
                    "source": "yara_rules",
                    "file": rule_file.name,
                    "type": "detection_rule"
                }))
            except Exception:
                pass

        return self.rag.add_documents_batch(docs)

    def index_analysis_evidence(self, evidence: Dict[str, Any], scan_id: str) -> int:
        """Index analysis evidence for future retrieval."""
        docs = []

        # Index suspicious patterns
        for pattern in evidence.get("suspicious_patterns", [])[:50]:
            content = f"Suspicious pattern: {pattern.get('category', '')} - {pattern.get('description', '')}"
            docs.append((content, {
                "source": "analysis_evidence",
                "scan_id": scan_id,
                "type": "suspicious_pattern",
                "category": pattern.get("category", ""),
                "severity": pattern.get("severity", ""),
            }))

        # Index network IOCs
        for url in evidence.get("network_iocs", {}).get("urls", [])[:20]:
            docs.append((url, {
                "source": "analysis_evidence",
                "scan_id": scan_id,
                "type": "network_ioc",
                "ioc_type": "url",
            }))

        return self.rag.add_documents_batch(docs)

    def _create_default_android_apis(self) -> int:
        """Create basic Android API reference documents."""
        apis = [
            {"class": "TelephonyManager", "methods": ["getDeviceId", "getSubscriberId", "getSimSerialNumber", "getImei"], "permission": "READ_PHONE_STATE", "risk": "HIGH"},
            {"class": "LocationManager", "methods": ["getLastKnownLocation", "requestLocationUpdates"], "permission": "ACCESS_FINE_LOCATION", "risk": "HIGH"},
            {"class": "SmsManager", "methods": ["sendTextMessage", "sendMultipartTextMessage"], "permission": "SEND_SMS", "risk": "CRITICAL"},
            {"class": "ContactsContract", "methods": ["query"], "permission": "READ_CONTACTS", "risk": "HIGH"},
            {"class": "Camera", "methods": ["open", "takePicture"], "permission": "CAMERA", "risk": "HIGH"},
            {"class": "MediaRecorder", "methods": ["start", "stop"], "permission": "RECORD_AUDIO", "risk": "HIGH"},
            {"class": "DexClassLoader", "methods": ["loadClass"], "permission": "NONE", "risk": "CRITICAL"},
            {"class": "Runtime", "methods": ["exec", "loadLibrary"], "permission": "NONE", "risk": "CRITICAL"},
            {"class": "DevicePolicyManager", "methods": ["lockNow", "resetPassword", "wipeData"], "permission": "BIND_DEVICE_ADMIN", "risk": "CRITICAL"},
            {"class": "AccessibilityService", "methods": ["onAccessibilityEvent"], "permission": "BIND_ACCESSIBILITY_SERVICE", "risk": "CRITICAL"},
        ]

        docs = []
        for api in apis:
            for method in api["methods"]:
                content = f"Android API: {api['class']}.{method}()\nPermission: {api['permission']}\nRisk Level: {api['risk']}\nDescription: Access to {api['class'].lower()} functionality"
                docs.append((content, {
                    "source": "android_api",
                    "class": api["class"],
                    "method": method,
                    "permission": api["permission"],
                    "risk": api["risk"],
                    "type": "api_reference"
                }))

        return self.rag.add_documents_batch(docs)

    def _split_text(self, text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
        """Split text into overlapping chunks."""
        if len(text) <= chunk_size:
            return [text]

        chunks = []
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            # Try to break at sentence boundary
            if end < len(text):
                last_period = text.rfind('.', start, end)
                if last_period > start + chunk_size // 2:
                    end = last_period + 1
            chunks.append(text[start:end].strip())
            start = end - overlap
            if start >= len(text):
                break
        return chunks


def get_rag_engine(config: Dict = None, persist_dir: str = "./chroma_db") -> RAGEngine:
    """Get singleton RAG engine instance."""
    return RAGEngine(config, persist_dir)