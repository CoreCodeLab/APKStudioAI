"""
Evidence Repository for APKStudioAI 2.1
Shared structured evidence storage for multi-agent communication.
"""
import json
import uuid
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from collections import defaultdict
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("evidence_repo")


class VerificationStatus(Enum):
    """Verification status of evidence."""
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REFUTED = "refuted"
    CONTRADICTED = "contradicted"
    PENDING = "pending"


class Severity(Enum):
    """Severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentID(Enum):
    """Agent identifiers."""
    APK_INTELLIGENCE = "apk_intelligence"
    STATIC_ANALYSIS = "static_analysis"
    REVERSE_ENGINEERING = "reverse_engineering"
    BEHAVIORAL = "behavioral"
    NETWORK_INTELLIGENCE = "network_intelligence"
    THREAT_RESEARCHER = "threat_researcher"
    VERIFICATION = "verification"
    SENIOR_ANALYST = "senior_analyst"


@dataclass
class Evidence:
    """Structured evidence item."""
    evidence_id: str
    agent_id: str
    analysis_module: str
    file_path: str
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    dex_id: Optional[str] = None
    source_reference: Optional[str] = None  # Smali line, Java line, etc.
    description: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    confidence: int = 50  # 0-100
    severity: str = "medium"
    verification_status: str = "unverified"
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicted_by: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'Evidence':
        return cls(**data)


class EvidenceRepository:
    """Centralized evidence repository for multi-agent system."""

    def __init__(self, config: Dict = None, db_path: str = "./evidence.db"):
        self.config = config or get_config().get_all()
        self.db_path = Path(db_path)
        self._init_db()
        self._cache = {}  # evidence_id -> Evidence
        self._agent_index = defaultdict(set)  # agent_id -> set(evidence_ids)
        self._tag_index = defaultdict(set)  # tag -> set(evidence_ids)
        self._load_cache()

    def _init_db(self):
        """Initialize SQLite database with FTS5."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    analysis_module TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    class_name TEXT,
                    method_name TEXT,
                    dex_id TEXT,
                    source_reference TEXT,
                    description TEXT,
                    raw_data TEXT,
                    confidence INTEGER,
                    severity TEXT,
                    verification_status TEXT,
                    supporting_evidence_ids TEXT,
                    contradicted_by TEXT,
                    tags TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            # FTS5 virtual table for full-text search
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(
                    evidence_id UNINDEXED,
                    description,
                    source_reference,
                    raw_data,
                    tags,
                    content='evidence',
                    content_rowid='rowid'
                )
            """)

            # Triggers to keep FTS in sync
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_ai AFTER INSERT ON evidence BEGIN
                    INSERT INTO evidence_fts(rowid, evidence_id, description, source_reference, raw_data, tags)
                    VALUES (new.rowid, new.evidence_id, new.description, new.source_reference, new.raw_data, new.tags);
                END
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_ad AFTER DELETE ON evidence BEGIN
                    INSERT INTO evidence_fts(evidence_fts, rowid, evidence_id, description, source_reference, raw_data, tags)
                    VALUES ('delete', old.rowid, old.evidence_id, old.description, old.source_reference, old.raw_data, old.tags);
                END
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_au AFTER UPDATE ON evidence BEGIN
                    INSERT INTO evidence_fts(evidence_fts, rowid, evidence_id, description, source_reference, raw_data, tags)
                    VALUES ('delete', old.rowid, old.evidence_id, old.description, old.source_reference, old.raw_data, old.tags);
                    INSERT INTO evidence_fts(rowid, evidence_id, description, source_reference, raw_data, tags)
                    VALUES (new.rowid, new.evidence_id, new.description, new.source_reference, new.raw_data, new.tags);
                END
            """)

            # Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent ON evidence(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_module ON evidence(analysis_module)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file ON evidence(file_path)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_class ON evidence(class_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON evidence(verification_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON evidence(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created ON evidence(created_at)")

            conn.commit()

        logger.info("evidence_repo_initialized", path=str(self.db_path))

    def _load_cache(self):
        """Load evidence into memory cache."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM evidence")
            for row in cursor:
                evidence = self._row_to_evidence(row)
                self._cache[evidence.evidence_id] = evidence
                self._agent_index[evidence.agent_id].add(evidence.evidence_id)
                for tag in evidence.tags:
                    self._tag_index[tag].add(evidence.evidence_id)

        logger.info("evidence_cache_loaded", count=len(self._cache))

    def _row_to_evidence(self, row: sqlite3.Row) -> Evidence:
        """Convert database row to Evidence object."""
        return Evidence(
            evidence_id=row["evidence_id"],
            agent_id=row["agent_id"],
            analysis_module=row["analysis_module"],
            file_path=row["file_path"],
            class_name=row["class_name"],
            method_name=row["method_name"],
            dex_id=row["dex_id"],
            source_reference=row["source_reference"],
            description=row["description"],
            raw_data=json.loads(row["raw_data"]) if row["raw_data"] else {},
            confidence=row["confidence"],
            severity=row["severity"],
            verification_status=row["verification_status"],
            supporting_evidence_ids=json.loads(row["supporting_evidence_ids"]) if row["supporting_evidence_ids"] else [],
            contradicted_by=json.loads(row["contradicted_by"]) if row["contradicted_by"] else [],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def add_evidence(self, evidence: Evidence) -> str:
        """Add evidence to repository."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.evidence_id,
                evidence.agent_id,
                evidence.analysis_module,
                evidence.file_path,
                evidence.class_name,
                evidence.method_name,
                evidence.dex_id,
                evidence.source_reference,
                evidence.description,
                json.dumps(evidence.raw_data),
                evidence.confidence,
                evidence.severity,
                evidence.verification_status,
                json.dumps(evidence.supporting_evidence_ids),
                json.dumps(evidence.contradicted_by),
                json.dumps(evidence.tags),
                evidence.created_at,
                evidence.updated_at,
            ))
            conn.commit()

        # Update cache
        self._cache[evidence.evidence_id] = evidence
        self._agent_index[evidence.agent_id].add(evidence.evidence_id)
        for tag in evidence.tags:
            self._tag_index[tag].add(evidence.evidence_id)

        logger.debug("evidence_added", id=evidence.evidence_id, agent=evidence.agent_id)
        return evidence.evidence_id

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        return self._cache.get(evidence_id)

    def update_evidence(self, evidence_id: str, updates: Dict[str, Any]) -> bool:
        """Update evidence fields."""
        evidence = self._cache.get(evidence_id)
        if not evidence:
            return False

        # Update fields
        for key, value in updates.items():
            if hasattr(evidence, key):
                setattr(evidence, key, value)

        evidence.updated_at = datetime.now().isoformat()

        # Save to DB
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE evidence SET
                    description=?, raw_data=?, confidence=?, severity=?,
                    verification_status=?, supporting_evidence_ids=?,
                    contradicted_by=?, tags=?, updated_at=?
                WHERE evidence_id=?
            """, (
                evidence.description,
                json.dumps(evidence.raw_data),
                evidence.confidence,
                evidence.severity,
                evidence.verification_status,
                json.dumps(evidence.supporting_evidence_ids),
                json.dumps(evidence.contradicted_by),
                json.dumps(evidence.tags),
                evidence.updated_at,
                evidence_id,
            ))
            conn.commit()

        # Update indexes
        self._agent_index[evidence.agent_id].add(evidence_id)
        for tag in evidence.tags:
            self._tag_index[tag].add(evidence_id)

        return True

    def verify_evidence(self, evidence_id: str, status: VerificationStatus,
                        verifier_agent: str, notes: str = "") -> bool:
        """Set verification status."""
        return self.update_evidence(evidence_id, {
            "verification_status": status.value,
            "raw_data": {**self._cache[evidence_id].raw_data, "verification": {
                "verifier": verifier_agent,
                "status": status.value,
                "notes": notes,
                "timestamp": datetime.now().isoformat(),
            }}
        })

    def add_supporting_evidence(self, evidence_id: str, supporting_id: str) -> bool:
        """Add supporting evidence reference."""
        evidence = self._cache.get(evidence_id)
        if not evidence:
            return False

        if supporting_id not in evidence.supporting_evidence_ids:
            evidence.supporting_evidence_ids.append(supporting_id)
            return self.update_evidence(evidence_id, {
                "supporting_evidence_ids": evidence.supporting_evidence_ids
            })
        return True

    def add_contradiction(self, evidence_id: str, contradicting_id: str) -> bool:
        """Add contradicting evidence reference."""
        evidence = self._cache.get(evidence_id)
        if not evidence:
            return False

        if contradicting_id not in evidence.contradicted_by:
            evidence.contradicted_by.append(contradicting_id)
            # Also update the contradicting evidence
            self.add_supporting_evidence(contradicting_id, evidence_id)
            return self.update_evidence(evidence_id, {
                "contradicted_by": evidence.contradicted_by
            })
        return True

    def search(self, query: str = "", agent_id: str = None,
               analysis_module: str = None, file_path: str = None,
               class_name: str = None, method_name: str = None,
               verification_status: str = None, severity: str = None,
               tags: List[str] = None, limit: int = 100) -> List[Evidence]:
        """Search evidence with multiple filters."""
        conditions = []
        params = []

        if query:
            # Use FTS5 for full-text search
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                fts_query = f"""
                    SELECT e.* FROM evidence e
                    JOIN evidence_fts f ON e.rowid = f.rowid
                    WHERE evidence_fts MATCH ?
                """
                params.append(query)
                conditions.append("e.rowid = f.rowid")
        else:
            fts_query = "SELECT * FROM evidence WHERE 1=1"

        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if analysis_module:
            conditions.append("analysis_module = ?")
            params.append(analysis_module)
        if file_path:
            conditions.append("file_path LIKE ?")
            params.append(f"%{file_path}%")
        if class_name:
            conditions.append("class_name LIKE ?")
            params.append(f"%{class_name}%")
        if method_name:
            conditions.append("method_name LIKE ?")
            params.append(f"%{method_name}%")
        if verification_status:
            conditions.append("verification_status = ?")
            params.append(verification_status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        if query:
            where_clause = f"evidence_fts MATCH ? AND {where_clause}"

        query_sql = f"{fts_query} AND {where_clause} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query_sql, params)
            return [self._row_to_evidence(row) for row in cursor]

    def get_by_agent(self, agent_id: str) -> List[Evidence]:
        """Get all evidence from an agent."""
        return [self._cache[eid] for eid in self._agent_index.get(agent_id, set())]

    def get_by_tag(self, tag: str) -> List[Evidence]:
        """Get all evidence with a tag."""
        return [self._cache[eid] for eid in self._tag_index.get(tag, set())]

    def get_unverified(self, agent_id: str = None) -> List[Evidence]:
        """Get unverified evidence."""
        return self.search(verification_status="unverified", agent_id=agent_id)

    def get_verified(self, agent_id: str = None) -> List[Evidence]:
        """Get verified evidence."""
        return self.search(verification_status="verified", agent_id=agent_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get repository statistics."""
        stats = {
            "total_evidence": len(self._cache),
            "by_agent": {},
            "by_module": defaultdict(int),
            "by_status": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_tag": defaultdict(int),
        }

        for evidence in self._cache.values():
            stats["by_agent"][evidence.agent_id] = stats["by_agent"].get(evidence.agent_id, 0) + 1
            stats["by_module"][evidence.analysis_module] += 1
            stats["by_status"][evidence.verification_status] += 1
            stats["by_severity"][evidence.severity] += 1
            for tag in evidence.tags:
                stats["by_tag"][tag] += 1

        return stats

    def export_for_agent(self, agent_id: str, include_unverified: bool = False) -> List[Dict]:
        """Export evidence in format suitable for agent consumption."""
        evidence_list = self.get_by_agent(agent_id)
        if not include_unverified:
            evidence_list = [e for e in evidence_list if e.verification_status != "refuted"]

        return [e.to_dict() for e in evidence_list]

    def create_evidence(self, agent_id: str, analysis_module: str,
                        file_path: str, description: str,
                        class_name: str = None, method_name: str = None,
                        dex_id: str = None, source_reference: str = None,
                        raw_data: Dict = None, confidence: int = 50,
                        severity: str = "medium", tags: List[str] = None) -> Evidence:
        """Convenience method to create and add evidence."""
        evidence = Evidence(
            evidence_id=str(uuid.uuid4()),
            agent_id=agent_id,
            analysis_module=analysis_module,
            file_path=file_path,
            class_name=class_name,
            method_name=method_name,
            dex_id=dex_id,
            source_reference=source_reference,
            description=description,
            raw_data=raw_data or {},
            confidence=confidence,
            severity=severity,
            tags=tags or [],
        )
        self.add_evidence(evidence)
        return evidence


def get_evidence_repository(config: Dict = None, db_path: str = "./evidence.db") -> EvidenceRepository:
    """Get singleton evidence repository instance."""
    return EvidenceRepository(config, db_path)