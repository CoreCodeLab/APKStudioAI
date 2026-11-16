"""
AI Package for APKStudioAI 2.1
Multi-agent malware investigation system.
"""
from .model_router import ModelRouter, get_model_router, TaskRequirements
from .rag_engine import RAGEngine, get_rag_engine, KnowledgeBaseBuilder
from .evidence_repository import EvidenceRepository, get_evidence_repository, Evidence, AgentID, VerificationStatus, Severity
from .agent_base import BaseAgent, AgentManager, create_agent_manager, AgentTask, AgentResult, AgentState

__all__ = [
    "ModelRouter",
    "get_model_router",
    "TaskRequirements",
    "RAGEngine",
    "get_rag_engine",
    "KnowledgeBaseBuilder",
    "EvidenceRepository",
    "get_evidence_repository",
    "Evidence",
    "AgentID",
    "VerificationStatus",
    "Severity",
    "BaseAgent",
    "AgentManager",
    "create_agent_manager",
    "AgentTask",
    "AgentResult",
    "AgentState",
]