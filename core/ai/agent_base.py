"""
Base Agent Classes for APKStudioAI 2.1
Foundation for the 8-agent malware investigation system.
"""
import json
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from ..config_manager import get_config
from ..logging_setup import get_module_logger
from .evidence_repository import EvidenceRepository, Evidence, AgentID, VerificationStatus

logger = get_module_logger("agent_base")


class AgentState(Enum):
    """Agent execution state."""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING = "waiting"


@dataclass
class AgentTask:
    """Task assigned to an agent."""
    task_id: str
    agent_id: str
    description: str
    input_data: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)  # Task IDs that must complete first
    priority: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AgentResult:
    """Result from agent execution."""
    task_id: str
    agent_id: str
    success: bool
    evidence_ids: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    completed_at: str = field(default_factory=lambda: datetime.now().isoformat())


class BaseAgent(ABC):
    """Base class for all investigation agents."""

    def __init__(self, agent_id: AgentID, config: Dict = None,
                 evidence_repo: EvidenceRepository = None,
                 ollama_client = None, rag_engine = None):
        self.agent_id = agent_id.value
        self.config = config or get_config().get_all()
        self.evidence_repo = evidence_repo
        self.ollama_client = ollama_client
        self.rag_engine = rag_engine
        self.state = AgentState.IDLE
        self.current_task: Optional[AgentTask] = None
        self.results: List[AgentResult] = []

    @abstractmethod
    def investigate(self, task: AgentTask) -> AgentResult:
        """Main investigation method - must be implemented by subclasses."""
        pass

    def execute(self, task: AgentTask) -> AgentResult:
        """Execute a task with state management."""
        self.state = AgentState.RUNNING
        self.current_task = task
        start_time = datetime.now()

        logger.info("agent_task_started", agent=self.agent_id, task=task.task_id)

        try:
            result = self.investigate(task)
            result.execution_time = (datetime.now() - start_time).total_seconds()
            result.completed_at = datetime.now().isoformat()

            self.results.append(result)
            self.state = AgentState.COMPLETED if result.success else AgentState.FAILED

            logger.info("agent_task_completed", agent=self.agent_id, task=task.task_id,
                       success=result.success, evidence_count=len(result.evidence_ids))
            return result

        except Exception as e:
            self.state = AgentState.FAILED
            error_msg = f"Agent {self.agent_id} failed: {str(e)}"
            logger.error("agent_task_failed", agent=self.agent_id, task=task.task_id, error=error_msg)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                errors=[error_msg],
                execution_time=(datetime.now() - start_time).total_seconds(),
            )

    def create_evidence(self, analysis_module: str, file_path: str, description: str,
                       class_name: str = None, method_name: str = None,
                       dex_id: str = None, source_reference: str = None,
                       raw_data: Dict = None, confidence: int = 50,
                       severity: str = "medium", tags: List[str] = None) -> Evidence:
        """Create and store evidence."""
        if not self.evidence_repo:
            raise RuntimeError("Evidence repository not configured")

        return self.evidence_repo.create_evidence(
            agent_id=self.agent_id,
            analysis_module=analysis_module,
            file_path=file_path,
            description=description,
            class_name=class_name,
            method_name=method_name,
            dex_id=dex_id,
            source_reference=source_reference,
            raw_data=raw_data,
            confidence=confidence,
            severity=severity,
            tags=tags or [self.agent_id],
        )

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence by ID."""
        if not self.evidence_repo:
            return None
        return self.evidence_repo.get_evidence(evidence_id)

    def search_evidence(self, **kwargs) -> List[Evidence]:
        """Search evidence repository."""
        if not self.evidence_repo:
            return []
        return self.evidence_repo.search(**kwargs)

    def query_rag(self, query: str, n_results: int = 5) -> List[Any]:
        """Query RAG engine for relevant knowledge."""
        if not self.rag_engine:
            return []
        return self.rag_engine.search(query, n_results)

    def query_llm(self, prompt: str, task_type: str = "general") -> Dict[str, Any]:
        """Query LLM via Ollama client."""
        if not self.ollama_client:
            return {"success": False, "error": "No Ollama client"}

        # Use model router if available
        try:
            from .model_router import get_model_router
            router = get_model_router(self.config)
            model = router.select_model(task_type)
            if model:
                # Temporarily override model
                original_model = self.ollama_client.model
                self.ollama_client.model = model
                result = self.ollama_client.analyze({"prompt": prompt})
                self.ollama_client.model = original_model
                return result
        except Exception:
            pass

        return self.ollama_client.analyze({"prompt": prompt})

    def sanitize_input(self, data: Any) -> Any:
        """Sanitize input to prevent prompt injection."""
        if hasattr(self.ollama_client, '_sanitize_input'):
            return self.ollama_client._sanitize_input(data)
        return data


class AgentManager:
    """Manages the 8-agent investigation system."""

    def __init__(self, config: Dict = None,
                 evidence_repo: EvidenceRepository = None,
                 ollama_client = None, rag_engine = None):
        self.config = config or get_config().get_all()
        self.evidence_repo = evidence_repo or EvidenceRepository()
        self.ollama_client = ollama_client
        self.rag_engine = rag_engine
        self.agents: Dict[str, BaseAgent] = {}
        self.task_queue: List[AgentTask] = []
        self.completed_tasks: Dict[str, AgentResult] = {}

    def register_agent(self, agent: BaseAgent):
        """Register an agent."""
        self.agents[agent.agent_id] = agent
        logger.info("agent_registered", agent=agent.agent_id)

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID."""
        return self.agents.get(agent_id)

    def create_task(self, agent_id: str, description: str,
                    input_data: Dict, dependencies: List[str] = None,
                    priority: int = 0) -> AgentTask:
        """Create a new task."""
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            agent_id=agent_id,
            description=description,
            input_data=input_data,
            dependencies=dependencies or [],
            priority=priority,
        )
        self.task_queue.append(task)
        return task

    def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute a single task."""
        agent = self.agents.get(task.agent_id)
        if not agent:
            return AgentResult(
                task_id=task.task_id,
                agent_id=task.agent_id,
                success=False,
                errors=[f"Agent {task.agent_id} not found"]
            )

        # Check dependencies
        for dep_id in task.dependencies:
            if dep_id not in self.completed_tasks:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=task.agent_id,
                    success=False,
                    errors=[f"Dependency {dep_id} not completed"]
                )
            if not self.completed_tasks[dep_id].success:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=task.agent_id,
                    success=False,
                    errors=[f"Dependency {dep_id} failed"]
                )

        # Inject dependency results into input
        for dep_id in task.dependencies:
            dep_result = self.completed_tasks[dep_id]
            task.input_data[f"dep_{dep_id}"] = dep_result.findings

        result = agent.execute(task)
        self.completed_tasks[task.task_id] = result
        return result

    def execute_pipeline(self, tasks: List[AgentTask]) -> List[AgentResult]:
        """Execute tasks in dependency order."""
        # Sort by priority and dependencies
        remaining = tasks.copy()
        results = []

        while remaining:
            # Find tasks with satisfied dependencies
            ready = []
            for task in remaining:
                deps_satisfied = all(
                    dep_id in self.completed_tasks and self.completed_tasks[dep_id].success
                    for dep_id in task.dependencies
                )
                if deps_satisfied:
                    ready.append(task)

            if not ready:
                # Circular dependency or missing dependency
                logger.error("pipeline_deadlock", remaining=[t.task_id for t in remaining])
                break

            # Execute highest priority ready task
            ready.sort(key=lambda t: -t.priority)
            task = ready[0]
            remaining.remove(task)

            result = self.execute_task(task)
            results.append(result)

        return results

    def get_all_evidence(self) -> List[Evidence]:
        """Get all evidence from all agents."""
        all_evidence = []
        for agent in self.agents.values():
            all_evidence.extend(self.evidence_repo.get_by_agent(agent.agent_id))
        return all_evidence


def create_agent_manager(config: Dict = None,
                        evidence_repo: EvidenceRepository = None,
                        ollama_client = None, rag_engine = None) -> AgentManager:
    """Factory function to create agent manager with all 8 agents."""
    manager = AgentManager(config, evidence_repo, ollama_client, rag_engine)

    # Import and register all 8 agents
    from .apk_intelligence_agent import APKIntelligenceAgent
    from .static_analysis_agent import StaticAnalysisAgent
    from .reverse_engineering_agent import ReverseEngineeringAgent
    from .behavioral_agent import BehavioralAgent
    from .network_intelligence_agent import NetworkIntelligenceAgent
    from .threat_researcher_agent import ThreatResearcherAgent
    from .verification_agent import VerificationAgent
    from .senior_analyst_agent import SeniorAnalystAgent

    agents = [
        APKIntelligenceAgent,
        StaticAnalysisAgent,
        ReverseEngineeringAgent,
        BehavioralAgent,
        NetworkIntelligenceAgent,
        ThreatResearcherAgent,
        VerificationAgent,
        SeniorAnalystAgent,
    ]

    for agent_class in agents:
        try:
            agent = agent_class(
                config=config,
                evidence_repo=evidence_repo,
                ollama_client=ollama_client,
                rag_engine=rag_engine,
            )
            manager.register_agent(agent)
        except Exception as e:
            logger.warning("agent_registration_failed", agent=agent_class.__name__, error=str(e))

    return manager