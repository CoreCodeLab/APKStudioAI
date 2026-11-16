"""
Incremental analysis support for APKStudioAI 2.1
Tracks file changes and only re-analyzes modified components.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from .cache_manager import get_cache
from .utils import calculate_sha256


@dataclass
class FileState:
    """Tracks the state of a file for incremental analysis."""
    path: str
    sha256: str
    size: int
    mtime: float
    analysis_version: int = 1
    stages_completed: List[str] = None

    def __post_init__(self):
        if self.stages_completed is None:
            self.stages_completed = []


class IncrementalAnalyzer:
    """
    Manages incremental analysis by tracking file states and determining
    which stages need to be re-run.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.cache = get_cache(config_path)
        self.analysis_version = 1
        self.file_states: Dict[str, FileState] = {}
        self._load_state()

    def _load_state(self):
        """Load file states from cache."""
        cached = self.cache.get("incremental", "file_states")
        if cached:
            for path, state_dict in cached.items():
                self.file_states[path] = FileState(**state_dict)

    def _save_state(self):
        """Save file states to cache."""
        state_dict = {path: asdict(state) for path, state in self.file_states.items()}
        self.cache.set("incremental", state_dict, "file_states")

    def register_file(self, file_path: Path) -> FileState:
        """Register a file and return its state."""
        sha256 = calculate_sha256(file_path)
        stat = file_path.stat()

        state = FileState(
            path=str(file_path),
            sha256=sha256,
            size=stat.st_size,
            mtime=stat.st_mtime,
            analysis_version=self.analysis_version
        )
        self.file_states[str(file_path)] = state
        return state

    def is_modified(self, file_path: Path) -> bool:
        """Check if a file has been modified since last analysis."""
        path_str = str(file_path)
        if path_str not in self.file_states:
            return True

        state = self.file_states[path_str]
        stat = file_path.stat()

        # Check size, mtime, and content hash
        if state.size != stat.st_size:
            return True
        if state.mtime != stat.st_mtime:
            return True
        if state.sha256 != calculate_sha256(file_path):
            return True

        return False

    def get_stages_to_run(self, file_path: Path, all_stages: List[str]) -> List[str]:
        """Determine which stages need to be run for a file."""
        path_str = str(file_path)

        if path_str not in self.file_states:
            return all_stages  # New file, run all stages

        state = self.file_states[path_str]

        if state.analysis_version < self.analysis_version:
            return all_stages  # Analysis version bumped, re-run all

        # Check if file is modified
        if self.is_modified(file_path):
            return all_stages  # File changed, re-run all

        # Return stages not yet completed
        completed = set(state.stages_completed)
        return [s for s in all_stages if s not in completed]

    def mark_stage_complete(self, file_path: Path, stage: str):
        """Mark a stage as complete for a file."""
        path_str = str(file_path)
        if path_str in self.file_states:
            state = self.file_states[path_str]
            if stage not in state.stages_completed:
                state.stages_completed.append(stage)
                state.analysis_version = self.analysis_version
                # Update hash after modification
                state.sha256 = calculate_sha256(file_path)
                stat = file_path.stat()
                state.size = stat.st_size
                state.mtime = stat.st_mtime

    def mark_all_complete(self, file_path: Path, stages: List[str]):
        """Mark all stages as complete for a file."""
        path_str = str(file_path)
        if path_str in self.file_states:
            state = self.file_states[path_str]
            state.stages_completed = stages.copy()
            state.analysis_version = self.analysis_version
            state.sha256 = calculate_sha256(file_path)
            stat = file_path.stat()
            state.size = stat.st_size
            state.mtime = stat.st_mtime

    def clear_file(self, file_path: Path):
        """Clear tracking for a file (e.g., after deletion)."""
        path_str = str(file_path)
        if path_str in self.file_states:
            del self.file_states[path_str]

    def bump_version(self):
        """Bump analysis version to force re-analysis."""
        self.analysis_version += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get incremental analysis statistics."""
        return {
            "tracked_files": len(self.file_states),
            "analysis_version": self.analysis_version,
            "cache_stats": self.cache.get_stats()
        }

    def save(self):
        """Persist state to cache."""
        self._save_state()


class APKIncrementalAnalyzer:
    """
    Incremental analyzer specifically for APK files.
    Tracks APK-level state and coordinates incremental scanning.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.cache = get_cache(config_path)
        self.analyzer = IncrementalAnalyzer(config_path)
        self.apk_stages = [
            "archive", "extract", "manifest", "dex", "jadx",
            "smali", "native", "jni", "strings",
            "permissions", "behavior", "network",
            "malware", "risk", "ai"
        ]

    def should_scan_apk(self, apk_path: Path) -> bool:
        """Determine if APK needs full scan."""
        return self.analyzer.is_modified(apk_path)

    def get_apk_stages_to_run(self, apk_path: Path) -> List[str]:
        """Get stages that need to run for an APK."""
        return self.analyzer.get_stages_to_run(apk_path, self.apk_stages)

    def mark_apk_stage_complete(self, apk_path: Path, stage: str):
        """Mark a stage complete for an APK."""
        self.analyzer.mark_stage_complete(apk_path, stage)

    def mark_apk_complete(self, apk_path: Path):
        """Mark all stages complete for an APK."""
        self.analyzer.mark_all_complete(apk_path, self.apk_stages)

    def get_scan_summary(self, apk_path: Path) -> Dict[str, Any]:
        """Get summary of what would be scanned."""
        stages_to_run = self.get_apk_stages_to_run(apk_path)
        is_modified = self.should_scan_apk(apk_path)

        return {
            "apk_path": str(apk_path),
            "is_modified": is_modified,
            "stages_to_run": stages_to_run,
            "stages_skipped": [s for s in self.apk_stages if s not in stages_to_run],
            "total_stages": len(self.apk_stages),
            "stages_remaining": len(stages_to_run)
        }

    def save(self):
        """Persist state."""
        self.analyzer.save()


def get_incremental_analyzer(config_path: Optional[str] = None) -> APKIncrementalAnalyzer:
    """Get global incremental analyzer instance."""
    return APKIncrementalAnalyzer(config_path)