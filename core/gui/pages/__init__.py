"""
GUI Pages package for APKStudioAI 2.1
Exports all 21 page classes.
"""
from .dashboard import DashboardPage
from .static_analysis import StaticAnalysisPage
from .dynamic_analysis import DynamicAnalysisPage
from .network_analysis import NetworkAnalysisPage
from .threat_intel import ThreatIntelPage
from .ml_classifier import MLClassifierPage
from .mitre_attack import MITREAttackPage
from .malware_families import MalwareFamiliesPage
from .ioc_graph import IOCGraphPage
from .code_browser import CodeBrowserPage
from .timeline import TimelinePage
from .behavioral import BehavioralPage
from .strings import StringsPage
from .manifest import ManifestPage
from .permissions import PermissionsPage
from .components import ComponentsPage
from .advanced_static import AdvancedStaticPage
from .correlation import CorrelationPage
from .reporting import ReportingPage
from .settings import SettingsPage
from .rea_analysis import REAAnalysisPage

__all__ = [
    "DashboardPage",
    "StaticAnalysisPage",
    "DynamicAnalysisPage",
    "NetworkAnalysisPage",
    "ThreatIntelPage",
    "MLClassifierPage",
    "MITREAttackPage",
    "MalwareFamiliesPage",
    "IOCGraphPage",
    "CodeBrowserPage",
    "TimelinePage",
    "BehavioralPage",
    "StringsPage",
    "ManifestPage",
    "PermissionsPage",
    "ComponentsPage",
    "AdvancedStaticPage",
    "CorrelationPage",
    "ReportingPage",
    "SettingsPage",
    "REAAnalysisPage",
]