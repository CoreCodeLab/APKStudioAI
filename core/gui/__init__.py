"""
Professional GUI Module for APKStudioAI 2.1
20-page SOC-style interface with CustomTkinter.
"""
from .main_window import MainWindow, run_gui
from .pages.dashboard import DashboardPage
from .pages.static_analysis import StaticAnalysisPage
from .pages.dynamic_analysis import DynamicAnalysisPage
from .pages.network_analysis import NetworkAnalysisPage
from .pages.threat_intel import ThreatIntelPage
from .pages.ml_classifier import MLClassifierPage
from .pages.mitre_attack import MITREAttackPage
from .pages.malware_families import MalwareFamiliesPage
from .pages.ioc_graph import IOCGraphPage
from .pages.code_browser import CodeBrowserPage
from .pages.timeline import TimelinePage
from .pages.behavioral import BehavioralPage
from .pages.strings import StringsPage
from .pages.manifest import ManifestPage
from .pages.permissions import PermissionsPage
from .pages.components import ComponentsPage
from .pages.advanced_static import AdvancedStaticPage
from .pages.correlation import CorrelationPage
from .pages.reporting import ReportingPage
from .pages.settings import SettingsPage

__all__ = [
    "MainWindow",
    "run_gui",
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
]