"""
Dynamic Analysis Module for APKStudioAI 2.1
AVD Manager, Frida Bridge, mitmproxy, Runtime Collector, Static-Dynamic Correlation.
"""
from .avd_manager import AVDManager, get_avd_manager
from .frida_bridge import FridaBridge, get_frida_bridge
from .mitmproxy_integration import MitmproxyIntegration, get_mitmproxy_integration
from .runtime_collector import RuntimeCollector, get_runtime_collector
from .correlation_engine import CorrelationEngine, get_correlation_engine

__all__ = [
    "AVDManager",
    "get_avd_manager",
    "FridaBridge",
    "get_frida_bridge",
    "MitmproxyIntegration",
    "get_mitmproxy_integration",
    "RuntimeCollector",
    "get_runtime_collector",
    "CorrelationEngine",
    "get_correlation_engine",
]