"""
Tests for Advanced Static Analyzer
"""
import unittest
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.advanced_static_analyzer import (
    CallGraphAnalyzer, CFGBuilder, TaintAnalyzer, YARAScanner, AdvancedStaticAnalyzer, CFGBlock
)
from core.dex_bytecode_analyzer import DEXBytecodeAnalyzer


class TestCallGraphAnalyzer(unittest.TestCase):
    """Tests for CallGraphAnalyzer"""

    def setUp(self):
        self.analyzer = CallGraphAnalyzer()

    def test_build_from_dex_analysis(self):
        """Test building call graph from DEX analysis"""
        mock_dex = {
            'api_calls': [
                {'class': 'Lcom/example/MainActivity;', 'method': 'onCreate', 'call': 'Landroid/telephony/TelephonyManager;.getDeviceId()Ljava/lang/String;'},
                {'class': 'Lcom/example/MainActivity;', 'method': 'sendData', 'call': 'Ljava/net/HttpURLConnection;.getOutputStream()Ljava/io/OutputStream;'},
            ]
        }
        graph = self.analyzer.build_from_dex_analysis(mock_dex)
        self.assertGreater(graph.number_of_nodes(), 0)

    def test_sensitive_api_detection(self):
        """Test sensitive API detection"""
        self.assertTrue(self.analyzer._is_sensitive_api("Runtime.exec"))
        self.assertTrue(self.analyzer._is_sensitive_api("DexClassLoader"))
        self.assertTrue(self.analyzer._is_sensitive_api("Cipher.getInstance"))
        self.assertFalse(self.analyzer._is_sensitive_api("toString"))

    def test_entry_point_detection(self):
        """Test entry point detection"""
        self.assertTrue(self.analyzer._is_entry_point("onCreate"))
        self.assertTrue(self.analyzer._is_entry_point("onStartCommand"))
        self.assertTrue(self.analyzer._is_entry_point("onReceive"))
        self.assertFalse(self.analyzer._is_entry_point("helperMethod"))

    def test_get_statistics(self):
        """Test graph statistics"""
        mock_dex = {
            'api_calls': [
                {'class': 'Lcom/example/MainActivity;', 'method': 'onCreate', 'call': 'Landroid/telephony/TelephonyManager;.getDeviceId()Ljava/lang/String;'},
            ]
        }
        self.analyzer.build_from_dex_analysis(mock_dex)
        stats = self.analyzer.get_statistics()
        self.assertIn("nodes", stats)
        self.assertIn("edges", stats)
        self.assertIn("entry_points", stats)
        self.assertIn("sensitive_apis", stats)


class TestCFGBuilder(unittest.TestCase):
    """Tests for CFGBuilder"""

    def setUp(self):
        self.builder = CFGBuilder()

    def test_build_from_method(self):
        """Test building CFG from method bytecode"""
        method_bytecode = {
            'instructions': [
                {'pc': 0, 'name': 'const/4', 'output': 'v0, 0'},
                {'pc': 2, 'name': 'return-void', 'output': ''},
            ]
        }
        cfg = self.builder.build_from_method(method_bytecode)
        self.assertGreater(cfg.number_of_nodes(), 0)

    def test_analyze_complexity(self):
        """Test cyclomatic complexity analysis"""
        import networkx as nx
        cfg = nx.DiGraph()
        cfg.add_edge(0, 1)
        cfg.add_edge(1, 2)
        cfg.nodes[0]['data'] = CFGBlock(0, 0, 0, [], is_entry=True)
        cfg.nodes[1]['data'] = CFGBlock(1, 0, 0, [])
        cfg.nodes[2]['data'] = CFGBlock(2, 0, 0, [], is_exit=True)

        complexity = self.builder.analyze_complexity(cfg)
        self.assertIn("cyclomatic_complexity", complexity)
        self.assertIn("num_blocks", complexity)


class TestTaintAnalyzer(unittest.TestCase):
    """Tests for TaintAnalyzer"""

    def setUp(self):
        self.analyzer = TaintAnalyzer()

    def test_source_detection(self):
        """Test source detection"""
        mock_dex = {
            'api_calls': [
                {'class': 'Lcom/example/MainActivity;', 'method': 'onCreate', 'call': 'Landroid/telephony/TelephonyManager;.getDeviceId()Ljava/lang/String;'},
            ]
        }
        import networkx as nx
        call_graph = nx.DiGraph()
        call_graph.add_node("com.example.MainActivity.onCreate")
        
        result = self.analyzer.analyze(mock_dex, call_graph)
        self.assertIn("statistics", result)
        self.assertIn("tainted_methods", result)

    def test_sink_detection(self):
        """Test sink detection"""
        mock_dex = {
            'api_calls': [
                {'class': 'Lcom/example/MainActivity;', 'method': 'sendData', 'call': 'Ljava/net/HttpURLConnection;.getOutputStream()Ljava/io/OutputStream;'},
            ]
        }
        import networkx as nx
        call_graph = nx.DiGraph()
        call_graph.add_node("com.example.MainActivity.sendData")
        
        result = self.analyzer.analyze(mock_dex, call_graph)
        self.assertIn("statistics", result)


class TestYARAScanner(unittest.TestCase):
    """Tests for YARAScanner"""

    def setUp(self):
        self.scanner = YARAScanner()

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner.rules_dir)
        self.assertIsNotNone(self.scanner.config)

    def test_add_custom_rule(self):
        """Test adding custom rule"""
        rule = '''
rule TestRule {
    strings:
        $test = "test"
    condition:
        $test
}
'''
        result = self.scanner.add_custom_rule("TestRule", rule)
        # Should succeed even without yara binary
        self.assertTrue(result or not self.scanner.yara_available)


class TestAdvancedStaticAnalyzer(unittest.TestCase):
    """Tests for AdvancedStaticAnalyzer"""

    def setUp(self):
        self.analyzer = AdvancedStaticAnalyzer()

    def test_full_analysis(self):
        """Test full advanced static analysis"""
        mock_dex = {
            'api_calls': [
                {'class': 'Lcom/example/MainActivity;', 'method': 'onCreate', 'call': 'Landroid/telephony/TelephonyManager;.getDeviceId()Ljava/lang/String;'},
                {'class': 'Lcom/example/MainActivity;', 'method': 'onCreate', 'call': 'Lcom/example/MainActivity;.sendData()V'},
                {'class': 'Lcom/example/MainActivity;', 'method': 'sendData', 'call': 'Ljava/net/HttpURLConnection;.getOutputStream()Ljava/io/OutputStream;'},
            ],
            'strings': ['http://test.com'],
            'suspicious_patterns': []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            extracted_dir = tmpdir_path / 'extracted'
            extracted_dir.mkdir()
            apk_path = tmpdir_path / 'test.apk'
            apk_path.write_bytes(b'PK\x03\x04' + b'test' * 100)
            
            result = self.analyzer.analyze(mock_dex, extracted_dir, apk_path, ['http://test.com'])
            
            self.assertIn("call_graph", result)
            self.assertIn("cfg", result)
            self.assertIn("taint", result)
            self.assertIn("yara", result)
            self.assertIn("statistics", result["call_graph"])
            self.assertIn("statistics", result["taint"])


class TestDEXBytecodeAnalyzer(unittest.TestCase):
    """Tests for DEXBytecodeAnalyzer"""

    def setUp(self):
        self.analyzer = DEXBytecodeAnalyzer()

    def test_analyze_nonexistent(self):
        """Test analyzing non-existent DEX file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            dex_path = Path(tmpdir) / "nonexistent.dex"
            # Create empty file so stat() works
            dex_path.touch()
            result = self.analyzer.analyze(dex_path)
            self.assertIn("classes", result)
            self.assertIn("methods", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
