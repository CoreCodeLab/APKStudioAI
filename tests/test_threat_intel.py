"""
Tests for Threat Intelligence Module (Phase 6)
"""
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


class TestIOCGraph:
    """Tests for IOC Graph."""

    def test_ioc_graph_import(self):
        from core.threat_intel.ioc_graph import IOCGraph
        graph = IOCGraph()
        assert graph is not None

    def test_ioc_creation(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType
        graph = IOCGraph()
        ioc = graph.add_ioc(IOCType.DOMAIN, "malicious.com", confidence=0.9, source="test")
        assert ioc.id is not None
        assert ioc.value == "malicious.com"
        assert ioc.ioc_type == IOCType.DOMAIN
        assert ioc.confidence == 0.9

    def test_ioc_deduplication(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType
        graph = IOCGraph()
        ioc1 = graph.add_ioc(IOCType.DOMAIN, "test.com", confidence=0.5)
        ioc2 = graph.add_ioc(IOCType.DOMAIN, "test.com", confidence=0.8)
        assert ioc1.id == ioc2.id
        assert ioc2.confidence == 0.8  # Higher confidence kept
        assert ioc2.sightings == 2

    def test_relationship_creation(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType, RelationshipType
        graph = IOCGraph()
        domain_ioc = graph.add_ioc(IOCType.DOMAIN, "example.com")
        ip_ioc = graph.add_ioc(IOCType.IP_ADDRESS, "192.168.1.1")
        rel = graph.add_relationship(domain_ioc.id, ip_ioc.id, RelationshipType.RESOLVES_TO)
        assert rel is not None
        assert rel.relationship_type == RelationshipType.RESOLVES_TO

    def test_get_neighbors(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType, RelationshipType
        graph = IOCGraph()
        domain_ioc = graph.add_ioc(IOCType.DOMAIN, "example.com")
        ip_ioc = graph.add_ioc(IOCType.IP_ADDRESS, "192.168.1.1")
        graph.add_relationship(domain_ioc.id, ip_ioc.id, RelationshipType.RESOLVES_TO)

        neighbors = graph.get_neighbors(domain_ioc.id, direction="out")
        assert len(neighbors) == 1
        assert neighbors[0].value == "192.168.1.1"

        neighbors_in = graph.get_neighbors(ip_ioc.id, direction="in")
        assert len(neighbors_in) == 1
        assert neighbors_in[0].value == "example.com"

    def test_find_paths(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType, RelationshipType
        graph = IOCGraph()
        a = graph.add_ioc(IOCType.DOMAIN, "a.com")
        b = graph.add_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        c = graph.add_ioc(IOCType.DOMAIN, "b.com")
        graph.add_relationship(a.id, b.id, RelationshipType.RESOLVES_TO)
        graph.add_relationship(b.id, c.id, RelationshipType.HOSTS)

        paths = graph.find_paths(a.id, c.id, max_depth=3)
        assert len(paths) >= 1
        assert paths[0][0] == a.id
        assert paths[0][-1] == c.id

    def test_get_subgraph(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType, RelationshipType
        graph = IOCGraph()
        a = graph.add_ioc(IOCType.DOMAIN, "a.com")
        b = graph.add_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        c = graph.add_ioc(IOCType.DOMAIN, "b.com")
        graph.add_relationship(a.id, b.id, RelationshipType.RESOLVES_TO)
        graph.add_relationship(b.id, c.id, RelationshipType.HOSTS)

        subgraph = graph.get_subgraph([a.id], depth=1)
        assert len(subgraph["nodes"]) >= 2
        assert len(subgraph["edges"]) >= 1

    def test_get_clusters(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType, RelationshipType
        graph = IOCGraph()
        # Cluster 1
        a1 = graph.add_ioc(IOCType.DOMAIN, "a1.com")
        b1 = graph.add_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        graph.add_relationship(a1.id, b1.id, RelationshipType.RESOLVES_TO)
        # Cluster 2 (disconnected)
        a2 = graph.add_ioc(IOCType.DOMAIN, "a2.com")
        b2 = graph.add_ioc(IOCType.IP_ADDRESS, "2.2.2.2")
        graph.add_relationship(a2.id, b2.id, RelationshipType.RESOLVES_TO)

        clusters = graph.get_clusters(min_size=2)
        assert len(clusters) == 2

    def test_enrich_from_analysis(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType
        graph = IOCGraph()
        analysis = {
            "network": {
                "urls": ["http://malicious.com/payload"],
                "domains": ["malicious.com", "c2.badguy.net"],
                "ips": ["192.168.1.100"],
            },
            "file_hashes": {"sha256": "abc123"},
            "strings": {"all_strings": ["http://evil.com/c2", "10.0.0.1"]},
        }
        graph.enrich_from_analysis(analysis)

        # Check IOCs were created
        assert graph.get_ioc_by_value("http://malicious.com/payload") is not None
        assert graph.get_ioc_by_value("malicious.com") is not None
        assert graph.get_ioc_by_value("c2.badguy.net") is not None
        assert graph.get_ioc_by_value("192.168.1.100") is not None
        assert graph.get_ioc_by_value("abc123") is not None

    def test_export_json(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType
        graph = IOCGraph()
        graph.add_ioc(IOCType.DOMAIN, "test.com")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = graph.export_graph(path, format="json")
            assert result is True
            with open(path) as f:
                data = json.load(f)
            assert len(data["nodes"]) == 1
            assert data["nodes"][0]["value"] == "test.com"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_get_stats(self):
        from core.threat_intel.ioc_graph import IOCGraph, IOCType, RelationshipType
        graph = IOCGraph()
        graph.add_ioc(IOCType.DOMAIN, "a.com")
        graph.add_ioc(IOCType.DOMAIN, "b.com")
        graph.add_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        a = graph.get_ioc_by_value("a.com")
        b = graph.get_ioc_by_value("1.1.1.1")
        graph.add_relationship(a.id, b.id, RelationshipType.RESOLVES_TO)

        stats = graph.get_stats()
        assert stats["total_iocs"] == 3
        assert stats["total_relationships"] == 1
        assert stats["by_type"]["domain"] == 2
        assert stats["by_type"]["ip_address"] == 1


class TestMITREMapper:
    """Tests for MITRE ATT&CK Mapper."""

    def test_mitre_mapper_import(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        assert mapper is not None

    def test_technique_definitions(self):
        from core.threat_intel.mitre_mapper import MITREMapper, Technique, Tactic
        mapper = MITREMapper()
        assert "T1474" in mapper.techniques
        tech = mapper.techniques["T1474"]
        assert tech.name == "Dynamic Code Loading"
        assert tech.tactic == Tactic.EXECUTION

    def test_map_dynamic_loading(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "dynamic_loading",
            "severity": "high",
            "evidence": {"class_loader": "DexClassLoader"},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1474" in technique_ids  # Dynamic Code Loading
        assert all(m.confidence > 0.7 for m in mappings)

    def test_map_reflection(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "reflection",
            "severity": "high",
            "evidence": {},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1106" in technique_ids  # Native API

    def test_map_crypto(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "crypto",
            "severity": "high",
            "evidence": {"crypto_algorithm": "AES"},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1511" in technique_ids  # Data Encryption

    def test_map_obfuscation(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "obfuscation",
            "severity": "high",
            "evidence": {"packer": "unknown"},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1480" in technique_ids  # Obfuscated/Stored Files

    def test_map_anti_analysis(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "anti_analysis",
            "severity": "high",
            "evidence": {},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1482" in technique_ids  # Anti-Forensics

    def test_map_network_c2(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "c2_beacon",
            "severity": "critical",
            "evidence": {"urls": ["http://c2.com/beacon"]},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1505" in technique_ids  # Web Service
        assert "T1502" in technique_ids  # Encrypted Channel

    def test_map_dga(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "dga_domain",
            "severity": "high",
            "evidence": {"dga_score": 0.9},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1507" in technique_ids  # Domain Generation Algorithm

    def test_map_permissions(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "dangerous_permission",
            "severity": "high",
            "evidence": {"permissions": ["SEND_SMS", "READ_CONTACTS"]},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1479" in technique_ids  # Permission Request

    def test_map_components(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "boot_receiver",
            "severity": "medium",
            "evidence": {},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1476" in technique_ids  # Boot Autostart

    def test_map_sms_collection(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {
            "id": "f1",
            "type": "sms_read",
            "severity": "high",
            "evidence": {},
        }
        mappings = mapper.map_finding(finding)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1497" in technique_ids  # SMS Collection

    def test_get_attack_matrix(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        # Add some mappings
        finding = {"id": "f1", "type": "dynamic_loading", "severity": "high", "evidence": {}}
        mapper.map_finding(finding)

        matrix = mapper.get_attack_matrix()
        assert "execution" in matrix
        exec_techs = matrix["execution"]
        assert len(exec_techs) > 0
        # Check our mapped technique is marked detected
        dyn_load = [t for t in exec_techs if t["id"] == "T1474"][0]
        assert dyn_load["detected"] is True

    def test_get_summary(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        findings = [
            {"id": "f1", "type": "dynamic_loading", "severity": "high", "evidence": {}},
            {"id": "f2", "type": "reflection", "severity": "high", "evidence": {}},
        ]
        for f in findings:
            mapper.map_finding(f)

        summary = mapper.get_summary()
        assert summary["total_mappings"] >= 2
        assert summary["unique_techniques"] >= 2
        assert summary["tactics_covered"] >= 2

    def test_export_mappings(self):
        from core.threat_intel.mitre_mapper import MITREMapper
        mapper = MITREMapper()
        finding = {"id": "f1", "type": "dynamic_loading", "severity": "high", "evidence": {}}
        mapper.map_finding(finding)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = mapper.export_mappings(path)
            assert result is True
            with open(path) as f:
                data = json.load(f)
            assert len(data) >= 1
            assert "technique_id" in data[0]
        finally:
            Path(path).unlink(missing_ok=True)


class TestMalwareSimilarity:
    """Tests for Malware Similarity."""

    def test_malware_similarity_import(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        assert sim is not None

    def test_add_sample(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sample = sim.add_sample("s1", "abc123", {"strings": ["test"], "api_calls": []}, family="test_family")
        assert sample.id == "s1"
        assert sample.family == "test_family"

    def test_add_sample_from_analysis(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        analysis = {
            "strings": {"all_strings": ["http://c2.com", "malicious"]},
            "network": {"urls": ["http://c2.com"], "domains": ["c2.com"]},
            "dex": {"class_count": 100, "method_count": 500},
        }
        sample = sim.add_sample_from_analysis(analysis, "hash123")
        assert sample.id == "hash123"[:16]
        assert "strings" in sample.features
        assert "api_calls" in sample.features

    def test_jaccard_similarity(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sim.add_sample("s1", "h1", {"strings": ["a", "b", "c"], "api_calls": []})
        sim.add_sample("s2", "h2", {"strings": ["b", "c", "d"], "api_calls": []})

        results = sim.compare_samples("s1", "s2", ["jaccard"])
        assert len(results) == 1
        assert results[0].similarity_score == 0.5  # 2/4 = 0.5

    def test_cosine_similarity(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sim.add_sample("s1", "h1", {"strings": [], "api_calls": ["A", "A", "B"]})
        sim.add_sample("s2", "h2", {"strings": [], "api_calls": ["A", "B", "B"]})

        results = sim.compare_samples("s1", "s2", ["cosine"])
        assert len(results) == 1
        # Cosine: (2*1 + 1*2) / (sqrt(5)*sqrt(5)) = 4/5 = 0.8
        assert abs(results[0].similarity_score - 0.8) < 0.01

    def test_feature_overlap(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sim.add_sample("s1", "h1", {
            "strings": ["a", "b"], "api_calls": ["A"],
            "permissions": ["PERM1"], "domains": ["d1.com"],
            "class_count": 100, "method_count": 200,
        })
        sim.add_sample("s2", "h2", {
            "strings": ["b", "c"], "api_calls": ["A"],
            "permissions": ["PERM1"], "domains": ["d2.com"],
            "class_count": 100, "method_count": 200,
        })

        results = sim.compare_samples("s1", "s2", ["feature_overlap"])
        assert len(results) == 1
        assert results[0].similarity_score > 0.5

    def test_find_similar(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sim.add_sample("s1", "h1", {"strings": ["a", "b", "c"], "api_calls": []})
        sim.add_sample("s2", "h2", {"strings": ["b", "c", "d"], "api_calls": []})
        sim.add_sample("s3", "h3", {"strings": ["x", "y", "z"], "api_calls": []})

        similar = sim.find_similar("s1", threshold=0.3, top_n=5)
        assert len(similar) >= 1
        assert similar[0].target_id == "s2"

    def test_attribute_family(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        # Add known family samples
        sim.add_sample("known1", "h1", {"strings": ["a", "b", "c"]}, family="family_a")
        sim.add_sample("known2", "h2", {"strings": ["b", "c", "d"]}, family="family_a")
        sim.add_sample("known3", "h3", {"strings": ["x", "y", "z"]}, family="family_b")
        # Add unknown sample similar to family_a
        sim.add_sample("unknown", "h4", {"strings": ["a", "b", "e"]})

        result = sim.attribute_family("unknown", threshold=0.3)
        assert result["family"] == "family_a"
        assert result["confidence"] > 0.5

    def test_cluster_samples(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        # Cluster 1
        sim.add_sample("s1", "h1", {"strings": ["a", "b", "c"]})
        sim.add_sample("s2", "h2", {"strings": ["b", "c", "d"]})
        # Cluster 2
        sim.add_sample("s3", "h3", {"strings": ["x", "y", "z"]})
        sim.add_sample("s4", "h4", {"strings": ["y", "z", "w"]})

        clusters = sim.cluster_samples(threshold=0.3)
        assert len(clusters) == 2

    def test_get_families(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sim.add_sample("s1", "h1", {}, family="fam1")
        sim.add_sample("s2", "h2", {}, family="fam2")
        sim.add_sample("s3", "h3", {}, family="fam1")

        families = sim.get_families()
        assert "fam1" in families
        assert "fam2" in families
        assert len(families) == 2

    def test_get_stats(self):
        from core.threat_intel.malware_similarity import MalwareSimilarity
        sim = MalwareSimilarity()
        sim.add_sample("s1", "h1", {}, family="fam1")
        sim.add_sample("s2", "h2", {}, family="fam1")

        stats = sim.get_stats()
        assert stats["total_samples"] == 2
        assert stats["families"] == 1
        assert stats["family_distribution"]["fam1"] == 2


class TestFeedIntegrations:
    """Tests for Feed Integrations."""

    def test_feed_integrations_import(self):
        from core.threat_intel.feed_integrations import FeedIntegrations
        feeds = FeedIntegrations()
        assert feeds is not None

    def test_feed_indicator_dataclass(self):
        from core.threat_intel.feed_integrations import FeedIndicator, FeedSource
        indicator = FeedIndicator(
            id="test1",
            source=FeedSource.URLHAUS,
            indicator_type="domain",
            value="malicious.com",
            confidence=0.9,
            severity="high",
        )
        assert indicator.value == "malicious.com"
        assert indicator.source == FeedSource.URLHAUS

    def test_feed_query_result(self):
        from core.threat_intel.feed_integrations import FeedQueryResult, FeedSource
        result = FeedQueryResult(
            source=FeedSource.URLHAUS,
            query="test.com",
            query_type="domain",
            found=True,
        )
        assert result.found is True
        assert result.source == FeedSource.URLHAUS

    def test_get_feed_status(self):
        from core.threat_intel.feed_integrations import FeedIntegrations
        feeds = FeedIntegrations()
        status = feeds.get_feed_status()
        assert "urlhaus" in status
        assert "abuse_ch" in status
        assert status["urlhaus"]["enabled"] is True

    @patch('core.threat_intel.feed_integrations.requests')
    def test_urlhaus_hash_check(self, mock_requests):
        from core.threat_intel.feed_integrations import FeedIntegrations
        feeds = FeedIntegrations()

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "payloads": [{
                "sha256": "abc123",
                "signatures": ["trojan.banker"],
                "file_type": "APK",
                "file_size": 12345,
                "first_seen": "2024-01-01",
                "last_seen": "2024-01-02",
            }]
        }
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        result = feeds._check_urlhaus_hash("abc123")
        assert result.found is True
        assert len(result.indicators) == 1
        assert result.indicators[0].malware_families == ["trojan.banker"]

    @patch('core.threat_intel.feed_integrations.requests')
    def test_urlhaus_domain_check(self, mock_requests):
        from core.threat_intel.feed_integrations import FeedIntegrations
        feeds = FeedIntegrations()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "urls": [{
                "url": "http://malicious.com/payload",
                "host": "malicious.com",
                "url_status": "online",
                "threat": "trojan",
                "date_added": "2024-01-01",
            }]
        }
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        result = feeds._check_urlhaus_domain("malicious.com")
        assert result.found is True
        assert len(result.indicators) == 1
        assert result.indicators[0].value == "http://malicious.com/payload"

    @patch('core.threat_intel.feed_integrations.requests')
    def test_malwarebazaar_check(self, mock_requests):
        from core.threat_intel.feed_integrations import FeedIntegrations
        feeds = FeedIntegrations()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [{
                "sha256_hash": "abc123",
                "signature": "trojan.banker",
                "file_type": "APK",
                "file_size": 12345,
                "first_seen": "2024-01-01",
                "reporter": "user",
                "tags": ["android", "banker"],
            }]
        }
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        result = feeds._check_abuse_ch_hash("abc123")
        assert result.found is True
        assert len(result.indicators) == 1
        assert result.indicators[0].malware_families == ["trojan.banker"]

    @patch('core.threat_intel.feed_integrations.requests')
    def test_threatfox_check(self, mock_requests):
        from core.threat_intel.feed_integrations import FeedIntegrations
        feeds = FeedIntegrations()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [{
                "ioc": "malicious.com",
                "ioc_type": "domain",
                "malware": "trojan.banker",
                "confidence_level": 90,
                "first_seen": "2024-01-01",
                "last_seen": "2024-01-02",
                "reporter": "abuse_ch",
            }]
        }
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        result = feeds._check_threatfox_domain("malicious.com")
        assert result.found is True
        assert len(result.indicators) == 1
        assert result.indicators[0].value == "malicious.com"


class TestThreatIntelIntegration:
    """Integration tests for threat intel module."""

    def test_module_imports(self):
        from core.threat_intel import (
            IOCGraph, get_ioc_graph,
            MITREMapper, get_mitre_mapper,
            MalwareSimilarity, get_malware_similarity,
            FeedIntegrations, get_feed_integrations,
        )
        assert IOCGraph is not None
        assert MITREMapper is not None
        assert MalwareSimilarity is not None
        assert FeedIntegrations is not None

    def test_singleton_patterns(self):
        from core.threat_intel import (
            get_ioc_graph, get_mitre_mapper,
            get_malware_similarity, get_feed_integrations,
        )
        assert get_ioc_graph() is get_ioc_graph()
        assert get_mitre_mapper() is get_mitre_mapper()
        assert get_malware_similarity() is get_malware_similarity()
        assert get_feed_integrations() is get_feed_integrations()

    def test_end_to_end_threat_intel(self):
        """Test full threat intelligence pipeline."""
        from core.threat_intel import (
            get_ioc_graph, get_mitre_mapper,
            get_malware_similarity, get_feed_integrations,
        )
        from core.threat_intel.ioc_graph import IOCType, RelationshipType

        # 1. Build IOC graph from analysis
        ioc_graph = get_ioc_graph()
        analysis = {
            "network": {
                "urls": ["http://c2.malicious.top/beacon", "http://evil.com/payload.apk"],
                "domains": ["c2.malicious.top", "evil.com"],
                "ips": ["192.168.1.100"],
            },
            "file_hashes": {"sha256": "abc123def456"},
            "strings": {"all_strings": ["http://c2.malicious.top/beacon", "bankbot", "overlay"]},
        }
        ioc_graph.enrich_from_analysis(analysis)

        # 2. Map to MITRE ATT&CK
        mitre_mapper = get_mitre_mapper()
        mitre_mapper.map_analysis_results(analysis)
        matrix = mitre_mapper.get_attack_matrix()

        # Check key techniques detected
        exec_techs = matrix["execution"]
        dyn_load = [t for t in exec_techs if t["id"] == "T1474"]
        assert len(dyn_load) > 0

        # 3. Add to malware similarity
        malware_sim = get_malware_similarity()
        sample = malware_sim.add_sample_from_analysis(analysis, "abc123def456")
        assert sample.family == "banking_trojan"  # Inferred from "bankbot" string

        # 4. Check feed integrations (mocked)
        feeds = get_feed_integrations()
        status = feeds.get_feed_status()
        assert "urlhaus" in status

        # Verify IOC graph has expected nodes
        assert ioc_graph.get_ioc_by_value("c2.malicious.top") is not None
        assert ioc_graph.get_ioc_by_value("http://c2.malicious.top/beacon") is not None
        assert ioc_graph.get_ioc_by_value("abc123def456") is not None

        # Verify relationships
        url_ioc = ioc_graph.get_ioc_by_value("http://c2.malicious.top/beacon")
        domain_ioc = ioc_graph.get_ioc_by_value("c2.malicious.top")
        neighbors = ioc_graph.get_neighbors(url_ioc.id, direction="out")
        assert any(n.value == "c2.malicious.top" for n in neighbors)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])