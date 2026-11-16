"""
IOC Graph for APKStudioAI 2.1
Builds and queries indicator of compromise relationship graphs.
"""
import json
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from ..config_manager import get_config
from ..logging_setup import get_module_logger

logger = get_module_logger("ioc_graph")


class IOCType(Enum):
    """Types of indicators of compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    FILE_PATH = "file_path"
    CERTIFICATE = "certificate"
    USER_AGENT = "user_agent"
    CRYPTO_ADDRESS = "crypto_address"
    PHONE_NUMBER = "phone_number"


class RelationshipType(Enum):
    """Relationship types between IOCs."""
    RESOLVES_TO = "resolves_to"         # Domain -> IP
    HOSTS = "hosts"                     # IP -> Domain
    CONTAINS = "contains"               # URL -> Domain/IP
    DOWNLOADS = "downloads"             # URL -> File Hash
    DROPS = "drops"                     # File Hash -> File Hash
    COMMUNICATES_WITH = "communicates_with"  # File Hash -> IP/Domain
    EMBEDS = "embeds"                   # File Hash -> IOC
    CONTACTS = "contacts"               # File Hash -> Email/Phone
    USES_CERT = "uses_certificate"      # File Hash -> Certificate
    RELATED_TO = "related_to"           # Generic relationship


@dataclass
class IOC:
    """Indicator of Compromise."""
    id: str
    ioc_type: IOCType
    value: str
    confidence: float = 1.0  # 0-1
    source: str = "analysis"
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=lambda: __import__('time').time())
    last_seen: float = field(default_factory=lambda: __import__('time').time())
    sightings: int = 1

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, IOC):
            return self.id == other.id
        return False


@dataclass
class IOCRelationship:
    """Relationship between two IOCs."""
    id: str
    source_ioc_id: str
    target_ioc_id: str
    relationship_type: RelationshipType
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: __import__('time').time())


class IOCGraph:
    """Graph of IOCs and their relationships."""

    def __init__(self, config: Dict = None):
        self.config = config or get_config().get_all()
        self.iocs: Dict[str, IOC] = {}
        self.relationships: List[IOCRelationship] = []
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)  # ioc_id -> set of connected ioc_ids
        self._reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)

        # Indexes for fast lookup
        self._by_type: Dict[IOCType, Set[str]] = defaultdict(set)
        self._by_value: Dict[str, str] = {}  # value -> ioc_id
        self._by_tag: Dict[str, Set[str]] = defaultdict(set)

    def add_ioc(self, ioc_type: IOCType, value: str, confidence: float = 1.0,
                source: str = "analysis", tags: List[str] = None,
                context: Dict = None) -> IOC:
        """Add or update an IOC."""
        # Generate deterministic ID
        ioc_id = hashlib.sha256(f"{ioc_type.value}:{value}".encode()).hexdigest()[:16]

        if ioc_id in self.iocs:
            # Update existing
            ioc = self.iocs[ioc_id]
            ioc.confidence = max(ioc.confidence, confidence)
            ioc.last_seen = __import__('time').time()
            ioc.sightings += 1
            if tags:
                ioc.tags.extend(t for t in tags if t not in ioc.tags)
                for t in tags:
                    self._by_tag[t].add(ioc_id)
            if context:
                ioc.context.update(context)
            return ioc

        # Create new
        ioc = IOC(
            id=ioc_id,
            ioc_type=ioc_type,
            value=value,
            confidence=confidence,
            source=source,
            tags=tags or [],
            context=context or {},
        )

        self.iocs[ioc_id] = ioc
        self._by_type[ioc_type].add(ioc_id)
        self._by_value[value] = ioc_id
        for tag in (tags or []):
            self._by_tag[tag].add(ioc_id)

        return ioc

    def add_relationship(self, source_ioc_id: str, target_ioc_id: str,
                         rel_type: RelationshipType, confidence: float = 1.0,
                         evidence: Dict = None) -> Optional[IOCRelationship]:
        """Add a relationship between two IOCs."""
        if source_ioc_id not in self.iocs or target_ioc_id not in self.iocs:
            return None

        rel_id = hashlib.sha256(f"{source_ioc_id}:{rel_type.value}:{target_ioc_id}".encode()).hexdigest()[:16]

        # Check for duplicate
        for rel in self.relationships:
            if rel.id == rel_id:
                return rel

        relationship = IOCRelationship(
            id=rel_id,
            source_ioc_id=source_ioc_id,
            target_ioc_id=target_ioc_id,
            relationship_type=rel_type,
            confidence=confidence,
            evidence=evidence or {},
        )

        self.relationships.append(relationship)
        self._adjacency[source_ioc_id].add(target_ioc_id)
        self._reverse_adjacency[target_ioc_id].add(source_ioc_id)

        return relationship

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        """Get IOC by ID."""
        return self.iocs.get(ioc_id)

    def get_ioc_by_value(self, value: str) -> Optional[IOC]:
        """Get IOC by value."""
        ioc_id = self._by_value.get(value)
        return self.iocs.get(ioc_id) if ioc_id else None

    def get_iocs_by_type(self, ioc_type: IOCType) -> List[IOC]:
        """Get all IOCs of a specific type."""
        return [self.iocs[ioc_id] for ioc_id in self._by_type.get(ioc_type, set())]

    def get_iocs_by_tag(self, tag: str) -> List[IOC]:
        """Get all IOCs with a specific tag."""
        return [self.iocs[ioc_id] for ioc_id in self._by_tag.get(tag, set())]

    def get_neighbors(self, ioc_id: str, direction: str = "both",
                      rel_type: RelationshipType = None) -> List[IOC]:
        """Get neighboring IOCs."""
        neighbors = set()

        if direction in ["out", "both"]:
            neighbors.update(self._adjacency.get(ioc_id, set()))
        if direction in ["in", "both"]:
            neighbors.update(self._reverse_adjacency.get(ioc_id, set()))

        results = []
        for nid in neighbors:
            ioc = self.iocs.get(nid)
            if ioc:
                if rel_type is None:
                    results.append(ioc)
                else:
                    # Check if relationship matches
                    for rel in self.relationships:
                        if ((rel.source_ioc_id == ioc_id and rel.target_ioc_id == nid) or
                            (rel.source_ioc_id == nid and rel.target_ioc_id == ioc_id)):
                            if rel.relationship_type == rel_type:
                                results.append(ioc)
                                break
        return results

    def get_relationships(self, ioc_id: str) -> List[IOCRelationship]:
        """Get all relationships for an IOC."""
        return [r for r in self.relationships
                if r.source_ioc_id == ioc_id or r.target_ioc_id == ioc_id]

    def find_paths(self, source_id: str, target_id: str,
                   max_depth: int = 4) -> List[List[str]]:
        """Find paths between two IOCs (BFS)."""
        if source_id not in self.iocs or target_id not in self.iocs:
            return []

        paths = []
        queue = [(source_id, [source_id])]
        visited = {source_id}

        while queue and len(paths) < 10:  # Limit paths
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            if current == target_id:
                paths.append(path)
                continue

            for neighbor in self._adjacency.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def get_subgraph(self, ioc_ids: List[str], depth: int = 1) -> Dict:
        """Extract subgraph around given IOCs."""
        nodes = set(ioc_ids)
        edges = []

        # Expand by depth
        for _ in range(depth):
            new_nodes = set()
            for nid in nodes:
                new_nodes.update(self._adjacency.get(nid, set()))
                new_nodes.update(self._reverse_adjacency.get(nid, set()))
            nodes.update(new_nodes)

        # Collect edges within subgraph
        for rel in self.relationships:
            if rel.source_ioc_id in nodes and rel.target_ioc_id in nodes:
                edges.append({
                    "source": rel.source_ioc_id,
                    "target": rel.target_ioc_id,
                    "type": rel.relationship_type.value,
                    "confidence": rel.confidence,
                })

        return {
            "nodes": [
                {
                    "id": ioc_id,
                    "type": self.iocs[ioc_id].ioc_type.value,
                    "value": self.iocs[ioc_id].value,
                    "confidence": self.iocs[ioc_id].confidence,
                    "tags": self.iocs[ioc_id].tags,
                }
                for ioc_id in nodes if ioc_id in self.iocs
            ],
            "edges": edges,
        }

    def get_central_iocs(self, top_n: int = 10) -> List[Tuple[IOC, int]]:
        """Get most connected IOCs (by degree)."""
        degrees = []
        for ioc_id, ioc in self.iocs.items():
            degree = len(self._adjacency.get(ioc_id, set())) + len(self._reverse_adjacency.get(ioc_id, set()))
            degrees.append((ioc, degree))

        degrees.sort(key=lambda x: x[1], reverse=True)
        return degrees[:top_n]

    def get_clusters(self, min_size: int = 3) -> List[List[IOC]]:
        """Find connected components (clusters) in the graph."""
        visited = set()
        clusters = []

        for ioc_id in self.iocs:
            if ioc_id in visited:
                continue

            # BFS to find component
            component = set()
            queue = [ioc_id]
            visited.add(ioc_id)

            while queue:
                current = queue.pop(0)
                component.add(current)

                for neighbor in self._adjacency.get(current, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
                for neighbor in self._reverse_adjacency.get(current, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            if len(component) >= min_size:
                clusters.append([self.iocs[nid] for nid in component if nid in self.iocs])

        return clusters

    def enrich_from_analysis(self, analysis_results: Dict):
        """Enrich graph from static/dynamic analysis results."""
        # Extract IOCs from network analysis
        network = analysis_results.get("network", {})
        for url in network.get("urls", []):
            ioc = self.add_ioc(IOCType.URL, url, source="static_analysis",
                              context={"analyzer": "network"})
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                if domain:
                    domain_ioc = self.add_ioc(IOCType.DOMAIN, domain, source="static_analysis")
                    self.add_relationship(ioc.id, domain_ioc.id, RelationshipType.CONTAINS)
            except Exception:
                pass

        for ip in network.get("ips", []):
            self.add_ioc(IOCType.IP_ADDRESS, ip, source="static_analysis")

        for domain in network.get("domains", []):
            self.add_ioc(IOCType.DOMAIN, domain, source="static_analysis")

        # File hashes
        file_hashes = analysis_results.get("file_hashes", {})
        for algo, hash_val in file_hashes.items():
            if hash_val:
                self.add_ioc(IOCType.FILE_HASH, hash_val, source="static_analysis",
                            context={"algorithm": algo})

        # Strings that look like IOCs
        strings = analysis_results.get("strings", {})
        for s in strings.get("all_strings", []):
            self._extract_iocs_from_string(s, analysis_results)

        # Dynamic analysis IOCs
        dynamic = analysis_results.get("dynamic", {})
        for flow in dynamic.get("http_flows", []):
            url = flow.get("url", "")
            if url:
                ioc = self.add_ioc(IOCType.URL, url, source="dynamic_analysis",
                                  context={"method": flow.get("method")})
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc
                    if domain:
                        domain_ioc = self.add_ioc(IOCType.DOMAIN, domain, source="dynamic_analysis")
                        self.add_relationship(ioc.id, domain_ioc.id, RelationshipType.CONTAINS)
                except Exception:
                    pass

            host = flow.get("host", "")
            if host:
                self.add_ioc(IOCType.DOMAIN, host, source="dynamic_analysis")

            server_ip = flow.get("server_ip", "")
            if server_ip:
                ip_ioc = self.add_ioc(IOCType.IP_ADDRESS, server_ip, source="dynamic_analysis")
                if host:
                    host_ioc = self.get_ioc_by_value(host)
                    if host_ioc:
                        self.add_relationship(host_ioc.id, ip_ioc.id, RelationshipType.RESOLVES_TO)

    def _extract_iocs_from_string(self, s: str, analysis_results: Dict):
        """Extract IOCs from a string."""
        import re

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for match in re.finditer(ip_pattern, s):
            ip = match.group()
            if self._is_valid_ip(ip):
                self.add_ioc(IOCType.IP_ADDRESS, ip, source="string_extraction",
                            context={"source_string": s[:100]})

        # Domains (simplified)
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b'
        for match in re.finditer(domain_pattern, s):
            domain = match.group().lower()
            if not self._is_ip(domain) and len(domain) > 3:
                self.add_ioc(IOCType.DOMAIN, domain, source="string_extraction",
                            context={"source_string": s[:100]})

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for match in re.finditer(url_pattern, s):
            url = match.group()
            self.add_ioc(IOCType.URL, url, source="string_extraction",
                        context={"source_string": s[:100]})

        # File hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            (r'\b[a-fA-F0-9]{32}\b', "md5"),
            (r'\b[a-fA-F0-9]{40}\b', "sha1"),
            (r'\b[a-fA-F0-9]{64}\b', "sha256"),
        ]
        for pattern, algo in hash_patterns:
            for match in re.finditer(pattern, s):
                hash_val = match.group().lower()
                self.add_ioc(IOCType.FILE_HASH, hash_val, source="string_extraction",
                            context={"algorithm": algo, "source_string": s[:100]})

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for match in re.finditer(email_pattern, s):
            email = match.group()
            self.add_ioc(IOCType.EMAIL, email, source="string_extraction",
                        context={"source_string": s[:100]})

        # Crypto addresses (Bitcoin, Ethereum)
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        for match in re.finditer(btc_pattern, s):
            addr = match.group()
            self.add_ioc(IOCType.CRYPTO_ADDRESS, addr, source="string_extraction",
                        context={"currency": "BTC", "source_string": s[:100]})
        for match in re.finditer(eth_pattern, s):
            addr = match.group()
            self.add_ioc(IOCType.CRYPTO_ADDRESS, addr, source="string_extraction",
                        context={"currency": "ETH", "source_string": s[:100]})

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)

    def _is_ip(self, s: str) -> bool:
        """Check if string is an IP."""
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', s))

    def export_graph(self, output_path: str, format: str = "json") -> bool:
        """Export graph to file."""
        try:
            if format == "json":
                data = {
                    "nodes": [
                        {
                            "id": ioc.id,
                            "type": ioc.ioc_type.value,
                            "value": ioc.value,
                            "confidence": ioc.confidence,
                            "source": ioc.source,
                            "tags": ioc.tags,
                            "context": ioc.context,
                            "first_seen": ioc.first_seen,
                            "last_seen": ioc.last_seen,
                            "sightings": ioc.sightings,
                        }
                        for ioc in self.iocs.values()
                    ],
                    "edges": [
                        {
                            "id": rel.id,
                            "source": rel.source_ioc_id,
                            "target": rel.target_ioc_id,
                            "type": rel.relationship_type.value,
                            "confidence": rel.confidence,
                            "evidence": rel.evidence,
                            "timestamp": rel.timestamp,
                        }
                        for rel in self.relationships
                    ],
                }
                with open(output_path, "w") as f:
                    json.dump(data, f, indent=2)

            elif format == "gexf":
                self._export_gexf(output_path)

            elif format == "graphml":
                self._export_graphml(output_path)

            return True
        except Exception as e:
            logger.error("ioc_graph_export_error", error=str(e))
            return False

    def _export_gexf(self, output_path: str):
        """Export as GEXF for Gephi."""
        import xml.etree.ElementTree as ET

        gexf = ET.Element("gexf", xmlns="http://www.gexf.net/1.2draft", version="1.2")
        graph = ET.SubElement(gexf, "graph", mode="static", defaultedgetype="directed")

        nodes_elem = ET.SubElement(graph, "nodes")
        for ioc in self.iocs.values():
            node = ET.SubElement(nodes_elem, "node", id=ioc.id, label=ioc.value)
            attvalues = ET.SubElement(node, "attvalues")
            for key, val in [("type", ioc.ioc_type.value), ("confidence", str(ioc.confidence)),
                            ("source", ioc.source), ("tags", ",".join(ioc.tags))]:
                ET.SubElement(attvalues, "attvalue", for_=key, value=str(val))

        edges_elem = ET.SubElement(graph, "edges")
        for rel in self.relationships:
            ET.SubElement(edges_elem, "edge", id=rel.id, source=rel.source_ioc_id,
                         target=rel.target_ioc_id, label=rel.relationship_type.value)

        tree = ET.ElementTree(gexf)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)

    def _export_graphml(self, output_path: str):
        """Export as GraphML."""
        import xml.etree.ElementTree as ET

        graphml = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        graph = ET.SubElement(graphml, "graph", edgedefault="directed")

        for ioc in self.iocs.values():
            node = ET.SubElement(graph, "node", id=ioc.id)
            for key, val in [("type", ioc.ioc_type.value), ("value", ioc.value),
                            ("confidence", str(ioc.confidence)), ("source", ioc.source)]:
                data = ET.SubElement(node, "data", key=key)
                data.text = str(val)

        for rel in self.relationships:
            edge = ET.SubElement(graph, "edge", id=rel.id, source=rel.source_ioc_id,
                                target=rel.target_ioc_id)
            data = ET.SubElement(edge, "data", key="type")
            data.text = rel.relationship_type.value

        tree = ET.ElementTree(graphml)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)

    def get_stats(self) -> Dict:
        """Get graph statistics."""
        type_counts = defaultdict(int)
        for ioc in self.iocs.values():
            type_counts[ioc.ioc_type.value] += 1

        rel_counts = defaultdict(int)
        for rel in self.relationships:
            rel_counts[rel.relationship_type.value] += 1

        return {
            "total_iocs": len(self.iocs),
            "total_relationships": len(self.relationships),
            "by_type": dict(type_counts),
            "by_relationship": dict(rel_counts),
            "clusters": len(self.get_clusters()),
            "avg_degree": sum(len(self._adjacency[n]) + len(self._reverse_adjacency[n])
                             for n in self.iocs) / len(self.iocs) if self.iocs else 0,
        }

    def clear(self):
        """Clear the graph."""
        self.iocs.clear()
        self.relationships.clear()
        self._adjacency.clear()
        self._reverse_adjacency.clear()
        self._by_type.clear()
        self._by_value.clear()
        self._by_tag.clear()


_ioc_graph_instance = None


def get_ioc_graph(config: Dict = None) -> IOCGraph:
    """Get singleton IOC graph instance."""
    global _ioc_graph_instance
    if _ioc_graph_instance is None:
        _ioc_graph_instance = IOCGraph(config)
    return _ioc_graph_instance