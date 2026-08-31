"""Asset Graph Data Model and In-Memory/Database Graph Store for Sentinel.

Represents attack surface relationships:
domain -> subdomain -> ip -> port -> service -> technology -> url
Provides neighbor queries, full attack-surface extraction, and exposure summaries.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import AssetCriticality, EnvironmentLabel


class NodeType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    URL = "url"
    ORGANIZATION = "organization"


class EdgeType(StrEnum):
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    LISTENS_ON = "listens_on"
    RUNS_SERVICE = "runs_service"
    USES_TECHNOLOGY = "uses_technology"
    EXPOSES_URL = "exposes_url"
    OWNS = "owns"


class GraphNode(BaseModel):
    id: str
    task_id: str
    node_type: NodeType
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)
    is_internet_facing: bool = True
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    environment: EnvironmentLabel = EnvironmentLabel.PRODUCTION
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GraphEdge(BaseModel):
    id: str = Field(default_factory=lambda: f"edge-{uuid.uuid4().hex[:8]}")
    task_id: str
    source_node_id: str
    target_node_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AttackSurfaceReport(BaseModel):
    task_id: str
    total_nodes: int
    total_edges: int
    domains_count: int
    ips_count: int
    services_count: int
    technologies: list[str] = Field(default_factory=list)
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    internet_facing_ratio: float = 1.0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AssetGraphStore:
    """Store managing attack surface graph nodes and relationships."""

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}

    def add_node(
        self,
        task_id: str,
        node_type: NodeType,
        label: str,
        properties: dict[str, Any] | None = None,
        is_internet_facing: bool = True,
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
    ) -> GraphNode:
        node_id = f"{node_type.value}:{label.strip().lower()}"
        if node_id in self._nodes:
            existing = self._nodes[node_id]
            if properties:
                existing.properties.update(properties)
            return existing

        node = GraphNode(
            id=node_id,
            task_id=task_id,
            node_type=node_type,
            label=label.strip().lower(),
            properties=properties or {},
            is_internet_facing=is_internet_facing,
            criticality=criticality,
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        task_id: str,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        properties: dict[str, Any] | None = None,
    ) -> GraphEdge:
        # Check duplicate edge
        for e in self._edges.values():
            if (
                e.task_id == task_id
                and e.source_node_id == source_id
                and e.target_node_id == target_id
                and e.edge_type == edge_type
            ):
                return e

        edge = GraphEdge(
            task_id=task_id,
            source_node_id=source_id,
            target_node_id=target_id,
            edge_type=edge_type,
            properties=properties or {},
        )
        self._edges[edge.id] = edge
        return edge

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        neighbor_ids = set()
        for e in self._edges.values():
            if e.source_node_id == node_id:
                neighbor_ids.add(e.target_node_id)
            elif e.target_node_id == node_id:
                neighbor_ids.add(e.source_node_id)
        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    def get_task_attack_surface(self, task_id: str) -> AttackSurfaceReport:
        nodes = [n for n in self._nodes.values() if n.task_id == task_id]
        edges = [e for e in self._edges.values() if e.task_id == task_id]

        domains = sum(1 for n in nodes if n.node_type in (NodeType.DOMAIN, NodeType.SUBDOMAIN))
        ips = sum(1 for n in nodes if n.node_type == NodeType.IP)
        services = sum(1 for n in nodes if n.node_type == NodeType.SERVICE)
        techs = list({n.label for n in nodes if n.node_type == NodeType.TECHNOLOGY})

        internet_facing_count = sum(1 for n in nodes if n.is_internet_facing)
        ratio = round(internet_facing_count / len(nodes), 2) if nodes else 0.0

        return AttackSurfaceReport(
            task_id=task_id,
            total_nodes=len(nodes),
            total_edges=len(edges),
            domains_count=domains,
            ips_count=ips,
            services_count=services,
            technologies=techs,
            nodes=nodes,
            edges=edges,
            internet_facing_ratio=ratio,
        )


# Global Asset Graph Store Singleton
asset_graph_store = AssetGraphStore()
