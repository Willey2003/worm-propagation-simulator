from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Callable
import random
import uuid
from abc import ABC, abstractmethod
import networkx as nx
import numpy as np


class NodeStatus(Enum):
    HEALTHY = "healthy"
    VULNERABLE = "vulnerable"
    INFECTED = "infected"
    PATCHED = "patched"
    QUARANTINED = "quarantined"


class SecurityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class WormType(Enum):
    RANDOM_SCAN = "random_scan"
    HITLIST = "hitlist"
    TOPOLOGICAL = "topological"
    PERMUTATION = "permutation"
    LOCAL_PREFERENCE = "local_preference"


@dataclass
class NetworkNode:
    node_id: str
    status: NodeStatus = NodeStatus.HEALTHY
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    is_patched: bool = False
    vulnerability_score: float = 0.5
    subnet: str = "default"
    metadata: Dict = field(default_factory=dict)
    
    # Infection tracking
    infected_at: Optional[int] = None
    infected_by: Optional[str] = None
    patch_attempts: int = 0
    
    def can_be_infected(self) -> bool:
        return self.status in [NodeStatus.HEALTHY, NodeStatus.VULNERABLE] and not self.is_patched
    
    def infect(self, tick: int, source_id: str):
        self.status = NodeStatus.INFECTED
        self.infected_at = tick
        self.infected_by = source_id
    
    def patch(self):
        self.status = NodeStatus.PATCHED
        self.is_patched = True
    
    def quarantine(self):
        self.status = NodeStatus.QUARANTINED


@dataclass
class FirewallRule:
    source_subnet: str
    dest_subnet: str
    action: str = "allow"  # allow, deny, rate_limit
    rate_limit: Optional[int] = None


class WormModel(ABC):
    @abstractmethod
    def select_targets(self, infected_nodes: List[NetworkNode], all_nodes: Dict[str, NetworkNode], 
                       topology: nx.Graph, scan_rate: int) -> Dict[str, List[str]]:
        pass


class RandomScanWorm(WormModel):
    def select_targets(self, infected_nodes: List[NetworkNode], all_nodes: Dict[str, NetworkNode],
                       topology: nx.Graph, scan_rate: int) -> Dict[str, List[str]]:
        targets = {}
        vulnerable_nodes = [n for n in all_nodes.values() if n.can_be_infected()]
        
        if not vulnerable_nodes:
            return targets
            
        for node in infected_nodes:
            targets[node.node_id] = random.sample(
                [n.node_id for n in vulnerable_nodes],
                min(scan_rate, len(vulnerable_nodes))
            )
        return targets


class HitlistWorm(WormModel):
    def __init__(self):
        self.hitlist: List[str] = []
        
    def select_targets(self, infected_nodes: List[NetworkNode], all_nodes: Dict[str, NetworkNode],
                       topology: nx.Graph, scan_rate: int) -> Dict[str, List[str]]:
        targets = {}
        vulnerable = [n.node_id for n in all_nodes.values() if n.can_be_infected()]
        
        for node in infected_nodes:
            if self.hitlist:
                scan_targets = self.hitlist[:scan_rate]
                self.hitlist = self.hitlist[scan_rate:]
            else:
                scan_targets = random.sample(vulnerable, min(scan_rate, len(vulnerable)))
            targets[node.node_id] = scan_targets
        return targets


class TopologicalWorm(WormModel):
    def select_targets(self, infected_nodes: List[NetworkNode], all_nodes: Dict[str, NetworkNode],
                       topology: nx.Graph, scan_rate: int) -> Dict[str, List[str]]:
        targets = {}
        for node in infected_nodes:
            neighbors = list(topology.neighbors(node.node_id))
            vulnerable_neighbors = [n for n in neighbors if all_nodes[n].can_be_infected()]
            targets[node.node_id] = random.sample(
                vulnerable_neighbors, 
                min(scan_rate, len(vulnerable_neighbors))
            )
        return targets


class PermutationWorm(WormModel):
    def __init__(self):
        self.permutation: List[str] = []
        self.index = 0
        
    def select_targets(self, infected_nodes: List[NetworkNode], all_nodes: Dict[str, NetworkNode],
                       topology: nx.Graph, scan_rate: int) -> Dict[str, NetworkNode]:
        targets = {}
        if not self.permutation:
            self.permutation = [n.node_id for n in all_nodes.values() if n.can_be_infected()]
            random.shuffle(self.permutation)
            
        for node in infected_nodes:
            end = min(self.index + scan_rate, len(self.permutation))
            targets[node.node_id] = self.permutation[self.index:end]
            self.index = end
        return targets


class LocalPreferenceWorm(WormModel):
    def __init__(self, local_prob: float = 0.7):
        self.local_prob = local_prob
        
    def select_targets(self, infected_nodes: List[NetworkNode], all_nodes: Dict[str, NetworkNode],
                       topology: nx.Graph, scan_rate: int) -> Dict[str, List[str]]:
        targets = {}
        for node in infected_nodes:
            local_targets = []
            remote_targets = []
            
            for n in all_nodes.values():
                if n.can_be_infected():
                    if n.subnet == node.subnet:
                        local_targets.append(n.node_id)
                    else:
                        remote_targets.append(n.node_id)
            
            local_scans = int(scan_rate * self.local_prob)
            remote_scans = scan_rate - local_scans
            
            selected = []
            if local_targets:
                selected.extend(random.sample(local_targets, min(local_scans, len(local_targets))))
            if remote_targets:
                selected.extend(random.sample(remote_targets, min(remote_scans, len(remote_targets))))
                
            targets[node.node_id] = selected
        return targets


def create_worm_model(worm_type: WormType, **kwargs) -> WormModel:
    models = {
        WormType.RANDOM_SCAN: RandomScanWorm,
        WormType.HITLIST: HitlistWorm,
        WormType.TOPOLOGICAL: TopologicalWorm,
        WormType.PERMUTATION: PermutationWorm,
        WormType.LOCAL_PREFERENCE: LocalPreferenceWorm,
    }
    return models[worm_type](**kwargs)