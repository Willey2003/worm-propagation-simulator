import logging
import random
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict
import networkx as nx
import numpy as np

from .models import (
    NetworkNode, NodeStatus, SecurityLevel, WormType, FirewallRule,
    create_worm_model, WormModel
)

logger = logging.getLogger(__name__)


@dataclass
class SimulationMetrics:
    tick: int = 0
    healthy: int = 0
    vulnerable: int = 0
    infected: int = 0
    patched: int = 0
    quarantined: int = 0
    new_infections: int = 0
    scan_attempts: int = 0
    blocked_by_firewall: int = 0
    blocked_by_patch: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tick": self.tick,
            "healthy": self.healthy,
            "vulnerable": self.vulnerable,
            "infected": self.infected,
            "patched": self.patched,
            "quarantined": self.quarantined,
            "new_infections": self.new_infections,
            "scan_attempts": self.scan_attempts,
            "blocked_by_firewall": self.blocked_by_firewall,
            "blocked_by_patch": self.blocked_by_patch,
            "total_nodes": self.healthy + self.vulnerable + self.infected + self.patched + self.quarantined,
            "infection_rate": self.infected / max(1, self.healthy + self.vulnerable + self.infected + self.patched + self.quarantined)
        }


@dataclass
class SimulationConfig:
    num_nodes: int = 100
    patch_rate: float = 0.3
    scan_rate: int = 10
    topology_type: str = "random"
    worm_type: WormType = WormType.RANDOM_SCAN
    worm_params: Dict = field(default_factory=dict)
    firewall_rules: List[FirewallRule] = field(default_factory=list)
    patient_zero_count: int = 1
    max_ticks: int = 100
    seed: Optional[int] = None
    intervention_tick: Optional[int] = None
    intervention_action: Optional[str] = None
    intervention_params: Dict = field(default_factory=dict)


class NetworkTopology:
    @staticmethod
    def create(topology_type: str, num_nodes: int, **params) -> nx.Graph:
        if topology_type == "random":
            return NetworkTopology._random_graph(num_nodes, params.get("p", 0.1))
        elif topology_type == "scale_free":
            return NetworkTopology._scale_free(num_nodes, params.get("m", 3))
        elif topology_type == "small_world":
            return NetworkTopology._small_world(num_nodes, params.get("k", 4), params.get("p", 0.1))
        elif topology_type == "hierarchical":
            return NetworkTopology._hierarchical(num_nodes, params.get("branching", 3))
        elif topology_type == "datacenter":
            return NetworkTopology._datacenter(num_nodes)
        else:
            return NetworkTopology._random_graph(num_nodes, 0.1)
    
    @staticmethod
    def _random_graph(n: int, p: float) -> nx.Graph:
        G = nx.erdos_renyi_graph(n, p)
        return nx.relabel_nodes(G, {i: f"node_{i}" for i in range(n)})
    
    @staticmethod
    def _scale_free(n: int, m: int) -> nx.Graph:
        G = nx.barabasi_albert_graph(n, m)
        return nx.relabel_nodes(G, {i: f"node_{i}" for i in range(n)})
    
    @staticmethod
    def _small_world(n: int, k: int, p: float) -> nx.Graph:
        G = nx.watts_strogatz_graph(n, k, p)
        return nx.relabel_nodes(G, {i: f"node_{i}" for i in range(n)})
    
    @staticmethod
    def _hierarchical(n: int, branching: int) -> nx.Graph:
        G = nx.balanced_tree(branching, int(np.log(n) / np.log(branching)))
        return nx.relabel_nodes(G, {i: f"node_{i}" for i in range(n)})
    
    @staticmethod
    def _datacenter(n: int) -> nx.Graph:
        G = nx.Graph()
        racks = max(1, n // 20)
        nodes_per_rack = n // racks
        
        for rack in range(racks):
            rack_nodes = [f"rack_{rack}_node_{i}" for i in range(nodes_per_rack)]
            G.add_nodes_from(rack_nodes)
            for i in range(len(rack_nodes)):
                for j in range(i+1, len(rack_nodes)):
                    G.add_edge(rack_nodes[i], rack_nodes[j])
            
            if rack > 0:
                G.add_edge(f"rack_{rack}_node_0", f"rack_{rack-1}_node_0")
        
        return G


class WormPropagationSimulator:
    def __init__(self, config: SimulationConfig):
        self.config = config
        self.tick = 0
        self.nodes: Dict[str, NetworkNode] = {}
        self.topology: nx.Graph = None
        self.worm_model: WormModel = None
        self.metrics_history: List[SimulationMetrics] = []
        self.event_log: List[Dict] = []
        self.running = False
        self.callbacks: List[Callable] = []
        
        if config.seed is not None:
            random.seed(config.seed)
            np.random.seed(config.seed)
        
        self._initialize()
    
    def _initialize(self):
        self.topology = NetworkTopology.create(
            self.config.topology_type, 
            self.config.num_nodes
        )
        
        subnets = self._assign_subnets()
        
        for node_id in self.topology.nodes():
            is_patched = random.random() < self.config.patch_rate
            security_level = random.choice(list(SecurityLevel))
            vuln_score = 1.0 - (security_level.value * 0.25)
            
            self.nodes[node_id] = NetworkNode(
                node_id=node_id,
                status=NodeStatus.VULNERABLE if not is_patched else NodeStatus.PATCHED,
                security_level=security_level,
                is_patched=is_patched,
                vulnerability_score=vuln_score,
                subnet=subnets.get(node_id, "default")
            )
        
        self.worm_model = create_worm_model(
            self.config.worm_type, 
            **self.config.worm_params
        )
        
        self._deploy_patient_zero()
        self._record_metrics()
    
    def _assign_subnets(self) -> Dict[str, str]:
        subnets = {}
        nodes = list(self.topology.nodes())
        num_subnets = max(1, self.config.num_nodes // 20)
        
        for i, node_id in enumerate(nodes):
            subnet_id = i % num_subnets
            subnets[node_id] = f"subnet_{subnet_id}"
        return subnets
    
    def _deploy_patient_zero(self):
        vulnerable_nodes = [n for n in self.nodes.values() if n.can_be_infected()]
        if not vulnerable_nodes:
            return
            
        patient_zero = random.sample(
            vulnerable_nodes, 
            min(self.config.patient_zero_count, len(vulnerable_nodes))
        )
        
        for node in patient_zero:
            node.infect(0, "external")
            self._log_event("infection", {
                "tick": 0,
                "node": node.node_id,
                "source": "patient_zero"
            })
    
    def _check_firewall(self, source: str, dest: str) -> bool:
        source_subnet = self.nodes[source].subnet
        dest_subnet = self.nodes[dest].subnet
        
        for rule in self.config.firewall_rules:
            if rule.source_subnet == source_subnet and rule.dest_subnet == dest_subnet:
                if rule.action == "deny":
                    return False
                elif rule.action == "rate_limit":
                    return random.random() < (rule.rate_limit / 100.0)
        return True
    
    def _attempt_exploit(self, source: str, target: str) -> bool:
        target_node = self.nodes[target]
        
        if not target_node.can_be_infected():
            if target_node.is_patched:
                self._record_metric("blocked_by_patch")
            return False
        
        if not self._check_firewall(source, target):
            self._record_metric("blocked_by_firewall")
            return False
        
        exploit_success = random.random() < target_node.vulnerability_score
        
        if exploit_success:
            target_node.infect(self.tick, source)
            self._log_event("infection", {
                "tick": self.tick,
                "node": target,
                "source": source
            })
            return True
        return False
    
    def step(self) -> SimulationMetrics:
        if not self.running:
            self.running = True
            
        self.tick += 1
        
        if self.config.intervention_tick == self.tick:
            self._apply_intervention()
        
        infected_nodes = [n for n in self.nodes.values() if n.status == NodeStatus.INFECTED]
        scan_targets = self.worm_model.select_targets(
            infected_nodes, self.nodes, self.topology, self.config.scan_rate
        )
        
        new_infections = 0
        
        for source_id, targets in scan_targets.items():
            self._record_metric("scan_attempts", len(targets))
            
            for target_id in targets:
                if self._attempt_exploit(source_id, target_id):
                    new_infections += 1
        
        self._record_metric("new_infections", new_infections)
        self._record_metrics()
        self._notify_callbacks()
        
        return self.metrics_history[-1]
    
    def _apply_intervention(self):
        action = self.config.intervention_action
        params = self.config.intervention_params
        
        if action == "patch_all":
            for node in self.nodes.values():
                if node.can_be_infected():
                    node.patch()
                    self._log_event("patch", {"tick": self.tick, "node": node.node_id})
                    
        elif action == "patch_subnet":
            subnet = params.get("subnet")
            for node in self.nodes.values():
                if node.subnet == subnet and node.can_be_infected():
                    node.patch()
                    
        elif action == "quarantine_infected":
            for node in self.nodes.values():
                if node.status == NodeStatus.INFECTED:
                    node.quarantine()
                    
        elif action == "rate_limit":
            self.config.firewall_rules.append(FirewallRule(
                source_subnet=params.get("source", "*"),
                dest_subnet=params.get("dest", "*"),
                action="rate_limit",
                rate_limit=params.get("rate", 50)
            ))
        
        logger.info(f"Applied intervention at tick {self.tick}: {action}")
    
    def run(self, max_ticks: Optional[int] = None) -> List[SimulationMetrics]:
        max_ticks = max_ticks or self.config.max_ticks
        
        for _ in range(max_ticks):
            if self._is_complete():
                break
            self.step()
        
        return self.metrics_history
    
    def _is_complete(self) -> bool:
        infected = sum(1 for n in self.nodes.values() if n.status == NodeStatus.INFECTED)
        vulnerable = sum(1 for n in self.nodes.values() if n.can_be_infected())
        return infected == 0 or vulnerable == 0
    
    def _record_metric(self, metric: str, value: int = 1):
        if self.metrics_history:
            current = self.metrics_history[-1]
            setattr(current, metric, getattr(current, metric) + value)
    
    def _record_metrics(self):
        counts = defaultdict(int)
        for node in self.nodes.values():
            counts[node.status.value] += 1
        
        metrics = SimulationMetrics(
            tick=self.tick,
            healthy=counts.get("healthy", 0),
            vulnerable=counts.get("vulnerable", 0),
            infected=counts.get("infected", 0),
            patched=counts.get("patched", 0),
            quarantined=counts.get("quarantined", 0)
        )
        self.metrics_history.append(metrics)
    
    def _log_event(self, event_type: str, data: Dict):
        self.event_log.append({
            "type": event_type,
            "timestamp": time.time(),
            **data
        })
    
    def add_callback(self, callback: Callable):
        self.callbacks.append(callback)
    
    def _notify_callbacks(self):
        for callback in self.callbacks:
            try:
                callback(self.get_state())
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def get_state(self) -> Dict:
        return {
            "tick": self.tick,
            "nodes": {k: v.__dict__ for k, v in self.nodes.items()},
            "metrics": self.metrics_history[-1].to_dict() if self.metrics_history else {},
            "topology_edges": list(self.topology.edges()) if self.topology else []
        }
    
    def get_summary(self) -> Dict:
        if not self.metrics_history:
            return {}
        
        final = self.metrics_history[-1]
        peak_infected = max(m.infected for m in self.metrics_history)
        time_to_peak = next((i for i, m in enumerate(self.metrics_history) 
                            if m.infected == peak_infected), 0)
        
        return {
            "total_ticks": self.tick,
            "final_infected": final.infected,
            "final_healthy": final.healthy,
            "final_patched": final.patched,
            "peak_infected": peak_infected,
            "time_to_peak": time_to_peak,
            "total_infections": sum(m.new_infections for m in self.metrics_history),
            "total_scans": sum(m.scan_attempts for m in self.metrics_history),
            "blocked_by_firewall": sum(m.blocked_by_firewall for m in self.metrics_history),
            "blocked_by_patch": sum(m.blocked_by_patch for m in self.metrics_history),
            "infection_curve": [m.to_dict() for m in self.metrics_history]
        }


def create_simulator_from_config(config_dict: Dict) -> WormPropagationSimulator:
    config = SimulationConfig(
        num_nodes=config_dict.get("num_nodes", 100),
        patch_rate=config_dict.get("patch_rate", 0.3),
        scan_rate=config_dict.get("scan_rate", 10),
        topology_type=config_dict.get("topology", "random"),
        worm_type=WormType(config_dict.get("worm_type", "random_scan")),
        worm_params=config_dict.get("worm_params", {}),
        firewall_rules=[FirewallRule(**r) for r in config_dict.get("firewall_rules", [])],
        patient_zero_count=config_dict.get("patient_zero", 1),
        max_ticks=config_dict.get("max_ticks", 100),
        seed=config_dict.get("seed"),
        intervention_tick=config_dict.get("intervention_tick"),
        intervention_action=config_dict.get("intervention_action"),
        intervention_params=config_dict.get("intervention_params", {})
    )
    return WormPropagationSimulator(config)