import pytest
from src.simulator.engine import (
    WormPropagationSimulator, SimulationConfig, WormType, FirewallRule, NetworkTopology
)
from src.simulator.models import NetworkNode, NodeStatus, SecurityLevel, create_worm_model, WormType


class TestNetworkNode:
    def test_node_creation(self):
        node = NetworkNode(node_id="test_1")
        assert node.node_id == "test_1"
        assert node.status == NodeStatus.HEALTHY
        assert not node.is_patched
    
    def test_node_infection(self):
        node = NetworkNode(node_id="test_1")
        node.infect(5, "source_1")
        assert node.status == NodeStatus.INFECTED
        assert node.infected_at == 5
        assert node.infected_by == "source_1"
    
    def test_node_patching(self):
        node = NetworkNode(node_id="test_1", is_patched=True)
        node.patch()
        assert node.status == NodeStatus.PATCHED
        assert node.is_patched
    
    def test_can_be_infected(self):
        healthy = NetworkNode(node_id="h1")
        vulnerable = NetworkNode(node_id="v1", status=NodeStatus.VULNERABLE)
        patched = NetworkNode(node_id="p1", is_patched=True)
        infected = NetworkNode(node_id="i1", status=NodeStatus.INFECTED)
        
        assert healthy.can_be_infected()
        assert vulnerable.can_be_infected()
        assert not patched.can_be_infected()
        assert not infected.can_be_infected()


class TestNetworkTopology:
    def test_random_graph(self):
        G = NetworkTopology.create("random", 10, p=0.3)
        assert G.number_of_nodes() == 10
        assert all(n.startswith("node_") for n in G.nodes())
    
    def test_scale_free(self):
        G = NetworkTopology.create("scale_free", 10, m=2)
        assert G.number_of_nodes() == 10
    
    def test_small_world(self):
        G = NetworkTopology.create("small_world", 10, k=4, p=0.1)
        assert G.number_of_nodes() == 10
    
    def test_datacenter(self):
        G = NetworkTopology.create("datacenter", 50)
        assert G.number_of_nodes() == 50


class TestWormModels:
    def setup_method(self):
        self.nodes = {
            f"node_{i}": NetworkNode(node_id=f"node_{i}", status=NodeStatus.INFECTED if i == 0 else NodeStatus.VULNERABLE)
            for i in range(10)
        }
        import networkx as nx
        self.topology = nx.complete_graph(10)
        self.topology = nx.relabel_nodes(self.topology, {i: f"node_{i}" for i in range(10)})
    
    def test_random_scan(self):
        worm = create_worm_model(WormType.RANDOM_SCAN)
        targets = worm.select_targets(
            [self.nodes["node_0"]], self.nodes, self.topology, 3
        )
        assert "node_0" in targets
        assert len(targets["node_0"]) <= 3
    
    def test_topological(self):
        worm = create_worm_model(WormType.TOPOLOGICAL)
        targets = worm.select_targets(
            [self.nodes["node_0"]], self.nodes, self.topology, 3
        )
        assert "node_0" in targets
    
    def test_local_preference(self):
        for node in self.nodes.values():
            node.subnet = "subnet_0" if int(node.node_id.split("_")[1]) < 5 else "subnet_1"
        
        worm = create_worm_model(WormType.LOCAL_PREFERENCE, local_prob=0.8)
        targets = worm.select_targets(
            [self.nodes["node_0"]], self.nodes, self.topology, 10
        )
        assert "node_0" in targets


class TestSimulator:
    def test_basic_simulation(self):
        config = SimulationConfig(
            num_nodes=50,
            patch_rate=0.3,
            scan_rate=5,
            topology_type="random",
            worm_type=WormType.RANDOM_SCAN,
            max_ticks=20,
            seed=42
        )
        
        simulator = WormPropagationSimulator(config)
        metrics = simulator.run(20)
        
        assert len(metrics) == 21  # tick 0 + 20 steps
        assert simulator.tick == 20
    
    def test_infection_spreads(self):
        config = SimulationConfig(
            num_nodes=100,
            patch_rate=0.1,
            scan_rate=10,
            topology_type="random",
            worm_type=WormType.RANDOM_SCAN,
            max_ticks=30,
            seed=42
        )
        
        simulator = WormPropagationSimulator(config)
        simulator.run(30)
        
        summary = simulator.get_summary()
        assert summary["final_infected"] > 0
        assert summary["total_infections"] > 0
    
    def test_patching_stops_spread(self):
        config = SimulationConfig(
            num_nodes=100,
            patch_rate=0.1,
            scan_rate=10,
            topology_type="random",
            worm_type=WormType.RANDOM_SCAN,
            max_ticks=50,
            seed=42,
            intervention_tick=10,
            intervention_action="patch_all"
        )
        
        simulator = WormPropagationSimulator(config)
        simulator.run(50)
        
        summary = simulator.get_summary()
        assert summary["blocked_by_patch"] > 0
    
    def test_firewall_blocks_spread(self):
        config = SimulationConfig(
            num_nodes=50,
            patch_rate=0.0,
            scan_rate=10,
            topology_type="random",
            worm_type=WormType.RANDOM_SCAN,
            max_ticks=20,
            seed=42,
            firewall_rules=[
                FirewallRule(source_subnet="subnet_0", dest_subnet="subnet_1", action="deny")
            ]
        )
        
        simulator = WormPropagationSimulator(config)
        simulator.run(20)
        
        summary = simulator.get_summary()
        assert summary["blocked_by_firewall"] > 0
    
    def test_different_worm_types(self):
        for worm_type in WormType:
            config = SimulationConfig(
                num_nodes=50,
                patch_rate=0.2,
                scan_rate=5,
                topology_type="random",
                worm_type=worm_type,
                max_ticks=15,
                seed=42
            )
            
            simulator = WormPropagationSimulator(config)
            simulator.run(15)
            
            summary = simulator.get_summary()
            assert summary["total_ticks"] == 15


class TestSimulationConfig:
    def test_from_dict(self):
        config_dict = {
            "num_nodes": 200,
            "patch_rate": 0.25,
            "scan_rate": 15,
            "topology": "scale_free",
            "worm_type": "hitlist",
            "max_ticks": 80
        }
        
        simulator = create_simulator_from_config(config_dict)
        
        assert simulator.config.num_nodes == 200
        assert simulator.config.patch_rate == 0.25
        assert simulator.config.scan_rate == 15
        assert simulator.config.topology_type == "scale_free"
        assert simulator.config.worm_type == WormType.HITLIST
        assert simulator.config.max_ticks == 80


if __name__ == "__main__":
    pytest.main([__file__, "-v"])