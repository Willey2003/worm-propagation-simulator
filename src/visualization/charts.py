import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np


class SimulationVisualizer:
    def __init__(self, metrics_history: List[Dict], topology_edges: List[tuple], node_states: Dict):
        self.metrics_history = metrics_history
        self.topology_edges = topology_edges
        self.node_states = node_states
    
    def create_infection_curve(self) -> go.Figure:
        ticks = [m["tick"] for m in self.metrics_history]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=ticks, y=[m["healthy"] for m in self.metrics_history],
            name="Healthy", line=dict(color="green"), fill='tozeroy'
        ))
        fig.add_trace(go.Scatter(
            x=ticks, y=[m["vulnerable"] for m in self.metrics_history],
            name="Vulnerable", line=dict(color="yellow"), fill='tonexty'
        ))
        fig.add_trace(go.Scatter(
            x=ticks, y=[m["infected"] for m in self.metrics_history],
            name="Infected", line=dict(color="red"), fill='tonexty'
        ))
        fig.add_trace(go.Scatter(
            x=ticks, y=[m["patched"] for m in self.metrics_history],
            name="Patched", line=dict(color="blue"), fill='tonexty'
        ))
        fig.add_trace(go.Scatter(
            x=ticks, y=[m["quarantined"] for m in self.metrics_history],
            name="Quarantined", line=dict(color="purple"), fill='tonexty'
        ))
        
        fig.update_layout(
            title="Worm Propagation - Infection Curve (S-Curve)",
            xaxis_title="Simulation Tick",
            yaxis_title="Number of Nodes",
            hovermode="x unified",
            template="plotly_dark"
        )
        return fig
    
    def create_network_graph(self, tick: int = -1) -> go.Figure:
        G = nx.Graph()
        G.add_edges_from(self.topology_edges)
        
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        node_colors = []
        node_sizes = []
        node_text = []
        
        for node in G.nodes():
            state = self.node_states.get(node, {})
            status = state.get("status", "healthy")
            
            color_map = {
                "healthy": "green",
                "vulnerable": "yellow",
                "infected": "red",
                "patched": "blue",
                "quarantined": "purple"
            }
            node_colors.append(color_map.get(status, "gray"))
            node_sizes.append(10 if status == "infected" else 6)
            node_text.append(f"{node}<br>Status: {status}")
        
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color="#888"),
            hoverinfo="none",
            mode="lines"
        ))
        
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in G.nodes()],
            y=[pos[n][1] for n in G.nodes()],
            mode="markers",
            marker=dict(size=node_sizes, color=node_colors, line=dict(width=1, color="white")),
            text=node_text,
            hoverinfo="text"
        ))
        
        fig.update_layout(
            title=f"Network Topology at Tick {tick}",
            showlegend=False,
            hovermode="closest",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            template="plotly_dark"
        )
        return fig
    
    def create_dashboard(self) -> go.Figure:
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Infection Curve", "New Infections per Tick", 
                          "Cumulative Infections", "Network Status Distribution"),
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"type": "pie"}]]
        )
        
        ticks = [m["tick"] for m in self.metrics_history]
        
        fig.add_trace(
            go.Scatter(x=ticks, y=[m["infected"] for m in self.metrics_history], 
                      name="Infected", line=dict(color="red")),
            row=1, col=1
        )
        fig.add_trace(
            go.Scatter(x=ticks, y=[m["healthy"] for m in self.metrics_history], 
                      name="Healthy", line=dict(color="green")),
            row=1, col=1
        )
        fig.add_trace(
            go.Scatter(x=ticks, y=[m["patched"] for m in self.metrics_history], 
                      name="Patched", line=dict(color="blue")),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Bar(x=ticks, y=[m["new_infections"] for m in self.metrics_history], 
                   name="New Infections", marker_color="orange"),
            row=1, col=2
        )
        
        cumulative = np.cumsum([m["new_infections"] for m in self.metrics_history])
        fig.add_trace(
            go.Scatter(x=ticks, y=cumulative, name="Cumulative", 
                      line=dict(color="purple"), fill='tozeroy'),
            row=2, col=1
        )
        
        final = self.metrics_history[-1]
        fig.add_trace(
            go.Pie(
                labels=["Healthy", "Vulnerable", "Infected", "Patched", "Quarantined"],
                values=[final["healthy"], final["vulnerable"], final["infected"], 
                       final["patched"], final["quarantined"]],
                marker_colors=["green", "yellow", "red", "blue", "purple"]
            ),
            row=2, col=2
        )
        
        fig.update_layout(
            height=800,
            title_text="Worm Propagation Simulation Dashboard",
            template="plotly_dark"
        )
        return fig
    
    def save_all(self, output_dir: str):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        self.create_infection_curve().write_html(f"{output_dir}/infection_curve.html")
        self.create_network_graph().write_html(f"{output_dir}/network_graph.html")
        self.create_dashboard().write_html(f"{output_dir}/dashboard.html")
        
        print(f"Visualizations saved to {output_dir}")


def create_comparison_chart(results: Dict[str, Dict]) -> go.Figure:
    fig = go.Figure()
    
    for name, data in results.items():
        if "infection_curve" in data:
            ticks = [m["tick"] for m in data["infection_curve"]]
            infected = [m["infected"] for m in data["infection_curve"]]
            fig.add_trace(go.Scatter(
                x=ticks, y=infected, name=name, mode="lines"
            ))
    
    fig.update_layout(
        title="Scenario Comparison - Infection Curves",
        xaxis_title="Tick",
        yaxis_title="Infected Nodes",
        template="plotly_dark"
    )
    return fig