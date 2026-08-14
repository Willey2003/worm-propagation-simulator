import typer
import json
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .engine import (
    WormPropagationSimulator, SimulationConfig, WormType, 
    create_simulator_from_config, FirewallRule
)
from .. import load_config

app = typer.Typer(help="Network Worm Propagation Simulator")
console = Console()


@app.command()
def run(
    scenario: str = typer.Option("default", "--scenario", "-s", help="Scenario config file"),
    ticks: int = typer.Option(50, "--ticks", "-t", help="Maximum simulation ticks"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Run a worm propagation simulation."""
    
    config_dict = load_config(f"{scenario}.yaml") if scenario != "default" else {}
    
    config = SimulationConfig(
        num_nodes=config_dict.get("num_nodes", 100),
        patch_rate=config_dict.get("patch_rate", 0.3),
        scan_rate=config_dict.get("scan_rate", 10),
        topology_type=config_dict.get("topology", "random"),
        worm_type=WormType(config_dict.get("worm_type", "random_scan")),
        worm_params=config_dict.get("worm_params", {}),
        firewall_rules=[FirewallRule(**r) for r in config_dict.get("firewall_rules", [])],
        patient_zero_count=config_dict.get("patient_zero", 1),
        max_ticks=ticks,
        seed=config_dict.get("seed"),
        intervention_tick=config_dict.get("intervention_tick"),
        intervention_action=config_dict.get("intervention_action"),
        intervention_params=config_dict.get("intervention_params", {})
    )
    
    simulator = WormPropagationSimulator(config)
    
    console.print(f"[bold green]Starting simulation:[/bold green] {scenario}")
    console.print(f"Nodes: {config.num_nodes}, Topology: {config.topology_type}, Worm: {config.worm_type.value}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running simulation...", total=ticks)
        
        for i in range(ticks):
            metrics = simulator.step()
            progress.update(task, advance=1, description=f"Tick {metrics.tick}: Infected={metrics.infected}")
            
            if simulator._is_complete():
                console.print(f"[yellow]Simulation complete at tick {metrics.tick}[/yellow]")
                break
    
    summary = simulator.get_summary()
    _print_summary(summary, console)
    
    if output:
        with open(output, 'w') as f:
            json.dump(summary, f, indent=2)
        console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def compare(
    scenarios: str = typer.Option(..., "--scenarios", help="Comma-separated scenario names"),
    ticks: int = typer.Option(50, "--ticks", help="Maximum ticks"),
    output: Optional[str] = typer.Option(None, "--output", help="Output JSON file")
):
    """Compare multiple scenarios."""
    
    scenario_list = [s.strip() for s in scenarios.split(",")]
    results = {}
    
    for scenario in scenario_list:
        console.print(f"Running {scenario}...")
        config_dict = load_config(f"{scenario}.yaml")
        
        config = SimulationConfig(
            num_nodes=config_dict.get("num_nodes", 100),
            patch_rate=config_dict.get("patch_rate", 0.3),
            scan_rate=config_dict.get("scan_rate", 10),
            topology_type=config_dict.get("topology", "random"),
            worm_type=WormType(config_dict.get("worm_type", "random_scan")),
            max_ticks=ticks,
            seed=42
        )
        
        simulator = WormPropagationSimulator(config)
        simulator.run(ticks)
        results[scenario] = simulator.get_summary()
    
    _print_comparison(results, console)
    
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)


@app.command()
def scenarios():
    """List available built-in scenarios."""
    
    table = Table(title="Built-in Scenarios")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Worm Type")
    table.add_column("Topology")
    
    scenarios_data = [
        ("code_red", "Code Red (2001) - IIS buffer overflow", "random_scan", "random"),
        ("slammer", "SQL Slammer (2003) - UDP 1434, fast scan", "random_scan", "random"),
        ("conficker", "Conficker (2008) - Multi-vector, DGA", "hitlist", "scale_free"),
        ("wannacry", "WannaCry (2017) - EternalBlue SMB", "topological", "datacenter"),
        ("mirai", "Mirai (2016) - IoT telnet brute force", "local_preference", "hierarchical"),
    ]
    
    for name, desc, worm, topo in scenarios_data:
        table.add_row(name, desc, worm, topo)
    
    console.print(table)


def _print_summary(summary: dict, console: Console):
    table = Table(title="Simulation Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    for key, value in summary.items():
        if key not in ["infection_curve"]:
            table.add_row(key.replace("_", " ").title(), str(value))
    
    console.print(table)


def _print_comparison(results: dict, console: Console):
    table = Table(title="Scenario Comparison")
    table.add_column("Scenario", style="cyan")
    table.add_column("Final Infected", style="red")
    table.add_column("Peak Infected", style="orange3")
    table.add_column("Time to Peak", style="yellow")
    table.add_column("Total Infections", style="blue")
    table.add_column("Blocked by Patch", style="green")
    
    for name, data in results.items():
        table.add_row(
            name,
            str(data.get("final_infected", 0)),
            str(data.get("peak_infected", 0)),
            str(data.get("time_to_peak", 0)),
            str(data.get("total_infections", 0)),
            str(data.get("blocked_by_patch", 0))
        )
    
    console.print(table)


if __name__ == "__main__":
    app()