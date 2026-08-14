from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import asyncio
import uuid
import json
from pathlib import Path

from ..simulator.engine import (
    WormPropagationSimulator, SimulationConfig, WormType, FirewallRule, create_simulator_from_config
)
from ..simulator.models import NodeStatus
from .. import load_config

app = FastAPI(title="Worm Propagation Simulator API", version="1.0.0")

simulations: Dict[str, Dict] = {}
active_websockets: Dict[str, List[WebSocket]] = {}


class SimulationRequest(BaseModel):
    scenario: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    max_ticks: int = 100
    seed: Optional[int] = 42


class InterventionRequest(BaseModel):
    action: str
    params: Dict[str, Any] = {}


class SimulationStatus(BaseModel):
    simulation_id: str
    status: str
    current_tick: int
    max_ticks: int
    metrics: Optional[Dict] = None


@app.post("/simulations", response_model=SimulationStatus)
async def create_simulation(request: SimulationRequest, background_tasks: BackgroundTasks):
    sim_id = str(uuid.uuid4())[:8]
    
    if request.scenario:
        config_dict = load_config(f"{request.scenario}.yaml")
    elif request.config:
        config_dict = request.config
    else:
        config_dict = {}
    
    config = SimulationConfig(
        num_nodes=config_dict.get("num_nodes", 100),
        patch_rate=config_dict.get("patch_rate", 0.3),
        scan_rate=config_dict.get("scan_rate", 10),
        topology_type=config_dict.get("topology", "random"),
        worm_type=WormType(config_dict.get("worm_type", "random_scan")),
        worm_params=config_dict.get("worm_params", {}),
        firewall_rules=[FirewallRule(**r) for r in config_dict.get("firewall_rules", [])],
        patient_zero_count=config_dict.get("patient_zero", 1),
        max_ticks=request.max_ticks,
        seed=request.seed,
        intervention_tick=config_dict.get("intervention_tick"),
        intervention_action=config_dict.get("intervention_action"),
        intervention_params=config_dict.get("intervention_params", {})
    )
    
    simulator = WormPropagationSimulator(config)
    
    simulations[sim_id] = {
        "simulator": simulator,
        "config": config,
        "status": "created",
        "task": None
    }
    
    return SimulationStatus(
        simulation_id=sim_id,
        status="created",
        current_tick=0,
        max_ticks=request.max_ticks
    )


@app.post("/simulations/{sim_id}/start")
async def start_simulation(sim_id: str, background_tasks: BackgroundTasks):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    
    sim_data = simulations[sim_id]
    simulator = sim_data["simulator"]
    
    async def run_sim():
        sim_data["status"] = "running"
        await _notify_ws(sim_id, {"type": "status", "status": "running"})
        
        for _ in range(simulator.config.max_ticks):
            if simulator._is_complete():
                break
            metrics = simulator.step()
            await _notify_ws(sim_id, {
                "type": "metrics",
                "tick": metrics.tick,
                "data": metrics.to_dict()
            })
            await asyncio.sleep(0.1)
        
        sim_data["status"] = "completed"
        summary = simulator.get_summary()
        sim_data["summary"] = summary
        await _notify_ws(sim_id, {"type": "completed", "summary": summary})
    
    background_tasks.add_task(run_sim)
    
    return {"message": "Simulation started", "simulation_id": sim_id}


@app.post("/simulations/{sim_id}/step")
async def step_simulation(sim_id: str):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    
    simulator = simulations[sim_id]["simulator"]
    metrics = simulator.step()
    
    return {
        "tick": metrics.tick,
        "metrics": metrics.to_dict(),
        "complete": simulator._is_complete()
    }


@app.post("/simulations/{sim_id}/intervene")
async def intervene(sim_id: str, request: InterventionRequest):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    
    simulator = simulations[sim_id]["simulator"]
    
    if request.action == "patch_all":
        for node in simulator.nodes.values():
            if node.can_be_infected():
                node.patch()
    elif request.action == "patch_subnet":
        subnet = request.params.get("subnet")
        for node in simulator.nodes.values():
            if node.subnet == subnet and node.can_be_infected():
                node.patch()
    elif request.action == "quarantine":
        for node in simulator.nodes.values():
            if node.status == NodeStatus.INFECTED:
                node.quarantine()
    elif request.action == "rate_limit":
        simulator.config.firewall_rules.append(FirewallRule(
            source_subnet=request.params.get("source", "*"),
            dest_subnet=request.params.get("dest", "*"),
            action="rate_limit",
            rate_limit=request.params.get("rate", 50)
        ))
    else:
        raise HTTPException(400, f"Unknown intervention: {request.action}")
    
    return {"message": f"Intervention {request.action} applied"}


@app.get("/simulations/{sim_id}/status", response_model=SimulationStatus)
async def get_status(sim_id: str):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    
    sim_data = simulations[sim_id]
    simulator = sim_data["simulator"]
    
    return SimulationStatus(
        simulation_id=sim_id,
        status=sim_data["status"],
        current_tick=simulator.tick,
        max_ticks=simulator.config.max_ticks,
        metrics=simulator.metrics_history[-1].to_dict() if simulator.metrics_history else None
    )


@app.get("/simulations/{sim_id}/summary")
async def get_summary(sim_id: str):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    
    simulator = simulations[sim_id]["simulator"]
    return simulator.get_summary()


@app.get("/simulations/{sim_id}/network")
async def get_network_state(sim_id: str):
    if sim_id not in simulations:
        raise HTTPException(404, "Simulation not found")
    
    simulator = simulations[sim_id]["simulator"]
    
    nodes = {}
    for node_id, node in simulator.nodes.items():
        nodes[node_id] = {
            "status": node.status.value,
            "subnet": node.subnet,
            "security_level": node.security_level.name,
            "is_patched": node.is_patched,
            "infected_at": node.infected_at,
            "infected_by": node.infected_by
        }
    
    return {
        "nodes": nodes,
        "edges": list(simulator.topology.edges()) if simulator.topology else []
    }


@app.websocket("/simulations/{sim_id}/ws")
async def websocket_endpoint(websocket: WebSocket, sim_id: str):
    await websocket.accept()
    
    if sim_id not in active_websockets:
        active_websockets[sim_id] = []
    active_websockets[sim_id].append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except Exception:
        pass
    finally:
        if sim_id in active_websockets:
            active_websockets[sim_id].remove(websocket)


async def _notify_ws(sim_id: str, message: Dict):
    if sim_id in active_websockets:
        for ws in active_websockets[sim_id]:
            try:
                await ws.send_json(message)
            except Exception:
                pass


@app.get("/scenarios")
async def list_scenarios():
    scenarios_dir = Path("configs")
    scenarios = []
    
    for file in scenarios_dir.glob("*.yaml"):
        config = load_config(file.name)
        scenarios.append({
            "name": file.stem,
            "description": config.get("description", ""),
            "worm_type": config.get("worm_type", ""),
            "topology": config.get("topology", "")
        })
    
    return {"scenarios": scenarios}


@app.get("/health")
async def health():
    return {"status": "healthy", "active_simulations": len(simulations)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)