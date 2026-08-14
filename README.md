# Network Worm Propagation Simulator

A discrete-event network simulator for modeling and analyzing how self-replicating worms spread through network topologies. Designed for defensive cybersecurity research and education - **no live malware, no network interaction**.

## Features

- **Discrete-event simulation** with configurable network topologies
- **Multiple worm models** (random scan, hitlist, topological, permutation)
- **Defensive interventions** (patching, segmentation, rate limiting)
- **Real-time visualization** with infection curves and network graphs
- **MITRE ATT&CK mapping** for technique analysis
- **Historical worm scenarios** (Code Red, Conficker, Slammer, WannaCry)
- **REST API** for programmatic control
- **Docker & Kubernetes** deployment ready

## Project Structure

```
worm-propagation-simulator/
├── src/
│   ├── simulator/          # Core simulation engine
│   ├── visualization/      # Real-time charts & network graphs
│   ├── api/                # FastAPI REST API
│   └── analysis/           # Metrics & reporting
├── configs/                # Simulation scenarios
├── docker/                 # Dockerfiles
├── k8s/                    # Kubernetes manifests
├── tests/                  # Unit & integration tests
��── docs/                   # Documentation
```

## Quick Start

### Local Development
```bash
pip install -r requirements.txt
python src/simulator/main.py --scenario configs/code_red.yaml
```

### Docker
```bash
docker-compose -f docker/docker-compose.yml up --build
```

### Kubernetes
```bash
kubectl apply -f k8s/
```

## Simulation Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `num_nodes` | Network size | 100 |
| `patch_rate` | Pre-patched node % | 0.3 |
| `scan_rate` | Scans per tick per infected | 10 |
| `topology` | Network topology type | `random` |
| `worm_type` | Worm propagation model | `random_scan` |
| `firewall_rules` | Subnet segmentation config | `[]` |

## Historical Scenarios

- **Code Red** (2001) - IIS buffer overflow, random scanning
- **SQL Slammer** (2003) - UDP port 1434, extremely fast scan
- **Conficker** (2008) - Multiple vectors, domain generation
- **WannaCry** (2017) - EternalBlue SMB exploit
- **Mirai** (2016) - IoT telnet brute force

## Safety Notice

> **This is a deterministic simulation only.** It creates no network traffic, modifies no systems, and contains no exploit code. It models propagation logic mathematically for defensive analysis.