import logging
from pathlib import Path
from typing import Dict, Any
import yaml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent.parent / "configs"

def load_config(config_name: str) -> Dict[str, Any]:
    config_path = CONFIG_DIR / config_name
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)