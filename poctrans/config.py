"""Configuration for PoCTrans."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
_project_root = Path(__file__).parent.parent.resolve()
load_dotenv(_project_root / ".env")

# ============================================================
# LLM API Configuration
# ============================================================
# Set these in .env file (see .env.example) or as environment variables
LLM_API_KEY = os.environ.get("POCTRANS_API_KEY", "")
LLM_BASE_URL = os.environ.get("POCTRANS_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.environ.get("POCTRANS_MODEL", "deepseek-chat")
LLM_MAX_TOKENS = 8192

if not LLM_API_KEY:
    raise RuntimeError(
        "POCTRANS_API_KEY not set. "
        "Copy .env.example to .env and fill in your API key, "
        "or set the POCTRANS_API_KEY environment variable."
    )

# ============================================================
# Project Paths
# ============================================================
PROJECT_ROOT = _project_root
DATA_DIR = PROJECT_ROOT / "data"
WORKSPACE_DIR = PROJECT_ROOT / "workspace"
DIFF_DIR = DATA_DIR / "diffs"
LOG_DIR = PROJECT_ROOT / "logs"

# ============================================================
# Docker Configuration
# ============================================================
DOCKER_IMAGE = "chenzirui118/diffploit:latest"
DOCKER_TIMEOUT = 300  # seconds

# ============================================================
# Maven Configuration
# ============================================================
MAVEN_CENTRAL_URL = "https://repo1.maven.org/maven2"

# ============================================================
# Agent Configuration
# ============================================================
AGENT_MAX_ITERATIONS = 15  # 最大修复循环次数
