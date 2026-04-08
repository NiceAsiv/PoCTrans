"""PoCTrans Demo - CVE-2024-1597 PoC 迁移演示。

演示将 PostgreSQL JDBC SQL 注入漏洞 PoC 从 9.4.1212 迁移到 9.2-1002-jdbc4。
"""

import json
import logging
import sys
from pathlib import Path

# 添加项目根目录到 PATH
project_root = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(project_root))

from poctrans.agent import MigrationAgent
from poctrans.config import DATA_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(project_root / "logs" / "demo.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("poctrans")


def main():
    # 确保日志目录存在
    (project_root / "logs").mkdir(exist_ok=True)

    # 加载 CVE 配置
    cve_config_file = DATA_DIR / "cves.json"
    with open(cve_config_file, encoding="utf-8") as f:
        cve_configs = json.load(f)

    # 选择 CVE-2024-1597
    cve_config = None
    for cfg in cve_configs:
        if cfg["CVE"] == "CVE-2024-1597":
            cve_config = cfg
            break

    if cve_config is None:
        logger.error("CVE-2024-1597 config not found!")
        sys.exit(1)

    # 原始 PoC 目录
    origin_poc_dir = project_root / "data" / "origin" / "CVE-2024-1597" / "exploit"
    if not origin_poc_dir.exists():
        logger.error(f"Origin PoC not found: {origin_poc_dir}")
        logger.error("请先运行: python demo/setup_demo_data.py")
        sys.exit(1)

    # 目标版本
    target_version = "9.2-1002-jdbc4"
    base_version = "9.4.1212"

    print("=" * 60)
    print(f"PoCTrans Demo: {cve_config['CVE']}")
    print(f"Library: {cve_config['groupId']}:{cve_config['artifactId']}")
    print(f"Migration: {base_version} -> {target_version}")
    print("=" * 60)

    # 创建 Agent 并执行迁移
    agent = MigrationAgent(cve_config)
    result = agent.migrate(
        origin_poc_dir=origin_poc_dir,
        target_version=target_version,
        base_version=base_version
    )

    print("\n" + "=" * 60)
    print("Migration Result:")
    print(f"  Success: {result['success']}")
    print(f"  Iterations: {result['iterations']}")
    print(f"  Summary: {result['summary']}")
    print(f"  Working Dir: {result['poc_dir']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
