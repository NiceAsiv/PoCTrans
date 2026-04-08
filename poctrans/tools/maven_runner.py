"""Maven Runner Tool - 通过 Docker 执行 Maven 测试。

在隔离的 Docker 容器中运行 PoC（mvn clean test），
确保 Java 版本和环境一致性。
"""

import subprocess
import shutil
from pathlib import Path
from typing import Tuple

from poctrans.config import DOCKER_IMAGE, DOCKER_TIMEOUT, WORKSPACE_DIR


def run_poc_test(cve_id: str, version: str, poc_dir: Path) -> Tuple[bool, str]:
    """在 Docker 容器中执行 PoC 的 Maven 测试。

    Args:
        cve_id: CVE 编号
        version: 目标库版本
        poc_dir: PoC 项目目录（包含 pom.xml 和 src/）

    Returns:
        (success, log_text): 是否成功执行（非 timeout），完整日志
    """
    poc_dir = Path(poc_dir).resolve()
    if not (poc_dir / "pom.xml").exists():
        return False, f"[ERROR] pom.xml not found in {poc_dir}"

    # 将路径转为 Docker 可挂载的格式（Windows）
    mount_path = str(poc_dir).replace("\\", "/")
    # Windows drive letter: D:\... -> /d/...
    if len(mount_path) > 1 and mount_path[1] == ":":
        mount_path = "/" + mount_path[0].lower() + mount_path[2:]

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{poc_dir}:/workspace/exploit",
        "-w", "/workspace/exploit",
        DOCKER_IMAGE,
        "bash", "-c", "mvn --batch-mode clean test 2>&1"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT,
            encoding="utf-8",
            errors="replace"
        )
        log_text = result.stdout + "\n" + result.stderr
        return True, log_text
    except subprocess.TimeoutExpired:
        return False, "[ERROR] Maven test execution timed out."
    except FileNotFoundError:
        return False, "[ERROR] Docker not found. Please install Docker and ensure it's running."
    except Exception as e:
        return False, f"[ERROR] Execution failed: {e}"


def verify_reproduction(log_text: str, reproduced_behavior: str,
                        reproduced_detail: list) -> Tuple[bool, str]:
    """验证 PoC 是否成功复现漏洞。

    通过在 Maven 日志中搜索特定字符串来判定。

    Args:
        log_text: Maven 执行日志
        reproduced_behavior: 主行为字符串（如 "org.junit.ComparisonFailure"）
        reproduced_detail: 细节字符串列表

    Returns:
        (verified, report): 是否验证通过，验证报告
    """
    report_lines = []
    all_matched = True

    if reproduced_behavior:
        if reproduced_behavior in log_text:
            report_lines.append(f"  ✓ Behavior matched: '{reproduced_behavior}'")
        else:
            report_lines.append(f"  ✗ Behavior NOT found: '{reproduced_behavior}'")
            all_matched = False

    for detail in reproduced_detail:
        if detail in log_text:
            report_lines.append(f"  ✓ Detail matched: '{detail}'")
        else:
            report_lines.append(f"  ✗ Detail NOT found: '{detail}'")
            all_matched = False

    status = "VERIFIED" if all_matched else "NOT VERIFIED"
    report = f"Reproduction {status}:\n" + "\n".join(report_lines)
    return all_matched, report


def prepare_poc_workspace(source_dir: Path, cve_id: str,
                          version: str) -> Path:
    """准备 PoC 工作目录。

    将源 PoC 复制到工作区，用于后续修改和测试。
    """
    target_dir = WORKSPACE_DIR / cve_id / version / "exploit"
    if target_dir.exists():
        shutil.rmtree(target_dir)
    shutil.copytree(source_dir, target_dir)
    return target_dir
