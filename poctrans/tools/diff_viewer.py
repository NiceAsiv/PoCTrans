"""Diff Viewer Tool - view and analyze code diffs between library versions.

This is a core agent capability: letting the model understand what changed
between versions so it can decide how to modify the PoC code.
"""

import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from poctrans.config import DIFF_DIR


def list_available_diffs(cve_id: str) -> List[str]:
    """List all available pre-computed diff files for a CVE.

    Returns:
        List of diff file names (e.g. ["9.4.1208.jre7-9.4.1209.diff"])
    """
    diff_dir = DIFF_DIR / cve_id
    if not diff_dir.exists():
        return []
    return sorted(f.name for f in diff_dir.glob("*.diff"))


def view_diff(cve_id: str, from_version: str, to_version: str) -> str:
    """查看两个版本之间的 diff。

    优先从本地缓存加载，否则通过 git 动态生成。
    返回完整的 diff 文本。
    """
    # 尝试加载预计算的 diff 文件
    diff_file = DIFF_DIR / cve_id / f"{to_version}-{from_version}.diff"
    if diff_file.exists():
        return diff_file.read_text(encoding="utf-8", errors="replace")

    # 也尝试反向 diff
    reverse_file = DIFF_DIR / cve_id / f"{from_version}-{to_version}.diff"
    if reverse_file.exists():
        content = reverse_file.read_text(encoding="utf-8", errors="replace")
        return _reverse_diff(content)

    return f"[ERROR] No diff found for {cve_id}: {from_version} -> {to_version}"


def view_diff_summary(cve_id: str, from_version: str, to_version: str) -> str:
    """查看 diff 的摘要信息（变更文件列表和统计）。"""
    diff_text = view_diff(cve_id, from_version, to_version)
    if diff_text.startswith("[ERROR]"):
        return diff_text

    files_changed = []
    additions = 0
    deletions = 0

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            parts = line.split(" b/")
            if len(parts) > 1:
                files_changed.append(parts[-1])
        elif line.startswith("+") and not line.startswith("+++"):
            additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1

    summary = f"Files changed: {len(files_changed)}\n"
    summary += f"Additions: {additions}, Deletions: {deletions}\n"
    summary += "\nChanged files:\n"
    for f in files_changed[:30]:  # 限制显示数量
        summary += f"  - {f}\n"
    if len(files_changed) > 30:
        summary += f"  ... and {len(files_changed) - 30} more\n"

    return summary


def search_diff(cve_id: str, from_version: str, to_version: str,
                keyword: str) -> str:
    """在 diff 中搜索包含特定关键字的代码块。

    返回包含关键字的 diff hunk 及其上下文。
    """
    diff_text = view_diff(cve_id, from_version, to_version)
    if diff_text.startswith("[ERROR]"):
        return diff_text

    results = []
    current_file = ""
    current_hunk = []
    in_relevant_hunk = False

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if in_relevant_hunk and current_hunk:
                results.append(f"--- File: {current_file} ---\n" + "\n".join(current_hunk))
            current_hunk = []
            in_relevant_hunk = False
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else line
        elif line.startswith("@@"):
            if in_relevant_hunk and current_hunk:
                results.append(f"--- File: {current_file} ---\n" + "\n".join(current_hunk))
            current_hunk = [line]
            in_relevant_hunk = False
        else:
            current_hunk.append(line)
            if keyword.lower() in line.lower():
                in_relevant_hunk = True

    if in_relevant_hunk and current_hunk:
        results.append(f"--- File: {current_file} ---\n" + "\n".join(current_hunk))

    if not results:
        return f"No diff hunks found containing '{keyword}'."

    return "\n\n".join(results[:10])  # 限制返回数量


def _reverse_diff(diff_text: str) -> str:
    """反转 diff（交换 +/- 号）。"""
    lines = []
    for line in diff_text.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            lines.append("-" + line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            lines.append("+" + line[1:])
        else:
            lines.append(line)
    return "\n".join(lines)
