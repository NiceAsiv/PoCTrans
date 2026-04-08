"""Error Parser Tool - 解析 Maven 构建错误日志。"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class BuildError:
    """结构化构建错误。"""
    file: str = ""
    line: int = 0
    column: int = 0
    message: str = ""
    error_type: str = ""  # compilation, test_failure, dependency, other


def parse_maven_errors(log_text: str) -> List[BuildError]:
    """从 Maven 日志中提取结构化错误信息。

    Args:
        log_text: Maven 执行的完整日志

    Returns:
        BuildError 列表
    """
    errors = []

    # 匹配编译错误：[ERROR] /path/File.java:[line,col] error: message
    compile_pattern = re.compile(
        r"\[ERROR\]\s*(.+\.java):\[(\d+),(\d+)\]\s*(?:error:\s*)?(.*)"
    )

    # 匹配测试失败
    test_fail_pattern = re.compile(
        r"Failed tests?:\s*(.*?)(?:\n|$)"
    )

    # 匹配一般错误行
    general_error_pattern = re.compile(
        r"\[ERROR\]\s+(.*)"
    )

    for line in log_text.split("\n"):
        m = compile_pattern.search(line)
        if m:
            errors.append(BuildError(
                file=m.group(1).strip(),
                line=int(m.group(2)),
                column=int(m.group(3)),
                message=m.group(4).strip(),
                error_type="compilation"
            ))
            continue

        m = test_fail_pattern.search(line)
        if m:
            errors.append(BuildError(
                message=m.group(1).strip(),
                error_type="test_failure"
            ))

    # 检查依赖解析失败
    if "Could not resolve dependencies" in log_text or "Could not find artifact" in log_text:
        dep_match = re.search(
            r"Could not (?:resolve dependencies|find artifact)\s*([^\n]+)",
            log_text
        )
        errors.append(BuildError(
            message=dep_match.group(0) if dep_match else "Dependency resolution failed",
            error_type="dependency"
        ))

    return errors


def classify_failure(log_text: str) -> str:
    """对 Maven 日志进行高层分类。

    Returns:
        "compilation" | "test_failure" | "dependency" | "timeout" | "success" | "unknown"
    """
    if "BUILD SUCCESS" in log_text:
        return "success"
    if "timed out" in log_text.lower() or "timeout" in log_text.lower():
        return "timeout"
    if "COMPILATION ERROR" in log_text:
        return "compilation"
    if "Could not resolve dependencies" in log_text or "Could not find artifact" in log_text:
        return "dependency"
    if "Tests run:" in log_text and ("Failures:" in log_text or "Errors:" in log_text):
        return "test_failure"
    return "unknown"


def extract_error_summary(log_text: str) -> str:
    """从日志中提取错误摘要，用于 LLM 上下文。"""
    lines = log_text.split("\n")
    error_lines = []

    for i, line in enumerate(lines):
        if "[ERROR]" in line or "FAILURE" in line or "error:" in line.lower():
            # 包含上下文
            start = max(0, i - 2)
            end = min(len(lines), i + 3)
            for j in range(start, end):
                if lines[j].strip() and lines[j] not in error_lines:
                    error_lines.append(lines[j])

    # 截断避免过长
    summary = "\n".join(error_lines[:50])
    if len(error_lines) > 50:
        summary += f"\n... ({len(error_lines) - 50} more error lines)"
    return summary
