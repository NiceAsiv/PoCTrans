"""Code Editor Tool - 读取和修改 PoC 源代码。"""

from pathlib import Path
from typing import Optional


def read_file(file_path: Path) -> str:
    """读取文件内容。"""
    file_path = Path(file_path)
    if not file_path.exists():
        return f"[ERROR] File not found: {file_path}"
    return file_path.read_text(encoding="utf-8", errors="replace")


def write_file(file_path: Path, content: str) -> str:
    """写入文件内容。"""
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return f"File written: {file_path}"


def list_project_files(project_dir: Path) -> str:
    """列出 PoC 项目中的所有文件。"""
    project_dir = Path(project_dir)
    if not project_dir.exists():
        return f"[ERROR] Directory not found: {project_dir}"

    files = []
    for f in sorted(project_dir.rglob("*")):
        if f.is_file() and ".git" not in f.parts and "target" not in f.parts:
            rel = f.relative_to(project_dir)
            files.append(str(rel))

    return "\n".join(files) if files else "No files found."


def find_java_files(project_dir: Path) -> list:
    """查找项目中所有 Java 源文件。"""
    project_dir = Path(project_dir)
    return sorted(project_dir.rglob("*.java"))


def find_pom_file(project_dir: Path) -> Optional[Path]:
    """查找 pom.xml 文件。"""
    pom = project_dir / "pom.xml"
    return pom if pom.exists() else None
