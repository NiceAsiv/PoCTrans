"""Version Manager Tool - Maven 版本获取与选择。"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
from urllib.request import urlopen
from urllib.error import URLError

from poctrans.config import DATA_DIR, MAVEN_CENTRAL_URL


def fetch_maven_versions(group_id: str, artifact_id: str,
                         use_cache: bool = True) -> List[str]:
    """从 Maven Central 获取库的所有版本列表。

    Args:
        group_id: Maven groupId (e.g., "org.postgresql")
        artifact_id: Maven artifactId (e.g., "postgresql")
        use_cache: 是否使用本地缓存

    Returns:
        版本列表
    """
    cache_file = DATA_DIR / "library" / f"{group_id.replace('.', '_')}_{artifact_id}.txt"

    if use_cache and cache_file.exists():
        return [line.strip() for line in cache_file.read_text().splitlines() if line.strip()]

    group_path = group_id.replace(".", "/")
    url = f"{MAVEN_CENTRAL_URL}/{group_path}/{artifact_id}/maven-metadata.xml"

    try:
        with urlopen(url, timeout=30) as response:
            xml_content = response.read().decode("utf-8")
        root = ET.fromstring(xml_content)
        versions = [v.text for v in root.findall(".//version") if v.text]

        # 缓存到本地
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text("\n".join(versions))
        return versions
    except (URLError, ET.ParseError) as e:
        if cache_file.exists():
            return [line.strip() for line in cache_file.read_text().splitlines() if line.strip()]
        return []


def select_nearest_version(pending_versions: List[str],
                           reproduced_versions: List[str],
                           all_versions: List[str]) -> Optional[tuple]:
    """选择离已复现版本最近的待适配版本。

    Args:
        pending_versions: 待适配版本列表
        reproduced_versions: 已复现版本列表
        all_versions: Maven 全版本列表（按发布顺序）

    Returns:
        (target_version, base_version) 或 None
    """
    if not pending_versions or not reproduced_versions:
        return None

    version_index = {v: i for i, v in enumerate(all_versions)}

    best_pending = None
    best_base = None
    best_distance = float("inf")

    for pv in pending_versions:
        if pv not in version_index:
            continue
        pi = version_index[pv]
        for rv in reproduced_versions:
            if rv not in version_index:
                continue
            ri = version_index[rv]
            dist = abs(pi - ri)
            if dist < best_distance:
                best_distance = dist
                best_pending = pv
                best_base = rv

    if best_pending:
        return (best_pending, best_base)
    return None


def update_pom_version(pom_path: Path, group_id: str, artifact_id: str,
                       new_version: str) -> bool:
    """更新 pom.xml 中指定依赖的版本号。

    Args:
        pom_path: pom.xml 文件路径
        group_id: 依赖的 groupId
        artifact_id: 依赖的 artifactId
        new_version: 新版本号

    Returns:
        是否成功更新
    """
    content = pom_path.read_text(encoding="utf-8")

    # 使用正则匹配并替换版本号
    # 匹配 <groupId>xxx</groupId> 后面跟着 <artifactId>yyy</artifactId> 再跟 <version>zzz</version>
    pattern = (
        rf"(<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*"
        rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*"
        rf"<version>)\s*[^<]+(\s*</version>)"
    )
    new_content, count = re.subn(pattern, rf"\g<1>{new_version}\2", content, flags=re.DOTALL)

    if count > 0:
        pom_path.write_text(new_content, encoding="utf-8")
        return True
    return False
