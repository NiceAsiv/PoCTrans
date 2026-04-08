"""Memory Store - persistent cross-run migration experience.

Stores successful migration records so the agent can learn from past
attempts: what API changes were encountered, what code transformations
worked, and what patterns to apply for similar version jumps.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from poctrans.config import DATA_DIR

logger = logging.getLogger("poctrans")

MEMORY_DIR = DATA_DIR / "memory"


class MemoryStore:
    """Simple file-based memory store for migration experience."""

    def __init__(self):
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    def save(self, cve_id: str, base_version: str, target_version: str,
             summary: str, adapted_code: dict):
        """Save a successful migration record.

        Args:
            cve_id: CVE identifier
            base_version: source version
            target_version: target version
            summary: migration summary
            adapted_code: dict of {relative_path: file_content}
        """
        cve_dir = MEMORY_DIR / cve_id
        cve_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "base_version": base_version,
            "target_version": target_version,
            "summary": summary,
            "adapted_code": adapted_code
        }

        record_file = cve_dir / f"{base_version}_to_{target_version}.json"
        record_file.write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        logger.info(f"Memory saved: {record_file}")

    def recall(self, cve_id: str, base_version: str = "",
               target_version: str = "", query: str = "") -> str:
        """Recall past migration experience.

        Returns a formatted string with relevant past experience.
        """
        cve_dir = MEMORY_DIR / cve_id
        if not cve_dir.exists():
            return "No prior migration experience found for this CVE. You are starting fresh."

        records = []
        for f in sorted(cve_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                records.append(data)
            except (json.JSONDecodeError, OSError):
                continue

        if not records:
            return "No prior migration experience found for this CVE."

        # Build context from past successful migrations
        result_parts = [f"Found {len(records)} prior migration record(s) for {cve_id}:\n"]

        for r in records:
            result_parts.append(
                f"--- {r['base_version']} -> {r['target_version']} ---\n"
                f"Summary: {r['summary']}\n"
            )
            # Include adapted code snippets (key context for the agent)
            for path, code in r.get("adapted_code", {}).items():
                if path.endswith(".java"):
                    result_parts.append(f"\nAdapted file: {path}\n```java\n{code}\n```\n")
                elif path == "pom.xml" or path.endswith(".xml"):
                    result_parts.append(f"\nAdapted file: {path}\n```xml\n{code}\n```\n")

            # If query matches something in the code/summary, highlight it
            if query:
                for path, code in r.get("adapted_code", {}).items():
                    if query.lower() in code.lower():
                        result_parts.append(
                            f"\n[MATCH] Query '{query}' found in {path}\n"
                        )

        full = "\n".join(result_parts)
        # Truncate if too long
        if len(full) > 6000:
            full = full[:6000] + "\n...[truncated]"
        return full

    def has_memory(self, cve_id: str) -> bool:
        """Check if any memory exists for a CVE."""
        cve_dir = MEMORY_DIR / cve_id
        return cve_dir.exists() and any(cve_dir.glob("*.json"))
