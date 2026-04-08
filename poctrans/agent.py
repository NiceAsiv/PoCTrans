"""PoCTrans Agent - ReAct-based PoC migration agent.

The agent has a set of tools (diff viewer, code editor, Maven runner, error
parser) and uses LLM function-calling to autonomously decide which tools to
invoke to migrate a PoC across library versions.
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from poctrans import llm_client
from poctrans.config import WORKSPACE_DIR, DATA_DIR, LOG_DIR, AGENT_MAX_ITERATIONS
from poctrans.tools import diff_viewer, maven_runner, version_manager, code_editor, error_parser
from poctrans.memory import MemoryStore

logger = logging.getLogger("poctrans")

# ============================================================
# Agent Tool Definitions (OpenAI Function Calling Schema)
# ============================================================

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "view_diff_summary",
            "description": "View a summary of code changes between two library versions (changed file list and statistics). Use this to get an overview of what changed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE identifier"},
                    "from_version": {"type": "string", "description": "Source version (already reproduced)"},
                    "to_version": {"type": "string", "description": "Target version (to adapt to)"}
                },
                "required": ["cve_id", "from_version", "to_version"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_diff",
            "description": "Search for code change hunks containing a specific keyword in the diff between two library versions. Use this to find API changes related to a compilation or test error.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE identifier"},
                    "from_version": {"type": "string", "description": "Source version"},
                    "to_version": {"type": "string", "description": "Target version"},
                    "keyword": {"type": "string", "description": "Search keyword (class name, method name, etc.)"}
                },
                "required": ["cve_id", "from_version", "to_version", "keyword"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "view_full_diff",
            "description": "View the complete diff between two library versions. WARNING: may be very large. Prefer search_diff for targeted queries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE identifier"},
                    "from_version": {"type": "string", "description": "Source version"},
                    "to_version": {"type": "string", "description": "Target version"}
                },
                "required": ["cve_id", "from_version", "to_version"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file in the PoC workspace (Java source, pom.xml, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative file path within the PoC workspace"}
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write/overwrite a file in the PoC workspace. Use this to modify Java test code or pom.xml. You MUST output the complete file content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative file path"},
                    "content": {"type": "string", "description": "Complete file content"}
                },
                "required": ["file_path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List all files in the current PoC workspace directory.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_test",
            "description": "Execute the PoC Maven test inside a Docker container (Java 11). Returns execution log with automatic verification of reproduction indicators.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "recall_memory",
            "description": "Retrieve past migration experience for this CVE or similar migrations. Returns notes from previous successful/failed attempts, known API changes, and adaptation patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What to recall — e.g. a class name, error message, or version pair"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "done",
            "description": "Call this when you believe the PoC has been successfully migrated, or when you are confident migration is not possible. Provide a summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean", "description": "Whether the migration succeeded"},
                    "summary": {"type": "string", "description": "Brief summary of the migration process and result"}
                },
                "required": ["success", "summary"]
            }
        }
    }
]

# ============================================================
# System Prompt
# ============================================================

SYSTEM_PROMPT = """You are a vulnerability PoC cross-version migration expert. Your task is to adapt a Proof-of-Concept exploit from one library version to another.

## Background
A vulnerability PoC is usually verified on a single library version, but the same vulnerability may affect many other versions. Due to API evolution between versions (class path changes, method signature changes, constructor parameter changes, interface additions/removals, etc.), the original PoC may not compile or run on the target version. You must analyze these differences and modify the PoC code so it triggers the same vulnerability on the target version.

## Tools Available
- `view_diff_summary` / `search_diff` / `view_full_diff`: Inspect code changes between two library versions
- `read_file` / `write_file` / `list_files`: Read/write PoC project files
- `run_test`: Execute Maven test in Docker (Java 11)
- `recall_memory`: Retrieve past migration experience and known adaptation patterns
- `done`: Complete the task

## Workflow
1. Recall any prior migration memory for this CVE (`recall_memory`)
2. Understand the current PoC structure (`list_files`, `read_file`)
3. Run the test to see current errors (`run_test`)
4. Analyze the compilation/test errors carefully
5. Search for relevant API changes in the version diff (`search_diff`)
6. If no diff is available, reason about the error messages to infer what changed
7. Modify the PoC code to adapt (`write_file`)
8. Re-run the test to verify (`run_test`)
9. Repeat 4-8 until verified or confirmed impossible

## Critical Rules
- Do NOT modify the target library version in pom.xml (it is already set)
- Preserve the vulnerability trigger semantics — the goal is to trigger the same (or equivalent) vulnerable behavior on the new version
- When writing files, output the COMPLETE file content, never abbreviate
- Make minimal necessary changes per iteration
- When diff data is unavailable, use error messages and Java reflection knowledge to infer API changes (e.g., different package paths, constructor signatures, method names)
- Always respond in English
"""


class MigrationAgent:
    """PoC migration agent using a ReAct loop.

    Observe → Think → Act → Observe → ...
    Includes memory (cross-run experience) and full trace logging.
    """

    def __init__(self, cve_config: dict):
        self.cve_id = cve_config["CVE"]
        self.config = cve_config
        self.group_id = cve_config["groupId"]
        self.artifact_id = cve_config["artifactId"]
        self.base_version = cve_config["exploitableVersion"]
        self.reproduced_behavior = cve_config.get("reproducedBehavior", "")
        self.reproduced_detail = cve_config.get("reproducedDetail", [])
        self.poc_dir: Optional[Path] = None
        self.messages = []
        self.trace = []  # full execution trace
        self.iteration = 0
        self.memory = MemoryStore()

    def migrate(self, origin_poc_dir: Path, target_version: str,
                base_version: Optional[str] = None) -> dict:
        if base_version is None:
            base_version = self.base_version

        # Prepare workspace
        self.poc_dir = maven_runner.prepare_poc_workspace(
            origin_poc_dir, self.cve_id, target_version
        )

        # Update target library version in pom.xml
        pom_path = self.poc_dir / "pom.xml"
        if pom_path.exists():
            version_manager.update_pom_version(
                pom_path, self.group_id, self.artifact_id, target_version
            )

        logger.info(f"Starting migration: {self.cve_id} {base_version} -> {target_version}")
        logger.info(f"Working directory: {self.poc_dir}")

        # Initialize trace
        self.trace = [{
            "event": "start",
            "cve_id": self.cve_id,
            "base_version": base_version,
            "target_version": target_version,
            "timestamp": datetime.now().isoformat(),
            "poc_dir": str(self.poc_dir)
        }]

        # Build initial messages
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self._build_task_prompt(
                base_version, target_version
            )}
        ]

        # ReAct loop
        self.iteration = 0
        while self.iteration < AGENT_MAX_ITERATIONS:
            self.iteration += 1
            logger.info(f"--- Iteration {self.iteration}/{AGENT_MAX_ITERATIONS} ---")

            response = llm_client.chat(
                self.messages,
                tools=TOOL_DEFINITIONS,
                temperature=0.0
            )

            if response.tool_calls:
                # Record assistant message
                assistant_msg = {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        for tc in response.tool_calls
                    ]
                }
                self.messages.append(assistant_msg)

                for tool_call in response.tool_calls:
                    name = tool_call.function.name
                    args = json.loads(tool_call.function.arguments)
                    logger.info(f"Tool call: {name}({json.dumps(args, ensure_ascii=False)[:200]})")

                    result = self._execute_tool(name, args, base_version, target_version)

                    # Record trace entry
                    self.trace.append({
                        "event": "tool_call",
                        "iteration": self.iteration,
                        "tool": name,
                        "args": args,
                        "result_preview": result[:500],
                        "timestamp": datetime.now().isoformat()
                    })

                    if name == "done":
                        success = args.get("success", False)
                        summary = args.get("summary", "")
                        self.trace.append({
                            "event": "done",
                            "success": success,
                            "summary": summary,
                            "iterations": self.iteration,
                            "timestamp": datetime.now().isoformat()
                        })
                        # Save trace and memory
                        self._save_trace(target_version)
                        if success:
                            self._save_memory(base_version, target_version, summary)
                        return {
                            "success": success,
                            "summary": summary,
                            "iterations": self.iteration,
                            "poc_dir": str(self.poc_dir)
                        }

                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result[:8000]
                    })
            else:
                content = response.content or ""
                logger.info(f"Agent thinking: {content[:200]}")
                self.messages.append({"role": "assistant", "content": content})
                self.trace.append({
                    "event": "thinking",
                    "iteration": self.iteration,
                    "content_preview": content[:300],
                    "timestamp": datetime.now().isoformat()
                })
                self.messages.append({
                    "role": "user",
                    "content": "Please continue using tools to complete the migration. Call `done` when finished."
                })

        self.trace.append({
            "event": "max_iterations",
            "iterations": self.iteration,
            "timestamp": datetime.now().isoformat()
        })
        self._save_trace(target_version)
        return {
            "success": False,
            "summary": f"Reached maximum iterations ({AGENT_MAX_ITERATIONS})",
            "iterations": self.iteration,
            "poc_dir": str(self.poc_dir)
        }

    def _build_task_prompt(self, base_version: str, target_version: str) -> str:
        """Build the initial task prompt with context."""
        # Gather memory context
        memory_context = self.memory.recall(self.cve_id, base_version, target_version)

        # Check available diffs
        available_diffs = diff_viewer.list_available_diffs(self.cve_id)
        diff_note = ""
        if available_diffs:
            diff_note = f"\n\nAvailable pre-computed diffs:\n"
            for d in available_diffs[:10]:
                diff_note += f"  - {d}\n"
        else:
            diff_note = "\n\nNOTE: No pre-computed diffs are available for this CVE. You will need to rely on error messages, Java reflection, and your knowledge to infer API changes between versions."

        prompt = f"""Migrate the vulnerability PoC from version {base_version} to {target_version}.

## Vulnerability Info
- CVE: {self.cve_id}
- Library: {self.group_id}:{self.artifact_id}
- Original PoC version: {base_version}
- Target version: {target_version}

## Verification Criteria
The migration is successful when the Maven test log contains ALL of these strings:
- Behavior: "{self.reproduced_behavior}"
- Details: {json.dumps(self.reproduced_detail, ensure_ascii=False)}

IMPORTANT: A test "failure" (BUILD FAILURE) does NOT mean migration failed. Many PoCs are designed so that an assertion failure proves the vulnerability exists. The key is whether the log contains the verification strings above.
{diff_note}"""

        if memory_context:
            prompt += f"\n\n## Prior Migration Experience\n{memory_context}"

        prompt += "\n\nThe PoC has been copied to the workspace with the target library version already set in pom.xml. Begin analysis and migration."
        return prompt

    def _execute_tool(self, name: str, args: dict,
                      base_version: str, target_version: str) -> str:
        """Execute a tool call and return the result string."""
        try:
            if name == "view_diff_summary":
                return diff_viewer.view_diff_summary(
                    args["cve_id"], args["from_version"], args["to_version"]
                )
            elif name == "search_diff":
                return diff_viewer.search_diff(
                    args["cve_id"], args["from_version"], args["to_version"],
                    args["keyword"]
                )
            elif name == "view_full_diff":
                result = diff_viewer.view_diff(
                    args["cve_id"], args["from_version"], args["to_version"]
                )
                if len(result) > 8000:
                    return result[:8000] + "\n\n[TRUNCATED - use search_diff for specific keywords]"
                return result
            elif name == "read_file":
                file_path = self.poc_dir / args["file_path"]
                return code_editor.read_file(file_path)
            elif name == "write_file":
                file_path = self.poc_dir / args["file_path"]
                return code_editor.write_file(file_path, args["content"])
            elif name == "list_files":
                return code_editor.list_project_files(self.poc_dir)
            elif name == "run_test":
                success, log_text = maven_runner.run_poc_test(
                    self.cve_id, target_version, self.poc_dir
                )
                verified, report = maven_runner.verify_reproduction(
                    log_text, self.reproduced_behavior, self.reproduced_detail
                )
                failure_type = error_parser.classify_failure(log_text)
                error_summary = error_parser.extract_error_summary(log_text)

                result = f"=== Execution Result ===\n"
                result += f"Build status: {failure_type}\n"
                result += f"\n=== Verification ===\n{report}\n"
                if verified:
                    result += "\n*** MIGRATION VERIFIED SUCCESSFULLY — call done(success=true) ***\n"
                result += f"\n=== Error Summary ===\n{error_summary}\n"
                log_lines = log_text.split("\n")
                tail = "\n".join(log_lines[-40:]) if len(log_lines) > 40 else log_text
                result += f"\n=== Log Tail ===\n{tail}"
                return result
            elif name == "recall_memory":
                return self.memory.recall(
                    self.cve_id, base_version, target_version,
                    query=args.get("query", "")
                )
            elif name == "done":
                return "Task completed."
            else:
                return f"[ERROR] Unknown tool: {name}"
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return f"[ERROR] Tool execution failed: {e}"

    def _save_trace(self, target_version: str):
        """Save the full agent trace to a JSON file."""
        trace_dir = LOG_DIR / "traces"
        trace_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        trace_file = trace_dir / f"{self.cve_id}_{target_version}_{ts}.json"

        # Also save the full conversation messages
        trace_data = {
            "cve_id": self.cve_id,
            "target_version": target_version,
            "iterations": self.iteration,
            "trace": self.trace,
            "messages": _sanitize_messages(self.messages)
        }
        trace_file.write_text(
            json.dumps(trace_data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        logger.info(f"Trace saved to {trace_file}")

    def _save_memory(self, base_version: str, target_version: str, summary: str):
        """Save successful migration experience to memory."""
        # Read the final adapted code
        java_files = code_editor.find_java_files(self.poc_dir)
        adapted_code = {}
        for f in java_files:
            rel = f.relative_to(self.poc_dir)
            adapted_code[str(rel)] = f.read_text(encoding="utf-8", errors="replace")

        self.memory.save(
            cve_id=self.cve_id,
            base_version=base_version,
            target_version=target_version,
            summary=summary,
            adapted_code=adapted_code
        )


def _sanitize_messages(messages: list) -> list:
    """Sanitize messages for JSON serialization (truncate long content)."""
    result = []
    for msg in messages:
        m = dict(msg)
        if "content" in m and m["content"] and len(m["content"]) > 2000:
            m["content"] = m["content"][:2000] + "\n...[truncated]"
        result.append(m)
    return result
