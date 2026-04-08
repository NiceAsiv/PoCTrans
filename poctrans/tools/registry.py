"""Tool Registry - unified tool schema + handler registration."""

import logging
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("poctrans")


class ToolRegistry:
    """Registry mapping tool names to their OpenAI schemas and handler callables.

    Usage:
        registry = ToolRegistry()
        registry.register(name="read_file", schema={...}, handler=my_func)
        result = registry.execute("read_file", {"file_path": "pom.xml"})
    """

    def __init__(self):
        self._schemas: Dict[str, dict] = {}
        self._handlers: Dict[str, Callable[..., str]] = {}

    def register(self, name: str, schema: dict, handler: Callable[..., str]):
        """Register a tool with its OpenAI function-calling schema and handler.

        Args:
            name: Tool name (must match schema's function.name).
            schema: OpenAI tool schema dict ({"type": "function", "function": {...}}).
            handler: Callable that accepts **kwargs matching the schema parameters
                     and returns a result string.
        """
        self._schemas[name] = schema
        self._handlers[name] = handler

    @property
    def definitions(self) -> List[dict]:
        """Return all tool schemas in the format expected by OpenAI API."""
        return list(self._schemas.values())

    def execute(self, name: str, args: dict) -> str:
        """Dispatch a tool call by name, passing args as kwargs to the handler."""
        handler = self._handlers.get(name)
        if handler is None:
            return f"[ERROR] Unknown tool: {name}"
        try:
            return handler(**args)
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return f"[ERROR] Tool execution failed: {e}"
