"""Tool Adapter Contract and Registry for Sentinel.

Defines the abstract interface for all security scanners, command wrappers,
and protocol adapters, along with a dynamic capability routing registry.
"""

from abc import ABC, abstractmethod

from sentinel.core.models import ActionRequest, ActionResult


class ToolAdapter(ABC):
    """Abstract contract for all external security tool integrations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique adapter name (e.g. 'dns_resolver', 'http_observer', 'network_scanner')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Adapter integration version."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> list[str]:
        """List of ActionRequest action_types this adapter can execute."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify underlying dependencies, binaries, or libraries are available."""
        pass

    @abstractmethod
    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        """Validate input parameters specifically for this adapter's execution."""
        pass

    @abstractmethod
    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        """Execute the action.

        Returns:
            (ActionResult, raw_evidence_bytes, mime_type)
        """
        pass


class ToolAdapterRegistry:
    """Registry coordinating available tool adapters and action-type routing."""

    def __init__(self):
        self._adapters: dict[str, ToolAdapter] = {}
        self._action_routing: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        """Register an adapter and index its capabilities."""
        self._adapters[adapter.name] = adapter
        for action_type in adapter.capabilities:
            self._action_routing[action_type] = adapter

    def get_adapter_for_action(self, action_type: str) -> ToolAdapter | None:
        """Find adapter registered to execute a given action_type."""
        # Exact match
        if action_type in self._action_routing:
            return self._action_routing[action_type]

        # Wildcard prefix match
        for registered_type, adapter in self._action_routing.items():
            if registered_type.endswith(".*"):
                prefix = registered_type[:-2]
                if action_type.startswith(prefix):
                    return adapter

        return None

    def get_adapter_by_name(self, name: str) -> ToolAdapter | None:
        return self._adapters.get(name)

    def list_adapters(self) -> list[ToolAdapter]:
        return list(self._adapters.values())


# Global Registry Singleton
adapter_registry = ToolAdapterRegistry()
