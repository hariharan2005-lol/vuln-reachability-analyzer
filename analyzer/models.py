from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Dict, Any


class EntryPointType(Enum):
    FLASK_ROUTE = "FLASK_ROUTE"
    FASTAPI_ROUTE = "FASTAPI_ROUTE"
    MAIN_BLOCK = "MAIN_BLOCK"
    STREAMLIT_SCRIPT = "STREAMLIT_SCRIPT"
    TOP_LEVEL_SCRIPT = "TOP_LEVEL_SCRIPT"
    CLI_COMMAND = "CLI_COMMAND"
    CUSTOM = "CUSTOM"


@dataclass(frozen=True)
class FunctionNode:
    """Represents a defined function or method in the analyzed project."""
    symbol: str  # Fully qualified or module-scoped name e.g. "app.process_user" or "module.Class.method"
    file_path: str
    line_number: int
    name: str
    is_method: bool = False
    decorators: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class CallSite:
    """Represents a function or method invocation."""
    caller_symbol: str
    callee_name: str  # Raw name or resolved target symbol
    line_number: int
    file_path: str


@dataclass(frozen=True)
class EntryPoint:
    """Represents an application entry point from which execution can begin."""
    symbol: str  # Caller function symbol or synthetic block symbol
    entry_type: EntryPointType
    file_path: str
    line_number: int
    metadata: Dict[str, Any] = field(default_factory=dict)  # E.g. route path, HTTP methods


@dataclass
class VulnerabilityInfo:
    """Represents vulnerability details retrieved or specified for a dependency."""
    package_name: str
    version: str
    advisory_id: str  # CVE or GHSA ID
    summary: str
    affected_symbols: List[str] = field(default_factory=list)  # Functions/classes marked vulnerable
    aliases: List[str] = field(default_factory=list)


@dataclass
class ReachabilityResult:
    """Result of a reachability analysis query for a target symbol."""
    target_symbol: str
    is_reachable: bool
    paths: List[List[str]] = field(default_factory=list)  # List of caller -> callee call chains
    entry_points_reached: List[EntryPoint] = field(default_factory=list)
    advisory_id: Optional[str] = None
    package_name: Optional[str] = None
