"""Core data types shared across the agent loop, LLM backends, and tools.

Provider-neutral: an LLM backend converts these to/from its own wire format, so the
agent loop and tools never see provider specifics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

ROLE_SYSTEM = "system"
ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ROLE_TOOL = "tool"


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # JSON-encoded object (the model's tool input)


@dataclass
class Message:
    role: str
    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)  # assistant turns
    tool_call_id: str = ""  # role == tool: which call this answers
    name: str = ""  # role == tool: the tool name


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict  # JSON Schema (object)


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class Completion:
    message: Message
    usage: Usage = field(default_factory=Usage)


@dataclass
class TurnLimits:
    """Per-turn ceilings. 0 means unlimited. See clamp()."""
    max_iterations: int = 0
    max_tokens: int = 0

    def clamp(self, req: "TurnLimits") -> "TurnLimits":
        """Constrain a request by this operator ceiling: a request may only tighten.
        A ceiling of 0 (unlimited) lets any positive request apply (it is stricter);
        against a finite ceiling a request applies only if smaller; unset inherits."""
        def tighter(r: int, c: int) -> bool:
            return r > 0 and (c <= 0 or r < c)

        out = TurnLimits(self.max_iterations, self.max_tokens)
        if tighter(req.max_iterations, self.max_iterations):
            out.max_iterations = req.max_iterations
        if tighter(req.max_tokens, self.max_tokens):
            out.max_tokens = req.max_tokens
        return out


# A streaming sink: called with each generated text chunk (worker stdout in Scenario B).
StreamFn = Optional[Callable[[str], None]]


class BudgetExceeded(Exception):
    """A hard per-turn or per-tenant ceiling was hit. ``result`` carries the partial
    turn stats (iterations / tokens spent) when raised mid-turn."""

    def __init__(self, message: str, result=None):
        super().__init__(message)
        self.result = result


class AuthError(Exception):
    """Caller token missing/invalid."""


class NotFound(Exception):
    """Session not found."""


class Forbidden(Exception):
    """Caller is not the session owner."""
