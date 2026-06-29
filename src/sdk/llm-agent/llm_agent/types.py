"""Shared type: the streaming sink. The Claude Agent SDK owns the loop, tools, and
conversation history, so the provider-message / tool / budget types are gone."""
from __future__ import annotations

from typing import Callable, Optional

# A streaming sink: called with each generated text chunk (worker stdout in Scenario B).
StreamFn = Optional[Callable[[str], None]]
