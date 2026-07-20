"""
Full-chain Trace ID — unified request tracing across all pipeline stages.
=========================================================================
Every user request gets a trace_id that follows it through:
  receive → perceive → classify → reason → validate → execute → result

TraceContext is propagated via contextvars (async-safe) and attached to
every audit event, log entry, and API response.

Format: kylin-{timestamp}-{random}  (e.g. kylin-20260601-a3f2b1c4)
"""
from __future__ import annotations
import contextvars
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


_trace_context: contextvars.ContextVar[Optional["TraceContext"]] = (
    contextvars.ContextVar("trace_context", default=None)
)


@dataclass
class TraceSpan:
    """A single span within a trace."""
    name: str                # e.g. "perceive", "reason", "execute"
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    metadata: dict = field(default_factory=dict)

    def elapsed_ms(self) -> float:
        if self.ended_at > 0:
            return (self.ended_at - self.started_at) * 1000
        return (time.time() - self.started_at) * 1000


@dataclass
class TraceContext:
    """Immutable trace context propagated through the pipeline."""
    trace_id: str
    user_id: str = "anonymous"
    role: str = "viewer"
    spans: list[TraceSpan] = field(default_factory=list)
    _current_span: Optional[TraceSpan] = None

    @classmethod
    def new(cls, user_id: str = "anonymous", role: str = "viewer") -> TraceContext:
        """Create a new trace."""
        trace_id = f"kylin-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        ctx = cls(trace_id=trace_id, user_id=user_id, role=role)
        _trace_context.set(ctx)
        return ctx

    @classmethod
    def current(cls) -> Optional[TraceContext]:
        """Get the current trace context from the async context."""
        return _trace_context.get()

    @classmethod
    def get_or_create(cls, user_id: str = "anonymous", role: str = "viewer") -> TraceContext:
        """Get current trace or create a new one."""
        ctx = _trace_context.get()
        if ctx is None:
            ctx = cls.new(user_id, role)
        return ctx

    def start_span(self, name: str, metadata: dict = None) -> TraceSpan:
        """Begin a new span. Ends any previous span."""
        if self._current_span and self._current_span.ended_at == 0:
            self._current_span.ended_at = time.time()

        span = TraceSpan(name=name, metadata=metadata or {})
        self._current_span = span
        self.spans.append(span)
        return span

    def end_span(self, metadata: dict = None):
        """End the current span."""
        if self._current_span:
            self._current_span.ended_at = time.time()
            if metadata:
                self._current_span.metadata.update(metadata)

    def span_summary(self) -> list[dict]:
        """Return compact span summary for audit/response."""
        return [
            {
                "name": s.name,
                "elapsed_ms": round(s.elapsed_ms(), 1),
                "metadata": s.metadata,
            }
            for s in self.spans
        ]

    def total_elapsed_ms(self) -> float:
        """Total trace duration."""
        if not self.spans:
            return 0
        start = self.spans[0].started_at
        end = max(s.ended_at if s.ended_at > 0 else time.time()
                  for s in self.spans)
        return (end - start) * 1000

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "user_id": self.user_id,
            "role": self.role,
            "total_elapsed_ms": round(self.total_elapsed_ms(), 1),
            "span_count": len(self.spans),
            "spans": self.span_summary(),
        }


def clear_trace():
    """Clear the trace context (called at request end)."""
    _trace_context.set(None)
