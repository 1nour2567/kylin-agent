"""In-memory session store with per-session conversation history.

Each session holds:
  - A deque of conversation turns: [{role, content, timestamp}]
  - Metadata: created_at, last_access, user_id

TTL-based eviction: sessions expire after 30 min of inactivity.
"""
import time
import threading
from collections import deque
from typing import Optional

MAX_HISTORY = 20          # last N turns kept per session
SESSION_TTL = 1800        # 30 min inactivity → expire
CLEANUP_INTERVAL = 300    # clean every 5 min


class SessionStore:
    def __init__(self):
        self._sessions: dict = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def get_or_create(self, session_id: str, user_id: str = "anonymous") -> dict:
        self._maybe_cleanup()
        with self._lock:
            if session_id in self._sessions:
                s = self._sessions[session_id]
                s["last_access"] = time.time()
                return s
            s = {
                "session_id": session_id,
                "user_id": user_id,
                "created_at": time.time(),
                "last_access": time.time(),
                "history": deque(maxlen=MAX_HISTORY),
            }
            self._sessions[session_id] = s
            return s

    def get(self, session_id: str) -> Optional[dict]:
        self._maybe_cleanup()
        with self._lock:
            s = self._sessions.get(session_id)
            if s:
                s["last_access"] = time.time()
            return s

    def add_turn(self, session_id: str, role: str, content: str):
        with self._lock:
            s = self._sessions.get(session_id)
            if s:
                s["history"].append({
                    "role": role,
                    "content": content,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                })
                s["last_access"] = time.time()

    def get_history(self, session_id: str) -> list:
        s = self.get(session_id)
        if s is None:
            return []
        return list(s["history"])

    def delete(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def _maybe_cleanup(self):
        now = time.time()
        if now - self._last_cleanup < CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        with self._lock:
            expired = [
                sid for sid, s in self._sessions.items()
                if now - s["last_access"] > SESSION_TTL
            ]
            for sid in expired:
                del self._sessions[sid]
