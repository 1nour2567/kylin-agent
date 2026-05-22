"""Tests for SessionStore — TTL expiry, history, concurrency safety."""
import sys, os, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.session_store import SessionStore


class TestSessionStore:
    def setup_method(self):
        self.store = SessionStore()

    def test_get_or_create_new_session(self):
        s = self.store.get_or_create("sid1", "alice")
        assert s["session_id"] == "sid1"
        assert s["user_id"] == "alice"
        assert len(s["history"]) == 0

    def test_get_or_create_returns_existing(self):
        s1 = self.store.get_or_create("sid1", "alice")
        s2 = self.store.get_or_create("sid1", "alice")
        assert s1 is s2

    def test_add_and_get_history(self):
        self.store.get_or_create("sid1", "alice")
        self.store.add_turn("sid1", "user", "查看进程")
        self.store.add_turn("sid1", "agent", "正在查看系统进程列表")
        history = self.store.get_history("sid1")
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "查看进程"
        assert history[1]["role"] == "agent"

    def test_history_max_length(self):
        self.store.get_or_create("sid1", "alice")
        for i in range(25):
            self.store.add_turn("sid1", "user", f"msg{i}")
        history = self.store.get_history("sid1")
        assert len(history) == 20  # MAX_HISTORY

    def test_get_nonexistent_session(self):
        s = self.store.get("nonexistent")
        assert s is None

    def test_history_nonexistent(self):
        assert self.store.get_history("nonexistent") == []

    def test_add_turn_nonexistent_session(self):
        # Should not raise
        self.store.add_turn("nonexistent", "user", "hello")

    def test_delete_session(self):
        self.store.get_or_create("sid1", "alice")
        assert self.store.delete("sid1") is True
        assert self.store.get("sid1") is None
        assert self.store.delete("sid1") is False

    def test_concurrent_access(self):
        self.store.get_or_create("sid1", "alice")
        errors = []

        def writer():
            try:
                for i in range(100):
                    self.store.add_turn("sid1", "user", f"msg{i}")
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    self.store.get_history("sid1")
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(3):
            threads.append(threading.Thread(target=writer))
        for _ in range(3):
            threads.append(threading.Thread(target=reader))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # History should be consistent
        history = self.store.get_history("sid1")
        assert len(history) <= 20  # max cap

    def test_cleanup_removes_expired_sessions(self):
        # Override TTL for testing
        old_ttl = self.store._sessions
        self.store.get_or_create("sid1", "alice")
        # Manually set last_access far in the past
        self.store._sessions["sid1"]["last_access"] = time.time() - 3600
        self.store._last_cleanup = 0  # force cleanup next call
        # get() triggers _maybe_cleanup
        s = self.store.get("sid1")
        assert s is None  # expired

    def test_metadata_present_in_session(self):
        s = self.store.get_or_create("sid1", "alice")
        assert "created_at" in s
        assert "last_access" in s
        assert "session_id" in s
        assert "user_id" in s
        assert "history" in s
        from collections import deque
        assert isinstance(s["history"], (list, deque))
