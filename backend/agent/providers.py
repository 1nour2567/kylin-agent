import json
from openai import OpenAI


class DeepSeekProvider:
    def __init__(self, api_key: str, base_url: str, model: str, timeout: int = 60):
        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=2048,
        )
        return resp.choices[0].message.content

    def generate_stream(self, system_prompt: str, user_prompt: str):
        """Yield text chunks from streaming completion."""
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=2048,
            stream=True,
        )
        for chunk in resp:
            content = chunk.choices[0].delta.content
            if content:
                yield content


class MockProvider:
    """Deterministic mock that returns valid tool calls for testing the full pipeline."""
    model = "mock"

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        user_lower = user_prompt.lower()
        # Check kill/stop BEFORE process (more specific pattern first)
        if any(kw in user_lower for kw in ("kill ", "终止", "强制结束", "stop service")):
            return json.dumps({
                "diagnosis": "用户请求终止进程",
                "intent": "process_investigation",
                "commands": [
                    {"tool": "ps_processes", "params": {"-9": "1234"}, "justification": "强制终止指定进程"}
                ],
                "explanation": "正在终止进程，此操作需要确认",
                "risk_awareness": "High",
            }, ensure_ascii=False)
        if "process" in user_lower or "进程" in user_prompt:
            return json.dumps({
                "diagnosis": "用户请求查看系统进程状态",
                "intent": "process_investigation",
                "commands": [
                    {"tool": "ps_processes", "params": {"limit": "10"}, "justification": "查看当前运行进程"}
                ],
                "explanation": "正在为您查看系统进程列表",
                "risk_awareness": "Low",
            }, ensure_ascii=False)
        if "disk" in user_lower or "磁盘" in user_prompt:
            return json.dumps({
                "diagnosis": "用户请求查看磁盘使用情况",
                "intent": "resource_check",
                "commands": [
                    {"tool": "df_disk", "params": {}, "justification": "查看磁盘使用率"}
                ],
                "explanation": "正在为您检查磁盘空间",
                "risk_awareness": "Low",
            }, ensure_ascii=False)
        if "memory" in user_lower or "内存" in user_prompt:
            return json.dumps({
                "diagnosis": "用户请求查看内存使用情况",
                "intent": "resource_check",
                "commands": [
                    {"tool": "free_memory", "params": {}, "justification": "查看内存使用率"}
                ],
                "explanation": "正在为您检查内存使用",
                "risk_awareness": "Low",
            }, ensure_ascii=False)
        if "网络" in user_prompt or "connection" in user_lower or "net" in user_lower:
            return json.dumps({
                "diagnosis": "用户请求查看网络连接状态",
                "intent": "resource_check",
                "commands": [
                    {"tool": "netstat_connections", "params": {}, "justification": "查看网络连接"}
                ],
                "explanation": "正在为您检查网络连接",
                "risk_awareness": "Low",
            }, ensure_ascii=False)
        if "log" in user_lower or "日志" in user_prompt:
            return json.dumps({
                "diagnosis": "用户请求查看系统日志",
                "intent": "log_analysis",
                "commands": [
                    {"tool": "journalctl_logs", "params": {"unit": "sshd", "lines": "30"}, "justification": "查看系统日志"}
                ],
                "explanation": "正在为您查看系统日志",
                "risk_awareness": "Low",
            }, ensure_ascii=False)
        return json.dumps({
            "diagnosis": "一般性问题咨询",
            "intent": "general_query",
            "commands": [],
            "explanation": "您好，我是麒麟OS安全运维助手。您可以让我查看进程、磁盘、内存、网络或日志信息。",
            "risk_awareness": "Low",
        }, ensure_ascii=False)


    def generate_stream(self, system_prompt: str, user_prompt: str):
        """Mock streaming: yield the canned response in chunks."""
        text = self.generate(system_prompt, user_prompt)
        chunk_size = max(1, len(text) // 8)
        for i in range(0, len(text), chunk_size):
            yield text[i:i + chunk_size]


class ProviderRegistry:
    def __init__(self):
        self._providers = {}
        self._active = None

    def register(self, provider):
        self._providers[provider.model] = provider
        if self._active is None:
            self._active = provider

    def get_active(self):
        return self._active

    def set_active(self, name: str) -> bool:
        if name in self._providers:
            self._active = self._providers[name]
            return True
        return False
