class Router:
    COMMANDS = {"help", "status", "health"}

    QUERY_KEYWORDS = [
        "查看", "列出", "显示", "检查", "多少", "有哪些",
        "状态", "运行", "占用", "空间", "内存", "cpu",
        "进程", "端口", "日志", "服务",
    ]

    ACTION_KEYWORDS = [
        "清理", "删除", "重启", "启动", "停止", "安装",
        "卸载", "修改", "配置", "修复", "优化",
    ]

    EMERGENCY_KEYWORDS = [
        "紧急", "宕机", "崩溃", "无法访问", "全部挂了",
        "数据丢失", "磁盘满",
    ]

    def classify(self, user_input: str) -> dict:
        cleaned = user_input.strip().lower()

        for cmd in self.COMMANDS:
            if cleaned == cmd or cleaned.startswith(cmd):
                return {"mode": "query", "command": cmd}

        for kw in self.EMERGENCY_KEYWORDS:
            if kw in cleaned:
                return {"mode": "emergency", "trigger": kw}

        for kw in self.ACTION_KEYWORDS:
            if kw in cleaned:
                return {"mode": "action", "trigger": kw}

        for kw in self.QUERY_KEYWORDS:
            if kw in cleaned:
                return {"mode": "query", "trigger": kw}

        return {"mode": "query"}
