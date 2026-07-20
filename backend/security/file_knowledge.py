"""
Ops File Knowledge Base — classify files for safe cleanup vs protection.
===========================================================
Answers: "Can I safely clean this file?" with structured reasoning.
Used by T2 constraint layer and exposed to LLM as context for diagnosis.
"""
import re
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class FileClassification:
    path: str
    category: str           # e.g. "expired_log", "temp_cache", "database_data"
    cleanable: bool         # safe to delete/truncate
    risk_score: int         # 1-10, higher = more dangerous to touch
    reason: str             # human-readable explanation
    suggestion: str         # recommended action
    retention_hint: str     # e.g. "keep 7 days", "never delete", "rotate only"


class FileKnowledgeBase:
    """Classify files for safe cleanup in ops scenarios."""

    # ── Category definitions (ordered by risk) ──
    CATEGORIES = {
        # SAFE TO CLEAN
        "temp_cache": {
            "risk": 1, "cleanable": True,
            "description": "临时缓存文件，删除不影响系统运行",
            "retention": "可立即删除",
        },
        "expired_log": {
            "risk": 2, "cleanable": True,
            "description": "过期轮转日志，已有后续版本可安全清理",
            "retention": "保留最近 3 天",
        },
        "package_cache": {
            "risk": 2, "cleanable": True,
            "description": "包管理器缓存，可重新下载",
            "retention": "yum/dnf clean 后删除",
        },
        "core_dump": {
            "risk": 3, "cleanable": True,
            "description": "核心转储文件，调试后应及时清理",
            "retention": "确认无调试需求后删除",
        },
        # NEEDS REVIEW
        "user_upload": {
            "risk": 4, "cleanable": False,
            "description": "用户上传文件，需确认是否仍在使用",
            "retention": "通知用户后 30 天删除",
        },
        "application_log": {
            "risk": 4, "cleanable": False,
            "description": "应用日志，可能有审计价值",
            "retention": "保留 30 天或多于 3 次轮转",
        },
        # DANGEROUS — CONFIRM REQUIRED
        "database_log": {
            "risk": 7, "cleanable": False,
            "description": "数据库日志，删除影响故障排查和审计",
            "retention": "使用 logrotate 轮转，不可直接删除",
        },
        "system_log": {
            "risk": 8, "cleanable": False,
            "description": "系统审计/安全日志，删除影响合规审计",
            "retention": "保留至少 90 天（等保要求），使用 logrotate",
        },
        # NEVER TOUCH
        "config_file": {
            "risk": 9, "cleanable": False,
            "description": "系统/服务配置文件，误删导致服务不可用",
            "retention": "永不可删除，修改前必须备份",
        },
        "database_data": {
            "risk": 10, "cleanable": False,
            "description": "数据库数据文件，删除导致数据永久丢失",
            "retention": "永不可删除",
        },
        "binary_library": {
            "risk": 10, "cleanable": False,
            "description": "系统可执行文件或共享库，删除导致系统/应用崩溃",
            "retention": "永不可删除",
        },
    }

    # ── Pattern-based classification rules ──
    # Format: (regex, category_name)
    # Ordered — first match wins (more specific patterns first)

    RULES = [
        # ── SAFE: temp / cache ──
        (r"/tmp/", "temp_cache"),
        (r"/var/tmp/", "temp_cache"),
        (r"/var/cache/(yum|dnf|apt)/", "package_cache"),
        (r"/var/cache/(man|fontconfig|ldconfig)", "temp_cache"),
        (r"\.cache/", "temp_cache"),
        (r"/dev/shm/", "temp_cache"),
        (r"cache/", "temp_cache"),
        # Core dumps
        (r"/var/lib/systemd/coredump/", "core_dump"),
        (r"/var/crash/", "core_dump"),
        (r"core\.\d+$", "core_dump"),
        # Expired rotated logs (.1, .2.gz, .old, .bak)
        (r"\.log\.\d+(\.gz|\.xz|\.bz2)?$", "expired_log"),
        (r"\.log\.\d{8}$", "expired_log"),
        (r"\.log\.old$", "expired_log"),
        (r"\.log\.bak$", "expired_log"),
        (r"messages-\d{8}(\.gz)?$", "expired_log"),
        (r"secure-\d{8}(\.gz)?$", "expired_log"),
        # Package manager logs
        (r"/var/log/(yum|dnf|dpkg)\.log(\.\d+)?$", "expired_log"),

        # ── APPLICATION: needs review ──
        (r"/var/log/(nginx|httpd|apache2|tomcat)/.*\.log(\.\d+)?$", "application_log"),
        (r"/var/log/(uwsgi|gunicorn|supervisor)/.*\.log", "application_log"),
        (r"/var/log/(php|python|node)/.*\.log", "application_log"),

        # ── DATABASE: confirm required ──
        (r"(mysql|mariadb|postgres|mongod|redis|etcd|elasticsearch)\.log", "database_log"),
        (r"slow.*query\.log", "database_log"),
        (r"(error|general).*\.log$", "database_log"),
        (r"pg_log/", "database_log"),

        # ── SYSTEM: dangerous ──
        (r"/var/log/(secure|messages|syslog|kern\.log|auth\.log|audit/)", "system_log"),
        (r"systemd.*\.journal", "system_log"),
        (r"/var/log/(lastlog|wtmp|btmp|faillog)", "system_log"),

        # ── NEVER TOUCH ──
        (r"\.(conf|cfg|ini|yaml|yml|toml|cnf)$", "config_file"),
        (r"nginx/.*\.conf", "config_file"),
        (r"(httpd|apache2)/.*\.conf", "config_file"),
        (r"/etc/(mysql|my\.cnf|postgresql|redis|mongod)", "config_file"),
        (r"\.(db|sqlite|sqlite3|mdb|mdf|ldf|dbf|frm|ibd|myi|myd)$", "database_data"),
        (r"(mysql|mariadb|postgres|mongodb|redis|etcd)/data", "database_data"),
        (r"\.(so|ko|o)$", "binary_library"),
        (r"/usr/(bin|sbin|lib|lib64|local/bin)/", "binary_library"),
        (r"/boot/", "binary_library"),
        (r"/etc/(passwd|shadow|group|sudoers|hosts|resolv\.conf)$", "config_file"),
    ]

    # ── Common disk hogs that are safe to clean ──
    COMMON_CLEANABLE = [
        ("/var/log/journal/", "systemd 日志（超过保留天数的可清理）"),
        ("/var/cache/yum/", "YUM 包缓存"),
        ("/var/cache/dnf/", "DNF 包缓存"),
        ("/var/cache/apt/archives/", "APT 包缓存"),
        ("/tmp/", "临时文件（7 天未访问可清理）"),
        ("/var/tmp/", "临时文件（30 天未访问可清理）"),
        ("/var/spool/postfix/maildrop/", "Postfix 邮件队列积压"),
        ("/var/spool/clientmqueue/", "Sendmail 客户端队列"),
        ("/var/log/*.log-*", "过期轮转日志"),
        ("~/.cache/", "用户缓存目录"),
        ("/var/lib/docker/overlay2/", "Docker 旧镜像层"),
        ("/var/lib/containerd/", "Containerd 旧快照"),
    ]

    @classmethod
    def classify(cls, path: str, size_bytes: Optional[int] = None,
                age_days: Optional[int] = None) -> FileClassification:
        """Classify a file and return its safety profile."""
        abs_path = os.path.abspath(os.path.expanduser(path))
        fname = os.path.basename(abs_path)

        matched_category = None
        for pattern, category in cls.RULES:
            if re.search(pattern, abs_path, re.IGNORECASE):
                matched_category = category
                break

        if matched_category is None:
            # Default: unknown file → conservative
            matched_category = "application_log"
            if abs_path.startswith("/var/log/"):
                matched_category = "application_log"
            elif abs_path.startswith("/home/") or abs_path.startswith("/root/"):
                matched_category = "user_upload"

        cat_info = cls.CATEGORIES.get(matched_category, cls.CATEGORIES["application_log"])

        # Build diagnostic message
        size_str = f"({size_bytes / 1024**3:.1f}GB)" if size_bytes and size_bytes > 10**7 else \
                   f"({size_bytes / 1024**2:.0f}MB)" if size_bytes and size_bytes > 10**4 else ""
        age_str = f", {age_days}天未修改" if age_days is not None else ""

        return FileClassification(
            path=abs_path,
            category=matched_category,
            cleanable=cat_info["cleanable"],
            risk_score=cat_info["risk"],
            reason=f"{cat_info['description']}{age_str}{size_str}",
            suggestion=f"{cat_info['retention']}{size_str}",
            retention_hint=cat_info["retention"],
        )

    @classmethod
    def get_cleanup_candidates(cls, file_list: list) -> list:
        """Given a list of {path, size, age} dicts, return only safe-to-clean files."""
        results = []
        for f in file_list:
            c = cls.classify(f.get("path", ""),
                            size_bytes=f.get("size"),
                            age_days=f.get("age_days"))
            results.append({
                "path": c.path,
                "category": c.category,
                "cleanable": c.cleanable,
                "risk_score": c.risk_score,
                "reason": c.reason,
                "suggestion": c.suggestion,
            })
        return sorted(results, key=lambda r: (r["cleanable"], r["risk_score"]))

    @classmethod
    def get_knowledge_summary(cls) -> str:
        """Return a compact knowledge base summary for the LLM prompt."""
        lines = ["## 文件清理知识库\n"]
        lines.append("| 文件类型 | 可清理? | 风险 | 处理建议 |")
        lines.append("|---------|--------|------|---------|")
        for cat, info in sorted(cls.CATEGORIES.items(), key=lambda x: x[1]["risk"]):
            lines.append(f"| {info['description']} | {'✓' if info['cleanable'] else '✗'} | {info['risk']} | {info['retention']} |")
        lines.append("\n常见可安全清理的位置：")
        for path, desc in cls.COMMON_CLEANABLE:
            lines.append(f"- {path}: {desc}")
        return "\n".join(lines)
