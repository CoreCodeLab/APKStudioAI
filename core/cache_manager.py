"""
Cache manager for APKStudioAI 2.1
Provides persistent caching for JADX, Apktool, DEX analysis, and other expensive operations.
"""
import os
import json
import hashlib
import shutil
import time
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional, Dict, List
from .config_manager import get_config
from .utils import get_project_root


class CacheManager:
    """Manages persistent caching with SQLite backend."""

    _instance: Optional['CacheManager'] = None
    _lock = threading.Lock()

    def __new__(cls, config_path: Optional[str] = None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, config_path: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True

        # Load config
        config = get_config(config_path)
        cache_config = config.get("scanner", {}).get("cache", {})
        self.enabled = cache_config.get("enabled", True)
        self.max_age_days = cache_config.get("max_age_days", 30)
        self.max_size_mb = cache_config.get("max_size_mb", 2000)

        # Determine cache directory
        cache_dir = cache_config.get("cache_dir", ".apkstudio_cache")
        if not Path(cache_dir).is_absolute():
            project_root = get_project_root()
            self.cache_dir = project_root / cache_dir
        else:
            self.cache_dir = Path(cache_dir)

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "cache.db"
        self._init_db()

        # Start cleanup thread if enabled
        if self.enabled:
            self._start_cleanup_thread()

    def _init_db(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    accessed_at REAL NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    tags TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON cache(created_at)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_accessed_at ON cache(accessed_at)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tags ON cache(tags)
            """)
            conn.commit()

    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        def cleanup():
            while True:
                time.sleep(3600)  # Run every hour
                if not self.enabled:
                    break
                self.cleanup_expired()

        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()

    def _make_key(self, namespace: str, *parts: str) -> str:
        """Create a cache key from namespace and parts."""
        key_parts = [namespace] + [str(p) for p in parts]
        return hashlib.sha256(":".join(key_parts).encode()).hexdigest()[:32]

    def get(self, namespace: str, *parts: str) -> Optional[Any]:
        """Get value from cache."""
        if not self.enabled:
            return None

        key = self._make_key(namespace, *parts)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT value, accessed_at FROM cache WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                if row:
                    # Update accessed time
                    conn.execute(
                        "UPDATE cache SET accessed_at = ? WHERE key = ?",
                        (time.time(), key)
                    )
                    conn.commit()
                    return json.loads(row[0])
        except Exception:
            pass
        return None

    def set(self, namespace: str, value: Any, *parts: str, tags: List[str] = None) -> bool:
        """Set value in cache."""
        if not self.enabled:
            return False

        key = self._make_key(namespace, *parts)
        try:
            value_json = json.dumps(value, default=str)
            size_bytes = len(value_json.encode('utf-8'))
            now = time.time()

            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO cache (key, value, created_at, accessed_at, size_bytes, tags)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (key, value_json, now, now, size_bytes, json.dumps(tags or []))
                )
                conn.commit()
            return True
        except Exception:
            return False

    def delete(self, namespace: str, *parts: str) -> bool:
        """Delete value from cache."""
        if not self.enabled:
            return False

        key = self._make_key(namespace, *parts)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
            return True
        except Exception:
            return False

    def clear_namespace(self, namespace: str) -> int:
        """Clear all entries in a namespace."""
        if not self.enabled:
            return 0

        # Since we use hashed keys, we need to check tags
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT key FROM cache WHERE tags LIKE ?",
                    (f'%"{namespace}"%',)
                )
                keys = [row[0] for row in cursor.fetchall()]
                if keys:
                    placeholders = ",".join("?" * len(keys))
                    conn.execute(f"DELETE FROM cache WHERE key IN ({placeholders})", keys)
                    conn.commit()
                return len(keys)
        except Exception:
            return 0

    def cleanup_expired(self) -> int:
        """Remove expired entries based on max_age_days."""
        if not self.enabled:
            return 0

        cutoff = time.time() - (self.max_age_days * 86400)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM cache WHERE accessed_at < ?",
                    (cutoff,)
                )
                conn.commit()
                return cursor.rowcount
        except Exception:
            return 0

    def cleanup_size(self) -> int:
        """Remove oldest entries if cache exceeds max_size_mb."""
        if not self.enabled:
            return 0

        max_bytes = self.max_size_mb * 1024 * 1024
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT SUM(size_bytes) FROM cache")
                total_size = cursor.fetchone()[0] or 0

                if total_size > max_bytes:
                    # Delete oldest entries until under limit
                    to_remove = total_size - max_bytes
                    cursor = conn.execute(
                        "SELECT key, size_bytes FROM cache ORDER BY accessed_at ASC"
                    )
                    removed = 0
                    for row in cursor.fetchall():
                        if removed >= to_remove:
                            break
                        conn.execute("DELETE FROM cache WHERE key = ?", (row[0],))
                        removed += row[1]
                    conn.commit()
                    return removed
        except Exception:
            pass
        return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.enabled:
            return {"enabled": False}

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*), SUM(size_bytes) FROM cache")
                count, total_size = cursor.fetchone()
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cache WHERE accessed_at > ?",
                    (time.time() - 86400,)
                )
                recent = cursor.fetchone()[0]
                return {
                    "enabled": True,
                    "entry_count": count or 0,
                    "total_size_mb": round((total_size or 0) / (1024 * 1024), 2),
                    "recent_entries_24h": recent or 0,
                    "cache_dir": str(self.cache_dir)
                }
        except Exception:
            return {"enabled": True, "error": "Failed to get stats"}

    def close(self):
        """Close cache (for testing)."""
        self.enabled = False


# Global instance getter
def get_cache(config_path: Optional[str] = None) -> CacheManager:
    """Get global CacheManager instance."""
    return CacheManager(config_path)


def cache_result(namespace: str, *key_parts: str, tags: List[str] = None):
    """Decorator to cache function results."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            cache = get_cache()
            # Create cache key from function args
            key_str = f"{func.__module__}.{func.__name__}:{args}:{kwargs}"
            cached = cache.get(namespace, key_str)
            if cached is not None:
                return cached
            result = func(*args, **kwargs)
            cache.set(namespace, result, key_str, tags=tags)
            return result
        return wrapper
    return decorator