"""SQLite 持久层：一次性 nonce 的存储与原子消费。

nonce 消费用单条 DELETE 语句完成——SQLite 单语句天然原子，
配合 affected-rows 检查，并发/多 worker 下同一 nonce 只会被一个请求消费成功。
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_expires_at ON nonces (expires_at);
"""


def _connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=10000")
    return con


def init_db(db_path: str) -> None:
    """启动时初始化数据库（建表 + WAL）。"""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as con:
        con.executescript(_SCHEMA)


def store_nonce(db_path: str, nonce: str, expires_at: int) -> None:
    with _connect(db_path) as con:
        con.execute(
            "INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)",
            (nonce, expires_at),
        )


def consume_nonce(db_path: str, nonce: str, now: int | None = None) -> bool:
    """原子消费 nonce：存在且未过期则删除并返回 True，否则返回 False。

    重放或并发重复消费时，只有第一个 DELETE 能命中（rowcount == 1）。
    """
    now = int(time.time()) if now is None else now
    with _connect(db_path) as con:
        cur = con.execute(
            "DELETE FROM nonces WHERE nonce = ? AND expires_at > ?",
            (nonce, now),
        )
        con.commit()
        return cur.rowcount == 1


def purge_expired(db_path: str, now: int | None = None) -> int:
    """清理已过期但未被消费的 nonce（令牌过期后无人使用会残留）。"""
    now = int(time.time()) if now is None else now
    with _connect(db_path) as con:
        cur = con.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
        con.commit()
        return cur.rowcount
