"""运行时配置，全部通过环境变量注入，无需任何第三方账号。"""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger("captoken.config")


@dataclass(frozen=True)
class Settings:
    secret: bytes          # HMAC 密钥
    db_path: str           # SQLite 数据库文件路径
    default_ttl: int       # 默认令牌有效期（秒）
    max_ttl: int           # 允许签发的最大有效期（秒）
    files_dir: str         # 演示下载端点的文件根目录


@lru_cache
def get_settings() -> Settings:
    secret_env = os.environ.get("TOKEN_SECRET", "").strip()
    if secret_env:
        secret = secret_env.encode("utf-8")
    else:
        # 未配置密钥时生成临时随机密钥：服务重启后旧令牌全部失效。
        # 生产环境必须显式设置 TOKEN_SECRET。
        secret = secrets.token_bytes(32)
        logger.warning(
            "TOKEN_SECRET 未设置，已生成临时随机密钥；重启后已签发的令牌将失效。"
            "生产环境请通过环境变量 TOKEN_SECRET 配置固定密钥。"
        )

    return Settings(
        secret=secret,
        db_path=os.environ.get("TOKEN_DB_PATH", "./data/tokens.db"),
        default_ttl=int(os.environ.get("TOKEN_DEFAULT_TTL", "300")),
        max_ttl=int(os.environ.get("TOKEN_MAX_TTL", "3600")),
        files_dir=os.environ.get("FILES_DIR", "./files"),
    )
