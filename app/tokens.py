"""能力令牌的签发与密码学验证（纯函数，不触碰数据库）。

令牌格式：  v1.<base64url(payload_json)>.<base64url(hmac_sha256)>
签名输入：  ASCII 字符串 "v1.<base64url(payload_json)>"，保证签发/验证双方字节一致。
payload:    {"m": 方法, "p": 规范化路径, "exp": 过期时间戳, "n": 可选一次性 nonce}
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import posixpath
import re
import time
from urllib.parse import quote, unquote, urlsplit

TOKEN_VERSION = "v1"

# 验证失败原因（供 API 层结构化返回）
MALFORMED = "malformed"                # 令牌格式非法
BAD_SIGNATURE = "bad_signature"        # 签名校验失败
EXPIRED = "expired"                    # 令牌已过期
METHOD_MISMATCH = "method_mismatch"    # HTTP 方法不匹配
PATH_MISMATCH = "path_mismatch"        # 路径不匹配
NONCE_INVALID = "nonce_invalid"        # nonce 不存在 / 已使用 / 已过期（重放）

_MULTI_SLASH = re.compile(r"/{2,}")
# RFC 3986：unreserved + sub-delims + ':' + '@' 无需百分号编码
_PATH_SAFE = "/-._~!$&'()*+,;=:@"


class TokenError(Exception):
    """令牌验证失败，reason 为上面的常量之一。"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def normalize_path(raw_path: str) -> str:
    """把 HTTP 路径规范化成唯一形式，用于令牌绑定与比对。

    规则：提取路径部分（容忍完整 URL / 查询串）→ 百分号解码 →
    合并重复斜杠 → 解析 "." / ".."（已 rooted，无法逃出根）→
    去掉末尾斜杠（根路径除外）→ 按 RFC 3986 重新百分号编码。
    """
    if not raw_path or not raw_path.strip():
        raise ValueError("path 不能为空")
    candidate = raw_path.strip()
    if "://" in candidate:  # 容忍传入完整 URL
        candidate = urlsplit(candidate).path
    candidate = candidate.split("?", 1)[0].split("#", 1)[0]
    decoded = unquote(candidate)
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    decoded = _MULTI_SLASH.sub("/", decoded)
    normalized = posixpath.normpath(decoded)  # 同时去掉末尾斜杠，根为 "/"
    return quote(normalized, safe=_PATH_SAFE)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue_token(
    secret: bytes,
    method: str,
    path: str,
    ttl_seconds: int,
    nonce: str | None = None,
    now: int | None = None,
) -> tuple[str, dict]:
    """签发令牌，返回 (token, payload)。"""
    now = int(time.time()) if now is None else now
    payload: dict = {
        "m": method.upper(),
        "p": normalize_path(path),
        "exp": now + ttl_seconds,
    }
    if nonce is not None:
        payload["n"] = nonce
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{TOKEN_VERSION}.{body}".encode("ascii")
    sig = _b64e(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{TOKEN_VERSION}.{body}.{sig}", payload


def decode_and_verify(
    secret: bytes,
    token: str,
    method: str,
    path: str,
    now: int | None = None,
) -> dict:
    """校验签名、过期时间、方法与路径绑定。成功返回 payload，失败抛 TokenError。

    注意：本函数不处理 nonce（nonce 的一次性消费由数据库层原子完成）。
    """
    now = int(time.time()) if now is None else now

    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_VERSION:
        raise TokenError(MALFORMED)
    _, body, sig = parts

    signing_input = f"{TOKEN_VERSION}.{body}".encode("ascii")
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    try:
        actual = _b64d(sig)
    except Exception:
        raise TokenError(MALFORMED)
    if not hmac.compare_digest(expected, actual):
        raise TokenError(BAD_SIGNATURE)

    try:
        payload = json.loads(_b64d(body))
    except Exception:
        raise TokenError(MALFORMED)
    if not isinstance(payload, dict):
        raise TokenError(MALFORMED)
    m, p, exp = payload.get("m"), payload.get("p"), payload.get("exp")
    if not (isinstance(m, str) and isinstance(p, str) and isinstance(exp, int)):
        raise TokenError(MALFORMED)

    if now >= exp:
        raise TokenError(EXPIRED)
    if m != method.upper():
        raise TokenError(METHOD_MISMATCH)
    try:
        if normalize_path(p) != normalize_path(path):
            raise TokenError(PATH_MISMATCH)
    except ValueError:
        raise TokenError(MALFORMED)
    return payload
