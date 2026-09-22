"""能力令牌 API：签发、验证（含原子 nonce 消费），外加一个演示用受保护下载端点。"""
from __future__ import annotations

import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import db, tokens
from .config import get_settings

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("captoken.main")

_PURGE_INTERVAL_SECONDS = 60
_last_purge = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db.init_db(settings.db_path)  # 启动时初始化数据库
    removed = db.purge_expired(settings.db_path)
    logger.info(
        "数据库已初始化: %s（清理过期 nonce %d 条，TTL 默认 %ds / 上限 %ds）",
        settings.db_path, removed, settings.default_ttl, settings.max_ttl,
    )
    yield


app = FastAPI(
    title="Capability Token API",
    version="1.0.0",
    description="为文件下载等 HTTP 操作签发短期 HMAC 能力令牌，绑定方法与规范化路径，支持一次性 nonce 防重放。",
    lifespan=lifespan,
)


# ---------- 请求 / 响应模型 ----------

class IssueRequest(BaseModel):
    method: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$",
                        description="令牌绑定的 HTTP 方法，如 GET", examples=["GET"])
    path: str = Field(min_length=1, max_length=2048,
                      description="令牌绑定的路径（会被规范化）", examples=["/download/report.pdf"])
    ttl_seconds: int | None = Field(default=None, ge=1,
                                    description="有效期秒数，缺省用服务默认值")
    one_time: bool = Field(default=False, description="是否一次性（验证成功后即失效，防重放）")


class IssueResponse(BaseModel):
    token: str
    token_type: str = "hmac-sha256"
    method: str
    path: str
    expires_at: int
    expires_in: int
    one_time: bool


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)
    method: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$", examples=["GET"])
    path: str = Field(min_length=1, max_length=2048, examples=["/download/report.pdf"])


class VerifyResponse(BaseModel):
    valid: bool
    reason: str | None = None       # 失败原因：malformed / bad_signature / expired /
                                    # method_mismatch / path_mismatch / nonce_invalid
    method: str | None = None
    path: str | None = None
    expires_at: int | None = None
    one_time: bool | None = None


# ---------- 核心逻辑 ----------

def _verify_token_value(token: str, method: str, path: str) -> VerifyResponse:
    """验证令牌；一次性令牌在全部检查通过后原子消费 nonce。"""
    settings = get_settings()
    try:
        payload = tokens.decode_and_verify(settings.secret, token, method, path)
    except tokens.TokenError as exc:
        return VerifyResponse(valid=False, reason=exc.reason)

    nonce = payload.get("n")
    if nonce is not None:
        # 单条 DELETE 原子消费：重放或并发重复使用时只有第一个请求成功
        if not db.consume_nonce(settings.db_path, nonce):
            return VerifyResponse(valid=False, reason=tokens.NONCE_INVALID)

    return VerifyResponse(
        valid=True,
        method=payload["m"],
        path=payload["p"],
        expires_at=payload["exp"],
        one_time=nonce is not None,
    )


def _maybe_purge() -> None:
    global _last_purge
    now = time.monotonic()
    if now - _last_purge >= _PURGE_INTERVAL_SECONDS:
        _last_purge = now
        db.purge_expired(get_settings().db_path)


# ---------- 接口 ----------

@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/tokens", response_model=IssueResponse, status_code=status.HTTP_201_CREATED,
          tags=["tokens"], summary="签发能力令牌")
def issue(req: IssueRequest) -> IssueResponse:
    settings = get_settings()
    ttl = req.ttl_seconds if req.ttl_seconds is not None else settings.default_ttl
    if ttl > settings.max_ttl:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ttl_seconds 超过服务上限 {settings.max_ttl} 秒",
        )

    try:
        nonce = secrets.token_urlsafe(16) if req.one_time else None
        token, payload = tokens.issue_token(
            settings.secret, req.method, req.path, ttl, nonce=nonce,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if nonce is not None:
        db.store_nonce(settings.db_path, nonce, payload["exp"])
        _maybe_purge()

    return IssueResponse(
        token=token,
        method=payload["m"],
        path=payload["p"],
        expires_at=payload["exp"],
        expires_in=ttl,
        one_time=req.one_time,
    )


@app.post("/tokens/verify", response_model=VerifyResponse, tags=["tokens"],
          summary="验证能力令牌（一次性令牌验证成功即消费）")
def verify(req: VerifyRequest) -> VerifyResponse:
    return _verify_token_value(req.token, req.method, req.path)


@app.get("/download/{file_path:path}", tags=["demo"],
         summary="演示端点：凭令牌下载文件")
def download(
    file_path: str,
    request: Request,
    token: str | None = Query(default=None, description="能力令牌（也可用 Authorization: Bearer 传入）"),
) -> FileResponse:
    # 支持 ?token= 或 Authorization: Bearer <token>
    creds = request.headers.get("authorization", "")
    bearer = creds.removeprefix("Bearer ").strip() if creds.startswith("Bearer ") else None
    token_value = token or bearer
    if not token_value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="缺少令牌（?token= 或 Authorization: Bearer）")

    result = _verify_token_value(token_value, "GET", f"/download/{file_path}")
    if not result.valid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"令牌无效: {result.reason}")

    # 令牌已授权该路径；再做一次文件系统层面的目录穿越防护
    root = Path(get_settings().files_dir).resolve()
    target = (root / result.path.removeprefix("/download/")).resolve()
    if root != target and root not in target.parents:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="路径越界")
    if not target.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="文件不存在")
    return FileResponse(target, filename=target.name)
