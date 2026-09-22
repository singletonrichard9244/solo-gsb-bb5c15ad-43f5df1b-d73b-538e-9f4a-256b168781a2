# Capability Token API（能力令牌服务）

基于 **FastAPI + SQLite** 的自托管令牌服务：为文件下载等 HTTP 操作签发**短期 HMAC-SHA256 签名能力令牌**。令牌绑定 **HTTP 方法 + 规范化路径**，校验过期时间与签名，并支持**一次性 nonce**——验证成功后原子消费，彻底防止重放。无需任何第三方账号，单容器即可运行。

## 令牌设计

```
v1.<base64url(payload_json)>.<base64url(HMAC-SHA256)>
```

- **签名输入**：ASCII 字符串 `v1.<base64url(payload)>`，保证签发/验证双方字节一致；比对使用 `hmac.compare_digest` 防时序攻击。
- **payload**：`{"m": "GET", "p": "/download/report.pdf", "exp": 1790037180, "n": "可选nonce"}`
- **路径规范化**：百分号解码 → 合并重复斜杠 → 解析 `.`/`..`（已 rooted，无法逃出根）→ 去末尾斜杠 → 按 RFC 3986 重新编码。因此 `//download/./report.txt/` 与 `/download/%72eport.txt` 视为同一路径。
- **一次性 nonce**：签发时生成随机 nonce 存入 SQLite；验证时在签名/过期/绑定**全部通过后**，用单条 `DELETE ... WHERE nonce=? AND expires_at>now` 原子消费并检查影响行数——并发或重放场景下只有第一个请求能成功（SQLite 单语句原子性保证，多 worker 同样安全）。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `POST` | `/tokens` | 签发令牌 |
| `POST` | `/tokens/verify` | 验证令牌（一次性令牌验证成功即消费） |
| `GET` | `/download/{path}` | 演示端点：凭令牌下载文件 |

交互式文档：服务启动后访问 `http://localhost:8000/docs`。

### 签发 `POST /tokens`

```bash
curl -X POST http://localhost:8000/tokens \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/download/report.pdf","ttl_seconds":300,"one_time":true}'
```

```json
{
  "token": "v1.eyJleHAiOj...",
  "token_type": "hmac-sha256",
  "method": "GET",
  "path": "/download/report.pdf",
  "expires_at": 1790037180,
  "expires_in": 300,
  "one_time": true
}
```

### 验证 `POST /tokens/verify`

```bash
curl -X POST http://localhost:8000/tokens/verify \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","method":"GET","path":"/download/report.pdf"}'
```

成功：`{"valid": true, "method": "GET", "path": "/download/report.pdf", "expires_at": ..., "one_time": true}`

失败（HTTP 200，`valid: false` + 结构化原因）：

| reason | 含义 |
|---|---|
| `malformed` | 令牌格式非法 |
| `bad_signature` | 签名校验失败 |
| `expired` | 已过期 |
| `method_mismatch` | HTTP 方法不匹配 |
| `path_mismatch` | 路径不匹配 |
| `nonce_invalid` | nonce 不存在/已消费/已过期（重放） |

> 注意：一次性令牌**验证成功即消费**。调用方应在验证通过后立即放行资源，不要先“试一下”再用。

### 演示下载 `GET /download/{path}`

```bash
curl "http://localhost:8000/download/report.pdf?token=<token>"
# 或
curl -H "Authorization: Bearer <token>" http://localhost:8000/download/report.pdf
```

文件从 `FILES_DIR` 目录提供，带目录穿越防护；令牌无效返回 403，缺少令牌返回 401。

## 快速开始

### Docker Compose（推荐）

```bash
export TOKEN_SECRET=$(openssl rand -hex 32)   # 生产必须设置固定密钥
docker compose up --build
```

### 本地运行

```bash
pip install -r requirements.txt
export TOKEN_SECRET=$(openssl rand -hex 32)
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

启动时自动初始化 SQLite（建表 + WAL + 清理过期 nonce），服务监听 **8000** 端口。

### 运行测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -q
```

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `TOKEN_SECRET` | —（随机生成） | HMAC 密钥。**生产必须显式设置**；未设置时生成临时密钥，重启后旧令牌全部失效 |
| `TOKEN_DB_PATH` | `./data/tokens.db`（容器内 `/data/tokens.db`） | SQLite 路径 |
| `TOKEN_DEFAULT_TTL` | `300` | 默认有效期（秒） |
| `TOKEN_MAX_TTL` | `3600` | 签发有效期上限（秒） |
| `FILES_DIR` | `./files`（容器内 `/files`） | 演示下载目录 |

## 安全说明

- 令牌是**持有者凭证**：请只在 TLS 下传输，并按需缩短 TTL。
- 签发接口本身未鉴权，部署时应放在内网/网关之后，或在反向代理层加访问控制。
- nonce 表会随过期令牌残留，服务启动时及运行中每分钟自动清理。
- 查询串不参与绑定，令牌只约束「方法 + 路径」。

## 项目结构

```
app/
  config.py   # 环境变量配置
  tokens.py   # 令牌签发/验证、路径规范化（纯函数）
  db.py       # SQLite：nonce 存储与原子消费
  main.py     # FastAPI 接口
tests/test_api.py
Dockerfile / docker-compose.yml / requirements*.txt
```
