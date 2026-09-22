"""API 与令牌核心逻辑的端到端测试。环境变量必须在导入 app 之前设置。"""
import os
import tempfile
import time

_tmp = tempfile.mkdtemp(prefix="captoken-test-")
os.environ["TOKEN_SECRET"] = "test-secret-key"
os.environ["TOKEN_DB_PATH"] = os.path.join(_tmp, "tokens.db")
os.environ["TOKEN_DEFAULT_TTL"] = "300"
os.environ["TOKEN_MAX_TTL"] = "3600"
os.environ["FILES_DIR"] = os.path.join(_tmp, "files")
os.makedirs(os.environ["FILES_DIR"], exist_ok=True)
with open(os.path.join(os.environ["FILES_DIR"], "hello.txt"), "w", encoding="utf-8") as f:
    f.write("hello capability token\n")

import pytest
from fastapi.testclient import TestClient

from app import tokens
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # 触发 lifespan：启动时初始化数据库
        yield c


def _issue(client, method="GET", path="/download/hello.txt", ttl=300, one_time=False):
    resp = client.post("/tokens", json={
        "method": method, "path": path, "ttl_seconds": ttl, "one_time": one_time,
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------- API 测试 ----------

def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_issue_and_verify_roundtrip(client):
    issued = _issue(client)
    assert issued["path"] == "/download/hello.txt"
    assert issued["one_time"] is False
    resp = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "GET", "path": "/download/hello.txt",
    })
    body = resp.json()
    assert resp.status_code == 200 and body["valid"] is True, body
    assert body["method"] == "GET" and body["one_time"] is False


def test_verify_method_mismatch(client):
    issued = _issue(client)
    body = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "POST", "path": "/download/hello.txt",
    }).json()
    assert body["valid"] is False and body["reason"] == "method_mismatch"


def test_verify_path_mismatch(client):
    issued = _issue(client)
    body = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "GET", "path": "/download/other.txt",
    }).json()
    assert body["valid"] is False and body["reason"] == "path_mismatch"


def test_verify_bad_signature(client):
    issued = _issue(client)
    tampered = issued["token"][:-2] + ("AA" if not issued["token"].endswith("AA") else "BB")
    body = client.post("/tokens/verify", json={
        "token": tampered, "method": "GET", "path": "/download/hello.txt",
    }).json()
    assert body["valid"] is False and body["reason"] == "bad_signature"


def test_verify_malformed(client):
    body = client.post("/tokens/verify", json={
        "token": "not-a-token", "method": "GET", "path": "/download/hello.txt",
    }).json()
    assert body["valid"] is False and body["reason"] == "malformed"


def test_one_time_nonce_consumed_atomically(client):
    issued = _issue(client, one_time=True)
    req = {"token": issued["token"], "method": "GET", "path": "/download/hello.txt"}
    first = client.post("/tokens/verify", json=req).json()
    second = client.post("/tokens/verify", json=req).json()  # 重放
    assert first["valid"] is True and first["one_time"] is True
    assert second["valid"] is False and second["reason"] == "nonce_invalid"


def test_reusable_token_survives_multiple_verifies(client):
    issued = _issue(client, one_time=False)
    req = {"token": issued["token"], "method": "GET", "path": "/download/hello.txt"}
    for _ in range(3):
        assert client.post("/tokens/verify", json=req).json()["valid"] is True


def test_failed_check_does_not_consume_nonce(client):
    """签名/方法/路径检查失败时不应消耗 nonce，修正后仍可验证通过。"""
    issued = _issue(client, one_time=True)
    bad = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "DELETE", "path": "/download/hello.txt",
    }).json()
    assert bad["valid"] is False and bad["reason"] == "method_mismatch"
    good = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "GET", "path": "/download/hello.txt",
    }).json()
    assert good["valid"] is True


def test_path_normalization_equivalent_forms(client):
    """签发与验证使用等价的不同写法（重复斜杠/点段/末尾斜杠/百分号编码）应匹配。"""
    issued = _issue(client, path="//download/./sub/../hello.txt/")
    assert issued["path"] == "/download/hello.txt"
    body = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "GET", "path": "/download/%68ello.txt",
    }).json()
    assert body["valid"] is True


def test_ttl_cap_enforced(client):
    resp = client.post("/tokens", json={
        "method": "GET", "path": "/download/hello.txt", "ttl_seconds": 999999,
    })
    assert resp.status_code == 400


def test_expired_token_rejected(client):
    issued = _issue(client, ttl=1)
    time.sleep(1.1)
    body = client.post("/tokens/verify", json={
        "token": issued["token"], "method": "GET", "path": "/download/hello.txt",
    }).json()
    assert body["valid"] is False and body["reason"] == "expired"


def test_download_with_token(client):
    issued = _issue(client, one_time=True)
    ok = client.get(f"/download/hello.txt?token={issued['token']}")
    assert ok.status_code == 200 and ok.text == "hello capability token\n"
    replay = client.get(f"/download/hello.txt?token={issued['token']}")  # 重放
    assert replay.status_code == 403 and "nonce_invalid" in replay.text


def test_download_with_bearer_header(client):
    issued = _issue(client)
    resp = client.get("/download/hello.txt",
                      headers={"Authorization": f"Bearer {issued['token']}"})
    assert resp.status_code == 200


def test_download_requires_token(client):
    assert client.get("/download/hello.txt").status_code == 401


def test_download_rejects_wrong_path_token(client):
    issued = _issue(client, path="/download/other.txt")
    resp = client.get(f"/download/hello.txt?token={issued['token']}")
    assert resp.status_code == 403


# ---------- 令牌层单元测试 ----------

def test_normalize_path_rules():
    n = tokens.normalize_path
    assert n("download/a.txt") == "/download/a.txt"
    assert n("/a//b///c") == "/a/b/c"
    assert n("/a/./b/../c") == "/a/c"
    assert n("/a/b/") == "/a/b"
    assert n("/") == "/"
    assert n("/%2e%2e/secret") == "/secret"          # 编码的 .. 同样被解析
    assert n("https://x.com/a/b?y=1#f") == "/a/b"     # 容忍完整 URL
    assert n("/a b/中 文") == "/a%20b/%E4%B8%AD%20%E6%96%87"
    with pytest.raises(ValueError):
        n("")


def test_decode_and_verify_expired_unit():
    token, _ = tokens.issue_token(b"k", "GET", "/x", ttl_seconds=10, now=1000)
    with pytest.raises(tokens.TokenError) as ei:
        tokens.decode_and_verify(b"k", token, "GET", "/x", now=1011)
    assert ei.value.reason == tokens.EXPIRED
    payload = tokens.decode_and_verify(b"k", token, "GET", "/x", now=1009)
    assert payload["exp"] == 1010
