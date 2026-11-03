"""IM 适配器回归测试（2026-10 对抗审计修复的行为锁定）。

覆盖:
- client 进程内单例（token 生命周期由 SDK provider 负责）；
- 去重表有界；默认只绑回环地址；可选令牌鉴权；
- 真实 HTTP 层：Content-Length 为负/超大 → 400/413（不再挂线程），
  非 JSON 对象 → 400，队列满 → 429，收件箱取后清空。
"""

import http.client
import json
import os
import queue
import threading
from http.server import ThreadingHTTPServer

import pytest

import adapter


def test_default_bind_is_loopback():
	assert adapter.BIND == "127.0.0.1"


def test_dedup_is_bounded(monkeypatch):
	monkeypatch.setattr(adapter, "MAX_EVENTS", 3)
	adapter._seen_events.clear()
	adapter._seen_order.clear()
	assert adapter._dedup_event("a") is False
	assert adapter._dedup_event("a") is True
	for e in ("b", "c", "d"):
		adapter._dedup_event(e)
	assert len(adapter._seen_events) == 3
	assert "a" not in adapter._seen_events  # 最旧的被淘汰


def test_client_is_singleton(monkeypatch):
	"""适配器进程内只建一个 client；构造失败不缓存（下次重试）。"""
	import dh_client

	built = []

	def fake_make():
		built.append(object())
		return built[-1]

	monkeypatch.setattr(adapter, "make_client", fake_make)
	monkeypatch.setattr(adapter, "_client_inst", None)
	assert adapter._client() is adapter._client()
	assert len(built) == 1


def test_inbox_is_bounded(monkeypatch):
	monkeypatch.setattr(adapter, "MAX_INBOX", 5)
	adapter._inbox.clear()
	for i in range(30):
		adapter._reply("u1", f"m{i}")
	assert len(adapter._inbox["u1"]) == 20  # 单户上限 20
	assert adapter._inbox["u1"][0] == "m10"  # 丢最旧
	adapter._inbox.clear()
	for u in ("a", "b", "c"):
		for i in range(3):
			adapter._reply(u, f"{u}{i}")
	total = sum(len(v) for v in adapter._inbox.values())
	assert total <= 5
	assert "a" not in adapter._inbox  # 最旧用户被整体淘汰
	assert "c" in adapter._inbox


def test_authorization_header(monkeypatch):
	h = adapter.Handler.__new__(adapter.Handler)
	monkeypatch.setattr(adapter, "IM_TOKEN", "secret")
	h.headers = {"Authorization": "Bearer secret"}
	assert h._authorized()
	h.headers = {"X-IM-Token": "secret"}
	assert h._authorized()
	h.headers = {"Authorization": "Bearer wrong"}
	assert not h._authorized()
	h.headers = {}
	assert not h._authorized()
	monkeypatch.setattr(adapter, "IM_TOKEN", "")
	assert h._authorized()


# ---- 真实 HTTP 层 ----


@pytest.fixture
def server(monkeypatch):
	monkeypatch.setattr(adapter, "_jobs", queue.Queue(maxsize=1))
	monkeypatch.setattr(adapter, "MAX_BODY", 64)
	monkeypatch.setattr(adapter, "IM_TOKEN", "")
	srv = ThreadingHTTPServer(("127.0.0.1", 0), adapter.Handler)
	threading.Thread(target=srv.serve_forever, daemon=True).start()
	yield srv.server_address[1]
	srv.shutdown()
	srv.server_close()


def _raw_post(port, path, body, content_length, timeout=3):
	conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
	conn.putrequest("POST", path)
	conn.putheader("Content-Type", "application/json")
	conn.putheader("Content-Length", str(content_length))
	conn.endheaders()
	if body:
		conn.send(body)
	resp = conn.getresponse()
	data = resp.read()
	conn.close()
	return resp.status, json.loads(data or b"{}")


def test_negative_content_length_is_400_not_hang(server):
	status, body = _raw_post(server, "/webhook/mock", b"", -1)
	assert status == 400
	assert body["error"] == "bad content-length"


def test_oversized_content_length_is_413(server):
	status, body = _raw_post(server, "/webhook/mock", b"", 10_000_000_000)
	assert status == 413


def test_non_object_json_is_400(server):
	payload = b"[1,2,3]"
	status, body = _raw_post(server, "/webhook/mock", payload, len(payload))
	assert status == 400
	assert body["error"] == "json object required"


def test_queue_full_is_429_and_inbox_roundtrip(server):
	payload = json.dumps({"user": "u1", "text": "hi"}).encode()
	assert _raw_post(server, "/webhook/mock", payload, len(payload))[0] == 202
	assert _raw_post(server, "/webhook/mock", payload, len(payload))[0] == 429  # maxsize=1
	adapter._reply("u1", "answer")
	conn = http.client.HTTPConnection("127.0.0.1", server, timeout=3)
	conn.request("GET", "/mock/inbox/u1?x=1")
	first = json.loads(conn.getresponse().read())
	conn.request("GET", "/mock/inbox/u1")
	second = json.loads(conn.getresponse().read())
	conn.close()
	assert first == {"user": "u1", "messages": ["answer"]}
	assert second["messages"] == []


def test_token_required_when_configured(server, monkeypatch):
	monkeypatch.setattr(adapter, "IM_TOKEN", "s3")
	conn = http.client.HTTPConnection("127.0.0.1", server, timeout=3)
	conn.request("GET", "/mock/inbox/u1")
	assert conn.getresponse().status == 401
	conn.request("GET", "/healthz")
	assert conn.getresponse().status == 200  # 健康检查不鉴权
	conn.request("GET", "/mock/inbox/u1", headers={"X-IM-Token": "s3"})
	assert conn.getresponse().status == 200
	conn.close()
